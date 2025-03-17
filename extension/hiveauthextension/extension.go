package hiveauthextension

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

var _ extensionauth.Server = (*hiveAuthExtension)(nil)

type hiveAuthExtension struct {
	logger *zap.Logger
	config *Config
	client *http.Client
	group  singleflight.Group
	cache  *cache.Cache
}

func (h *hiveAuthExtension) Start(ctx context.Context, host component.Host) error {
	h.logger.Info("Starting hive auth extension", zap.String("endpoint", h.config.Endpoint), zap.Duration("timeout", h.config.Timeout))
	return nil
}

func (h *hiveAuthExtension) Shutdown(ctx context.Context) error {
	h.logger.Info("Shutting down hive auth extension")
	return nil
}

type AuthStatusError struct {
	Code int
	Msg  string
}

func (e *AuthStatusError) Error() string {
	return fmt.Sprintf("authentication failed: status %d, %s", e.Code, e.Msg)
}

func getAuthHeader(h map[string][]string) string {
	const (
		canonicalHeaderKey = "Authorization"
		metadataKey        = "authorization"
	)

	authHeaders, ok := h[canonicalHeaderKey]

	if !ok {
		authHeaders, ok = h[metadataKey]
	}

	if !ok {
		for k, v := range h {
			if strings.EqualFold(k, metadataKey) {
				authHeaders = v
				break
			}
		}
	}

	if len(authHeaders) == 0 {
		return ""
	}

	return authHeaders[0]
}

type authResult struct {
	err error
}

func (h *hiveAuthExtension) doAuthRequest(ctx context.Context, auth string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", h.config.Endpoint, nil)
	if err != nil {
		h.logger.Error("failed to create auth request", zap.Error(err))
		return err
	}
	req.Header.Set("Authorization", auth)

	// Retry parameters.
	const maxRetries = 3
	const retryDelay = 100 * time.Millisecond
	var lastStatus int

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := h.client.Do(req)
		if err != nil {
			h.logger.Error("error calling authentication service", zap.Error(err))
			return err
		}
		lastStatus = resp.StatusCode

		// Success.
		if resp.StatusCode == http.StatusOK {
			h.logger.Debug("authentication succeeded")
			resp.Body.Close()
			return nil
		}

		// For 5XX responses, retry.
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			h.logger.Warn("received 5xx response, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("status", resp.Status))
			resp.Body.Close()

			select {
			case <-time.After(retryDelay):
				// Continue to next attempt.
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}

		// For non-retryable errors.
		errMsg := fmt.Sprintf("authentication failed: received status %s", resp.Status)
		h.logger.Warn(errMsg)
		resp.Body.Close()
		return &AuthStatusError{
			Code: resp.StatusCode,
			Msg:  "non-retryable error",
		}
	}

	return &AuthStatusError{
		Code: lastStatus,
		Msg:  "authentication failed after retries",
	}
}

func (h *hiveAuthExtension) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	auth := getAuthHeader(headers)
	if auth == "" {
		return ctx, errors.New("No auth provided")
	}

	if cached, found := h.cache.Get(auth); found {
		res := cached.(authResult)
		return ctx, res.err
	}

	// Deduplicate concurrent calls.
	_, err, _ := h.group.Do(auth, func() (interface{}, error) {
		// Call the externalized HTTP request function.
		return nil, h.doAuthRequest(ctx, auth)
	})

	var ttl time.Duration
	if err == nil {
		ttl = 30 * time.Second
	} else {
		ttl = 10 * time.Second
	}
	h.cache.Set(auth, authResult{err: err}, ttl)

	return ctx, err
}

func newHiveAuthExtension(
	logger *zap.Logger,
	cfg component.Config,
) (extensionauth.Server, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, errors.New("invalid configuration")
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return &hiveAuthExtension{
		logger: logger,
		config: c,
		client: &http.Client{
			Timeout: c.Timeout,
		},
		cache: cache.New(30*time.Second, time.Minute),
	}, nil
}
