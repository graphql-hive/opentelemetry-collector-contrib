// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension"

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

var _ credentials.PerRPCCredentials = (*PerRPCAuth)(nil)

// PerRPCAuth is a gRPC credentials.PerRPCCredentials implementation that returns an 'authorization' header.
type PerRPCAuth struct {
	auth *HiveAuth
}

// GetRequestMetadata returns the request metadata to be used with the RPC.
func (c *PerRPCAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": c.auth.authorizationValue()}, nil
}

// RequireTransportSecurity always returns true for this implementation.
func (c *PerRPCAuth) RequireTransportSecurity() bool {
	return true
}

var (
	_ extension.Extension      = (*HiveAuth)(nil)
	_ extensionauth.Server     = (*HiveAuth)(nil)
	_ extensionauth.HTTPClient = (*HiveAuth)(nil)
	_ extensionauth.GRPCClient = (*HiveAuth)(nil)
)

// HiveAuth is an implementation of extensionauth interfaces for Hive GraphQL authentication.
type HiveAuth struct {
	apiToken string
	endpoint string
	logger   *zap.Logger
	component.StartFunc
	component.ShutdownFunc
}

func newHiveAuth(cfg *Config, logger *zap.Logger) *HiveAuth {
	return &HiveAuth{
		apiToken: string(cfg.APIToken),
		endpoint: cfg.Endpoint,
		logger:   logger,
	}
}

// authorizationValue returns the Authorization header value for Hive authentication
func (h *HiveAuth) authorizationValue() string {
	return "Bearer " + h.apiToken
}

// PerRPCCredentials returns PerRPCAuth an implementation of credentials.PerRPCCredentials
func (h *HiveAuth) PerRPCCredentials() (credentials.PerRPCCredentials, error) {
	return &PerRPCAuth{
		auth: h,
	}, nil
}

// RoundTripper implements extensionauth.HTTPClient interface
func (h *HiveAuth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	return &HiveAuthRoundTripper{
		baseTransport: base,
		auth:          h,
	}, nil
}

// Authenticate checks whether the given context contains valid auth data for server auth
func (h *HiveAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	auth, ok := headers["authorization"]
	if !ok {
		auth, ok = headers["Authorization"]
	}
	if !ok || len(auth) == 0 {
		return ctx, errors.New("missing or empty authorization header")
	}
	
	token := auth[0]
	expectedToken := h.authorizationValue()
	
	if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(token)) == 1 {
		return ctx, nil
	}
	
	return ctx, fmt.Errorf("invalid Hive API token")
}

// HiveAuthRoundTripper intercepts and adds Hive authorization headers to each http request.
type HiveAuthRoundTripper struct {
	baseTransport http.RoundTripper
	auth          *HiveAuth
}

// RoundTrip modifies the original request and adds Hive authorization headers.
func (interceptor *HiveAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	if req2.Header == nil {
		req2.Header = make(http.Header)
	}
	req2.Header.Set("Authorization", interceptor.auth.authorizationValue())
	// Add additional Hive-specific headers if needed
	req2.Header.Set("User-Agent", "OpenTelemetry-Collector-Contrib")
	return interceptor.baseTransport.RoundTrip(req2)
}