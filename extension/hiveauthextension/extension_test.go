// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHiveAuth_AuthorizationValue(t *testing.T) {
	cfg := &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}

	auth := newHiveAuth(cfg, zap.NewNop())
	authValue := auth.authorizationValue()

	assert.Equal(t, "Bearer test-token", authValue)
}

func TestHiveAuth_PerRPCCredentials(t *testing.T) {
	cfg := &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}

	auth := newHiveAuth(cfg, zap.NewNop())
	creds, err := auth.PerRPCCredentials()

	require.NoError(t, err)
	assert.NotNil(t, creds)

	// Test RequireTransportSecurity
	assert.True(t, creds.RequireTransportSecurity())

	// Test GetRequestMetadata
	metadata, err := creds.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-token", metadata["authorization"])
}

func TestHiveAuth_RoundTripper(t *testing.T) {
	cfg := &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}

	auth := newHiveAuth(cfg, zap.NewNop())
	base := http.DefaultTransport

	rt, err := auth.RoundTripper(base)
	require.NoError(t, err)
	assert.NotNil(t, rt)

	// Test that it's the correct type
	_, ok := rt.(*HiveAuthRoundTripper)
	assert.True(t, ok)
}

func TestHiveAuth_Authenticate(t *testing.T) {
	cfg := &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}

	auth := newHiveAuth(cfg, zap.NewNop())
	ctx := context.Background()

	tests := []struct {
		name        string
		headers     map[string][]string
		expectError bool
	}{
		{
			name: "valid authorization header",
			headers: map[string][]string{
				"authorization": {"Bearer test-token"},
			},
			expectError: false,
		},
		{
			name: "valid Authorization header (capitalized)",
			headers: map[string][]string{
				"Authorization": {"Bearer test-token"},
			},
			expectError: false,
		},
		{
			name: "invalid token",
			headers: map[string][]string{
				"authorization": {"Bearer wrong-token"},
			},
			expectError: true,
		},
		{
			name:        "missing authorization header",
			headers:     map[string][]string{},
			expectError: true,
		},
		{
			name: "empty authorization header",
			headers: map[string][]string{
				"authorization": {},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultCtx, err := auth.Authenticate(ctx, tt.headers)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, ctx, resultCtx)
			}
		})
	}
}
