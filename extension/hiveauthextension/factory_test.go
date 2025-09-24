// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension/internal/metadata"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestCreateExtension(t *testing.T) {
	cfg := &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}

	ext, err := createExtension(context.Background(), extensiontest.NewNopSettings(extensiontest.NopType), cfg)
	require.NoError(t, err)
	assert.NotNil(t, ext)
}

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	assert.NotNil(t, factory)
	assert.Equal(t, metadata.Type, factory.Type())
}