// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	sub, err := cm.Sub(component.NewIDWithName(metadata.Type, "").String())
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(cfg))

	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
	assert.Equal(t, &Config{
		APIToken: "test-token",
		Endpoint: "https://app.graphql-hive.com/graphql",
	}, cfg)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectedErr string
	}{
		{
			name: "valid config",
			config: &Config{
				APIToken: "test-token",
				Endpoint: "https://app.graphql-hive.com/graphql",
			},
			expectedErr: "",
		},
		{
			name: "missing api token",
			config: &Config{
				Endpoint: "https://app.graphql-hive.com/graphql",
			},
			expectedErr: "no API token provided",
		},
		{
			name: "missing endpoint",
			config: &Config{
				APIToken: "test-token",
			},
			expectedErr: "no endpoint provided",
		},
		{
			name:        "empty config",
			config:      &Config{},
			expectedErr: "no API token provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr)
			}
		})
	}
}
