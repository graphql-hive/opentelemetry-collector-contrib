// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension/internal/metadata"
)

// NewFactory creates a factory for the Hive Authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newHiveAuth(cfg.(*Config), set.Logger), nil
}
