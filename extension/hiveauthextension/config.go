// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hiveauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/hiveauthextension"

import (
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"
)

// Config specifies how the Hive authentication data should be obtained.
type Config struct {
	// APIToken specifies the API token to use for Hive authentication.
	APIToken configopaque.String `mapstructure:"api_token,omitempty"`

	// Endpoint specifies the Hive GraphQL endpoint.
	Endpoint string `mapstructure:"endpoint,omitempty"`

	// prevent unkeyed literal initialization
	_ struct{}
}

var (
	_                     component.Config = (*Config)(nil)
	errNoAPITokenProvided                  = errors.New("no API token provided")
	errNoEndpointProvided                  = errors.New("no endpoint provided")
)

// Validate checks if the extension configuration is valid
func (cfg *Config) Validate() error {
	if cfg.APIToken == "" {
		return errNoAPITokenProvided
	}
	if cfg.Endpoint == "" {
		return errNoEndpointProvided
	}
	return nil
}
