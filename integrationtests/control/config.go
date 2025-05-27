/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"fmt"

	"github.com/strseb/zdvv/pkg/common"
)

// TestConfig holds the configuration for integration tests
type TestConfig struct {
	ControlURL  string `env:"ZDVV_CONTROL_URL,default=http://localhost:8080"`
	APIKey      string `env:"ZDVV_API_KEY,default=my-secret-key"`
	Debug       bool   `env:"ZDVV_TEST_DEBUG,default=false"`
	HTTPTimeout int    `env:"ZDVV_HTTP_TIMEOUT,default=10"` // Timeout in seconds
}

// LoadTestConfig loads the test configuration from environment variables
func LoadTestConfig() (*TestConfig, error) {
	cfg := &TestConfig{}
	if err := common.LoadEnvToStruct(cfg); err != nil {
		return nil, fmt.Errorf("error loading test config from environment: %w", err)
	}

	// Validate config
	if cfg.ControlURL == "" {
		return nil, fmt.Errorf("ZDVV_CONTROL_URL must be set")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ZDVV_API_KEY must be set")
	}

	return cfg, nil
}

// SetupTest prepares the test environment
func SetupTest() (*TestConfig, error) {
	// Import dotenv file if available
	common.ImportDotenv()

	// Load configuration
	cfg, err := LoadTestConfig()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
