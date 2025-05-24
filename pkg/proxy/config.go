// Package proxy provides the proxy server implementation.
package proxy

import (
	"fmt"
	"log"

	"github.com/basti/zdvv/pkg/common"
)

// Config holds all application configuration settings
type Config struct {
	Insecure bool `env:"ZDVV_INSECURE,default=false"` // Global insecure mode flag
	// Control server settings
	ControlServerURL    string `env:"ZDVV_CONTROL_SERVER_URL"`
	ControlServerSecret string `env:"ZDVV_CONTROL_SERVER_SHARED_SECRET"`
}

// NewConfig creates and returns a new Config struct with values from environment variables
func NewConfig() (*Config, error) {
	cfg := &Config{
		// Defaults for fields like Insecure are handled by struct tags.
		// JWTPublicKeyFile and AdminToken will be empty if not set by env and no default tag.
	}

	// Load tagged fields from environment variables
	if err := common.LoadEnvToStruct(cfg); err != nil {
		return nil, fmt.Errorf("error loading proxy config from environment: %w", err)
	}
	return cfg, nil
}

// LogSettings logs the current proxy-specific configuration settings
func (c *Config) LogSettings() {
	if c.Insecure {
		log.Println("Global Insecure Mode: ENABLED (JWT authentication disabled, may affect HTTP listener)")
	}
	if c.ControlServerURL != "" {
		log.Printf("Control Server URL: %s", c.ControlServerURL)
		log.Println("Control Server Shared Secret: [SET]")
	} else {
		log.Println("Control Server integration: DISABLED")
	}
}
