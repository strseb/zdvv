// package main provides the proxy server implementation.
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/strseb/zdvv/pkg/common"
)

// Config holds all application configuration settings
type ProxyConfig struct {
	Insecure bool `env:"ZDVV_INSECURE,default=false"` // Global insecure mode flag
	// Control server settings
	ControlServerURL    string `env:"ZDVV_CONTROL_SERVER_URL"`
	ControlServerSecret string `env:"ZDVV_CONTROL_SERVER_SHARED_SECRET"`
	// Server information for registration
	Latitude           float64 `env:"ZDVV_LATITUDE,default=0"`
	Longitude          float64 `env:"ZDVV_LONGITUDE,default=0"`
	City               string  `env:"ZDVV_CITY,default=Unknown"`
	Country            string  `env:"ZDVV_COUNTRY,default=Unknown"`
	SupportsConnectTCP bool    `env:"ZDVV_SUPPORTS_CONNECT_TCP,default=true"`
	SupportsConnectUDP bool    `env:"ZDVV_SUPPORTS_CONNECT_UDP,default=false"`
	SupportsConnectIP  bool    `env:"ZDVV_SUPPORTS_CONNECT_IP,default=false"`
	ProxyEndpointURL   string  `env:"ZDVV_PROXY_ENDPOINT_URL,default=https://proxy.example.com"`
}

// NewConfig creates and returns a new Config struct with values from environment variables
func NewProxyConfig() (*ProxyConfig, error) {
	cfg := &ProxyConfig{
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
func (c *ProxyConfig) LogSettings() {
	if c.Insecure {
		log.Println("Global Insecure Mode: ENABLED (JWT authentication disabled, may affect HTTP listener)")
	}
	if c.ControlServerURL != "" {
		log.Printf("Control Server URL: %s", c.ControlServerURL)
		log.Println("Control Server Shared Secret: [SET]")
	} else {
		log.Println("Control Server integration: DISABLED")
	}

	log.Printf("Location: %s, %s (%.4f, %.4f)",
		c.City, c.Country, c.Latitude, c.Longitude)
	log.Printf("Capabilities: TCP=%v, UDP=%v, IP=%v",
		c.SupportsConnectTCP, c.SupportsConnectUDP, c.SupportsConnectIP)

}

// CreateServer creates a common.Server object from the current configuration
func (c *ProxyConfig) CreateServer(hostname string) common.Server {
	// If ProxyURL isn't set, construct it using the hostname

	return common.Server{
		ProxyURL:           c.ProxyEndpointURL,
		Latitude:           c.Latitude,
		Longitude:          c.Longitude,
		City:               c.City,
		Country:            c.Country,
		SupportsConnectTCP: c.SupportsConnectTCP,
		SupportsConnectUDP: c.SupportsConnectUDP,
		SupportsConnectIP:  c.SupportsConnectIP,
	}
}

// HTTPConfig holds HTTP server specific configuration settings
type HTTPConfig struct {
	HTTPAddr       string   `env:"ZDVV_HTTP_ADDR"`        // Address for the plain HTTP listener
	HTTPSAddr      string   `env:"ZDVV_HTTPS_ADDR"`       // Address for the HTTPS listener
	CertFile       string   `env:"ZDVV_HTTPS_CERT_FILE"`  // Path to the TLS certificate file
	KeyFile        string   `env:"ZDVV_HTTPS_KEY_FILE"`   // Path to the TLS key file
	Hostname       string   `env:"ZDVV_HTTPS_HOSTNAME"`   // Hostname for TLS certificate (Let's Encrypt)
	HTTPEnabled    bool     `env:"ZDVV_HTTP_ENABLED"`     // Flag to enable the plain HTTP listener
	HTTPSV1Enabled bool     `env:"ZDVV_HTTPS_V1_ENABLED"` // Enable HTTPS/1.1 support
	HTTPSV2Enabled bool     `env:"ZDVV_HTTPS_V2_ENABLED"` // Enable HTTPS/2 support
	HTTPSV3Enabled bool     `env:"ZDVV_HTTPS_V3_ENABLED"` // Enable HTTPS/3 support
	AllowedOrigins []string // No tag, handled manually
}

// NewHTTPConfig creates a new HTTPConfig, populating it from environment variables.
func NewHTTPConfig() (*HTTPConfig, error) {
	cfg := &HTTPConfig{
		HTTPAddr:       ":80",  // Default HTTP address
		HTTPSAddr:      ":443", // Default HTTPS address
		HTTPSV1Enabled: true,   // Default to HTTP/1.1 support enabled
		HTTPSV2Enabled: true,   // Default to HTTP/2 support enabled
		HTTPSV3Enabled: true,   // Default to HTTP/3 support enabled
		HTTPEnabled:    false,  // Default to disabled plain HTTP
		AllowedOrigins: []string{"*"},
	}

	// Load tagged fields from environment variables
	if err := common.LoadEnvToStruct(cfg); err != nil {
		return nil, fmt.Errorf("error loading HTTP config from environment: %w", err)
	}

	// Manual handling for ZDVV_HTTP_ALLOWED_ORIGINS
	if val, ok := os.LookupEnv("ZDVV_HTTP_ALLOWED_ORIGINS"); ok {
		if strings.TrimSpace(val) == "" {
			cfg.AllowedOrigins = []string{"*"} // Explicit empty string means default to all
		} else {
			origins := strings.Split(val, ",")
			cfg.AllowedOrigins = make([]string, 0, len(origins))
			for _, origin := range origins {
				trimmedOrigin := strings.TrimSpace(origin)
				if trimmedOrigin != "" { // Avoid adding empty strings if input is like "a,,b"
					cfg.AllowedOrigins = append(cfg.AllowedOrigins, trimmedOrigin)
				}
			}
			if len(cfg.AllowedOrigins) == 0 { // If all origins were empty strings after trim (e.g. ",, ,")
				cfg.AllowedOrigins = []string{"*"} // Default to all
			}
		}
	}

	// If one of CertFile or KeyFile is provided, the other must also be provided.
	if (cfg.CertFile != "" && cfg.KeyFile == "") || (cfg.CertFile == "" && cfg.KeyFile != "") {
		return nil, fmt.Errorf("both ZDVV_HTTPS_CERT_FILE and ZDVV_HTTPS_KEY_FILE must be set if HTTPS is to be enabled, or neither should be set")
	}

	// Validate HTTP listener settings
	if cfg.HTTPEnabled {
		if strings.TrimSpace(cfg.HTTPAddr) == "" {
			return nil, fmt.Errorf("HTTP address (ZDVV_HTTP_ADDR) must be set and not empty if HTTP is enabled")
		}
	}

	// If HTTPS/3 is enabled, and a Hostname is not provided for autocert, then CertFile and KeyFile must be provided.
	if (cfg.HTTPSV1Enabled || cfg.HTTPSV2Enabled || cfg.HTTPSV3Enabled) &&
		cfg.Hostname == "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
		cfg.LogSettings()
		return nil, fmt.Errorf("when HTTPS is enabled and ZDVV_HTTPS_HOSTNAME is not set for autocert, then ZDVV_HTTPS_CERT_FILE and ZDVV_HTTPS_KEY_FILE must be provided")
	}

	return cfg, nil
}

// LogSettings logs the HTTP-specific configuration settings
func (c *HTTPConfig) LogSettings() {
	log.Printf("HTTPS Listen Address: %s", c.HTTPSAddr)
	if c.HTTPEnabled {
		log.Printf("HTTP Listen Address: %s", c.HTTPAddr)
	} else {
		log.Println("HTTP Server: Disabled")
	}
	log.Printf("TLS Certificate File: %s", c.CertFile)
	log.Printf("TLS Key File: %s", c.KeyFile)
	if c.Hostname != "" {
		log.Printf("TLS Hostname (Let's Encrypt): %s", c.Hostname)
	}
	if c.HTTPSV1Enabled {
		log.Println("HTTPS/1.1 Support: Enabled")
	} else {
		log.Println("HTTPS/1.1 Support: Disabled")
	}
	if c.HTTPSV2Enabled {
		log.Println("HTTPS/2 Support: Enabled")
	} else {
		log.Println("HTTPS/2 Support: Disabled")
	}
	if c.HTTPSV3Enabled {
		log.Println("HTTPS/3 Support: Enabled")
	} else {
		log.Println("HTTPS/3 Support: Disabled")
	}
	log.Printf("Allowed CORS Origins: %s", strings.Join(c.AllowedOrigins, ", "))
}
