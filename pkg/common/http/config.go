package http

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/basti/zdvv/pkg/common"
)

// HTTPConfig holds HTTP server specific configuration settings
type HTTPConfig struct {
	Addr                 string   `env:"ZDVV_HTTP_ADDR"`
	CertFile             string   `env:"ZDVV_HTTP_CERT_FILE"`
	KeyFile              string   `env:"ZDVV_HTTP_KEY_FILE"`
	InsecureListenAddr   string   `env:"ZDVV_HTTP_INSECURE_ADDR"` // Address for the insecure HTTP listener
	Hostname             string   `env:"ZDVV_HTTP_HOSTNAME"`      // Hostname for TLS certificate (Let's Encrypt)
	HTTP2Enabled         bool     `env:"ZDVV_HTTP_HTTP2_ENABLED"`
	HTTP3Enabled         bool     `env:"ZDVV_HTTP_HTTP3_ENABLED"`
	EnableInsecureListen bool     `env:"ZDVV_HTTP_ENABLE_INSECURE_LISTENER"` // Flag to enable the insecure HTTP listener
	AllowedOrigins       []string // No tag, handled manually
}

// NewHTTPConfig creates a new HTTPConfig, populating it from environment variables.
func NewHTTPConfig() (*HTTPConfig, error) {
	cfg := &HTTPConfig{
		Addr:                 ":443", // Default will be overridden by env if ZDVV_HTTP_ADDR is set
		HTTP2Enabled:         true,
		HTTP3Enabled:         true,
		EnableInsecureListen: false,   // Default will be overridden by env if ZDVV_HTTP_ENABLE_INSECURE_LISTENER is set
		InsecureListenAddr:   ":8080", // Default will be overridden by env if ZDVV_HTTP_INSECURE_ADDR is set
		AllowedOrigins:       []string{"*"},
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

	// Validations
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, fmt.Errorf("HTTP address (ZDVV_HTTP_ADDR) must be set and not empty")
	}

	// ZDVV_HTTP_HOSTNAME cannot be an empty string if set
	if _, ok := os.LookupEnv("ZDVV_HTTP_HOSTNAME"); ok && strings.TrimSpace(cfg.Hostname) == "" {
		return nil, fmt.Errorf("ZDVV_HTTP_HOSTNAME cannot be an empty string if set")
	}

	// If one of CertFile or KeyFile is provided, the other must also be provided.
	if (cfg.CertFile != "" && cfg.KeyFile == "") || (cfg.CertFile == "" && cfg.KeyFile != "") {
		return nil, fmt.Errorf("both ZDVV_HTTP_CERT_FILE and ZDVV_HTTP_KEY_FILE must be set if HTTPS is to be enabled, or neither should be set")
	}

	// Validate insecure listener settings
	if cfg.EnableInsecureListen {
		if strings.TrimSpace(cfg.InsecureListenAddr) == "" {
			return nil, fmt.Errorf("insecure address (ZDVV_HTTP_INSECURE_ADDR) must be set and not empty if insecure listener is enabled")
		}
	}

	// If HTTP3 is enabled, and a Hostname is not provided for autocert, then CertFile and KeyFile must be provided.
	if cfg.HTTP3Enabled && cfg.Hostname == "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return nil, fmt.Errorf("when HTTP/3 is enabled (ZDVV_HTTP_HTTP3_ENABLED is not 'false' or is not set) and ZDVV_HTTP_HOSTNAME is not set for autocert, then ZDVV_HTTP_CERT_FILE and ZDVV_HTTP_KEY_FILE must be provided")
	}

	return cfg, nil
}

// LogSettings logs the HTTP-specific configuration settings
func (c *HTTPConfig) LogSettings() {
	log.Printf("HTTP Listen Address: %s", c.Addr)
	log.Printf("TLS Certificate File: %s", c.CertFile)
	log.Printf("TLS Key File: %s", c.KeyFile)
	if c.Hostname != "" {
		log.Printf("TLS Hostname (Let's Encrypt): %s", c.Hostname)
	}
	if c.HTTP2Enabled {
		log.Println("HTTP/2 Support: Enabled")
	} else {
		log.Println("HTTP/2 Support: Disabled")
	}
	if c.HTTP3Enabled {
		log.Println("HTTP/3 Support: Enabled")
	} else {
		log.Println("HTTP/3 Support: Disabled")
	}
	log.Printf("Allowed CORS Origins: %s", strings.Join(c.AllowedOrigins, ", "))
	// Logging for insecure listener will be handled by the server logic based on global insecure flag.
}
