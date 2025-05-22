// Package config provides configuration handling for the ZDVV application.
package config

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
)

// Config holds all application configuration settings
type Config struct {
	// Server settings
	Addr         string
	CertFile     string
	KeyFile      string
	InsecureAddr string // Used when running in insecure mode
	Hostname     string // Hostname for TLS certificate and Let's Encrypt

	// Authentication settings
	JWTSecret  []byte
	AdminToken string
	Insecure   bool

	// Protocol support
	HTTP2Enabled bool
	HTTP3Enabled bool

	// Version information
	Version string
}

// NewConfig creates and returns a new Config struct with values from flags and environment variables
func NewConfig() (*Config, error) {
	// Default configuration
	cfg := &Config{
		Addr:         ":443",
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		InsecureAddr: ":8080",
		HTTP2Enabled: true,
		HTTP3Enabled: true,
		Insecure:     false,
		Version:      "1.0.0",
		Hostname:     "",
	}

	// Define command line flags
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "Listen address")
	flag.StringVar(&cfg.CertFile, "cert", cfg.CertFile, "TLS certificate file")
	flag.StringVar(&cfg.KeyFile, "key", cfg.KeyFile, "TLS key file")
	flag.StringVar(&cfg.Hostname, "hostname", "", "Hostname for TLS certificate (required for Let's Encrypt)")

	jwtSecretFlag := flag.String("jwt-secret", "", "JWT secret key")
	adminTokenFlag := flag.String("admin-token", "", "Admin API token")

	disableHTTP2 := flag.Bool("no-http2", false, "Disable HTTP/2 support")
	disableHTTP3 := flag.Bool("no-http3", false, "Disable HTTP/3 support")
	flag.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "Skip JWT authentication (insecure mode)")

	// Parse flags
	flag.Parse()

	// Process boolean flags for protocol support
	cfg.HTTP2Enabled = !*disableHTTP2
	cfg.HTTP3Enabled = !*disableHTTP3

	// Handle JWT secret from flag or environment variable
	jwtSecret := *jwtSecretFlag
	if !cfg.Insecure {
		if jwtSecret == "" {
			jwtSecret = os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				return nil, fmt.Errorf("jwt secret must be provided via -jwt-secret flag or JWT_SECRET environment variable when not in insecure mode")
			}
		}
		decodedSecret, err := base64.StdEncoding.DecodeString(jwtSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT secret from base64: %v", err)
		}
		cfg.JWTSecret = decodedSecret
	}

	// Handle admin token from flag or environment variable
	adminToken := *adminTokenFlag
	if !cfg.Insecure {
		if adminToken == "" {
			adminToken = os.Getenv("ADMIN_TOKEN")
			if adminToken == "" {
				return nil, fmt.Errorf("admin token must be provided via -admin-token flag or ADMIN_TOKEN environment variable when not in insecure mode")
			}
		}
		cfg.AdminToken = adminToken
	}

	return cfg, nil
}

// LogSettings logs the current configuration settings
func (c *Config) LogSettings() {
	log.Printf("Server address: %s", c.Addr)
	log.Printf("TLS certificate file: %s", c.CertFile)
	log.Printf("TLS key file: %s", c.KeyFile)
	if c.Hostname != "" {
		log.Printf("Server hostname: %s", c.Hostname)
	}

	if c.Insecure {
		log.Println("WARNING: Running in insecure mode - authentication disabled")
		log.Printf("Insecure HTTP server address: %s", c.InsecureAddr)
	} else {
		log.Println("Running in secure mode with JWT authentication")
		// Don't log secret values, but confirm they're set
		if len(c.JWTSecret) > 0 {
			log.Println("JWT secret: [SET]")
		}
		if c.AdminToken != "" {
			log.Println("Admin token: [SET]")
		}
	}

	// Log protocol support
	protocols := []string{"HTTP/1.1"}
	if c.HTTP2Enabled {
		protocols = append(protocols, "HTTP/2")
		log.Println("HTTP/2 support: enabled")
	} else {
		log.Println("HTTP/2 support: disabled")
	}

	if c.HTTP3Enabled {
		protocols = append(protocols, "HTTP/3")
		log.Println("HTTP/3 support: enabled")
	} else {
		log.Println("HTTP/3 support: disabled")
	}

	log.Printf("Enabled protocols: %v", protocols)
}
