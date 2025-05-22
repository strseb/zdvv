// Package config provides configuration handling for the ZDVV application.
package config

import (
	"crypto/tls"
	"log"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// GetTLSConfig builds a TLS configuration based on the current application settings.
// It supports both static certificates and automatic certificates via Let's Encrypt.
func (c *Config) GetTLSConfig() (*tls.Config, error) {
	// Basic TLS configuration with protocol support
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	// Add HTTP/2 support if enabled
	if c.HTTP2Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
	}

	// Add HTTP/3 support if enabled
	if c.HTTP3Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")
	}

	// Check if certificate files exist
	_, certErr := os.Stat(c.CertFile)
	_, keyErr := os.Stat(c.KeyFile)
	certFilesExist := certErr == nil && keyErr == nil

	// If certificate files exist, use them
	if certFilesExist {
		log.Printf("Using existing certificate files: %s and %s", c.CertFile, c.KeyFile)
		// Let the standard library handle loading the certificate files during server startup
		return tlsConfig, nil
	}

	// If no certificate files and no hostname, we can't use Let's Encrypt
	if c.Hostname == "" {
		log.Printf("No certificate files found and no hostname provided.")
		log.Printf("Either provide certificate files or specify a hostname for Let's Encrypt.")
		return tlsConfig, nil
	}

	// Set up Let's Encrypt autocert manager
	log.Printf("No certificate files found. Setting up Let's Encrypt for hostname: %s", c.Hostname)
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(c.Hostname), // Only allow the specified hostname
		Cache:      autocert.DirCache("certs"),         // Cache certificates in local directory
		Email:      getEmailFromEnv(),                  // Use email from environment or empty
	}

	// Configure TLS with autocert
	tlsConfig.GetCertificate = certManager.GetCertificate
	// For HTTP-01 challenge, the client cert feature is disabled
	tlsConfig.ClientAuth = tls.NoClientCert
	// Set client key for ACME ALPN TLS-ALPN-01 challenge
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, acme.ALPNProto)

	log.Println("Configured automatic TLS certificates via Let's Encrypt")
	return tlsConfig, nil
}

// getEmailFromEnv gets the email address for Let's Encrypt registration from environment
func getEmailFromEnv() string {
	email := os.Getenv("LETSENCRYPT_EMAIL")
	if email == "" {
		log.Println("Warning: No LETSENCRYPT_EMAIL environment variable set")
	}
	return email
}

// MustGetTLSConfig is a helper that calls GetTLSConfig and panics on error
func (c *Config) MustGetTLSConfig() *tls.Config {
	tlsConfig, err := c.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	return tlsConfig
}
