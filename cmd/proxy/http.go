package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// getTLSConfig builds a TLS configuration based on the HTTPConfig settings.
// It supports both static certificates and automatic certificates via Let's Encrypt.
func getTLSConfig(cfg *HTTPConfig) (*tls.Config, bool, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{}, // We'll add protocols based on configuration
	}

	if cfg.HTTPSV1Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}

	if cfg.HTTPSV2Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
	}

	// Note: HTTP/3 is handled by a separate server, but NextProtos for h3 might be relevant
	// if the same TLSConfig is intended for both, though typically http3.Server manages its own.
	// For clarity, we'll keep it here if cfg.HTTPSV3Enabled is true, as it doesn't hurt.
	if cfg.HTTPSV3Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")
	}
	// Check if certificate files exist
	_, certErr := os.Stat(cfg.CertFile)
	_, keyErr := os.Stat(cfg.KeyFile)
	certFilesExist := certErr == nil && keyErr == nil
	usingAutocert := false

	if certFilesExist {
		log.Printf("Using existing certificate files for HTTPS: %s and %s", cfg.CertFile, cfg.KeyFile)
		// Server will load these files.
		return tlsConfig, usingAutocert, nil
	}

	if cfg.Hostname == "" {
		log.Println("No certificate files found and no hostname provided for HTTPS. TLS will likely fail or use self-signed certs if not configured elsewhere.")
		// Returning a basic tlsConfig; server startup will fail if certs are strictly required and not found.
		return tlsConfig, usingAutocert, nil
	}

	log.Printf("No certificate files found for HTTPS. Setting up Let's Encrypt for hostname: %s", cfg.Hostname)
	usingAutocert = true
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Hostname),
		Cache:      autocert.DirCache("certs"),     // Consider making cache path configurable
		Email:      os.Getenv("LETSENCRYPT_EMAIL"), // Standard way to get email for Let's Encrypt
	}

	tlsConfig.GetCertificate = certManager.GetCertificate
	tlsConfig.ClientAuth = tls.NoClientCert                             // For HTTP-01 challenge
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, acme.ALPNProto) // For TLS-ALPN-01 challenge

	log.Println("Configured automatic TLS certificates via Let's Encrypt for HTTP/S")
	return tlsConfig, usingAutocert, nil
}

// CreateHTTPServers starts the HTTPS and potentially a plain HTTP server based on the provided configuration and handler.
// It also handles HTTP/3 if enabled in the config.
func CreateHTTPServers(httpCfg *HTTPConfig, mainHandler http.Handler, globalInsecureMode bool) {
	tlsConfig, usingAutocert, err := getTLSConfig(httpCfg)
	if err != nil {
		log.Fatalf("Failed to get TLS config for HTTPS server: %v", err)
	}

	// Configure HTTPS server with appropriate HTTP versions
	httpsServer := &http.Server{
		Addr:      httpCfg.HTTPSAddr,
		Handler:   mainHandler,
		TLSConfig: tlsConfig,
	}

	// Start HTTP/3 server if enabled
	if httpCfg.HTTPSV3Enabled {
		// http3.Server typically uses a copy of the tls.Config or a compatible one.
		// Ensure it's correctly set up for QUIC.
		h3Server := &http3.Server{
			Addr:      httpCfg.HTTPSAddr, // HTTP/3 often runs on the same port as HTTPS
			Handler:   mainHandler,
			TLSConfig: tlsConfig, // Re-use or adapt tlsConfig for QUIC
		}
		go func() {
			log.Printf("Starting HTTPS/3 server on %s", httpCfg.HTTPSAddr)
			var h3Err error
			if usingAutocert {
				h3Err = h3Server.ListenAndServeTLS("", "") // Autocert handles certs
			} else {
				h3Err = h3Server.ListenAndServeTLS(httpCfg.CertFile, httpCfg.KeyFile)
			}
			if h3Err != nil {
				log.Printf("HTTPS/3 server error: %v", h3Err)
			}
		}()
	}

	// Start plain HTTP listener if enabled
	if httpCfg.HTTPEnabled {
		go func() {
			log.Printf("Starting plain HTTP server on %s", httpCfg.HTTPAddr)
			httpServer := &http.Server{
				Addr:    httpCfg.HTTPAddr,
				Handler: mainHandler,
			}
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Plain HTTP server error: %v", err)
			}
		}()
	}
	// Start the main HTTPS server
	log.Printf("Starting HTTPS server on %s", httpCfg.HTTPSAddr)
	if usingAutocert {
		err = httpsServer.ListenAndServeTLS("", "") // Autocert handles certs
	} else {
		err = httpsServer.ListenAndServeTLS(httpCfg.CertFile, httpCfg.KeyFile)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTPS Server error: %v", err)
	} else if err == http.ErrServerClosed {
		log.Println("HTTPS Server closed gracefully.")
	}
}
