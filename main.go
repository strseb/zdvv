package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/basti/zdvv/admin"
	"github.com/basti/zdvv/auth"
	"github.com/basti/zdvv/config"
	"github.com/basti/zdvv/proxy"
	"github.com/quic-go/quic-go/http3"
)

const (
	asciiArt = `
  _____  ______      ______      _____               
 |__  / |  _  \   /  _____\    /  _  \               
   / /  | | | |  /  /     |   /  /_\  \     __     __
  / /_  | |/ /   |  |     |  /  _____  \   /  \   /  \
 /____| |___/    \  \_____/ /  /     \  \  \   \ /   /
                  \_______/ /__/       \__\  \___V___/
                                                            
 Zentrale Datenverkehrsvermittlung  (Build %s)
 Abteilung ZDVV steht bereit.                     
`
)

// newMainRouter creates a new http.Handler that routes CONNECT requests
// directly to the connectHandler and all other requests to the defaultHandler (mux).
func newMainRouter(defaultHandler http.Handler, connectHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[MainRouter] Received request: Method=%s, URL=%s, Host=%s, RemoteAddr=%s", r.Method, r.URL.String(), r.Host, r.RemoteAddr)
		if r.Method == http.MethodConnect {
			log.Printf("[MainRouter] Routing to ConnectHandler for: %s %s", r.Method, r.URL.Host)
			connectHandler.ServeHTTP(w, r)
		} else {
			log.Printf("[MainRouter] Routing to default MUX for: %s %s", r.Method, r.URL.Path)
			defaultHandler.ServeHTTP(w, r)
		}
	})
}

func main() {
	// Load configuration
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Print banner
	fmt.Printf(asciiArt, cfg.Version)

	// Log configuration settings
	cfg.LogSettings()

	// Initialize services
	revocationSvc := auth.NewRevocationService()

	// Determine which authenticators to use
	var proxyAuthenticator auth.Authenticator
	var adminAuthenticator auth.Authenticator

	if cfg.Insecure {
		// Use insecure authenticators in insecure mode
		proxyAuthenticator = auth.NewProxyInsecureAuthenticator()
		adminAuthenticator = auth.NewInsecureAdminAuthenticator()
	} else {
		// Create JWT validator for proxy and admin authenticator
		jwtValidator := auth.NewJWTValidator(cfg.JWTSecret, revocationSvc)
		proxyAuthenticator = jwtValidator // JWTValidator already implements Authenticator interface
		adminAuthenticator = auth.NewStandardAdminAuthenticator(cfg.AdminToken)
	}

	// Create handlers with the appropriate authenticators
	adminHandler := admin.NewAdminHandler(adminAuthenticator, revocationSvc)
	connectHandler := proxy.NewConnectHandler()

	// Wrap connect handler with authentication middleware
	authenticatedConnectHandler := proxyAuthenticator.Middleware(connectHandler)

	// Set up HTTP mux
	mux := http.NewServeMux()

	// Set up admin routes
	adminHandler.SetupRoutes(mux)

	// Create the main router with authenticated connect handler
	mainRouter := newMainRouter(mux, authenticatedConnectHandler)

	// Set up TLS config with protocol support
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	// Add HTTP/2 support if enabled
	if cfg.HTTP2Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
	}

	// Add HTTP/3 support if enabled
	if cfg.HTTP3Enabled {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")

		// Start HTTP/3 server
		h3Server := &http3.Server{
			Addr:      cfg.Addr,
			Handler:   mainRouter, // Use mainRouter
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("Starting HTTP/3 server on %s", cfg.Addr)
			err := h3Server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				log.Printf("HTTP/3 server error: %v", err)
			}
		}()
	}

	// Configure HTTP/1.1 and HTTP/2 server
	server := &http.Server{
		Addr:      cfg.Addr,
		Handler:   mainRouter, // Use mainRouter
		TLSConfig: tlsConfig,
	}

	// If insecure mode is enabled, also start an unencrypted HTTP server on port 8080
	if cfg.Insecure {
		go func() {
			log.Printf("WARNING: Starting unencrypted HTTP server on %s due to -insecure flag", cfg.InsecureAddr)
			insecureServer := &http.Server{
				Addr:    cfg.InsecureAddr,
				Handler: mainRouter, // Use the same mainRouter
			}
			if err := insecureServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Unencrypted HTTP server error: %v", err)
			}
		}()
	}

	// Start the server
	log.Printf("Starting TLS server on %s", cfg.Addr)
	err = server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
