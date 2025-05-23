package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/basti/zdvv/auth"
	"github.com/basti/zdvv/config"
	"github.com/basti/zdvv/controlserver"
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

	// Control server integration
	var revocationSvc interface{ IsRevoked(string) bool }
	var jwtPublicKeyPEM string
	var controlClient *controlserver.Client

	if cfg.ControlServerURL != "" && cfg.ControlServerSecret != "" {
		controlClient = controlserver.NewClient(cfg.ControlServerURL, cfg.ControlServerSecret, cfg.Hostname)
		if err := controlClient.FetchPublicKey(); err != nil {
			log.Fatalf("Failed to fetch public key from control server: %v", err)
		}
		jwtPublicKeyPEM = controlClient.GetPublicKeyPEM()
		// Register on startup
		if err := controlClient.RegisterServer(); err != nil {
			log.Fatalf("Failed to register with control server: %v", err)
		}
		// Deregister on shutdown
		defer func() {
			if err := controlClient.DeregisterServer(); err != nil {
				log.Printf("Failed to deregister from control server: %v", err)
			}
		}()
		// Periodically fetch revocations
		go func() {
			for {
				if err := controlClient.FetchRevoked(); err != nil {
					log.Printf("Failed to fetch revoked tokens: %v", err)
				}
				time.Sleep(30 * time.Minute)
			}
		}()
		revocationSvc = controlClient.GetRevocationService()
	} else {
		revocationSvc = auth.NewRevocationService()
		jwtPublicKeyPEM = ""
	}

	// Parse the public key PEM (from control server or config)
	var jwtPublicKey *rsa.PublicKey
	if jwtPublicKeyPEM != "" {
		block, _ := pem.Decode([]byte(jwtPublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" {
			log.Fatalf("Failed to decode JWT public key PEM block from control server")
		}
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse JWT public key from control server: %v", err)
		}
		var ok bool
		jwtPublicKey, ok = parsedKey.(*rsa.PublicKey)
		if !ok {
			log.Fatalf("JWT public key from control server is not an RSA public key")
		}
	} else {
		jwtPublicKey = cfg.JWTPublicKey
	}

	requiredConnectPermissions := []auth.PermissionFunc{auth.PermissionConnectTCP}

	var proxyAuthenticator auth.Authenticator

	if cfg.Insecure {
		proxyAuthenticator = auth.NewInsecureJWTValidator(revocationSvc.(*auth.RevocationService), requiredConnectPermissions)
	} else {
		proxyAuthenticator = auth.NewJWTValidator(jwtPublicKey, revocationSvc.(*auth.RevocationService), requiredConnectPermissions)
	}

	// Create handlers with the appropriate authenticators
	connectHandler := proxy.NewConnectHandler()

	// Wrap connect handler with authentication middleware
	authenticatedConnectHandler := proxyAuthenticator.Middleware(connectHandler)

	// Set up HTTP mux
	mux := http.NewServeMux()

	// Create the main router with authenticated connect handler
	mainRouter := newMainRouter(mux, authenticatedConnectHandler)

	// Get TLS config with Let's Encrypt support if needed
	tlsConfig := cfg.MustGetTLSConfig()

	// Detect if Let's Encrypt (autocert) is being used
	usingAutocert := tlsConfig.GetCertificate != nil

	// Add HTTP/3 support if enabled
	if cfg.HTTP3Enabled {
		// Start HTTP/3 server
		h3Server := &http3.Server{
			Addr:      cfg.Addr,
			Handler:   mainRouter, // Use mainRouter
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("Starting HTTP/3 server on %s", cfg.Addr)
			var err error
			if usingAutocert {
				err = h3Server.ListenAndServeTLS("", "")
			} else {
				err = h3Server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
			}
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
	if usingAutocert {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	}
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
