package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/basti/zdvv/auth"
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

	version = "1.0.0"
)

var (
	addr         = flag.String("addr", ":8443", "Listen address")
	certFile     = flag.String("cert", "server.crt", "TLS certificate file")
	keyFile      = flag.String("key", "server.key", "TLS key file")
	jwtSecret    = flag.String("jwt-secret", "", "JWT secret key")
	adminToken   = flag.String("admin-token", "", "Admin API token")
	disableHTTP2 = flag.Bool("no-http2", false, "Disable HTTP/2 support")
	disableHTTP3 = flag.Bool("no-http3", false, "Disable HTTP/3 support")
	insecure     = flag.Bool("insecure", false, "Skip JWT authentication (insecure mode)")
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
	flag.Parse()

	// Print banner
	fmt.Printf(asciiArt, version)

	// Print warning if insecure mode is enabled
	if *insecure {
		log.Println("WARNING: Running in insecure mode - authentication disabled")
	} // Initialize services
	revocationSvc := auth.NewRevocationService()

	// Determine which validator to use
	var tokenValidator auth.TokenValidator
	var adminAuthenticator auth.AdminAuthenticator

	if *insecure {
		// Use insecure validator and authenticator in insecure mode
		tokenValidator = auth.NewInsecureValidator()
		adminAuthenticator = auth.NewInsecureAdminAuthenticator()
	} else {
		// In secure mode, require JWT secret and admin token
		secret := []byte(*jwtSecret)
		if len(secret) == 0 {
			envSecret := os.Getenv("JWT_SECRET")
			if envSecret == "" {
				log.Fatal("JWT secret must be provided via -jwt-secret flag or JWT_SECRET environment variable when not in insecure mode")
			}
			secret = []byte(envSecret)
		}

		// Get admin token from flag or environment variable
		adminTokenValue := *adminToken
		if adminTokenValue == "" {
			envToken := os.Getenv("ADMIN_TOKEN")
			if envToken == "" {
				log.Fatal("Admin token must be provided via -admin-token flag or ADMIN_TOKEN environment variable when not in insecure mode")
			}
			adminTokenValue = envToken
		}

		// Create standard JWT validator and admin authenticator
		tokenValidator = auth.NewJWTValidator(secret, revocationSvc)
		adminAuthenticator = auth.NewStandardAdminAuthenticator(adminTokenValue)
	}

	adminHandler := auth.NewAdminHandler(adminAuthenticator, revocationSvc)
	connectHandler := proxy.NewConnectHandler(tokenValidator)

	// Set up HTTP mux
	mux := http.NewServeMux()

	// Set up admin routes
	adminHandler.SetupRoutes(mux)

	// connectHandler will be invoked by newMainRouter for CONNECT requests
	// mux.Handle("CONNECT */*", connectHandler) // This line is now removed/handled by newMainRouter

	// Create the main router
	mainRouter := newMainRouter(mux, connectHandler)

	// Set up TLS config with protocol support
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	// Add HTTP/2 support unless disabled
	if !*disableHTTP2 {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		log.Printf("HTTP/2 support enabled")
	} else {
		log.Printf("HTTP/2 support disabled")
	}
	// Add HTTP/3 support unless disabled
	if !*disableHTTP3 {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")
		log.Printf("HTTP/3 support enabled")

		// Start HTTP/3 server
		h3Server := &http3.Server{
			Addr:      *addr,
			Handler:   mainRouter, // Use mainRouter
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("Starting HTTP/3 server on %s", *addr)
			err := h3Server.ListenAndServeTLS(*certFile, *keyFile)
			if err != nil {
				log.Printf("HTTP/3 server error: %v", err)
			}
		}()
	} else {
		log.Printf("HTTP/3 support disabled")
	}

	// Configure HTTP/1.1 and HTTP/2 server
	server := &http.Server{
		Addr:      *addr,
		Handler:   mainRouter, // Use mainRouter
		TLSConfig: tlsConfig,
	}

	// If insecure mode is enabled, also start an unencrypted HTTP server on port 8080
	if *insecure {
		go func() {
			insecureAddr := ":8080"
			log.Printf("WARNING: Starting unencrypted HTTP server on %s due to -insecure flag", insecureAddr)
			insecureServer := &http.Server{
				Addr:    insecureAddr,
				Handler: mainRouter, // Use the same mainRouter
			}
			if err := insecureServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Unencrypted HTTP server error: %v", err)
			}
		}()
	}

	// Start the server with the enabled protocols
	protocols := "HTTP/1.1"
	if !*disableHTTP2 {
		protocols += " and HTTP/2"
	}
	log.Printf("Starting %s server on %s", protocols, *addr)
	err := server.ListenAndServeTLS(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
