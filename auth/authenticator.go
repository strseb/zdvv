package auth

import (
	"log"
	"net/http"
)

// Since JWTValidator now directly implements Authenticator,
// we don't need this adapter anymore.
// The code has been removed as JWTValidator is now the primary implementation.

// ProxyInsecureAuthenticator allows all proxy requests to pass through
type ProxyInsecureAuthenticator struct{}

// NewProxyInsecureAuthenticator creates a new insecure authenticator for proxy
func NewProxyInsecureAuthenticator() *ProxyInsecureAuthenticator {
	log.Println("WARNING: Using insecure validator - all requests will be allowed without authentication")
	return &ProxyInsecureAuthenticator{}
}

// Middleware implements the Authenticator interface
func (a *ProxyInsecureAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow access in insecure mode
		next.ServeHTTP(w, r)
	})
}
