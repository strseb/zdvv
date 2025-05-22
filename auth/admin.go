package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// AdminAuthenticator defines the interface for admin authentication
type AdminAuthenticator interface {
	// Middleware provides HTTP middleware for admin authentication
	Middleware(next http.Handler) http.Handler
}

// StandardAdminAuthenticator implements admin authentication using a token
type StandardAdminAuthenticator struct {
	AdminToken string
}

// NewStandardAdminAuthenticator creates a new standard admin authenticator
func NewStandardAdminAuthenticator(adminToken string) *StandardAdminAuthenticator {
	return &StandardAdminAuthenticator{
		AdminToken: adminToken,
	}
}

// Middleware provides HTTP middleware for admin authentication
func (a *StandardAdminAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check the format of the header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Validate the token
		if parts[1] != a.AdminToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed
		next.ServeHTTP(w, r)
	})
}

// InsecureAdminAuthenticator always allows admin access
type InsecureAdminAuthenticator struct{}

// NewInsecureAdminAuthenticator creates a new insecure admin authenticator
func NewInsecureAdminAuthenticator() *InsecureAdminAuthenticator {
	log.Println("WARNING: Using insecure admin authenticator - all admin requests will be allowed")
	return &InsecureAdminAuthenticator{}
}

// Middleware is a pass-through for insecure admin authentication
func (a *InsecureAdminAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow access in insecure mode
		next.ServeHTTP(w, r)
	})
}

// RevokeRequest represents a token revocation request
type RevokeRequest struct {
	JTI string `json:"jti"`
}

// AdminHandler handles admin API requests
type AdminHandler struct {
	Authenticator AdminAuthenticator
	RevocationSvc *RevocationService
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(authenticator AdminAuthenticator, revocationSvc *RevocationService) *AdminHandler {
	return &AdminHandler{
		Authenticator: authenticator,
		RevocationSvc: revocationSvc,
	}
}

// handleRevokeToken handles the actual token revocation after authentication
func (h *AdminHandler) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.JTI == "" {
		http.Error(w, "Missing jti field", http.StatusBadRequest)
		return
	}

	// Revoke the token
	h.RevocationSvc.Revoke(req.JTI)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Token revoked",
	})
}

// HandleRevokeToken is the HTTP handler that applies authentication middleware
func (h *AdminHandler) HandleRevokeToken() http.Handler {
	return h.Authenticator.Middleware(http.HandlerFunc(h.handleRevokeToken))
}

// SetupRoutes configures the admin API routes
func (h *AdminHandler) SetupRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.Handle("/revoke", h.HandleRevokeToken())
}
