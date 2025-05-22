package admin

import (
	"encoding/json"
	"net/http"

	"github.com/basti/zdvv/auth"
)

// RevokeRequest represents a token revocation request
type RevokeRequest struct {
	JTI string `json:"jti"`
}

// AdminHandler handles admin API requests
type AdminHandler struct {
	Authenticator auth.Authenticator
	RevocationSvc *auth.RevocationService
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(authenticator auth.Authenticator, revocationSvc *auth.RevocationService) *AdminHandler {
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
