package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStandardAdminAuthenticator(t *testing.T) {
	adminToken := "test-admin-token"
	authenticator := NewStandardAdminAuthenticator(adminToken)

	// Create a handler to verify middleware passes control
	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Apply middleware
	handler := authenticator.Middleware(nextHandler)

	tests := []struct {
		name         string
		headerValue  string
		shouldPass   bool
		expectedCode int
	}{
		{
			name:         "Valid admin token",
			headerValue:  "Bearer " + adminToken,
			shouldPass:   true,
			expectedCode: http.StatusOK,
		},
		{
			name:         "No authorization header",
			headerValue:  "",
			shouldPass:   false,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Invalid scheme",
			headerValue:  "Basic " + adminToken,
			shouldPass:   false,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Wrong token",
			headerValue:  "Bearer wrong-token",
			shouldPass:   false,
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset state
			handlerCalled = false

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			if tc.headerValue != "" {
				req.Header.Add("Authorization", tc.headerValue)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(rr, req)

			// Check if next handler was called
			if tc.shouldPass && !handlerCalled {
				t.Fatal("Expected next handler to be called")
			}

			if !tc.shouldPass && handlerCalled {
				t.Fatal("Expected next handler not to be called")
			}

			// Check status code
			if rr.Code != tc.expectedCode {
				t.Fatalf("Expected status code %d, got %d", tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestInsecureAdminAuthenticator(t *testing.T) {
	authenticator := NewInsecureAdminAuthenticator()

	// Create a handler to verify middleware always passes control
	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Apply middleware
	handler := authenticator.Middleware(nextHandler)

	tests := []struct {
		name        string
		headerValue string
	}{
		{
			name:        "No token",
			headerValue: "",
		},
		{
			name:        "Any token",
			headerValue: "Bearer any-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset state
			handlerCalled = false

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			if tc.headerValue != "" {
				req.Header.Add("Authorization", tc.headerValue)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(rr, req)

			// Insecure authenticator should always pass
			if !handlerCalled {
				t.Fatal("Expected insecure authenticator to always pass to next handler")
			}

			// Check status code
			if rr.Code != http.StatusOK {
				t.Fatalf("Expected status code %d, got %d", http.StatusOK, rr.Code)
			}
		})
	}
}

func TestAdminHandler(t *testing.T) {
	adminToken := "test-admin-token"
	revocationSvc := NewRevocationService()
	authenticator := NewStandardAdminAuthenticator(adminToken)
	handler := NewAdminHandler(authenticator, revocationSvc)

	// Setup test mux
	mux := http.NewServeMux()
	handler.SetupRoutes(mux)

	// Create test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test cases for token revocation
	tests := []struct {
		name         string
		method       string
		path         string
		headerValue  string
		payload      RevokeRequest
		expectedCode int
	}{
		{
			name:         "Revoke token with valid auth",
			method:       "POST",
			path:         "/revoke",
			headerValue:  "Bearer " + adminToken,
			payload:      RevokeRequest{JTI: "token-to-revoke"},
			expectedCode: http.StatusOK,
		},
		{
			name:         "Revoke token with invalid auth",
			method:       "POST",
			path:         "/revoke",
			headerValue:  "Bearer wrong-token",
			payload:      RevokeRequest{JTI: "token-to-revoke"},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Revoke token with missing JTI",
			method:       "POST",
			path:         "/revoke",
			headerValue:  "Bearer " + adminToken,
			payload:      RevokeRequest{JTI: ""},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Revoke token with wrong method",
			method:       "GET",
			path:         "/revoke",
			headerValue:  "Bearer " + adminToken,
			expectedCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			var body bytes.Buffer
			if tc.method == "POST" {
				json.NewEncoder(&body).Encode(tc.payload)
			}

			req, err := http.NewRequest(tc.method, server.URL+tc.path, &body)
			if err != nil {
				t.Fatalf("Error creating request: %v", err)
			}

			// Set headers
			if tc.headerValue != "" {
				req.Header.Set("Authorization", tc.headerValue)
			}
			if tc.method == "POST" {
				req.Header.Set("Content-Type", "application/json")
			}

			// Send request
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Error sending request: %v", err)
			}
			defer resp.Body.Close()

			// Check status code
			if resp.StatusCode != tc.expectedCode {
				t.Fatalf("Expected status code %d, got %d", tc.expectedCode, resp.StatusCode)
			}

			// If it was a successful revocation, verify token is actually revoked
			if tc.expectedCode == http.StatusOK && tc.payload.JTI != "" {
				if !revocationSvc.IsRevoked(tc.payload.JTI) {
					t.Fatalf("Token %s should be revoked", tc.payload.JTI)
				}
			}
		})
	}
}
