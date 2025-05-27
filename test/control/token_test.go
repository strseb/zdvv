package control

import (
	"net/http"
	"testing"
)

// TestTokenEndpoint tests the /api/v1/token endpoint
func TestTokenEndpoint(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	t.Run("GET /api/v1/token should return 200 OK and a valid JWT token", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/api/v1/token",
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Verify response content type
		contentType := resp.Headers.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
		}

		// Parse token response
		var tokenResponse struct {
			Token string `json:"token"`
		}

		ParseJSON(t, resp, &tokenResponse)

		// Verify token is not empty
		if tokenResponse.Token == "" {
			t.Errorf("Token is empty")
		}
		// Check token format (should be 3 parts separated by dots)
		parts := len(tokenResponse.Token)
		if parts < 10 || !ContainsSubstring(tokenResponse.Token, ".") {
			t.Errorf("Token does not appear to be a valid JWT: %s", tokenResponse.Token)
		}
	})

	// Negative test - incorrect method
	t.Run("POST /api/v1/token should return method not allowed", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/token",
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Method Not Allowed or Not Found depending on how the server is configured
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status code %d or %d, got %d",
				http.StatusMethodNotAllowed, http.StatusNotFound, resp.StatusCode)
		}
	})
}
