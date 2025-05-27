package control

import (
	"net/http"
	"testing"
)

// TestJWKSEndpoint tests the /.well-known/jwks.json endpoint
func TestJWKSEndpoint(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	t.Run("GET /.well-known/jwks.json should return 200 OK and valid JWKS", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/.well-known/jwks.json",
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

		// Parse and validate JWKS response
		var jwksResponse struct {
			Keys []map[string]interface{} `json:"keys"`
		}

		ParseJSON(t, resp, &jwksResponse)

		// Verify that keys are present
		if len(jwksResponse.Keys) == 0 {
			t.Errorf("Expected at least one key in JWKS response, got none")
		}

		// Verify each key has required JWKS fields
		for i, key := range jwksResponse.Keys {
			for _, field := range []string{"kty", "kid"} {
				if _, ok := key[field]; !ok {
					t.Errorf("Key %d is missing required field '%s'", i, field)
				}
			}
		}
	})

	// Negative test - incorrect method
	t.Run("POST /.well-known/jwks.json should return method not allowed", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/.well-known/jwks.json",
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
