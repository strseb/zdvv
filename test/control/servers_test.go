package control

import (
	"net/http"
	"testing"
)

// TestServersEndpoint tests the /api/v1/servers endpoint
func TestServersEndpoint(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg.ControlURL, cfg.APIKey)

	t.Run("GET /api/v1/servers should return 200 OK and server list", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/api/v1/servers",
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

		// Parse servers response
		var serversResponse struct {
			Servers []interface{} `json:"servers"`
		}

		ParseJSON(t, resp, &serversResponse)

		// Servers might be empty if none are registered, which is valid
		if serversResponse.Servers == nil {
			t.Errorf("Expected 'servers' field in response, got nil")
		}
	})

	// Negative test - incorrect method
	t.Run("POST /api/v1/servers should return method not allowed", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/servers",
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
