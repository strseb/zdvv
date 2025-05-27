/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"net/http"
	"testing"
)

// TestHealthEndpoint tests the /api/v1/health endpoint
func TestHealthEndpoint(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	t.Run("GET /api/v1/health should return 200 OK", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/api/v1/health",
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Verify response body
		if string(resp.Body) != "OK" {
			t.Errorf("Expected response body 'OK', got '%s'", resp.Body)
		}
	})

	// Negative test - incorrect method
	t.Run("POST /api/v1/health should return method not allowed", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/health",
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
