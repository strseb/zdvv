/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"net/http"
	"testing"

	"github.com/basti/zdvv/pkg/common"
)

// TestServerManagementEndpoints tests the server management endpoints (/api/v1/server)
func TestServerManagementEndpoints(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	// Test server data
	testServer := common.Server{
		ProxyURL:           "https://test-proxy.example.com",
		Latitude:           51.5074,
		Longitude:          -0.1278,
		City:               "London",
		Country:            "UK",
		SupportsConnectTCP: true,
		SupportsConnectUDP: false,
		SupportsConnectIP:  false,
	}

	var revocationToken string

	// Test adding a server
	t.Run("POST /api/v1/server should add a server with authentication", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/server",
			Body:   testServer,
			Auth:   true, // Include authentication
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Parse response to get revocation token
		var response struct {
			RevocationToken string `json:"revocationToken"`
		}

		ParseJSON(t, resp, &response)

		// Verify token is not empty
		if response.RevocationToken == "" {
			t.Fatalf("Expected revocation token in response, got empty string")
		}

		// Save token for later deletion
		revocationToken = response.RevocationToken
	})

	// Negative test - adding a server without authentication
	t.Run("POST /api/v1/server without auth should return 401 Unauthorized", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/server",
			Body:   testServer,
			Auth:   false, // No authentication
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify unauthorized status
		AssertStatusCode(t, resp, http.StatusUnauthorized)
	})

	// Negative test - invalid request body
	t.Run("POST /api/v1/server with invalid body should return 400 Bad Request", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodPost,
			Path:   "/api/v1/server",
			// Raw bytes for invalid JSON
			Body: map[string]string{"invalid": "missing required fields"},
			Auth: true,
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Server might return 400 Bad Request or another error status
		if resp.StatusCode < 400 {
			t.Errorf("Expected error status code (4xx), got %d", resp.StatusCode)
		}
	})

	// Test that the server was added by checking the servers list
	t.Run("Verify server was added to the list", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/api/v1/servers",
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Parse response
		var serversResponse struct {
			Servers []map[string]interface{} `json:"servers"`
		}

		ParseJSON(t, resp, &serversResponse)

		// Look for our server by URL
		found := false
		for _, server := range serversResponse.Servers {
			if proxyURL, ok := server["proxyUrl"].(string); ok && proxyURL == testServer.ProxyURL {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Added server was not found in the server list")
		}
	})

	// Skip deletion if we don't have a token
	if revocationToken == "" {
		t.Skip("Skipping deletion test because no revocation token was obtained")
	}

	// Test removing the server
	t.Run("DELETE /api/v1/server/{token} should remove the server", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodDelete,
			Path:   "/api/v1/server/" + revocationToken,
			Auth:   true, // Include authentication
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Verify response
		if string(resp.Body) != "Server removed successfully" {
			t.Errorf("Expected 'Server removed successfully', got '%s'", resp.Body)
		}
	})

	// Negative test - removing a server without authentication
	t.Run("DELETE /api/v1/server/{token} without auth should return 401 Unauthorized", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodDelete,
			Path:   "/api/v1/server/" + revocationToken,
			Auth:   false, // No authentication
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify unauthorized status
		AssertStatusCode(t, resp, http.StatusUnauthorized)
	})

	// Negative test - invalid revocation token
	t.Run("DELETE /api/v1/server with invalid token should fail", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodDelete,
			Path:   "/api/v1/server/invalid-token-that-doesnt-exist",
			Auth:   true,
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Server should return an error status
		if resp.StatusCode < 400 {
			t.Errorf("Expected error status code (4xx), got %d", resp.StatusCode)
		}
	})

	// Verify the server was removed
	t.Run("Verify server was removed from the list", func(t *testing.T) {
		resp, err := client.Do(Request{
			Method: http.MethodGet,
			Path:   "/api/v1/servers",
		})

		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		// Verify status code
		AssertStatusCode(t, resp, http.StatusOK)

		// Parse response
		var serversResponse struct {
			Servers []map[string]interface{} `json:"servers"`
		}

		ParseJSON(t, resp, &serversResponse)

		// Look for our server by URL - should not be found
		for _, server := range serversResponse.Servers {
			if proxyURL, ok := server["proxyUrl"].(string); ok && proxyURL == testServer.ProxyURL {
				t.Errorf("Removed server was still found in the server list")
				break
			}
		}
	})
}
