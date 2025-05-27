/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"net/http"
	"testing"

	"github.com/strseb/zdvv/pkg/common"
)

// TestServersEndpoint tests the /api/v1/servers endpoint
func TestServersEndpoint(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

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

// TestServersEndpointPrivacy tests that the /api/v1/servers endpoint doesn't expose private fields like revocation tokens
func TestServersEndpointPrivacy(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	// First, add a server so we have data to test with
	testServer := common.Server{
		ProxyURL:           "https://privacy-test-server.example.com",
		Latitude:           51.5074,
		Longitude:          -0.1278,
		City:               "London",
		Country:            "UK",
		SupportsConnectTCP: true,
	}

	var revocationToken string

	// Add a server to test with
	t.Run("Setup: Add a server with known revocation token", func(t *testing.T) {
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

		revocationToken = response.RevocationToken
	})

	// Now test that the servers endpoint doesn't expose the revocation token
	t.Run("GET /api/v1/servers should not expose revocation tokens", func(t *testing.T) {
		// Skip test if we couldn't get a token
		if revocationToken == "" {
			t.Skip("Skipping test because no revocation token was obtained")
		}

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

		// Find our test server and check if it has a revocation token
		for _, server := range serversResponse.Servers {
			if proxyURL, ok := server["proxyUrl"].(string); ok && proxyURL == testServer.ProxyURL {
				// Check if the server has a "revocationToken" field
				if _, found := server["revocationToken"]; found {
					t.Errorf("Server response contains 'revocationToken' field, which should be private")
				}

				// Also check for any field with "token" in the name as a precaution
				for key := range server {
					if key != "proxyUrl" && key != "latitude" && key != "longitude" &&
						key != "city" && key != "country" &&
						key != "supportsConnectTcp" && key != "supportsConnectUdp" &&
						key != "supportsConnectIp" {
						t.Errorf("Server response contains unexpected field '%s'", key)
					}
				}
				return
			}
		}

		t.Errorf("Test server was not found in the servers list. Test cannot verify token privacy.")
	})

	// Clean up: remove the server we added
	t.Run("Cleanup: Remove test server", func(t *testing.T) {
		// Skip cleanup if we couldn't get a token
		if revocationToken == "" {
			t.Skip("Skipping cleanup because no revocation token was obtained")
		}

		resp, err := client.Do(Request{
			Method: http.MethodDelete,
			Path:   "/api/v1/server/" + revocationToken,
			Auth:   true, // Include authentication
		})

		if err != nil {
			t.Fatalf("Cleanup failed: %v", err)
		}

		// Just verify the server was removed
		AssertStatusCode(t, resp, http.StatusOK)
	})
}
