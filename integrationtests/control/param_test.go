/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"net/http"
	"testing"
)

// TestParamEndpoints demonstrates parameterized testing of multiple endpoints
func TestParamEndpoints(t *testing.T) {
	cfg, err := SetupTest()
	if err != nil {
		t.Fatalf("Failed to set up test: %v", err)
	}

	client := NewHTTPClient(cfg)

	// Define test cases for multiple endpoints
	testCases := []TestCase{
		// Health endpoint tests
		{
			Name: "Health endpoint - GET",
			Request: Request{
				Method: http.MethodGet,
				Path:   "/api/v1/health",
			},
			ExpectedStatus: http.StatusOK,
			ResponseCheck: func(t *testing.T, resp *Response) {
				if string(resp.Body) != "OK" {
					t.Errorf("Expected response body 'OK', got '%s'", resp.Body)
				}
			},
		},
		{
			Name: "Health endpoint - POST (Method Not Allowed)",
			Request: Request{
				Method: http.MethodPost,
				Path:   "/api/v1/health",
			},
			ExpectedStatus: http.StatusMethodNotAllowed,
		},

		// Token endpoint tests
		{
			Name: "Token endpoint - GET",
			Request: Request{
				Method: http.MethodGet,
				Path:   "/api/v1/token",
			},
			ExpectedStatus: http.StatusOK,
			ResponseCheck: func(t *testing.T, resp *Response) {
				var tokenResponse struct {
					Token string `json:"token"`
				}

				ParseJSON(t, resp, &tokenResponse)

				// Verify token is not empty and has JWT format
				if tokenResponse.Token == "" {
					t.Errorf("Token is empty")
				}

				if !ContainsSubstring(tokenResponse.Token, ".") {
					t.Errorf("Token does not appear to be a valid JWT: %s", tokenResponse.Token)
				}
			},
		},

		// Servers endpoint tests
		{
			Name: "Servers endpoint - GET",
			Request: Request{
				Method: http.MethodGet,
				Path:   "/api/v1/servers",
			},
			ExpectedStatus: http.StatusOK,
			ResponseCheck: func(t *testing.T, resp *Response) {
				contentType := resp.Headers.Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}

				var serversResponse struct {
					Servers []interface{} `json:"servers"`
				}

				ParseJSON(t, resp, &serversResponse)

				// Servers field should exist (even if empty)
				if serversResponse.Servers == nil {
					t.Errorf("Expected 'servers' field in response, got nil")
				}
			},
		},

		// Authorization tests
		{
			Name: "Server creation - without auth",
			Request: Request{
				Method: http.MethodPost,
				Path:   "/api/v1/server",
				Body:   map[string]string{"proxyURL": "https://example.com"},
				Auth:   false, // No auth
			},
			ExpectedStatus: http.StatusUnauthorized,
		},
	}

	// Run all test cases
	RunTestCases(t, client, testCases)
}
