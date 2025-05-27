/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// HTTPClient is a wrapper around http.Client for testing
type HTTPClient struct {
	client    *http.Client
	baseURL   string
	authToken string
	debug     bool
}

// NewHTTPClient creates a new HTTP client for tests
func NewHTTPClient(config *TestConfig) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: time.Duration(config.HTTPTimeout) * time.Second,
		},
		baseURL:   config.ControlURL,
		authToken: config.APIKey,
		debug:     config.Debug,
	}
}

// Request represents a test HTTP request
type Request struct {
	Method      string
	Path        string
	Body        interface{}
	QueryParams map[string]string
	Headers     map[string]string
	Auth        bool
}

// Response wraps the HTTP response for easier testing
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
}

// Do executes an HTTP request based on the provided Request and returns a Response
func (c *HTTPClient) Do(req Request) (*Response, error) {
	var body io.Reader
	var bodyBytes []byte

	if req.Body != nil {
		jsonData, err := json.Marshal(req.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsonData)
		bodyBytes = jsonData
	}

	url := c.baseURL + req.Path

	// Add query parameters
	if len(req.QueryParams) > 0 {
		url += "?"
		for k, v := range req.QueryParams {
			url += k + "=" + v + "&"
		}
		url = url[:len(url)-1] // Remove the trailing &
	}

	httpReq, err := http.NewRequest(req.Method, url, body)
	if err != nil {
		return nil, err
	}

	// Set default headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Set auth header if needed
	if req.Auth && c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	// Set custom headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Log request details if debug is enabled
	if c.debug {
		fmt.Printf("[DEBUG] Request: %s %s\n", req.Method, url)
		fmt.Printf("[DEBUG] Headers: %v\n", httpReq.Header)
		if bodyBytes != nil {
			fmt.Printf("[DEBUG] Body: %s\n", string(bodyBytes))
		}
	}

	startTime := time.Now()
	resp, err := c.client.Do(httpReq)
	elapsed := time.Since(startTime)

	if err != nil {
		if c.debug {
			fmt.Printf("[DEBUG] Request failed after %v: %v\n", elapsed, err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Log response details if debug is enabled
	if c.debug {
		fmt.Printf("[DEBUG] Response: %d (%v)\n", resp.StatusCode, elapsed)
		fmt.Printf("[DEBUG] Response Headers: %v\n", resp.Header)
		fmt.Printf("[DEBUG] Response Body: %s\n", string(respBody))
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}, nil
}

// AssertStatusCode checks if the status code matches the expected one
func AssertStatusCode(t *testing.T, resp *Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("Expected status code %d, got %d. Response body: %s", expected, resp.StatusCode, resp.Body)
	}
}

// ParseJSON parses the response body into the provided interface
func ParseJSON(t *testing.T, resp *Response, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(resp.Body, v); err != nil {
		t.Fatalf("Failed to parse JSON response: %v. Body: %s", err, resp.Body)
	}
}

// TestCase represents a parameterized test case
type TestCase struct {
	Name           string
	Request        Request
	ExpectedStatus int
	ResponseCheck  func(*testing.T, *Response)
}

// RunTestCases runs a series of parameterized test cases
func RunTestCases(t *testing.T, client *HTTPClient, cases []TestCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := client.Do(tc.Request)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			// Check status code
			AssertStatusCode(t, resp, tc.ExpectedStatus)

			// Run custom response checks if provided
			if tc.ResponseCheck != nil {
				tc.ResponseCheck(t, resp)
			}
		})
	}
}

// ContainsSubstring checks if a string contains a substring
func ContainsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
