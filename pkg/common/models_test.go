/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package common

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/basti/zdvv/pkg/common/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTKeySignWithClaims(t *testing.T) {
	// Create a new JWT key
	key, err := NewJWTKey()
	if err != nil {
		t.Fatalf("Failed to create JWT key: %v", err)
	}

	// Define test parameters
	issuer := "test-issuer"
	duration := time.Hour * 24 // Set to a fixed duration for test
	permissions := []string{string(auth.PERMISSION_CONNECT_TCP)}

	// Sign the token
	token, err := key.SignWithClaims(issuer, duration, permissions)
	if err != nil {
		t.Fatalf("Failed to sign claims: %v", err)
	}

	// Parse the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Decode the public key
		keyBytes, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return nil, err
		}

		// Parse the public key
		publicKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})

	// Verify token is valid
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatalf("Token should be valid")
	}
	// Verify claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("Expected claims to be of type MapClaims")
	}

	// Check issuer
	if iss, ok := claims["iss"].(string); !ok || iss != "test-issuer" {
		t.Fatalf("Expected issuer to be 'test-issuer', got %v", claims["iss"])
	}

	// Check that expiration is set to future time
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) <= time.Now().Unix() {
		t.Fatalf("Expected expiration to be in the future, got %v", claims["exp"])
	}

	// Check permission
	if permit, ok := claims["connect-tcp"].(bool); !ok || !permit {
		t.Fatalf("Expected connect-tcp to be true, got %v", claims["connect-tcp"])
	}
	// Check kid is present (float64 in JSON)
	if kid, ok := claims["kid"]; !ok {
		t.Fatalf("Expected kid to be present, but it was missing")
	} else if _, ok := kid.(float64); !ok {
		t.Fatalf("Expected kid to be a number, got %T", kid)
	}
}

// TestServerIsValid tests the IsValid method of the Server struct
func TestServerIsValid(t *testing.T) {
	tests := []struct {
		name          string
		server        Server
		expectValid   bool
		expectedError string
	}{
		{
			name: "Valid server",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           45.0,
				Longitude:          90.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   true,
			expectedError: "",
		},
		{
			name: "Missing ProxyURL",
			server: Server{
				Latitude:           45.0,
				Longitude:          90.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "proxyUrl is required",
		},
		{
			name: "Invalid latitude (too high)",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           95.0,
				Longitude:          90.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "latitude must be between -90 and 90",
		},
		{
			name: "Invalid latitude (too low)",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           -91.0,
				Longitude:          90.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "latitude must be between -90 and 90",
		},
		{
			name: "Invalid longitude (too high)",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           45.0,
				Longitude:          181.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "longitude must be between -180 and 180",
		},
		{
			name: "Invalid longitude (too low)",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           45.0,
				Longitude:          -181.0,
				City:               "Test City",
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "longitude must be between -180 and 180",
		},
		{
			name: "Missing city",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           45.0,
				Longitude:          90.0,
				Country:            "TC",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "city is required",
		},
		{
			name: "Missing country",
			server: Server{
				ProxyURL:           "https://example.com",
				Latitude:           45.0,
				Longitude:          90.0,
				City:               "Test City",
				SupportsConnectTCP: true,
			},
			expectValid:   false,
			expectedError: "country is required",
		},
		{
			name: "No connection types supported",
			server: Server{
				ProxyURL:  "https://example.com",
				Latitude:  45.0,
				Longitude: 90.0,
				City:      "Test City",
				Country:   "TC",
			},
			expectValid:   false,
			expectedError: "at least one connection type must be supported",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, message := tc.server.IsValid()
			if valid != tc.expectValid {
				t.Errorf("Expected valid=%v, got %v", tc.expectValid, valid)
			}
			if message != tc.expectedError {
				t.Errorf("Expected message=%q, got %q", tc.expectedError, message)
			}
		})
	}
}
