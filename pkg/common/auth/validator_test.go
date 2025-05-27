package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// mockSingleKeyProvider provides a single public key for testing
type mockSingleKeyProvider struct {
	publicKey *rsa.PublicKey
}

func (m *mockSingleKeyProvider) PublicKeys() (map[string]*rsa.PublicKey, error) {
	return map[string]*rsa.PublicKey{
		"1": m.publicKey,
	}, nil
}

// Helper function to create a new valid JWT token signed with RSA
func createTestToken(t *testing.T, jti string) (string, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA private key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": jti,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Error creating test token: %v", err)
	}

	return tokenString, &privateKey.PublicKey
}

// Helper function to create a token signed with a specific private key
func createTokenWithKey(t *testing.T, privateKey *rsa.PrivateKey, jti string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": jti,
	})
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Error creating test token with key: %v", err)
	}
	return tokenString
}

// TestTokenExtraction tests the token extraction logic that's now part of the Middleware function
func TestTokenExtraction(t *testing.T) {
	// Generate a dummy public key for validator initialization
	_, publicKey := createTestToken(t, "dummy-jti-for-extract")

	// Test cases
	tests := []struct {
		name                string
		header              string
		headerValue         string
		expectStatusCode    int
		expectHandlerCalled bool
	}{
		{
			name:                "No header",
			header:              "",
			headerValue:         "",
			expectStatusCode:    http.StatusUnauthorized,
			expectHandlerCalled: false,
		},
		{
			name:                "Invalid scheme",
			header:              "Proxy-Authorization",
			headerValue:         "Basic token123",
			expectStatusCode:    http.StatusUnauthorized,
			expectHandlerCalled: false,
		},
		{
			name:                "Valid header but invalid token",
			header:              "Proxy-Authorization",
			headerValue:         "Bearer invalid-token",
			expectStatusCode:    http.StatusUnauthorized,
			expectHandlerCalled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyProvider := &mockSingleKeyProvider{publicKey: publicKey}
			validator := NewMultiKeyJWTValidator(keyProvider, nil)
			handlerCalled := false

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			middleware := validator.Middleware(nextHandler)

			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Add(tc.header, tc.headerValue)
			}

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			if rr.Code != tc.expectStatusCode {
				t.Errorf("Expected status code %d, got %d", tc.expectStatusCode, rr.Code)
			}

			if handlerCalled != tc.expectHandlerCalled {
				t.Errorf("Expected handler called: %v, got: %v", tc.expectHandlerCalled, handlerCalled)
			}
		})
	}
}

// TestMultiKeyJWTValidatorPermissions tests the permission checking in MultiKeyJWTValidator
func TestMultiKeyJWTValidatorPermissions(t *testing.T) {
	// Create a key pair for tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create a token with connect permission
	tokenWithConnect := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":         "test-user",
		"jti":         "permission-test",
		"connect-tcp": true,
		"connect_ip":  false,
	})
	tokenWithConnect.Header["kid"] = 1 // Add key ID to match our mock provider
	tokenWithConnectStr, _ := tokenWithConnect.SignedString(privateKey)

	// Create a token without connect permission
	tokenWithoutConnect := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":        "test-user",
		"jti":        "permission-test-2",
		"connect_ip": true,
	})
	tokenWithoutConnect.Header["kid"] = 1 // Add key ID to match our mock provider
	tokenWithoutConnectStr, _ := tokenWithoutConnect.SignedString(privateKey)

	// Test cases for permission checking
	tests := []struct {
		name         string
		tokenString  string
		permissions  []Permission
		shouldPass   bool
		expectedCode int
	}{
		{
			name:         "Token with required permission",
			tokenString:  tokenWithConnectStr,
			permissions:  []Permission{PERMISSION_CONNECT_TCP},
			shouldPass:   true,
			expectedCode: http.StatusOK,
		},
		{
			name:         "Token missing required permission",
			tokenString:  tokenWithoutConnectStr,
			permissions:  []Permission{PERMISSION_CONNECT_TCP},
			shouldPass:   false,
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			keyProvider := &mockSingleKeyProvider{publicKey: publicKey}
			validator := NewMultiKeyJWTValidator(keyProvider, tc.permissions)
			middleware := validator.Middleware(nextHandler)

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Add("Proxy-Authorization", "Bearer "+tc.tokenString)

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			if tc.shouldPass && !handlerCalled {
				t.Fatal("Expected next handler to be called")
			}

			if !tc.shouldPass && handlerCalled {
				t.Fatal("Expected next handler not to be called")
			}

			if rr.Code != tc.expectedCode {
				t.Fatalf("Expected status code %d, got %d", tc.expectedCode, rr.Code)
			}
		})
	}
}

func TestMultiKeyJWTValidatorMiddleware(t *testing.T) {

	// Create a key pair for valid tokens
	validPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA private key: %v", err)
	}
	validPublicKey := &validPrivateKey.PublicKey

	// Create a valid token
	validJTI := "valid-token-id-middleware"
	validToken := createTokenWithKey(t, validPrivateKey, validJTI)

	// Create a handler to verify middleware passes control
	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Test cases
	tests := []struct {
		name         string
		token        string
		shouldPass   bool
		expectedCode int
	}{
		{
			name:         "Valid token",
			token:        validToken,
			shouldPass:   true,
			expectedCode: http.StatusOK,
		},
		{
			name:         "No token",
			token:        "",
			shouldPass:   false,
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset state
			handlerCalled = false
			keyProvider := &mockSingleKeyProvider{publicKey: validPublicKey}
			currentValidator := NewMultiKeyJWTValidator(keyProvider, nil)
			currentHandler := currentValidator.Middleware(nextHandler)

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			if tc.token != "" {
				req.Header.Add("Proxy-Authorization", "Bearer "+tc.token)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			currentHandler.ServeHTTP(rr, req)

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
