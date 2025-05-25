package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

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

func TestJWTValidatorExtractToken(t *testing.T) {
	// Generate a dummy public key for validator initialization, as this test doesn't validate the signature.
	_, publicKey := createTestToken(t, "dummy-jti-for-extract")
	validator := NewJWTValidator(publicKey, nil)

	// Test cases
	tests := []struct {
		name          string
		header        string
		headerValue   string
		expectedError error
		expectedToken string
	}{
		{
			name:          "No header",
			header:        "",
			headerValue:   "",
			expectedError: ErrNoAuthHeader,
		},
		{
			name:          "Invalid scheme",
			header:        "Proxy-Authorization",
			headerValue:   "Basic token123",
			expectedError: ErrInvalidScheme,
		},
		{
			name:          "Valid header",
			header:        "Proxy-Authorization",
			headerValue:   "Bearer token123",
			expectedError: nil,
			expectedToken: "token123",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Add(tc.header, tc.headerValue)
			}

			token, err := validator.ExtractToken(req)

			// Check error
			if err != tc.expectedError {
				t.Fatalf("Expected error %v, got %v", tc.expectedError, err)
			}

			// If we expected success, check the token
			if tc.expectedError == nil && token != tc.expectedToken {
				t.Fatalf("Expected token %s, got %s", tc.expectedToken, token)
			}
		})
	}
}

func TestJWTValidatorValidateToken(t *testing.T) {
	// Create a key pair for valid tokens
	validPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA private key: %v", err)
	}
	validPublicKey := &validPrivateKey.PublicKey

	// Create a valid token
	validJTI := "valid-token-id"
	validToken := createTokenWithKey(t, validPrivateKey, validJTI)

	// Create a token with invalid signature (signed by a different key)
	invalidPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating another RSA private key: %v", err)
	}
	invalidToken := createTokenWithKey(t, invalidPrivateKey, "invalid-sig-jti")

	// Create a token without JTI, signed with the valid key
	tokenWithoutJTI := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
	})
	tokenWithoutJTIString, _ := tokenWithoutJTI.SignedString(validPrivateKey)

	// Test cases
	tests := []struct {
		name          string
		tokenString   string
		shouldBeValid bool
	}{
		{
			name:          "Valid token",
			tokenString:   validToken,
			shouldBeValid: true,
		},
		{
			name:          "Invalid signature",
			tokenString:   invalidToken,
			shouldBeValid: false,
		},
		{
			name:          "Token without JTI",
			tokenString:   tokenWithoutJTIString,
			shouldBeValid: false,
		},
		{
			name:          "Malformed token",
			tokenString:   "not-a-valid-token",
			shouldBeValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset validator for each test, ensuring correct public key
			currentValidator := NewJWTValidator(validPublicKey, nil)

			token, err := currentValidator.ValidateToken(tc.tokenString)

			if tc.shouldBeValid {
				if err != nil {
					t.Fatalf("Expected valid token, got error: %v", err)
				}
				if !token.Valid {
					t.Fatal("Token should be valid")
				}
			} else {
				if err == nil {
					t.Fatal("Expected error for invalid token")
				}
			}
		})
	}
}

func TestJWTValidatorMiddleware(t *testing.T) {

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
			currentValidator := NewJWTValidator(validPublicKey, nil)
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
