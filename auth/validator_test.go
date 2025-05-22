package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Helper function to create a new valid JWT token
func createTestToken(t *testing.T, secret []byte, jti string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": jti,
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("Error creating test token: %v", err)
	}

	return tokenString
}

func TestJWTValidatorExtractToken(t *testing.T) {
	secret := []byte("test-secret")
	revocationSvc := NewRevocationService()
	validator := NewJWTValidator(secret, revocationSvc)

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
	secret := []byte("test-secret")
	revocationSvc := NewRevocationService()
	validator := NewJWTValidator(secret, revocationSvc)

	// Create a valid token
	validJTI := "valid-token-id"
	validToken := createTestToken(t, secret, validJTI)

	// Create a token with invalid signature
	invalidToken := createTestToken(t, []byte("wrong-secret"), validJTI)

	// Create a token without JTI
	tokenWithoutJTI := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
	})
	tokenWithoutJTIString, _ := tokenWithoutJTI.SignedString(secret)

	// Test cases
	tests := []struct {
		name          string
		tokenString   string
		revokeFirst   bool
		shouldBeValid bool
	}{
		{
			name:          "Valid token",
			tokenString:   validToken,
			revokeFirst:   false,
			shouldBeValid: true,
		},
		{
			name:          "Invalid signature",
			tokenString:   invalidToken,
			revokeFirst:   false,
			shouldBeValid: false,
		},
		{
			name:          "Revoked token",
			tokenString:   validToken,
			revokeFirst:   true,
			shouldBeValid: false,
		},
		{
			name:          "Token without JTI",
			tokenString:   tokenWithoutJTIString,
			revokeFirst:   false,
			shouldBeValid: false,
		},
		{
			name:          "Malformed token",
			tokenString:   "not-a-valid-token",
			revokeFirst:   false,
			shouldBeValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset revocation service for each test
			revocationSvc = NewRevocationService()
			validator = NewJWTValidator(secret, revocationSvc)

			// Revoke token if needed for this test
			if tc.revokeFirst {
				revocationSvc.Revoke(validJTI)
			}
			token, err := validator.ValidateToken(tc.tokenString)

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
	secret := []byte("test-secret")
	revocationSvc := NewRevocationService()
	validator := NewJWTValidator(secret, revocationSvc)

	// Create a valid token
	validJTI := "valid-token-id"
	validToken := createTestToken(t, secret, validJTI)

	// Create a handler to verify middleware passes control
	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	// Apply middleware
	handler := validator.Middleware(nextHandler)

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

			// Create request
			req := httptest.NewRequest("GET", "/", nil)
			if tc.token != "" {
				req.Header.Add("Proxy-Authorization", "Bearer "+tc.token)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(rr, req)

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
