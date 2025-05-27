package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Mock implementation of KeyProvider for testing
type mockKeyProvider struct {
	keys      map[string]*rsa.PublicKey
	err       error
	callCount int
}

func (m *mockKeyProvider) PublicKeys() (map[string]*rsa.PublicKey, error) {
	m.callCount++
	return m.keys, m.err
}

func TestMultiKeyJWTValidator(t *testing.T) {
	// Generate test keys
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}
	// Create mock key provider
	mockProvider := &mockKeyProvider{
		keys: map[string]*rsa.PublicKey{
			"1": &key1.PublicKey,
			"2": &key2.PublicKey,
		},
	}

	// Create validator
	validator := NewMultiKeyJWTValidator(mockProvider, []Permission{PERMISSION_CONNECT_TCP})
	tests := []struct {
		name          string
		keyID         string
		key           *rsa.PrivateKey
		permissions   map[string]interface{}
		expectSuccess bool
	}{
		{
			name:          "Valid token with key1",
			keyID:         "1",
			key:           key1,
			permissions:   map[string]interface{}{"connect-tcp": true},
			expectSuccess: true,
		},
		{
			name:          "Valid token with key2",
			keyID:         "2",
			key:           key2,
			permissions:   map[string]interface{}{"connect-tcp": true},
			expectSuccess: true,
		},
		{
			name:          "Invalid keyID",
			keyID:         "3",
			key:           key1, // Using key1 but with wrong ID
			permissions:   map[string]interface{}{"connect-tcp": true},
			expectSuccess: false,
		},
		{
			name:          "Missing permission",
			keyID:         "1",
			key:           key1,
			permissions:   map[string]interface{}{}, // No connect-tcp permission
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockProvider.callCount = 0 // Reset call count

			// Create token with specified key and permissions
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(tc.permissions))
			token.Header["kid"] = tc.keyID
			tokenString, err := token.SignedString(tc.key)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			// Create request with token
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set(authHeader, authScheme+" "+tokenString)

			// Create response recorder
			recorder := httptest.NewRecorder()

			// Set up a simple handler that just returns 200 OK
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			// Apply middleware
			middleware := validator.Middleware(handler)
			middleware.ServeHTTP(recorder, req)

			// Check result
			if tc.expectSuccess && recorder.Code != http.StatusOK {
				t.Errorf("Expected success but got status %d", recorder.Code)
			} else if !tc.expectSuccess && recorder.Code == http.StatusOK {
				t.Errorf("Expected failure but got success")
			}
		})
	}
}

func TestMultiKeyJWTValidatorProviderError(t *testing.T) {
	// Create mock key provider that returns an error
	mockProvider := &mockKeyProvider{
		err: errors.New("provider error"),
	}

	// Create validator
	validator := NewMultiKeyJWTValidator(mockProvider, []Permission{PERMISSION_CONNECT_TCP})

	// Generate a test key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"connect-tcp": true,
	})
	token.Header["kid"] = "1"
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(authHeader, authScheme+" "+tokenString)

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Set up a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply middleware
	middleware := validator.Middleware(handler)
	middleware.ServeHTTP(recorder, req)

	// Should fail with 401 due to provider error
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 but got %d", recorder.Code)
	}
}
