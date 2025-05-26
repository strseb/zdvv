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
