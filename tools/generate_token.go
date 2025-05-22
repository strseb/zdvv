package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Generate a random secret key
	secretKey := make([]byte, 32) // 32 bytes for a 256-bit key
	_, err := rand.Read(secretKey)
	if err != nil {
		panic(err)
	}
	secretKeyBase64 := base64.StdEncoding.EncodeToString(secretKey)

	// Create a test JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": "test-token-id-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})

	// Sign the token with the generated secret
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Secret Key (for main.go):\n%s\n\n", secretKeyBase64)
	fmt.Printf("Test JWT Token:\n%s\n", tokenString)
}
