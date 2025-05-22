package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Create a test JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": "test-token-id-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})

	// Sign the token with our secret
	tokenString, err := token.SignedString([]byte("test-secret-key"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Test JWT Token:\n%s\n", tokenString)
}
