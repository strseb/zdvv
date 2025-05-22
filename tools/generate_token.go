package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	insecure := flag.Bool("insecure", false, "Generate an unsigned JWT (alg: none) for insecure mode")
	o := flag.String("o", "", "Output path for generated public key PEM (optional)")
	flag.Parse()

	if *insecure {
		// Generate an unsigned JWT (alg: none)
		token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"sub": "test-user",
			"jti": "test-token-id-123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Unsigned JWT Token (alg: none):\n%s\n", tokenString)
		return
	}

	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Encode the public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	if *o != "" {
		err := os.WriteFile(*o, pubPEM, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to write public key to file: %w", err))
		}
		fmt.Printf("Public key written to %s\n", *o)
	} else {
		fmt.Printf("Public Key (for main.go, PEM):\n%s\n\n", pubPEM)
	}

	// Create a test JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test-user",
		"jti": "test-token-id-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Test JWT Token:\n%s\n", tokenString)
}
