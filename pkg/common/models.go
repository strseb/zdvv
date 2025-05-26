package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	// Full URI of the endpoint Accepting CONNECT requests
	ProxyURL string `json:"proxyUrl"`
	// Latitude of the server in decimal degrees.
	Latitude float64 `json:"latitude"`
	// Longitude of the server in decimal degrees.
	Longitude float64 `json:"longitude"`
	// Name of the City ... in the local language?
	City string `json:"city"`
	// ISO 3166 country code
	Country string `json:"country"`
	// SupportsConnectTCP indicates if the server supports the Connect TCP feature (RFC 7231).
	SupportsConnectTCP bool `json:"supportsConnectTcp"`
	// SupportsConnectUDP indicates if the server supports the Connect UDP feature (RFC 9298).
	SupportsConnectUDP bool `json:"supportsConnectUdp"`
	// SupportsConnectIP indicates if the server supports the Connect IP feature (RFC 9484).
	SupportsConnectIP bool `json:"supportsConnectIp"`
	/*
	* A server can only be revoked by itself.
	* We will send this to the server when it registers.
	* The server will then use this token to revoke itself.
	 */
	RevocationToken string
}

type JWTKey struct {
	// base64 encoded public key used to verify JWT tokens
	Kty       string `json:"kty"` // Key type, e.g., "RSA"
	PublicKey string `json:"k"`
	Kid       int64  `json:"kid"` // Key ID for the public key
	// Expiration date of the key in Unix timestamp
	// JWT tokens can be signed with this key until it expires.
	// If the key is expired tokens are still valid until their own expiration date.
	ExpiresAt int64 `json:"expiresAt"` // Expiration time of the key in Unix timestamp

	privateKey *rsa.PrivateKey `json:"-"`
}

func (jwt *JWTKey) IsExpired() bool {
	return jwt.ExpiresAt < 0 || jwt.ExpiresAt < time.Now().Unix()
}

// SignWithClaims creates and signs a JWT token with specific permissions without exposing the private key
// Only permissions are allowed to be specified, along with standard JWT claims
func (key *JWTKey) SignWithClaims(issuer string, validDuration time.Duration, permissions []string) (string, error) {
	// Generate a random JTI (JWT ID)
	jti, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		return "", err
	}

	// Create the base claims
	claims := jwt.MapClaims{
		"iss": issuer,
		"exp": time.Now().Add(validDuration).Unix(),
		"jti": jti.Int64(),
		"kid": key.Kid,
	}

	// Add the specified permissions
	for _, permission := range permissions {
		claims[permission] = true
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.Kid

	// Sign the token with the private key
	return token.SignedString(key.privateKey)
}

func NewJWTKey() (*JWTKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	// Marshal the public key to PKIX, ASN.1 DER form
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	kid, err := rand.Int(rand.Reader, big.NewInt(1<<63-1)) // Generate a random key ID
	if err != nil {
		return nil, err
	}

	return &JWTKey{
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		Kid:        kid.Int64(), // random id
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
		privateKey: privateKey,
		Kty:        "RSA",
	}, nil
}

func (s *Server) GenerateRevocationToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	s.RevocationToken = base64.URLEncoding.EncodeToString(tokenBytes)
	return s.RevocationToken, nil
}
