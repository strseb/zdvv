package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Default auth configuration
const (
	DefaultAuthHeader = "Proxy-Authorization"
	DefaultAuthScheme = "Bearer"
)

// Errors
var (
	ErrNoAuthHeader  = errors.New("no authorization header")
	ErrInvalidScheme = errors.New("invalid authorization scheme")
	ErrInvalidToken  = errors.New("invalid token")
	ErrTokenRevoked  = errors.New("token has been revoked")
)

// Authenticator defines the interface for authentication middleware
type Authenticator interface {
	// Middleware provides HTTP middleware for authentication
	Middleware(next http.Handler) http.Handler
}

// JWTValidator validates JWT tokens from HTTP requests
type JWTValidator struct {
	Header        string
	Scheme        string
	Secret        []byte
	RevocationSvc *RevocationService
}

// NewJWTValidator creates a new JWT validator
func NewJWTValidator(secret []byte, revocationSvc *RevocationService) *JWTValidator {
	return &JWTValidator{
		Header:        DefaultAuthHeader,
		Scheme:        DefaultAuthScheme,
		Secret:        secret,
		RevocationSvc: revocationSvc,
	}
}

// ExtractToken extracts the token from the request
func (v *JWTValidator) ExtractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(v.Header)
	if authHeader == "" {
		return "", ErrNoAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != v.Scheme {
		return "", ErrInvalidScheme
	}

	return parts[1], nil
}

// ValidateToken validates the JWT token and returns the token
func (v *JWTValidator) ValidateToken(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.Secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract the jti claim to check for revocation
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			// Check if the token has been revoked
			if v.RevocationSvc.IsRevoked(jti) {
				return nil, ErrTokenRevoked
			}
		} else {
			return nil, errors.New("token missing jti claim")
		}
	}

	return token, nil
}

// Middleware is an HTTP middleware for JWT authentication
func (v *JWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := v.ExtractToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := v.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Add the token claims to the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "token", token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InsecureValidator is a validator that always passes authentication
type InsecureValidator struct{}

// NewInsecureValidator creates a new insecure validator
func NewInsecureValidator() *InsecureValidator {
	log.Println("WARNING: Using insecure validator - all requests will be allowed without authentication")
	return &InsecureValidator{}
}

// Middleware is a pass-through for insecure validator
func (v *InsecureValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always pass through in insecure mode
		next.ServeHTTP(w, r)
	})
}
