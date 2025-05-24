package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
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
	Header             string
	Scheme             string
	PublicKey          *rsa.PublicKey
	RevocationSvc      *RevocationService
	AllowNoneSignature bool         // Allow 'none' alg in insecure mode
	Permissions        []Permission // List of permission check functions
}

// NewJWTValidator creates a new JWT validator
func NewJWTValidator(publicKey *rsa.PublicKey, revocationSvc *RevocationService, permissions []Permission) *JWTValidator {
	return &JWTValidator{
		Header:        DefaultAuthHeader,
		Scheme:        DefaultAuthScheme,
		PublicKey:     publicKey,
		RevocationSvc: revocationSvc,
		Permissions:   permissions,
	}
}

// NewInsecureJWTValidator creates a JWT validator that allows 'none' algorithm
func NewInsecureJWTValidator(revocationSvc *RevocationService, permissions []Permission) *JWTValidator {
	return &JWTValidator{
		Header:             DefaultAuthHeader,
		Scheme:             DefaultAuthScheme,
		PublicKey:          nil, // Not needed for 'none'
		RevocationSvc:      revocationSvc,
		AllowNoneSignature: true,
		Permissions:        permissions,
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
	if v.AllowNoneSignature {
		// Parse header to check alg before full parsing
		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err == nil && token.Method.Alg() == "none" {
			token.Valid = true
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if jti, ok := claims["jti"].(string); ok {
					if v.RevocationSvc.IsRevoked(jti) {
						return nil, ErrTokenRevoked
					}
				} else {
					return nil, errors.New("token missing jti claim")
				}
				// Check permissions
				for _, perm := range v.Permissions {
					if !perm.Check(claims) {
						return nil, errors.New("missing required permission: " + string(perm))
					}
				}
			}
			return token, nil
		}
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			if v.RevocationSvc.IsRevoked(jti) {
				return nil, ErrTokenRevoked
			}
		} else {
			return nil, errors.New("token missing jti claim")
		}
		// Check permissions
		for _, perm := range v.Permissions {
			if !perm.Check(claims) {
				return nil, errors.New("missing required permission: " + string(perm))
			}
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
