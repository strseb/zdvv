package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// KeyProvider interface for services that can provide public keys for JWT validation
type KeyProvider interface {
	// PublicKeys returns a map of key IDs to RSA public keys
	PublicKeys() (map[uint64]*rsa.PublicKey, error)
}

// MultiKeyJWTValidator validates JWT tokens using multiple public keys
// It fetches keys from a KeyProvider as needed
type MultiKeyJWTValidator struct {
	keyProvider        KeyProvider
	keyCache           map[uint64]*rsa.PublicKey
	keyCacheMutex      sync.RWMutex
	allowNoneSignature bool
	permissions        []Permission
}

// NewMultiKeyJWTValidator creates a new validator that can handle multiple keys
func NewMultiKeyJWTValidator(keyProvider KeyProvider, permissions []Permission) *MultiKeyJWTValidator {
	return &MultiKeyJWTValidator{
		keyProvider: keyProvider,
		keyCache:    make(map[uint64]*rsa.PublicKey),
		permissions: permissions,
	}
}

// getKey retrieves a public key by ID, fetching from the provider if necessary
func (v *MultiKeyJWTValidator) getKey(keyID uint64) (*rsa.PublicKey, error) {
	// First check the cache with a read lock
	v.keyCacheMutex.RLock()
	key, exists := v.keyCache[keyID]
	v.keyCacheMutex.RUnlock()

	if exists {
		return key, nil
	}

	// Key not found, fetch all keys with a write lock
	v.keyCacheMutex.Lock()
	defer v.keyCacheMutex.Unlock()

	// Double-check if the key was added while waiting for lock
	if key, exists := v.keyCache[keyID]; exists {
		return key, nil
	}

	// Fetch keys from provider
	keys, err := v.keyProvider.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys: %w", err)
	}

	// Update the cache with all fetched keys
	for id, pubKey := range keys {
		v.keyCache[id] = pubKey
	}

	// Check if our key is now in the cache
	key, exists = v.keyCache[keyID]
	if !exists {
		return nil, fmt.Errorf("key ID %d not found", keyID)
	}

	return key, nil
}

// Middleware implements HTTP middleware for JWT validation
func (v *MultiKeyJWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from header
		authHeader := r.Header.Get(authHeader)
		if authHeader == "" {
			http.Error(w, ErrNoAuthHeader.Error(), http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != authScheme {
			http.Error(w, ErrInvalidScheme.Error(), http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]

		// Handle "none" algorithm if allowed
		if v.allowNoneSignature {
			parser := jwt.NewParser()
			token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
			if err == nil && token.Method.Alg() == "none" {
				token.Valid = true
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					// Check permissions
					for _, perm := range v.permissions {
						if !perm.Check(claims) {
							http.Error(w, "missing required permission: "+string(perm), http.StatusUnauthorized)
							return
						}
					}
				}

				// Add token to context and proceed
				ctx := context.WithValue(r.Context(), "token", token)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Parse token without validation to extract the kid
		parser := jwt.NewParser()
		unsafeToken, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			http.Error(w, fmt.Sprintf("%s: %v", ErrInvalidToken.Error(), err), http.StatusUnauthorized)
			return
		}

		// Extract the kid from token header
		kidRaw, ok := unsafeToken.Header["kid"]
		if !ok {
			http.Error(w, "token missing 'kid' header", http.StatusUnauthorized)
			return
		}

		// Convert kid to uint64
		var keyID uint64
		switch kid := kidRaw.(type) {
		case float64:
			keyID = uint64(kid)
		case int64:
			keyID = uint64(kid)
		case int:
			keyID = uint64(kid)
		default:
			http.Error(w, "invalid kid format in token", http.StatusUnauthorized)
			return
		}

		// Get the public key for this kid
		publicKey, err := v.getKey(keyID)
		if err != nil {
			http.Error(w, fmt.Sprintf("key not found: %v", err), http.StatusUnauthorized)
			return
		}

		// Validate token with the correct public key
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("%s: %v", ErrInvalidToken.Error(), err), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}

		// Check permissions
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			for _, perm := range v.permissions {
				if !perm.Check(claims) {
					http.Error(w, "missing required permission: "+string(perm), http.StatusUnauthorized)
					return
				}
			}
		}

		// Add the token to the context and continue
		ctx := context.WithValue(r.Context(), "token", token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
