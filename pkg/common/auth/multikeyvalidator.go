/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyProvider interface for services that can provide public keys for JWT validation
type KeyProvider interface {
	// PublicKeys returns a map of key IDs to RSA public keys
	PublicKeys() (map[string]*rsa.PublicKey, error)
}

// MultiKeyJWTValidator validates JWT tokens using multiple public keys
// It fetches keys from a KeyProvider as needed
type MultiKeyJWTValidator struct {
	keyProvider        KeyProvider
	keyCache           map[string]*rsa.PublicKey
	keyCacheMutex      sync.RWMutex
	allowNoneSignature bool
	permissions        []Permission
}

// NewMultiKeyJWTValidator creates a new validator that can handle multiple keys
func NewMultiKeyJWTValidator(keyProvider KeyProvider, permissions []Permission) *MultiKeyJWTValidator {
	permStrings := make([]string, len(permissions))
	for i, p := range permissions {
		permStrings[i] = string(p)
	}

	log.Printf("Initializing MultiKeyJWTValidator with permissions: %v", permStrings)

	return &MultiKeyJWTValidator{
		keyProvider: keyProvider,
		keyCache:    make(map[string]*rsa.PublicKey),
		permissions: permissions,
	}
}

// getKey retrieves a public key by ID, fetching from the provider if necessary
func (v *MultiKeyJWTValidator) getKey(keyID string) (*rsa.PublicKey, error) {
	log.Printf("JWT: Attempting to retrieve key with ID %s", keyID)

	// First check the cache with a read lock
	v.keyCacheMutex.RLock()
	key, exists := v.keyCache[keyID]
	v.keyCacheMutex.RUnlock()

	if exists {
		log.Printf("JWT: Key ID %s found in cache", keyID)
		return key, nil
	}

	log.Printf("JWT: Key ID %s not in cache, fetching from provider", keyID)

	// Key not found, fetch all keys with a write lock
	v.keyCacheMutex.Lock()
	defer v.keyCacheMutex.Unlock()

	// Double-check if the key was added while waiting for lock
	if key, exists := v.keyCache[keyID]; exists {
		log.Printf("JWT: Key ID %s was added to cache while waiting for lock", keyID)
		return key, nil
	}

	// Fetch keys from provider
	startTime := time.Now()
	keys, err := v.keyProvider.PublicKeys()
	fetchDuration := time.Since(startTime)

	if err != nil {
		log.Printf("JWT: Error fetching public keys from provider after %v: %v", fetchDuration, err)
		return nil, fmt.Errorf("failed to fetch public keys: %w", err)
	}

	log.Printf("JWT: Successfully fetched %d keys from provider in %v", len(keys), fetchDuration)

	// Update the cache with all fetched keys
	for id, pubKey := range keys {
		v.keyCache[id] = pubKey
		log.Printf("JWT: Added key ID %s to cache", id)
	}

	// Check if our key is now in the cache
	key, exists = v.keyCache[keyID]
	if !exists {
		log.Printf("JWT: Key ID %s not found in provider's keys", keyID)
		return nil, fmt.Errorf("key ID %s not found", keyID)
	}

	log.Printf("JWT: Successfully retrieved key ID %s", keyID)
	return key, nil
}

// Middleware implements HTTP middleware for JWT validation
func (v *MultiKeyJWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		reqPath := r.URL.Path
		reqMethod := r.Method
		reqID := r.Header.Get("X-Request-ID") // Use request ID from header if available
		if reqID == "" {
			// Generate a simple unique identifier if none exists
			reqID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		logPrefix := fmt.Sprintf("JWT-Auth [%s] %s %s:", reqID, reqMethod, reqPath)
		log.Printf("%s Starting authentication check", logPrefix)

		// Extract token from header
		authHeader := r.Header.Get(authHeader)
		if authHeader == "" {
			log.Printf("%s Missing authorization header", logPrefix)
			http.Error(w, ErrNoAuthHeader.Error(), http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != authScheme {
			log.Printf("%s Invalid authorization scheme: %s", logPrefix, parts[0])
			http.Error(w, ErrInvalidScheme.Error(), http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		log.Printf("%s Authorization header found, token length: %d chars", logPrefix, len(tokenStr))

		// Handle "none" algorithm if allowed
		if v.allowNoneSignature {
			log.Printf("%s Checking for 'none' algorithm (insecure mode)", logPrefix)
			parser := jwt.NewParser()
			token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
			if err == nil && token.Method.Alg() == "none" {
				log.Printf("%s Token uses 'none' algorithm and none is allowed", logPrefix)
				token.Valid = true
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					// Check permissions
					log.Printf("%s Checking permissions for 'none' token", logPrefix)
					for _, perm := range v.permissions {
						if !perm.Check(claims) {
							log.Printf("%s Permission denied: missing %s", logPrefix, string(perm))
							http.Error(w, "missing required permission: "+string(perm), http.StatusUnauthorized)
							return
						}
					}
					log.Printf("%s All permissions granted for 'none' token", logPrefix)
				}

				// Add token to context and proceed
				log.Printf("%s Authentication successful with 'none' token in %v", logPrefix, time.Since(startTime))
				ctx := context.WithValue(r.Context(), "token", token)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Parse token without validation to extract the kid
		log.Printf("%s Parsing token to extract key ID (kid)", logPrefix)
		parser := jwt.NewParser()
		unsafeToken, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			log.Printf("%s Error parsing token: %v", logPrefix, err)
			http.Error(w, fmt.Sprintf("%s: %v", ErrInvalidToken.Error(), err), http.StatusUnauthorized)
			return
		}

		// Extract the kid from token header
		kidRaw, ok := unsafeToken.Header["kid"]
		if !ok {
			log.Printf("%s Token missing 'kid' header", logPrefix)
			http.Error(w, "token missing 'kid' header", http.StatusUnauthorized)
			return
		}

		// Convert kid to string format
		var keyID string
		switch kid := kidRaw.(type) {
		case string:
			keyID = kid
		case float64:
			keyID = fmt.Sprintf("%v", kid)
		case int64:
			keyID = fmt.Sprintf("%d", kid)
		case int:
			keyID = fmt.Sprintf("%d", kid)
		default:
			log.Printf("%s Invalid kid format in token: %T", logPrefix, kidRaw)
			http.Error(w, "invalid kid format in token", http.StatusUnauthorized)
			return
		}
		log.Printf("%s Extracted key ID (kid): %s", logPrefix, keyID)

		// Get the public key for this kid
		log.Printf("%s Retrieving public key for kid: %s", logPrefix, keyID)
		publicKey, err := v.getKey(keyID)
		if err != nil {
			log.Printf("%s Failed to retrieve key: %v", logPrefix, err)
			http.Error(w, fmt.Sprintf("key not found: %v", err), http.StatusUnauthorized)
			return
		}
		log.Printf("%s Public key retrieved successfully", logPrefix)

		// Validate token with the correct public key
		log.Printf("%s Validating token signature", logPrefix)
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				alg, _ := token.Header["alg"].(string)
				log.Printf("%s Unexpected signing method: %v, expected RSA", logPrefix, alg)
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil {
			log.Printf("%s Token validation failed: %v", logPrefix, err)
			http.Error(w, fmt.Sprintf("%s: %v", ErrInvalidToken.Error(), err), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			log.Printf("%s Token is invalid", logPrefix)
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}
		log.Printf("%s Token signature validated successfully", logPrefix)

		// Check permissions
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			log.Printf("%s Checking token claims and permissions", logPrefix)

			// Log claim information for debugging (be careful with sensitive info)
			if sub, ok := claims["sub"].(string); ok {
				log.Printf("%s Token subject: %s", logPrefix, sub)
			}
			if iss, ok := claims["iss"].(string); ok {
				log.Printf("%s Token issuer: %s", logPrefix, iss)
			}
			if exp, ok := claims["exp"].(float64); ok {
				expTime := time.Unix(int64(exp), 0)
				log.Printf("%s Token expires: %s (in %v)", logPrefix, expTime, time.Until(expTime))
			}

			// Check required permissions
			for _, perm := range v.permissions {
				if !perm.Check(claims) {
					log.Printf("%s Permission denied: missing %s", logPrefix, string(perm))
					http.Error(w, "missing required permission: "+string(perm), http.StatusUnauthorized)
					return
				}
			}
			log.Printf("%s All required permissions granted", logPrefix)
		} else {
			log.Printf("%s Token has invalid claims format", logPrefix)
		}

		// Add the token to the context and continue
		log.Printf("%s Authentication successful in %v", logPrefix, time.Since(startTime))
		ctx := context.WithValue(r.Context(), "token", token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
