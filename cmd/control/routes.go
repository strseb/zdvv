package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
)

func createRouter(db Database, cfg *Config) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	jwtKeyMutex := sync.RWMutex{}
	jwtKey, err := newJWTKey()
	if err != nil {
		log.Fatalf("Failed to create JWT key: %v", err)
	}

	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		keys, err := db.GetAllActiveJWTKeys()
		if err != nil {
			http.Error(w, "Failed to retrieve JWT keys", http.StatusInternalServerError)
			log.Printf("Error retrieving JWT keys: %v", err)
			return
		}
		if len(keys) == 0 {
			http.Error(w, "No JWT keys found", http.StatusNotFound)
			log.Println("No JWT keys found")
			return
		}
		jwks := map[string]interface{}{
			"keys": keys,
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(jwks)
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Unauthenticated routes
		r.Group(func(r chi.Router) {
			r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			r.Get("/token", func(w http.ResponseWriter, r *http.Request) {
				jwtKeyMutex.RLock()
				if jwtKey.IsExpired() {
					jwtKeyMutex.RUnlock()
					jwtKeyMutex.Lock()
					defer jwtKeyMutex.Unlock()
					if jwtKey.IsExpired() {
						newKey, err := newJWTKey()
						if err != nil {
							http.Error(w, "Failed to create new JWT key", http.StatusInternalServerError)
							return
						}
						if err := db.PutJWTKey(newKey); err != nil {
							http.Error(w, "Failed to store new JWT key", http.StatusInternalServerError)
							log.Printf("Error storing new JWT key: %v", err)
							return
						}
						jwtKey = newKey
					}
				} else {
					defer jwtKeyMutex.RUnlock()
				}

				jti, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
				if err != nil {
					http.Error(w, "Failed to generate JTI", http.StatusInternalServerError)
					return
				}
				jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"iss": "zdvv-control-server",
					"exp": time.Now().Add(time.Hour * 1).Unix(),
					"jti": jti.Int64(),
					"kid": jwtKey.Kid,
				})
				signedToken, err := jwtToken.SignedString(jwtKey.privateKey)
				if err != nil {
					http.Error(w, "Failed to sign JWT token", http.StatusInternalServerError)
					log.Printf("Error signing JWT token: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"token":"` + signedToken + `"}`))
			})

			r.Get("/servers", func(w http.ResponseWriter, r *http.Request) {
				servers, err := db.GetAllServers()
				if err != nil {
					http.Error(w, "Failed to retrieve servers", http.StatusInternalServerError)
					log.Printf("Error retrieving servers: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"servers": servers,
				})
			})
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authHeader := r.Header.Get("Authorization")
					expectedAuth := "Bearer " + cfg.AuthSecret
					if authHeader != expectedAuth {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r)
				})
			})

			r.Get("/demo", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Demo route accessed"))
			})
		})
	})

	return r
}
