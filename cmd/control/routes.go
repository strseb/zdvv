/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/strseb/zdvv/pkg/common"
	"github.com/strseb/zdvv/pkg/common/auth"
)

func createRouter(db Database, cfg *Config) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	jwtKeyMutex := sync.RWMutex{}
	jwtKey, err := common.NewJWTKey()
	db.PutJWTKey(jwtKey) // Store the initial JWT key in the database
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
						newKey, err := common.NewJWTKey()
						db.PutJWTKey(jwtKey)
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

				// Sign the token using the SignWithClaims method with specific permissions
				signedToken, err := jwtKey.SignWithClaims(
					"zdvv-control-server",
					time.Hour*1,
					auth.GetPermissionStrings([]auth.Permission{auth.PERMISSION_CONNECT_TCP}),
				)
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

			r.Post("/server", func(w http.ResponseWriter, r *http.Request) {
				var server common.Server
				if err := json.NewDecoder(r.Body).Decode(&server); err != nil {
					http.Error(w, "Invalid request payload", http.StatusBadRequest)
					return
				}

				// Validate the server object
				if valid, message := server.IsValid(); !valid {
					http.Error(w, message, http.StatusBadRequest)
					return
				}

				revocationToken, err := server.GenerateRevocationToken()
				if err != nil {
					http.Error(w, "Failed to generate revocation token", http.StatusInternalServerError)
					return
				}

				if err := db.AddServer(&server); err != nil {
					http.Error(w, "Failed to add server", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"revocationToken": revocationToken,
				})
			})

			r.Delete("/server/{revocationToken}", func(w http.ResponseWriter, r *http.Request) {
				revocationToken := chi.URLParam(r, "revocationToken")
				if err := db.RemoveServerByToken(revocationToken); err != nil {
					http.Error(w, "Failed to remove server", http.StatusInternalServerError)
					return
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Server removed successfully"))
			})
		})
	})

	return r
}
