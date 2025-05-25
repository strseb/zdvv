package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/basti/zdvv/pkg/common"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	ListenAddr    string `env:"ZDVV_PORT" default:"localhost:8080"`
	RedisAddr     string `env:"ZDVV_REDIS_ADDR" default:"localhost:6379"`
	RedisPassword string `env:"ZDVV_REDIS_PASSWORD" default:""`
	RedisDB       int    `env:"ZDVV_REDIS_DB" default:"0"`
	AuthSecret    string `env:"ZDVV_AUTH_SECRET" default:"my-secret-key"`
}

func main() {
	common.ImportDotenv()
	cfg := &Config{}
	if err := common.LoadEnvToStruct(cfg); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer rdb.Close()

	// Test the connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	log.Println("Successfully connected to Redis")

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
	r.Get(".well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		keys, err := getAllActiveJWTKeys(rdb)
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

	// Create API v1 router group
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
					// Re-check if the key is still expired after acquiring the lock
					if jwtKey.IsExpired() {
						newKey, err := newJWTKey()
						if err != nil {
							http.Error(w, "Failed to create new JWT key", http.StatusInternalServerError)
							return
						}
						if err := put(newKey, rdb); err != nil {
							http.Error(w, "Failed to store new JWT key", http.StatusInternalServerError)
							log.Printf("Error storing new JWT key: %v", err)
							return
						}
						jwtKey = newKey
					}
				} else {
					defer jwtKeyMutex.RUnlock()
				}

				jti, err := rand.Int(rand.Reader, big.NewInt(1<<63-1)) // Generate a random key ID
				if err != nil {
					http.Error(w, "Failed to generate JTI", http.StatusInternalServerError)
					return
				}

				jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
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
				ctx := r.Context()
				servers, err := rdb.SMembers(ctx, "servers").Result()
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
			// Middleware to check for Authorization header with secret from config
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

			// Authenticated /demo route
			r.Get("/demo", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Demo route accessed"))
			})
		})
	})

	log.Printf("Starting control server on %s", cfg.ListenAddr)
	http.ListenAndServe(":3000", r)
}
