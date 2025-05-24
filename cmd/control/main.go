package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/basti/zdvv/pkg/common"
)

type Config struct {
	ListenAddr    string `env:"ZDVV_PORT" default:"localhost:8080"`
	RedisAddr     string `env:"ZDVV_REDIS_ADDR" default:"localhost:6379"`
	RedisPassword string `env:"ZDVV_REDIS_PASSWORD" default:""`
	RedisDB       int    `env:"ZDVV_REDIS_DB" default:"0"`
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
	log.Printf("Starting control server on %s", cfg.ListenAddr)
	http.ListenAndServe(":3000", r)
}
