/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/strseb/zdvv/pkg/common"
)

type Config struct {
	ListenAddr    string `env:"ZDVV_LISTEN_ADDR" default:":8080"`
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

	// Initialize the RedisDatabase
	db := NewRedisDatabase(rdb)
	r := createRouter(db, cfg)

	log.Printf("Starting control server on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, r); err != nil {
		log.Fatalf("Failed to start control server: %v", err)
	}
}
