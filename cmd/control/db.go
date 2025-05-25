package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Database defines an interface for database operations.
type Database interface {
	PutServer(val *Server) error
	GetAllServers() ([]*Server, error)
	PutJWTKey(val *JWTKey) error
	GetAllActiveJWTKeys() ([]*JWTKey, error)
}

// RedisDatabase is an implementation of the Database interface using Redis.
type RedisDatabase struct {
	db *redis.Client
}

// NewRedisDatabase creates a new RedisDatabase instance.
func NewRedisDatabase(db *redis.Client) *RedisDatabase {
	return &RedisDatabase{db: db}
}

// PutServer stores the Server object in Redis as a hash using proxyUrl as the key.
func (r *RedisDatabase) PutServer(val *Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	key := fmt.Sprintf("server:%s", val.ProxyURL)
	data := map[string]interface{}{
		"proxyUrl":           val.ProxyURL,
		"latitude":           val.Latitude,
		"longitude":          val.Longitude,
		"city":               val.City,
		"country":            val.Country,
		"supportsConnectTcp": val.SupportsConnectTCP,
		"supportsConnectUdp": val.SupportsConnectUDP,
		"supportsConnectIp":  val.SupportsConnectIP,
		"revocationToken":    val.RevocationToken,
	}

	return r.db.HSet(ctx, key, data).Err()
}

// GetAllServers retrieves all Server objects stored in Redis hashes.
func (r *RedisDatabase) GetAllServers() ([]*Server, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var keys []string
	iter := r.db.Scan(ctx, 0, "server:*", 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	var servers []*Server
	for _, key := range keys {
		data, err := r.db.HGetAll(ctx, key).Result()
		if err != nil {
			return nil, err
		}

		server := &Server{
			ProxyURL:           data["proxyUrl"],
			Latitude:           parseFloat(data["latitude"]),
			Longitude:          parseFloat(data["longitude"]),
			City:               data["city"],
			Country:            data["country"],
			SupportsConnectTCP: parseBool(data["supportsConnectTcp"]),
			SupportsConnectUDP: parseBool(data["supportsConnectUdp"]),
			SupportsConnectIP:  parseBool(data["supportsConnectIp"]),
			RevocationToken:    data["revocationToken"],
		}
		servers = append(servers, server)
	}

	return servers, nil
}

// PutJWTKey stores the JWTKey object in Redis as a hash using kid as the key.
func (r *RedisDatabase) PutJWTKey(val *JWTKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	key := fmt.Sprintf("kid:%d", val.Kid)
	data := map[string]interface{}{
		"kty":       val.Kty,
		"publicKey": val.PublicKey,
		"kid":       val.Kid,
		"expiresAt": val.ExpiresAt,
	}

	expireAt := time.Unix(val.ExpiresAt, 0).Add(25 * time.Hour)
	ttl := time.Until(expireAt)
	if ttl <= 0 {
		return fmt.Errorf("expiration time is in the past")
	}

	pipe := r.db.TxPipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// GetAllActiveJWTKeys retrieves all JWTKey objects stored in Redis hashes.
func (r *RedisDatabase) GetAllActiveJWTKeys() ([]*JWTKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var keys []string
	iter := r.db.Scan(ctx, 0, "kid:*", 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	var jwtKeys []*JWTKey
	for _, key := range keys {
		data, err := r.db.HGetAll(ctx, key).Result()
		if err != nil {
			return nil, err
		}

		jwtKey := &JWTKey{
			Kty:       data["kty"],
			PublicKey: data["publicKey"],
			Kid:       parseInt64(data["kid"]),
			ExpiresAt: parseInt64(data["expiresAt"]),
		}
		jwtKeys = append(jwtKeys, jwtKey)
	}

	return jwtKeys, nil
}

// Helper functions to parse string values from Redis
func parseFloat(value string) float64 {
	v, _ := strconv.ParseFloat(value, 64)
	return v
}

func parseBool(value string) bool {
	v, _ := strconv.ParseBool(value)
	return v
}

func parseInt64(value string) int64 {
	v, _ := strconv.ParseInt(value, 10, 64)
	return v
}
