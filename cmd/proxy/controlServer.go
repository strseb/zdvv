package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/basti/zdvv/pkg/common"
	"github.com/golang-jwt/jwt/v5"
)

/**
 * The ControlServer may live in the same process as the server or in a different process.
 */
type ControlServer interface {
	Alive() bool
	RegisterProxyServer(common.Server) error
	DeregisterProxyServer(common.Server) error
	Servers() ([]common.Server, error)
	PublicKeys() (map[uint64]*rsa.PublicKey, error)
}

type HTTPControlServer struct {
	ServerURL    string
	SharedSecret string
	client       *http.Client
}

func NewHTTPControlServer(serverURL, sharedSecret string) *HTTPControlServer {
	return &HTTPControlServer{
		ServerURL:    serverURL,
		SharedSecret: sharedSecret,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Alive checks if the control server is reachable
func (h *HTTPControlServer) Alive() bool {
	resp, err := h.client.Get(fmt.Sprintf("%s/api/v1/health", h.ServerURL))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// Servers retrieves the list of servers from the control server
func (h *HTTPControlServer) Servers() ([]common.Server, error) {
	resp, err := h.client.Get(fmt.Sprintf("%s/api/v1/servers", h.ServerURL))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from server: %d", resp.StatusCode)
	}

	var response struct {
		Servers []common.Server `json:"servers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w", err)
	}

	return response.Servers, nil
}

// PublicKeys retrieves the public keys from the control server's JWKS endpoint
func (h *HTTPControlServer) PublicKeys() (map[uint64]*rsa.PublicKey, error) {
	resp, err := h.client.Get(fmt.Sprintf("%s/.well-known/jwks.json", h.ServerURL))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from JWKS endpoint: %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty       string `json:"kty"`
			K         string `json:"k"`
			Kid       int64  `json:"kid"`
			ExpiresAt int64  `json:"expiresAt"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS response: %w", err)
	}

	publicKeys := make(map[uint64]*rsa.PublicKey)

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		// Decode the base64 key
		keyBytes, err := base64.StdEncoding.DecodeString(key.K)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key %d: %w", key.Kid, err)
		}

		// Parse the key bytes into a public key
		pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %d: %w", key.Kid, err)
		}

		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key %d is not an RSA key", key.Kid)
		}

		publicKeys[uint64(key.Kid)] = rsaKey
	}

	return publicKeys, nil
}

// RegisterProxyServer registers the proxy server with the control server
func (h *HTTPControlServer) RegisterProxyServer(server common.Server) error {
	serverJSON, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("failed to marshal server data: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/v1/server", h.ServerURL),
		bytes.NewBuffer(serverJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.SharedSecret))

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to register server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server registration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		RevocationToken string `json:"revocationToken"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	// Let the caller handle storing the revocation token if needed
	server.RevocationToken = response.RevocationToken

	// Make a copy available for DeregisterProxyServer
	return nil
}

// DeregisterProxyServer removes the proxy server from the control server
func (h *HTTPControlServer) DeregisterProxyServer(server common.Server) error {
	if server.RevocationToken == "" {
		return fmt.Errorf("cannot deregister server without revocation token")
	}

	req, err := http.NewRequest(
		http.MethodDelete,
		fmt.Sprintf("%s/api/v1/server/%s", h.ServerURL, server.RevocationToken),
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.SharedSecret))

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to deregister server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server deregistration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CreateToken obtains a JWT token from the control server
func (h *HTTPControlServer) CreateToken(permissions interface{}) (*jwt.Token, error) {
	resp, err := h.client.Get(fmt.Sprintf("%s/api/v1/token", h.ServerURL))
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token creation failed with status %d", resp.StatusCode)
	}

	var response struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Parse the token to return a jwt.Token object
	token, err := jwt.Parse(response.Token, func(token *jwt.Token) (interface{}, error) {
		// This will be replaced by actual verification during validation
		// Here we just want to parse the token into an object
		return nil, nil
	})

	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		// Ignore the expected error about the key being invalid since we provided nil
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Set the raw token string for later access
	token.Raw = response.Token

	return token, nil
}
