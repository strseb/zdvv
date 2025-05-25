package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// MockDatabase is a mock implementation of the Database interface.
type MockDatabase struct{}

func (m *MockDatabase) AddServer(val *Server) error {
	return nil
}

func (m *MockDatabase) GetAllServers() ([]*Server, error) {
	return []*Server{
		{
			ProxyURL:           "http://example.com",
			Latitude:           12.34,
			Longitude:          56.78,
			City:               "TestCity",
			Country:            "TestCountry",
			SupportsConnectTCP: true,
			SupportsConnectUDP: false,
			SupportsConnectIP:  true,
			RevocationToken:    "test-token",
		},
	}, nil
}

func (m *MockDatabase) PutJWTKey(val *JWTKey) error {
	return nil
}

func (m *MockDatabase) GetAllActiveJWTKeys() ([]*JWTKey, error) {
	return []*JWTKey{
		{
			Kty:       "RSA",
			PublicKey: "test-public-key",
			Kid:       123,
			ExpiresAt: 9999999999,
		},
	}, nil
}

func (m *MockDatabase) RemoveServerByToken(revocationToken string) error {
	if revocationToken == "test-token" {
		return nil
	}
	return fmt.Errorf("server with revocation token not found")
}

func TestHeartbeatEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestRootEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
	if body := w.Body.String(); body != "Hello World!" {
		t.Errorf("expected body 'Hello World!', got %v", body)
	}
}

func TestJWKSJsonEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestTokenEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/token", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestServersEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestDemoEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/demo", nil)
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
	if body := w.Body.String(); body != "Demo route accessed" {
		t.Errorf("expected body 'Demo route accessed', got %v", body)
	}
}

func TestAddServerEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	server := `{
		"proxyUrl": "http://example.com",
		"latitude": 12.34,
		"longitude": 56.78,
		"city": "TestCity",
		"country": "TestCountry",
		"supportsConnectTcp": true,
		"supportsConnectUdp": false,
		"supportsConnectIp": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/server", strings.NewReader(server))
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestRemoveServerEndpoint(t *testing.T) {
	mockDB := &MockDatabase{}
	cfg := &Config{
		ListenAddr: "localhost:8080",
		AuthSecret: "my-secret-key",
	}
	r := createRouter(mockDB, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/server/test-token", nil)
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
	if body := w.Body.String(); body != "Server removed successfully" {
		t.Errorf("expected body 'Server removed successfully', got %v", body)
	}
}
