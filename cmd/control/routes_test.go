package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockDatabase is a mock implementation of the Database interface.
type MockDatabase struct{}

func (m *MockDatabase) PutServer(val *Server) error {

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
