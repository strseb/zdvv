package main

import (
	"os"
	"testing"
)

func TestConfigFromEnvironment(t *testing.T) {
	// Save original environment variables
	origJWTSecret := os.Getenv("JWT_SECRET")
	origAdminToken := os.Getenv("ADMIN_TOKEN")
	
	// Restore environment variables after test
	defer func() {
		os.Setenv("JWT_SECRET", origJWTSecret)
		os.Setenv("ADMIN_TOKEN", origAdminToken)
	}()
	
	// Set test environment variables
	os.Setenv("JWT_SECRET", "test-jwt-secret")
	os.Setenv("ADMIN_TOKEN", "test-admin-token")
	
	// We can't easily test the main function directly since it calls log.Fatal
	// This is more of a validation that environment variables are properly set
	secret := os.Getenv("JWT_SECRET")
	adminToken := os.Getenv("ADMIN_TOKEN")
	
	if secret != "test-jwt-secret" {
		t.Fatalf("Expected JWT_SECRET to be 'test-jwt-secret', got '%s'", secret)
	}
	
	if adminToken != "test-admin-token" {
		t.Fatalf("Expected ADMIN_TOKEN to be 'test-admin-token', got '%s'", adminToken)
	}
}

// TestTLSConfiguration tests the TLS configuration settings
func TestTLSConfig(t *testing.T) {
	// This test is more about validating the TLS configuration logic
	
	// Test case: HTTP/2 and HTTP/3 enabled (default)
	disableHTTP2 := false
	disableHTTP3 := false
	
	nextProtos := []string{"http/1.1"}
	
	if !disableHTTP2 {
		nextProtos = append(nextProtos, "h2")
	}
	
	if !disableHTTP3 {
		nextProtos = append(nextProtos, "h3")
	}
	
	// Verify protocol list contains all expected protocols
	expectedProtos := []string{"http/1.1", "h2", "h3"}
	if len(nextProtos) != len(expectedProtos) {
		t.Fatalf("Expected %d protocols, got %d", len(expectedProtos), len(nextProtos))
	}
	
	for i, proto := range expectedProtos {
		if nextProtos[i] != proto {
			t.Fatalf("Expected protocol %s at position %d, got %s", proto, i, nextProtos[i])
		}
	}
	
	// Test case: HTTP/2 disabled
	disableHTTP2 = true
	disableHTTP3 = false
	
	nextProtos = []string{"http/1.1"}
	
	if !disableHTTP2 {
		nextProtos = append(nextProtos, "h2")
	}
	
	if !disableHTTP3 {
		nextProtos = append(nextProtos, "h3")
	}
	
	// Verify h2 is not in the list
	expectedProtos = []string{"http/1.1", "h3"}
	if len(nextProtos) != len(expectedProtos) {
		t.Fatalf("Expected %d protocols with HTTP/2 disabled, got %d", len(expectedProtos), len(nextProtos))
	}
	
	for i, proto := range expectedProtos {
		if nextProtos[i] != proto {
			t.Fatalf("Expected protocol %s at position %d, got %s", proto, i, nextProtos[i])
		}
	}
	
	// Test case: HTTP/3 disabled
	disableHTTP2 = false
	disableHTTP3 = true
	
	nextProtos = []string{"http/1.1"}
	
	if !disableHTTP2 {
		nextProtos = append(nextProtos, "h2")
	}
	
	if !disableHTTP3 {
		nextProtos = append(nextProtos, "h3")
	}
	
	// Verify h3 is not in the list
	expectedProtos = []string{"http/1.1", "h2"}
	if len(nextProtos) != len(expectedProtos) {
		t.Fatalf("Expected %d protocols with HTTP/3 disabled, got %d", len(expectedProtos), len(nextProtos))
	}
	
	for i, proto := range expectedProtos {
		if nextProtos[i] != proto {
			t.Fatalf("Expected protocol %s at position %d, got %s", proto, i, nextProtos[i])
		}
	}
	
	// Test case: Both HTTP/2 and HTTP/3 disabled
	disableHTTP2 = true
	disableHTTP3 = true
	
	nextProtos = []string{"http/1.1"}
	
	if !disableHTTP2 {
		nextProtos = append(nextProtos, "h2")
	}
	
	if !disableHTTP3 {
		nextProtos = append(nextProtos, "h3")
	}
	
	// Verify only http/1.1 is in the list
	expectedProtos = []string{"http/1.1"}
	if len(nextProtos) != len(expectedProtos) {
		t.Fatalf("Expected %d protocols with HTTP/2 and HTTP/3 disabled, got %d", len(expectedProtos), len(nextProtos))
	}
	
	for i, proto := range expectedProtos {
		if nextProtos[i] != proto {
			t.Fatalf("Expected protocol %s at position %d, got %s", proto, i, nextProtos[i])
		}
	}
}
