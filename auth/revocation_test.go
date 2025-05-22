package auth

import (
	"testing"
)

func TestRevocationService(t *testing.T) {
	// Create a new revocation service
	svc := NewRevocationService()

	// Test initial state
	if len(svc.GetRevokedList()) != 0 {
		t.Fatal("Expected empty revocation list on initialization")
	}

	// Test revoking a token
	testJTI := "test-token-id"
	svc.Revoke(testJTI)

	// Check if the token is revoked
	if !svc.IsRevoked(testJTI) {
		t.Fatal("Expected token to be revoked")
	}

	// Check if the revoked list contains the token
	revokedList := svc.GetRevokedList()
	if len(revokedList) != 1 || revokedList[0] != testJTI {
		t.Fatal("Expected revoked list to contain the revoked token")
	}

	// Test revoking multiple tokens
	testJTI2 := "test-token-id-2"
	svc.Revoke(testJTI2)

	// Check if both tokens are revoked
	if !svc.IsRevoked(testJTI) || !svc.IsRevoked(testJTI2) {
		t.Fatal("Expected both tokens to be revoked")
	}

	// Check if a non-revoked token is correctly identified
	if svc.IsRevoked("non-revoked-token") {
		t.Fatal("Expected non-revoked token to not be identified as revoked")
	}

	// Check revoked list length
	revokedList = svc.GetRevokedList()
	if len(revokedList) != 2 {
		t.Fatalf("Expected 2 tokens in revoked list, got %d", len(revokedList))
	}
}

func TestRevocationServiceConcurrency(t *testing.T) {
	// This test ensures the RevocationService is safe for concurrent use
	svc := NewRevocationService()
	
	// Create a large number of tokens to revoke concurrently
	tokenCount := 100
	done := make(chan bool)
	
	// Revoke tokens concurrently
	for i := 0; i < tokenCount; i++ {
		go func(idx int) {
			jti := "concurrent-token-" + string(rune(idx))
			svc.Revoke(jti)
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < tokenCount; i++ {
		<-done
	}
	
	// Check if all tokens are revoked and the list has the expected length
	revokedList := svc.GetRevokedList()
	if len(revokedList) != tokenCount {
		t.Fatalf("Expected %d tokens in revoked list, got %d", tokenCount, len(revokedList))
	}
}
