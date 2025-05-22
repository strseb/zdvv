package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestGenerateToken tests the token generation functionality
func TestGenerateToken(t *testing.T) {
	// Create a buffer to capture output
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run the main function
	main()

	// Restore stdout
	w.Close()
	os.Stdout = origStdout
	// Read the captured output
	bytes, _ := io.ReadAll(r)
	output := string(bytes)

	// Check that the output contains a token
	if !strings.Contains(output, "Test JWT Token:") {
		t.Errorf("Expected output to contain token header, got: %s", output)
	}

	// Extract the token string
	lines := strings.Split(output, "\n")
	var tokenString string
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" && !strings.Contains(lines[i], "Test JWT Token:") {
			tokenString = strings.TrimSpace(lines[i])
			break
		}
	}

	if tokenString == "" {
		t.Fatal("No token found in output")
	}

	// Verify the token is valid JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("test-secret-key"), nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Verify token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		t.Fatal("Invalid token claims")
	}

	// Check required claims
	sub, ok := claims["sub"]
	if !ok || sub != "test-user" {
		t.Errorf("Expected 'sub' claim to be 'test-user', got %v", sub)
	}

	jti, ok := claims["jti"]
	if !ok || jti != "test-token-id-123" {
		t.Errorf("Expected 'jti' claim to be 'test-token-id-123', got %v", jti)
	}

	if _, ok := claims["exp"]; !ok {
		t.Error("Token missing 'exp' claim")
	}
	if _, ok := claims["iat"]; !ok {
		t.Error("Token missing 'iat' claim")
	}

	// Verify expiration is in the future
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if !expTime.After(time.Now()) {
			t.Errorf("Token expiration %v is not in the future", expTime)
		}

		// Token should expire in approximately 24 hours
		expectedExp := time.Now().Add(24 * time.Hour)
		diff := expectedExp.Sub(expTime)
		if diff < -5*time.Second || diff > 5*time.Second {
			t.Errorf("Expiration time differs from expected by %v", diff)
		}
	} else {
		t.Error("Token 'exp' claim has invalid type")
	}
}

// TestTokenGenerationPerformance tests the performance of token generation
func TestTokenGenerationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	// Create a null writer to discard output
	oldStdout := os.Stdout
	nullFile, _ := os.Open(os.DevNull)
	os.Stdout = nullFile
	defer func() {
		os.Stdout = oldStdout
		nullFile.Close()
	}()

	// Measure the time to generate 100 tokens
	const iterations = 100
	startTime := time.Now()

	for i := 0; i < iterations; i++ {
		main()
	}

	duration := time.Since(startTime)
	avgTime := duration / iterations

	t.Logf("Generated %d tokens in %v (average %v per token)",
		iterations, duration, avgTime)

	// Ensure generation time is reasonable
	if avgTime > 5*time.Millisecond {
		t.Logf("Token generation seems slow: %v per token", avgTime)
	}
}

// TestTokenOutputFormat ensures the token is properly formatted in the output
func TestTokenOutputFormat(t *testing.T) { // Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Generate token
	main()
	// Generate token
	main()

	// Read output
	w.Close()
	bytes, _ := io.ReadAll(r)
	output := string(bytes)

	// Check output format
	if !strings.Contains(output, "Test JWT Token:") {
		t.Errorf("Output doesn't contain expected header: %s", output)
	}

	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		t.Fatalf("Expected at least 2 lines of output, got %d", len(lines))
	}

	// Check that the second non-empty line has the token
	tokenFound := false
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			// This should be the token
			tokenParts := strings.Split(line, ".")
			if len(tokenParts) != 3 {
				t.Errorf("Token doesn't have the expected 3 parts: %s", line)
			} else {
				tokenFound = true
			}
			break
		}
	}

	if !tokenFound {
		t.Error("No token found in the output")
	}
}
