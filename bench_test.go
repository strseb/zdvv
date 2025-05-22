package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/basti/zdvv/auth"
	"github.com/basti/zdvv/proxy"
	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkJWTValidation benchmarks JWT validation performance
func BenchmarkJWTValidation(b *testing.B) {
	// Create necessary components
	secret := []byte("bench-secret")
	revocationSvc := auth.NewRevocationService()
	validator := auth.NewJWTValidator(secret, revocationSvc)
	
	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "bench-user",
		"jti": "bench-token-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	
	tokenString, err := token.SignedString(secret)
	if err != nil {
		b.Fatalf("Failed to create token: %v", err)
	}
	
	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.ValidateToken(tokenString)
		if err != nil {
			b.Fatalf("Token validation failed: %v", err)
		}
	}
}

// BenchmarkJWTRevocationCheck benchmarks checking if a token is revoked
func BenchmarkJWTRevocationCheck(b *testing.B) {
	// Create revocation service and populate it
	revocationSvc := auth.NewRevocationService()
	
	// Add some revoked tokens
	for i := 0; i < 1000; i++ {
		revocationSvc.Revoke("revoked-token-" + string(rune(i)))
	}
	
	// Run the benchmark on a non-revoked token
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if revocationSvc.IsRevoked("not-revoked-token") {
			b.Fatal("Token should not be revoked")
		}
	}
}

// BenchmarkJWTRevokedCheck benchmarks checking a token that is revoked
func BenchmarkJWTRevokedCheck(b *testing.B) {
	// Create revocation service and populate it
	revocationSvc := auth.NewRevocationService()
	
	// Add some revoked tokens
	const revokedToken = "revoked-benchmark-token"
	revocationSvc.Revoke(revokedToken)
	
	// Add more tokens to make the revocation list larger
	for i := 0; i < 1000; i++ {
		revocationSvc.Revoke("extra-token-" + string(rune(i)))
	}
	
	// Run the benchmark on the revoked token
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !revocationSvc.IsRevoked(revokedToken) {
			b.Fatal("Token should be revoked")
		}
	}
}

// BenchmarkGetRevokedList benchmarks retrieving the list of revoked tokens
func BenchmarkGetRevokedList(b *testing.B) {
	// Create revocation service with various sizes
	benchmarks := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_100", 100},
		{"Large_1000", 1000},
		{"XLarge_10000", 10000},
	}
	
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			revocationSvc := auth.NewRevocationService()
			
			// Add revoked tokens
			for i := 0; i < bm.count; i++ {
				revocationSvc.Revoke("token-" + string(rune(i)))
			}
			
			// Run the benchmark
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				list := revocationSvc.GetRevokedList()
				if len(list) != bm.count {
					b.Fatalf("Expected %d tokens, got %d", bm.count, len(list))
				}
			}
		})
	}
}

// BenchmarkAuthMiddleware benchmarks the authentication middleware
func BenchmarkAuthMiddleware(b *testing.B) {
	// Create necessary components
	secret := []byte("bench-secret")
	revocationSvc := auth.NewRevocationService()
	validator := auth.NewJWTValidator(secret, revocationSvc)
	
	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "bench-user",
		"jti": "bench-token-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	
	tokenString, err := token.SignedString(secret)
	if err != nil {
		b.Fatalf("Failed to create token: %v", err)
	}
	
	// Create a handler to use with the middleware
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	// Apply middleware
	handler := validator.Middleware(nextHandler)
	
	// Create a request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Proxy-Authorization", "Bearer "+tokenString)
	
	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("Expected status code %d, got %d", http.StatusOK, rr.Code)
		}
	}
}

// BenchmarkInsecureValidator benchmarks the insecure validator
func BenchmarkInsecureValidator(b *testing.B) {
	// Create an insecure validator
	validator := auth.NewInsecureValidator()
	
	// Create a handler to use with the middleware
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	// Apply middleware
	handler := validator.Middleware(nextHandler)
	
	// Create a request
	req := httptest.NewRequest("GET", "/", nil)
	
	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("Expected status code %d, got %d", http.StatusOK, rr.Code)
		}
	}
}

// BenchmarkProxyHandler benchmarks the proxy handler without actual network connections
func BenchmarkProxyHandler(b *testing.B) {
	// Create a validator
	validator := auth.NewInsecureValidator()
	
	// Create the handler
	handler := proxy.NewConnectHandler(validator)
	
	// Create a request for the CONNECT method
	req := httptest.NewRequest("CONNECT", "/", nil)
	req.Host = "example.com:443"
	
	// Run the benchmark for initial request handling (will fail at hijacking)
	// but still benchmarks the path until that point
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkTokenRevocation benchmarks the token revocation process
func BenchmarkTokenRevocation(b *testing.B) {
	// Create revocation service
	revocationSvc := auth.NewRevocationService()
	
	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a different token for each iteration to avoid skewed results
		jti := "bench-token-" + string(rune(i))
		revocationSvc.Revoke(jti)
		
		if !revocationSvc.IsRevoked(jti) {
			b.Fatalf("Token %s should be revoked", jti)
		}
	}
}
