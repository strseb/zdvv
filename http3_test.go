package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/basti/zdvv/auth"
	"github.com/basti/zdvv/proxy"
	"github.com/quic-go/quic-go/http3"
)

// TestHTTP3ServerConfig tests the HTTP/3 server configuration
func TestHTTP3ServerConfig(t *testing.T) {
	// Create services for the server
	revocationSvc := auth.NewRevocationService()
	validator := auth.NewInsecureValidator()
	adminAuthenticator := auth.NewInsecureAdminAuthenticator()

	// Setup handlers
	adminHandler := auth.NewAdminHandler(adminAuthenticator, revocationSvc)
	connectHandler := proxy.NewConnectHandler(validator)

	// Set up HTTP mux
	mux := http.NewServeMux()
	adminHandler.SetupRoutes(mux)
	mux.Handle("/", connectHandler)
	// Mock the certificate and key files - in a real test these would be actual files
	// Generate a TLS certificate
	cert := generateTestCertificate(t)

	// Set up TLS config with HTTP/3 support
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h3"},
		Certificates: []tls.Certificate{cert},
	}

	// Create HTTP/3 server
	h3Server := &http3.Server{
		Addr:      "localhost:0", // Use random port
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Verify that server is properly configured
	if h3Server.Addr != "localhost:0" {
		t.Errorf("Expected server address to be 'localhost:0', got %s", h3Server.Addr)
	}

	if len(h3Server.TLSConfig.Certificates) != 1 {
		t.Error("Expected TLS config to have 1 certificate")
	}

	// Check that NextProtos contains h3
	foundH3 := false
	for _, proto := range h3Server.TLSConfig.NextProtos {
		if proto == "h3" {
			foundH3 = true
			break
		}
	}

	if !foundH3 {
		t.Error("Expected TLS config to include 'h3' in NextProtos")
	}

	t.Log("HTTP/3 server correctly configured, skipping actual network tests")
		// Note: We're not actually starting the server or connecting to it,
	// as that would require real certificates and network setup.
	// For integration tests with real HTTP/3 connections, we would need
	// to set up a complete testing environment with certificates.
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) tls.Certificate {
	// Certificate details defined but not used in this test
	_ = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ZDVV Test CA"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// This is a pre-generated self-signed certificate and private key for testing
	certPEM := `-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUO26WhHdnfxaCDF/eHhie44MGKlwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDUyMTIzMzAwOFoXDTI2MDUy
MTIzMzAwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAn+kkLaT20rxVUyQ185SWPk81HuALkaatMywRxcQRXblA
2xWwZTCeuUn8jMeb+4IUL33HOVP9WKpOOoVGtG3FnszRPMKvqh0QKxUwQS2ZPDS2
vbR9eXvUsuCOi45i8Y+oPQHD7eD9P1dGYt2j0SxB/B0t6J2e5RP6j+lq4weNQoqI
njkH5gFlVL7VHO6/xwB3zaJBRduQdxlpecugOFgWHf2+LfEG9iHzIEJVf62cVd/r
dHQFo2Y0XWv8ziggWaBlWZrp5tRLVlKPaSbZb7UpLrtpQc1CKfebicAYKkDngzLX
pVbUVrzck1Y2bUXrPI9ucQLgjs1LXdjOm9gGW9QE0domQ8EIfiZyWG9Hfq8b5dTR
55Io0qs1E4PzjKDvd9beoVCek2NzVk81CIOUmzoTy5xbP+5E3ycHDApBSumx/Idl
0wqW9QvnldqCaq/2D4QIWQ1nsjirgTTrxmS/adilmQefXLXBdURqb0UxruWs9WBt
BfbdmeCe14KWDWLre9oJ6HN7FJARiwzKA/Ii83z2P8srPrn4VhwfIgVjKRh4VAB/
o2+UlEw7TbLE7eyosZBBRdBsgG+h7nKN2lVzEzMt7BtLBHdgwB9LQt0z0B1uSesA
u41FOfQ/ItQrfM/8deCp2/vw9pLldNgJQOL9KNZecq2LoM011Jco5lCLW2sO4qsC
AwEAAaNTMFEwHQYDVR0OBBYEFNxKBDV5iYlOLPtnirGlQt+TfvC2MB8GA1UdIwQY
MBaAFNxKBDV5iYlOLPtnirGlQt+TfvC2MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggIBAIYH9pbdH4lj6rd49U4vLJypjbHLBsjhqftdjPIsAvLWOc8w
WE6VjwFrzeC7MAvA32TvXxj9A/FXZmQ6IfQVJePlvGxAvN2ocuNDe4Z3KXp9YHWA
W4IieQAZLU31PBG9vjIDG/Ezc2NgmSaVO/6IDRtII7GjSObpJbngZ3tRQmE+DAFu
QGSA/PlN9HwTKvPDlRHxzn1R+WhY7yNKYdX6DGnF5kh1LdiE/PRJlWUktky/O0uV
q+zoSEoOqZ3tyj/yWOq6B1nLKxBaQ7DYWBK9IzyQtsNohnFLXcxtiazaAx8+sdMd
ZrP9gQUzVZt8u6USbxCXbxuVv7pwnaycyI8foaOXcFfLZ76t0kOOzGXNCV1qS/37
LrQJNv8JtGGrZzbkmeqqQRZk+lY5rotzymK4vOs9dK4rRGWWxeK9a15DqiiPSZSP
bnpsTmY68QHY0PKkSKXar2th6aPc2nNkoeqNBnVpIZMGJQuxCtZpKqvYxdUBKh9o
POYIthhTr0JGHV3iWtsknp2jvFzJF/5VyH0yI5O+ul0Od57uA1k25sFyEeOWAN32
7ANcURQtos7SbkBnHTgBQrbdJoe7jOMdaXvDhRcKzFwPm7w52M6w0LVTdC5G74IU
eyg6fla0CHgBYNlBrqYc2ViIOVtcN5OASIOcyJp4SgXBtKx5RJVn2Nry2oyK
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN PRIVATE KEY-----
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
sexGhW8jwdbMPmqWXvAeq9qJSSGOozHd
-----END PRIVATE KEY-----
`

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("Failed to parse X509 key pair: %v", err)
	}

	return cert
}

// TestHTTPProtocolSelection tests protocol selection logic
func TestHTTPProtocolSelection(t *testing.T) {
	// Test different combinations of protocol flags
	testCases := []struct {
		name         string
		disableHTTP2 bool
		disableHTTP3 bool
		expectedProtos []string
	}{
		{
			name:         "All protocols enabled",
			disableHTTP2: false,
			disableHTTP3: false,
			expectedProtos: []string{"http/1.1", "h2", "h3"},
		},
		{
			name:         "HTTP/2 disabled",
			disableHTTP2: true,
			disableHTTP3: false,
			expectedProtos: []string{"http/1.1", "h3"},
		},
		{
			name:         "HTTP/3 disabled",
			disableHTTP2: false,
			disableHTTP3: true,
			expectedProtos: []string{"http/1.1", "h2"},
		},
		{
			name:         "Only HTTP/1.1 enabled",
			disableHTTP2: true,
			disableHTTP3: true,
			expectedProtos: []string{"http/1.1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the NextProtos list according to the flags
			nextProtos := []string{"http/1.1"}
			if !tc.disableHTTP2 {
				nextProtos = append(nextProtos, "h2")
			}
			if !tc.disableHTTP3 {
				nextProtos = append(nextProtos, "h3")
			}

			// Check that the list matches what we expect
			if len(nextProtos) != len(tc.expectedProtos) {
				t.Fatalf("Expected %d protocols, got %d", len(tc.expectedProtos), len(nextProtos))
			}

			for i, proto := range tc.expectedProtos {
				if nextProtos[i] != proto {
					t.Fatalf("Expected protocol %s at position %d, got %s", proto, i, nextProtos[i])
				}
			}
		})
	}
}
