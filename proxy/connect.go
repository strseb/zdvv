package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/basti/zdvv/auth"
)

// ConnectHandler implements the HTTP CONNECT proxy
type ConnectHandler struct {
	Validator auth.TokenValidator
}

// NewConnectHandler creates a new CONNECT proxy handler
func NewConnectHandler(validator auth.TokenValidator) *ConnectHandler {
	return &ConnectHandler{
		Validator: validator,
	}
}

// handleConnect handles the CONNECT proxy operation after authentication
func (h *ConnectHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("ConnectHandler.handleConnect: Entered for Method=%s, URL.Host=%s, URL.Path=[%s], RequestURI=[%s]", r.Method, r.URL.Host, r.URL.Path, r.RequestURI) // DEBUG LINE
	// Only handle CONNECT requests
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the target host
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// Connect to the target server
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to target server", http.StatusBadGateway)
		log.Printf("Failed to connect to %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	// Respond with 200 OK to indicate that the connection is established
	w.WriteHeader(http.StatusOK)

	// Get the underlying connection from the ResponseWriter
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		log.Printf("Failed to hijack connection: %v", err)
		return
	}
	defer clientConn.Close()

	// Run bidirectional copy
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Client -> Target
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		if err != nil && ctx.Err() == nil {
			log.Printf("Client to target copy failed: %v", err)
		}
		cancel()
	}()

	// Target -> Client
	_, err = io.Copy(clientConn, targetConn)
	if err != nil && ctx.Err() == nil {
		log.Printf("Target to client copy failed: %v", err)
	}

	log.Printf("Proxy connection to %s closed", host)
}

// ServeHTTP handles HTTP CONNECT requests with authentication
func (h *ConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("ConnectHandler.ServeHTTP: Received request: Method=%s, URL=%s, Path=[%s], Host=%s, RequestURI=[%s]", r.Method, r.URL.String(), r.URL.Path, r.Host, r.RequestURI) // DEBUG LINE
	// Use the validator middleware to handle authentication
	authHandler := h.Validator.Middleware(http.HandlerFunc(h.handleConnect))
	authHandler.ServeHTTP(w, r)
}
