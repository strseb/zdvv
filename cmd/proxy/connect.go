package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// HandleConnectRequest handles the HTTP CONNECT proxy operation.
// It establishes a connection to the target server and hijacks the client connection
// to proxy data between the client and the target.
func HandleConnectRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("HandleConnectRequest: Entered for Method=%s, URL.Host=%s, URL.Path=[%s], RequestURI=[%s]", r.Method, r.URL.Host, r.URL.Path, r.RequestURI)
	// This function assumes the request is already validated as a CONNECT request
	// by the caller if necessary, though it also checks here.
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		log.Printf("HandleConnectRequest: Received non-CONNECT method %s", r.Method)
		return
	}

	// Parse the target host
	host := r.Host
	if host == "" {
		host = r.URL.Host // Fallback to URL.Host if r.Host is not set (e.g. by some clients for CONNECT)
	}
	if host == "" {
		http.Error(w, "Target host not specified", http.StatusBadRequest)
		log.Println("HandleConnectRequest: Target host is empty")
		return
	}

	log.Printf("HandleConnectRequest: Attempting to connect to target: %s", host)
	// Connect to the target server
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to target server", http.StatusBadGateway)
		log.Printf("HandleConnectRequest: Failed to connect to %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	log.Printf("HandleConnectRequest: Successfully connected to target: %s. Sending 200 OK to client.", host)
	// Respond with 200 OK to indicate that the connection is established
	w.WriteHeader(http.StatusOK)

	// Get the underlying connection from the ResponseWriter
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP hijacking not supported", http.StatusInternalServerError)
		log.Println("HandleConnectRequest: HTTP hijacking not supported by ResponseWriter")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		// Cannot send http.Error here as the connection is already hijacked or in an unknown state.
		log.Printf("HandleConnectRequest: Failed to hijack connection: %v", err)
		// Ensure targetConn is closed if hijacking fails after it's opened.
		// clientConn is not valid here.
		return
	}
	defer clientConn.Close()
	log.Printf("HandleConnectRequest: Connection hijacked successfully for %s. Starting data proxy.", host)

	// Run bidirectional copy
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Client -> Target
	go func() {
		defer cancel() // Ensure other goroutine stops if this one finishes/errors
		log.Printf("HandleConnectRequest: Starting client to target copy for %s", host)
		written, err := io.Copy(targetConn, clientConn)
		if err != nil && ctx.Err() == nil { // Don't log error if context was cancelled
			log.Printf("HandleConnectRequest: Client to target copy for %s failed after %d bytes: %v", host, written, err)
		} else if ctx.Err() != nil {
			log.Printf("HandleConnectRequest: Client to target copy for %s cancelled after %d bytes.", host, written)
		} else {
			log.Printf("HandleConnectRequest: Client to target copy for %s completed (%d bytes).", host, written)
		}
	}()

	// Target -> Client
	log.Printf("HandleConnectRequest: Starting target to client copy for %s", host)
	written, err := io.Copy(clientConn, targetConn)
	if err != nil && ctx.Err() == nil { // Don't log error if context was cancelled
		log.Printf("HandleConnectRequest: Target to client copy for %s failed after %d bytes: %v", host, written, err)
	} else if ctx.Err() != nil {
		log.Printf("HandleConnectRequest: Target to client copy for %s cancelled after %d bytes.", host, written)
	} else {
		log.Printf("HandleConnectRequest: Target to client copy for %s completed (%d bytes).", host, written)
	}
	cancel() // Ensure goroutine is stopped

	log.Printf("HandleConnectRequest: Proxy connection to %s closed", host)
}
