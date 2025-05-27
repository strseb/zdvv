package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestProxyNetworkFlow simulates a more realistic network flow with actual TCP connections
func TestProxyNetworkFlow(t *testing.T) {
	// Skip test if we are in a CI environment or we want to skip actual network tests
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Set up a simple echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0") // Use port 0 to get a random port
	if err != nil {
		t.Fatalf("Failed to create echo server: %v", err)
	}
	defer listener.Close() // Get the address
	_, addrPart, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to extract address part: %v", err)
	}

	// Server goroutine - simply echoes back everything it receives
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		// Echo back received data
		io.Copy(conn, conn)
	}()

	// Set up an HTTP server with the proxy handler
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		HandleConnectRequest(w, r)
	}))
	defer proxyServer.Close()

	// Extract proxy host and port
	proxyURL := proxyServer.URL
	proxyHost := strings.TrimPrefix(proxyURL, "http://")
	// We'll skip creating a client since we're not using it in this test

	// Manual CONNECT request to the proxy
	connectReq, err := http.NewRequest("CONNECT", "http://"+proxyHost, nil)
	if err != nil {
		t.Fatalf("Failed to create CONNECT request: %v", err)
	}
	connectReq.Host = "127.0.0.1:" + addrPart

	// We can't fully test this without refactoring the code to accept a custom dialer
	// or advanced mock support. This test serves as a sketch of how it would work.
	t.Skip("Skipping full network test as it requires infrastructure changes")
}

// TestConcurrentConnections tests how the proxy handler deals with multiple concurrent connections
func TestConcurrentConnections(t *testing.T) {

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		HandleConnectRequest(w, r)
	}))
	defer server.Close()

	// Test concurrent connections
	numConnections := 10
	var wg sync.WaitGroup
	wg.Add(numConnections)

	for i := 0; i < numConnections; i++ {
		go func(idx int) {
			defer wg.Done()

			// Create a CONNECT request
			req, err := http.NewRequest("CONNECT", server.URL, nil)
			if err != nil {
				t.Logf("Connection %d: Failed to create request: %v", idx, err)
				return
			}
			req.Host = "example.com:443"

			// Send the request
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// Error is expected in this mock setup
				return
			}
			resp.Body.Close()
		}(i)
	}

	// Wait with a timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All good
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out after 5 seconds")
	}
}

// HijackableResponse is a mock ResponseWriter that supports Hijack
type HijackableResponse struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *HijackableResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Create a pipe that we can hijack
	clientConn, serverConn := net.Pipe()
	h.conn = serverConn

	// Create a buffered reader/writer
	bufrw := bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn))

	return clientConn, bufrw, nil
}

// Close closes the connection
func (h *HijackableResponse) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}
