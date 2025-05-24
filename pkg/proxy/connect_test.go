package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockDialer is used to mock the network connection for testing
type MockDialer struct {
	DialFunc func(network, addr string) (net.Conn, error)
}

// MockConn implements the net.Conn interface for testing
type MockConn struct {
	ReadFunc  func(b []byte) (n int, err error)
	WriteFunc func(b []byte) (n int, err error)
	CloseFunc func() error
}

func (c *MockConn) Read(b []byte) (n int, err error)  { return c.ReadFunc(b) }
func (c *MockConn) Write(b []byte) (n int, err error) { return c.WriteFunc(b) }
func (c *MockConn) Close() error                      { return c.CloseFunc() }
func (c *MockConn) LocalAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }
func (c *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *MockConn) SetDeadline(t time.Time) error      { return nil }
func (c *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHandleConnectRequest(t *testing.T) {
	// Test that non-CONNECT methods are rejected
	t.Run("Non-CONNECT method", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		rr := httptest.NewRecorder()

		HandleConnectRequest(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("CONNECT method with empty host", func(t *testing.T) {
		// Create a request with an empty r.Host and r.URL.Host
		req := httptest.NewRequest("CONNECT", "", nil)
		// httptest.NewRequest will parse the target and put it in URL.Host if it's a valid URI.
		// To truly test empty host, we might need to manipulate the request object more directly
		// or ensure the test server setup results in an empty host.
		// For CONNECT, r.RequestURI is usually the authority (host:port), which NewRequest sets as URL.Host.
		// Let's try setting URL to nil or empty to force the host check.
		// req.URL = nil // This would cause a panic in the handler when accessing req.URL.Host
		// Instead, we ensure r.Host is empty and r.URL.Host is also empty.
		req.Host = ""
		req.URL.Host = "" // Explicitly make it empty

		rr := httptest.NewRecorder()
		HandleConnectRequest(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status code %d for empty host, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	// Testing the full CONNECT flow with hijacking is complex with httptest.ResponseRecorder
	// as it doesn't fully support hijacking.
	// The original tests noted this limitation.
	// We can test up to the point of Dial failure if we can't mock net.DialTimeout easily
	// without more significant refactoring of HandleConnectRequest to allow dialer injection.

	t.Run("CONNECT method to unresolvable host", func(t *testing.T) {
		// Using a host that is unlikely to resolve or connect quickly.
		// The .invalid TLD is reserved for such purposes.
		req := httptest.NewRequest("CONNECT", "http://unresolvable.invalid:80", nil)
		// httptest.NewRequest sets req.Host from the URL if the URL includes a host.
		// For CONNECT, the target is in req.RequestURI, which NewRequest parses into req.URL.Host.
		// So, req.Host will be "unresolvable.invalid:80"
		rr := httptest.NewRecorder()

		HandleConnectRequest(rr, req)

		// We expect a BadGateway if the DialTimeout fails.
		if rr.Code != http.StatusBadGateway {
			t.Errorf("Expected status code %d for unresolvable host, got %d. Body: %s", http.StatusBadGateway, rr.Code, rr.Body.String())
		}
	})

	// Further tests would require a way to mock net.DialTimeout or use a real server
	// and a client that can handle hijacked connections.
}

// MockDialer and MockConn are kept if needed for more advanced tests later,
// but are not directly used in the refactored TestHandleConnectRequest above
// due to the difficulty of injecting a dialer into the current HandleConnectRequest.

// MockDialer is used to mock the network connection for testing
// type MockDialer struct { // Keep if planning to refactor HandleConnectRequest for DI
// 	DialFunc func(network, addr string) (net.Conn, error)
// }
