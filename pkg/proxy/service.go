package proxy

import (
	"log"
	"net/http"

	"github.com/basti/zdvv/pkg/control"
)

// Proxy handles HTTP requests for the proxy service.
type Proxy struct {
	controlServer control.ControlServer
	// Potentially add other dependencies here, like a logger or config
}

// NewProxyService creates a new Proxy service.
func NewProxyService(cs control.ControlServer) *Proxy {
	return &Proxy{
		controlServer: cs,
	}
}

// ServeHTTP implements the http.Handler interface.
// It currently delegates CONNECT requests to a ConnectHandler (assumed to be defined elsewhere in pkg/proxy)
// and rejects other methods. This is where core proxy logic will reside.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[ProxyService] Received request: Method=%s, URL=%s, Host=%s", r.Method, r.URL.String(), r.Host)
	if r.Method == http.MethodConnect {
		// Here you might interact with p.controlServer before, during, or after handling the CONNECT.
		// For example, to authorize the request based on control server data,
		// or to register/deregister connections.
		log.Printf("[ProxyService] Handling CONNECT request for %s", r.URL.Host)
		HandleConnectRequest(w, r) // Use the new function
	} else {
		// Handle other requests or return an error
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
