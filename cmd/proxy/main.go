package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt" // Added fmt import
	"log"
	"time"

	"github.com/basti/zdvv/pkg/common"
	"github.com/basti/zdvv/pkg/common/auth"
	"github.com/basti/zdvv/pkg/control"
	"github.com/golang-jwt/jwt/v5"
)

const (
	asciiArt = `
  _____  ______      ______      _____               
 |__  / |  _  \   /  _____\    /  _  \               
   / /  | | | |  /  /     |   /  /_\  \     __     __
  / /_  | |/ /   |  |     |  /  _____  \   /  \   /  \
 /____| |___/    \  \_____/ /  /     \  \  \   \ /   /
                  \_______/ /__/       \__\  \___V___/
                                                            
 Zentrale Datenverkehrsvermittlung  (Build ?)
 Abteilung ZDVV steht bereit.                     
`
)

// MockControlServer is a mock implementation of the ControlServer interface for setup.
// Replace this with your actual control server client or a more sophisticated mock.
type MockControlServer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// initKeys generates an RSA key pair for the mock server.
func (m *MockControlServer) initKeys() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	m.privateKey = privateKey
	m.publicKey = &privateKey.PublicKey
	log.Println("[MockControlServer] RSA key pair generated.")
	return nil
}

func (m *MockControlServer) RegisterProxyServer(hostName string) error {
	log.Printf("[MockControlServer] RegisterProxyServer called with hostName: %s", hostName)
	return nil
}
func (m *MockControlServer) DeregisterProxyServer(hostName string) error {
	log.Printf("[MockControlServer] DeregisterProxyServer called with hostName: %s", hostName)
	return nil
}
func (m *MockControlServer) CurrentServers() ([]string, error) { // Exported name
	log.Println("[MockControlServer] CurrentServers called")
	return []string{"mockserver1.example.com", "mockserver2.example.com"}, nil
}
func (m *MockControlServer) PublicKey() (*rsa.PublicKey, error) {
	log.Println("[MockControlServer] PublicKey called")
	if m.publicKey == nil {
		log.Println("[MockControlServer] Error: RSA keys not initialized before calling PublicKey")
		return nil, fmt.Errorf("RSA keys not initialized")
	}
	return m.publicKey, nil
}
func (m *MockControlServer) CreateToken(permissions []auth.Permission) (*jwt.Token, error) {
	log.Printf("[MockControlServer] CreateToken called with permissions: %v", permissions)
	if m.privateKey == nil {
		log.Println("[MockControlServer] Error: RSA keys not initialized before calling CreateToken")
		return nil, fmt.Errorf("RSA keys not initialized")
	}

	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"iss": "MockControlServer",                      // Added issuer for clarity
		"jti": fmt.Sprintf("%d", time.Now().UnixNano()), // Unique identifier for the token
	}
	for _, perm := range permissions {
		claims[string(perm)] = true
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedString, err := token.SignedString(m.privateKey)
	if err != nil {
		log.Printf("[MockControlServer] Error signing token: %v", err)
		return nil, err
	}
	token.Raw = signedString // Populate the Raw field with the signed token string

	log.Println("[MockControlServer] Token created and signed with RS256.")
	return token, nil
}

func main() {
	common.ImportDotenv()
	proxyCfg, err := NewProxyConfig()
	if err != nil {
		log.Fatalf("Proxy configuration error: %v", err)
	}
	httpCfg, err := NewHTTPConfig()
	if err != nil {
		log.Fatalf("HTTP configuration error: %v", err)
	}

	proxyCfg.LogSettings()
	httpCfg.LogSettings()

	mockServer := &MockControlServer{}
	if err := mockServer.initKeys(); err != nil {
		log.Fatalf("Failed to initialize keys for MockControlServer: %v", err)
	}
	var controlServer control.ControlServer = mockServer
	// TODO: Replace with actual client:
	// controlServer = controlserverclient.New(proxyCfg.ControlServerURL, proxyCfg.ControlServerSecret, httpCfg.Hostname)

	if err := controlServer.RegisterProxyServer(httpCfg.Hostname); err != nil {
		log.Printf("Warning: Failed to register with control server: %v", err)
	}
	defer func() {
		if err := controlServer.DeregisterProxyServer(httpCfg.Hostname); err != nil {
			log.Printf("Warning: Failed to deregister from control server: %v", err)
		}
	}()

	jwtPublicKey, err := controlServer.PublicKey()
	if err != nil {
		log.Printf("Warning: Failed to get public key from control server: %v. Will try config.", err)
	} else if jwtPublicKey != nil {
		log.Println("Successfully fetched JWT public key from control server.")
	}

	requiredConnectPermissions := []auth.Permission{auth.PERMISSION_CONNECT_TCP}
	var proxyAuthenticator auth.Authenticator

	log.Println("Operating in SECURE mode. JWTs will be validated.")
	proxyAuthenticator = auth.NewJWTValidator(jwtPublicKey, requiredConnectPermissions)

	proxyService := NewProxyService(controlServer)
	authenticatedProxyService := proxyAuthenticator.Middleware(proxyService)

	// Create a token and print it
	token, err := controlServer.CreateToken([]auth.Permission{auth.PERMISSION_CONNECT_TCP})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	log.Printf("Generated token: %s", token.Raw)

	log.Println("Starting ZDVV Proxy Service...")
	CreateHTTPServers(httpCfg, authenticatedProxyService, proxyCfg.Insecure)

	log.Println("ZDVV Proxy Service has shut down.")
}
