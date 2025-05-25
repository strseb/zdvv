package main

import (
	"log"

	"github.com/basti/zdvv/pkg/common"
	"github.com/basti/zdvv/pkg/common/auth"
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

	var controlServer ControlServer = NewHTTPControlServer(
		proxyCfg.ControlServerURL,
		proxyCfg.ControlServerSecret,
	)

	var server common.Server = proxyCfg.CreateServer(httpCfg.Hostname)

	if err := controlServer.RegisterProxyServer(server); err != nil {
		log.Printf("Warning: Failed to register with control server: %v", err)
	}
	defer func() {
		if err := controlServer.DeregisterProxyServer(server); err != nil {
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
