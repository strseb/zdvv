/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"log"

	"github.com/strseb/zdvv/pkg/common"
	"github.com/strseb/zdvv/pkg/common/auth"
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

	requiredConnectPermissions := []auth.Permission{auth.PERMISSION_CONNECT_TCP}
	var proxyAuthenticator auth.Authenticator

	log.Println("Operating in SECURE mode. JWTs will be validated using multiple keys.")
	proxyAuthenticator = auth.NewMultiKeyJWTValidator(controlServer, requiredConnectPermissions)

	proxyService := NewProxyService(controlServer)
	authenticatedProxyService := proxyAuthenticator.Middleware(proxyService)

	log.Println("Starting ZDVV Proxy Service...")
	CreateHTTPServers(httpCfg, authenticatedProxyService, proxyCfg.Insecure)

	log.Println("ZDVV Proxy Service has shut down.")
}
