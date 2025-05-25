package control

import (
	"crypto/rsa"

	"github.com/basti/zdvv/pkg/common/auth"
	"github.com/golang-jwt/jwt/v5"
)

/**
 * The ControlServer may live in the same process as the server or in a different process.
 */
type ControlServer interface {
	ServerController
	JwtController
}

type ServerController interface {
	RegisterProxyServer(hostName string) error
	DeregisterProxyServer(hostName string) error
	CurrentServers() ([]string, error)
}

type JwtController interface {
	PublicKey() (*rsa.PublicKey, error)
	CreateToken([]auth.Permission) (*jwt.Token, error)
}
