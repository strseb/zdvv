package auth

import "github.com/golang-jwt/jwt/v5"

// PermissionFunc defines a function that checks a JWT claim set for a permission.
type Permission string

const (
	PERMISSION_CONNECT_TCP Permission = "connect-tcp"
)

func (p *Permission) Check(claims jwt.MapClaims) bool {
	if claims == nil {
		return false
	}
	if val, ok := claims[string(*p)]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
		if s, ok := val.(string); ok {
			return s == "true"
		}
	}
	return false
}
