package auth

import "github.com/golang-jwt/jwt/v5"

// PermissionFunc defines a function that checks a JWT claim set for a permission.
type PermissionFunc func(claims jwt.MapClaims) error

// PermissionConnectTCP checks for the 'connect-tcp' permission.
func PermissionConnectTCP(claims jwt.MapClaims) error {
	val, ok := claims["connect-tcp"]
	if !ok || val != true {
		return ErrMissingPermission("connect-tcp")
	}
	return nil
}

// Example: add more permissions as needed
// func PermissionA(claims jwt.MapClaims) error { ... }
// func PermissionB(claims jwt.MapClaims) error { ... }

// ErrMissingPermission is returned when a required permission is missing or false.
type ErrMissingPermission string

func (e ErrMissingPermission) Error() string {
	return "token missing or invalid required permission: " + string(e)
}
