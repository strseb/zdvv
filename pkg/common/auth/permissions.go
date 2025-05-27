/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package auth

import "github.com/golang-jwt/jwt/v5"

// PermissionFunc defines a function that checks a JWT claim set for a permission.
type Permission string

const (
	PERMISSION_CONNECT_TCP Permission = "connect-tcp"
	PERMISSION_CONNECT_UDP Permission = "connect-udp"
	PERMISSION_CONNECT_IP  Permission = "connect-ip"
)

// GetPermissionStrings converts Permission constants to their string representations
func GetPermissionStrings(permissions []Permission) []string {
	result := make([]string, len(permissions))
	for i, p := range permissions {
		result[i] = string(p)
	}
	return result
}

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
