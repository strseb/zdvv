/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package auth

import (
	"errors"
	"net/http"
)

// Default auth configuration
const (
	authHeader = "Proxy-Authorization"
	authScheme = "Bearer"
)

// Errors
var (
	ErrNoAuthHeader  = errors.New("no authorization header")
	ErrInvalidScheme = errors.New("invalid authorization scheme")
	ErrInvalidToken  = errors.New("invalid token")
	ErrTokenRevoked  = errors.New("token has been revoked")
)

// Authenticator defines the interface for authentication middleware
type Authenticator interface {
	Middleware(next http.Handler) http.Handler
}
