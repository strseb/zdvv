# Zentrale Datenverkehrsvermittlung (ZDVV)
```
  _____  ______      ______      _____               
 |__  / |  _  \   /  _____\    /  _  \               
   / /  | | | |  /  /     |   /  /_\  \     __     __
  / /_  | |/ /   |  |     |  /  _____  \   /  \   /  \
 /____| |___/    \  \_____/ /  /     \  \  \   \ /   /
                  \_______/ /__/       \__\  \___V___/
                                                            
 Zentrale Datenverkehrsvermittlung
 Abteilung ZDVV steht bereit.
```

A Go-based HTTP/2 and HTTP/3 proxy service designed with the aesthetics and structure of a formal German authority.

## Features

- ✅ **HTTP CONNECT Proxy**
  - Full support for HTTP/1.1, HTTP/2, and HTTP/3 (QUIC)

- ✅ **JWT-based Authentication**
  - Incoming requests must include `Proxy-Authorization: Bearer <token>`
  - Token must have a `jti` (JWT ID) claim

- ✅ **Revocation Endpoint**
  - Admins can revoke tokens via POST /revoke

- ✅ **In-Memory Revocation List**
  - No Redis or database required

- ✅ **TLS Support**
  - Single server instance handles all 3 protocols using ALPN

- ✅ **OPS Unikernel Compatible**
  - Easily packaged and deployed as a unikernel

## JWT Revocation API

### Revoke Token

```
POST /revoke
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{
  "jti": "revoked-token-id-123"
}
```

- Stores the `jti` in an in-memory set
- All future requests with that `jti` will be denied
- Note: revocations are not persisted across restarts

## Usage

Client connects through proxy:

```bash
curl --http2 --proxy https://localhost:8443 \
     --proxy-insecure \
     --proxy-header "Proxy-Authorization: Bearer $JWT" \
     https://example.com
```

## Building

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o zdvv main.go
```

## Local Run

```bash
./zdvv
```

Generate a self-signed certificate if needed:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

## Run as Unikernel

```bash
ops run -c config.json zdvv
```

## Configuration

The service can be configured using command-line flags or environment variables:

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `-addr` | | Listen address (default: ":8443") |
| `-cert` | | TLS certificate file (default: "server.crt") |
| `-key` | | TLS key file (default: "server.key") |
| `-jwt-secret` | `JWT_SECRET` | JWT secret key (required unless `-insecure` is set) |
| `-admin-token` | `ADMIN_TOKEN` | Admin API token (required unless `-insecure` is set) |
| `-no-http2` | | Disable HTTP/2 support (default: false) |
| `-no-http3` | | Disable HTTP/3 support (default: false) |
| `-insecure` | | Disable all authentication requirements (insecure, for testing only) |

## Security Notes

- TLS enabled by default with ALPN (http/1.1, h2, h3)
- ADMIN_TOKEN for /revoke endpoint stored as environment variable or config
- No persistent state required

## Future Additions

- MASQUE CONNECT-UDP support
- Revocation list with TTL or persistent backend
- Rate limiting and logging
- Admin UI for viewing revoked tokens
