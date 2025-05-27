<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

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

A Go-based HTTP/2 and HTTP/3 proxy service.

## Features

- ✅ **HTTP CONNECT Proxy**
  - Full support for HTTP/1.1, HTTP/2, and HTTP/3 (QUIC)

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

## Configuration

The service can be configured using environment variables:

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `ZDVV_INSECURE` | Disable all authentication requirements (insecure, for testing only) | `false` |
| `ZDVV_CONTROL_SERVER_URL` | URL of the control server |  |
| `ZDVV_CONTROL_SERVER_SHARED_SECRET` | Shared secret for communication with the control server |  |
| `ZDVV_LATITUDE` | Latitude of the proxy server | `0` |
| `ZDVV_LONGITUDE` | Longitude of the proxy server | `0` |
| `ZDVV_CITY` | City of the proxy server | `Unknown` |
| `ZDVV_COUNTRY` | Country of the proxy server | `Unknown` |
| `ZDVV_SUPPORTS_CONNECT_TCP` | Whether the proxy supports CONNECT TCP | `true` |
| `ZDVV_SUPPORTS_CONNECT_UDP` | Whether the proxy supports CONNECT UDP | `false` |
| `ZDVV_SUPPORTS_CONNECT_IP` | Whether the proxy supports CONNECT IP | `false` |
| `ZDVV_HTTPS_ADDR` | HTTPS listen address | `:443` |
| `ZDVV_HTTP_ADDR` | HTTP listen address (when enabled) | `:8080` |
| `ZDVV_HTTP_ENABLED` | Enable plain HTTP listener | `false` |
| `ZDVV_HTTPS_CERT_FILE` | Path to the TLS certificate file |  |
| `ZDVV_HTTPS_KEY_FILE` | Path to the TLS key file |  |
| `ZDVV_HTTPS_HOSTNAME` | Hostname for TLS certificate (Let's Encrypt) |  |
| `ZDVV_HTTPS_V1_ENABLED` | Enable HTTPS/1.1 support | `true` |
| `ZDVV_HTTPS_V2_ENABLED` | Enable HTTPS/2 support | `true` |
| `ZDVV_HTTPS_V3_ENABLED` | Enable HTTPS/3 (QUIC) support | `true` |
| `ZDVV_HTTP_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |

## Security Notes

- TLS enabled by default with ALPN (http/1.1, h2, h3)
- ADMIN_TOKEN for /revoke endpoint stored as environment variable or config
- No persistent state required
