
## ZDVV 


| ![Logo](https://github.com/user-attachments/assets/209effe3-4a2e-4519-b371-d4abe71d16d1) | This repository is a Golang monorepo featuring two services designed for experimentation around http connect. |
| --- | --- | 


## zdvv-control /cmd/control: 
This is a stateless http server that provides a REST API for managing proxy servers. It is designed to be used in conjunction with zdvv-proxy.
It provides endpoints for:
- Registering new proxy servers
- Retrieving a list of all registered proxy servers
- Issuing JSON Web Tokens (JWTs) for authenticated access to proxy servers
- Providing a JSON Web Key Set (JWKS) for validating issued JWTs

## zdvv-proxy /cmd/proxy:
This is a stateless HTTP/1, HTTP/2 and HTTP/3 proxy server that handles HTTP CONNECT requests and forwards traffic to the appropriate destination. It is designed to work with the zdvv-control service for authentication and authorization.

It will pull keys from the control server and use them to validate JWTs provided by clients. It supports HTTP/1, HTTP/2, and HTTP/3 (QUIC) protocols. It can automatically use ACME to obtain TLS certificates itself, or it can be configured to use a custom certificate.

## Architecture Overview
```plaintext
  ┌────────────────┐                          ┌────────────────┐                  
  │Client          │CONNECT Auth:{jwt}        │Proxy           │          ┌─────┐ 
  │                ├─────────────────────────►│                ├─────────►│ WEB │ 
  │                │                          │                │◄─────────┤     │ 
  │                │                          │                │          └─────┘ 
  └▲───────────────┘                          └───────────┬───▲┘                  
   │                                                      │   │                   
   │                                                      │   │                   
   │                                                      │   │                   
   │                                                      │   │                   
   │GET /servers                                          │   │                   
   │GET /jwt/token  ┌────────────────┐                    │   │                   
   └───────────────►│Control         │ POST /servers      │   │                   
                    │                │◄───────────────────┘   │                   
                    │                │GET /wk/jkws.json       │                   
                    │                │◄───────────────────────┘                   
                    └─────┬───▲──────┘                                            
                          │   │                                                   
                          │   │Keys& Servers                                      
                          │   │                                                   
                       ┌──▼───┴───┐                                               
                       │Database  │                                               
                       └──────────┘                                               
                                                                                  
```

## Todo
This project does not include, but might in the future if i'm feeling like it:
- ❌ Authenticate the token endpoint aginst an OAuth2 server (i.e FXA)
- ❌ Use a Pairing flow for the Proxy Server, requesting a 2FA from an Admin before offering it to users.
- ❌ Add a Web UI for the Control Server to manage the Proxy Servers
- ❌ Support RFC 9484 (connect-ip)
- 👀 Support RFC 9298 (connect-udp)
- ❌ Support HTTP Authentication Scheme (proxy as origin/validator, control as issuer)


## Building

To build the zdvv services, you need to have Go installed on your machine. You can build both services using the following commands:
```bash
# Build zdvv-control
go build -o zdvv-control ./cmd/control
# Build zdvv-proxy
go build -o zdvv-proxy ./cmd/proxy
```

## Running the Services
For local development, you can run the services using the following commands:
```bash
docker compose -f docker-compose.dev.yml up
```

## Running Integration Tests
To run integration tests for the zdvv-control service, you can use the following command:
```bash
#Make sure the dev-compose is running
docker compose -f docker-compose.dev.yml up -d
go test -v ./test/control/...
```

## Running unit tests
To run unit tests for the zdvv-control service, you can use the following command:
```bash
go test -v ./cmd/...
go test -v ./pkg/...
```
