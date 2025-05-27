<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# ZDVV Control Server

The ZDVV Control Server keeps a record of all proxy servers, allows servers to register themselves, and enables users to query them. Additionally, ZDVV can issue JWTs for connecting to proxy servers.

## Configuration
The server can be configured using environment variables. Below are the available configuration parameters:

| Environment Variable       | Default Value         | Description                          |
|----------------------------|-----------------------|--------------------------------------|
| `ZDVV_LISTEN_ADDR`                | `localhost:8080`      | The address the server listens on.   |
| `ZDVV_REDIS_ADDR`          | `localhost:6379`      | The Redis server address.            |
| `ZDVV_REDIS_PASSWORD`      | `""`                 | The Redis server password.           |
| `ZDVV_REDIS_DB`            | `0`                   | The Redis database index.            |
| `ZDVV_AUTH_SECRET`         | `my-secret-key`       | The secret key for authentication.   |

## Routes
The following routes are available in the server:

### Unauthenticated Routes
- `GET /.well-known/jwks.json` - Retrieves all active JWT keys in JSON Web Key Set (JWKS) format.
- `GET /api/v1/health` - Health check endpoint, returns `OK`.
- `GET /api/v1/token` - Generates a new JWT token.
- `GET /api/v1/servers` - Retrieves a list of all servers.

### Authenticated Routes
- `POST /api/v1/server` - Adds a new server to the database and returns a revocation token.
- `DELETE /api/v1/server/{revocationToken}` - Removes a server matching the provided revocation token.

Authentication for the authenticated routes is done using a Bearer token in the `Authorization` header. The token must match the value of `ZDVV_AUTH_SECRET`.

## Running the Server
To run the server, execute the following command:

```bash
# Ensure environment variables are set, then run:
go run ./cmd/control/main.go
```

The server will start and listen on the address specified by `ZDVV_PORT` (default: `localhost:8080`).
