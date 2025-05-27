# Control Server Integration Tests

This directory contains integration tests for the ZDVV Control Server endpoints.

## Overview

These tests verify the functionality of all control server API endpoints, including:

- Health check endpoint (`/api/v1/health`)
- JWKS endpoint (`/.well-known/jwks.json`)
- Token management endpoint (`/api/v1/token`)
- Server listing endpoint (`/api/v1/servers`)
- Server management endpoints (creation and deletion)

## Test Structure

- `config.go` - Configuration management using environment variables
- `utils.go` - Test utilities for HTTP requests and assertions
- Individual test files for each endpoint:
  - `health_test.go`
  - `jwks_test.go`
  - `token_test.go`
  - `servers_test.go`
  - `server_management_test.go`

## Setup and Configuration

The tests are configured using environment variables:

- `ZDVV_CONTROL_URL` - The URL of the control server (default: `http://localhost:8080`)
- `ZDVV_API_KEY` - API key for authentication (default: `my-secret-key`)

You can set these environment variables directly or use a `.env` file in the root directory.

## Running Tests

To run all integration tests:

```bash
cd /path/to/zdvv
go test -v ./test/control/...
```

To run a specific test file:

```bash
go test -v ./test/control/health_test.go
```

## Testing Strategies

The integration tests follow these strategies:

1. **Positive Testing**: Tests with valid inputs to verify expected successful behavior
2. **Negative Testing**: Tests with invalid inputs to verify proper error handling
3. **Authentication Testing**: Tests to ensure proper authentication requirements
4. **Parameterized Testing**: Tests that use a common structure to test multiple endpoints

Each test includes assertions for:
- HTTP status code
- Response body structure
- Response content validation

### Parameterized Testing

The test suite supports a parameterized testing approach using the `TestCase` struct and `RunTestCases` function. This allows for concise, table-driven tests covering multiple scenarios. See `param_test.go` for examples.

## CI/CD Integration

These tests are designed to be run in CI/CD pipelines. See the root `.github/workflows` directory for the GitHub Actions configuration that executes these tests.
