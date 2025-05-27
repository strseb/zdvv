# Control Server Integration Tests

This directory contains integration tests for the ZDVV Control Server endpoints.

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
