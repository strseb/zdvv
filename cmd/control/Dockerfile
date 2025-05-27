# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Use the official Golang image as a base image
FROM golang:latest as builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o control-server ./cmd/control/

# Use a minimal base image for the final build
FROM gcr.io/distroless/base

# Use a non-root user (UID 1000) for security
USER 1000

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/control-server .

# Expose the port the application runs on
EXPOSE 8080

# Command to run the application
CMD ["./control-server"]
