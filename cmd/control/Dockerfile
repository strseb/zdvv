# Use the official Golang image as a base image
FROM golang:1.24 as builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o control-server ./main.go

# Use a minimal base image for the final build
FROM gcr.io/distroless/base-debian11

# Add a non-root user and switch to it
RUN useradd -m zdvv
USER zdvv

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/control-server .

# Expose the port the application runs on
EXPOSE 8080

# Command to run the application
CMD ["./control-server"]
