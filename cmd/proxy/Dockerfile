FROM golang:latest AS builder

WORKDIR /app

COPY . .

RUN go build -o zdvv-proxy ./cmd/proxy

FROM gcr.io/distroless/base

COPY --from=builder /app/zdvv-proxy /zdvv-proxy

ENTRYPOINT ["/zdvv-proxy"]
