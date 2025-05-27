# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS builder

WORKDIR /app

COPY . .

RUN go build -o zdvv-proxy ./cmd/proxy

FROM gcr.io/distroless/base

COPY --from=builder /app/zdvv-proxy /zdvv-proxy

ENTRYPOINT ["/zdvv-proxy"]
