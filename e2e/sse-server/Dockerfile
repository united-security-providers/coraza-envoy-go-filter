# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0

# Multi-stage Dockerfile for the SSE test server
# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Copy only the server source
COPY main.go ./

# Install git for fetching modules and build the binary
RUN apk add --no-cache git \
    && go mod init sse-server \
    && go get github.com/rifaideen/sse-server@latest \
    && go build -ldflags="-s -w" -o /app/sse-server ./main.go

# Runtime stage
FROM alpine:3.20
WORKDIR /app

# Copy the built binary
COPY --from=builder /app/sse-server /app/sse-server

# Environment-based configuration (no CLI args)
ENV SSE_PORT=8080 \
    SSE_PATH=/events \
    SSE_INTERVAL=1 \
    HEALTH_PATH=/healthz

# Expose default port (can be changed by setting SSE_PORT)
EXPOSE 8080

# Optional healthcheck against configurable health path
HEALTHCHECK --interval=10s --timeout=2s --retries=3 CMD wget -qO- http://127.0.0.1:${SSE_PORT}${HEALTH_PATH} || exit 1

ENTRYPOINT ["/app/sse-server"]
