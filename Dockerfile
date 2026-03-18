# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy only the source file (single-file, no external deps)
COPY tlsproxy.go .

# Build a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "-s -w" -o tlsproxy tlsproxy.go

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

# ca-certificates needed for outbound TLS connections the proxy makes
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/tlsproxy .

# Directory for generated CA cert, key, and logs
# (Railway mounts ephemeral storage here unless you attach a volume)
RUN mkdir -p /app/certs /app/logs

EXPOSE 8080
EXPOSE 4040

# Launch both proxy instances in parallel sharing the same CA cert dir.
# The shell waits for both; if either exits, the container stops.
ENTRYPOINT ["sh", "-c", \
  "/app/tlsproxy --skip-install --certdir /app/certs --port 8080 & \
   /app/tlsproxy --skip-install --certdir /app/certs --port 4040 & \
   wait"]
