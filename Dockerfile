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

# Railway injects PORT; fall back to 8080 for local use
ENV PORT=8080

EXPOSE 8080

# --skip-install: don't try to modify the OS trust store inside the container
# --certdir:      keep certs in a dedicated subdirectory
# --port:         read from the PORT env var Railway provides
ENTRYPOINT ["sh", "-c", \
  "exec /app/tlsproxy --skip-install --certdir /app/certs --port ${PORT}"]
