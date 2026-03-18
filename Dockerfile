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
RUN apk add --no-cache ca-certificates tzdata python3

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/tlsproxy .

# Directory for generated CA cert, key, and logs
# (Railway mounts ephemeral storage here unless you attach a volume)
RUN mkdir -p /app/certs /app/logs

EXPOSE 8080
EXPOSE 4040
EXPOSE 8888

# Launch both proxy instances + a lightweight HTTP file server for cert retrieval.
# Access the CA cert at: http://<host>:8888/proxy-ca.crt
# The shell waits for all; if any process exits, the container stops.
ENTRYPOINT ["sh", "-c", \
  "/app/tlsproxy --skip-install --certdir /app/certs --port 8080 & \
   /app/tlsproxy --skip-install --certdir /app/certs --port 4040 & \
   cd /app/certs && python3 -m http.server 8888 & \
   wait"]

# Grab Cert for proxy 
# curl http://<your-railway-host>:8888/proxy-ca.crt -o proxy-ca.crt
# Add
# sudo cp proxy-ca.crt /usr/local/share/ca-certificates/tlsproxy.crt
# sudo update-ca-certificates
# Remove
# sudo rm /usr/local/share/ca-certificates/tlsproxy.crt
# sudo update-ca-certificates --fresh
