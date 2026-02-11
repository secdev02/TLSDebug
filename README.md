# TLS Debugging Proxy

A minimalist TLS intercepting proxy written in Go. Single file, no external dependencies, cross-platform.

## Features

- Automatic CA certificate generation and system installation
- TLS 1.2 and TLS 1.3 support
- Request/response logging with headers and POST parameters
- Console output sanitization (prevents terminal beeping)
- Extensible logging module system
- Configurable certificate extensions (SAN, AIA, CDP, OCSP)
- Single binary, no dependencies
- Cross-platform (Windows, macOS, Linux)

## Quick Start

```bash
# Build
go build tlsproxy.go

# Run (attempts automatic certificate installation)
./tlsproxy

# Skip automatic installation
./tlsproxy --skip-install
```

The proxy listens on `localhost:8080` by default.

## Certificate Installation

The proxy automatically generates a CA certificate (`proxy-ca.crt`) and attempts to install it to your system trust store on first run.

### Windows

**Command Line:**
```cmd
# User store
certutil -addstore -user Root proxy-ca.crt

# System store (requires Admin)
certutil -addstore Root proxy-ca.crt
```

**GUI Method:**
1. Double-click `proxy-ca.crt`
2. Install Certificate → Current User
3. Place in "Trusted Root Certification Authorities"

**Verify:**
```cmd
certutil -user -verifystore Root "TLS Proxy Root CA"
```

### macOS

**Command Line:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy-ca.crt
```

**GUI Method:**
Double-click `proxy-ca.crt` → Keychain Access → Always Trust

### Linux

**System-Wide:**
```bash
# Ubuntu/Debian
sudo cp proxy-ca.crt /usr/local/share/ca-certificates/tlsproxy.crt
sudo update-ca-certificates

# RHEL/CentOS/Fedora
sudo cp proxy-ca.crt /etc/pki/ca-trust/source/anchors/tlsproxy.crt
sudo update-ca-trust
```

### Chrome/Chromium on Linux

Chrome requires the certificate in its own NSS database:

```bash
# Install certutil if needed
sudo apt install libnss3-tools

# Add certificate to Chrome's certificate database
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TLSDebug CA" -i proxy-ca.crt
```

**Verify installation:**
```bash
certutil -d sql:$HOME/.pki/nssdb -L
```

**Important:** Restart Chrome completely after installation.

### Firefox

Firefox uses its own certificate store:

1. Settings → Privacy & Security → Certificates → View Certificates
2. Authorities → Import
3. Select `proxy-ca.crt`
4. Check "Trust this CA to identify websites"

## Usage

### Configure Your Client

**Browser:**
- Proxy: `localhost`
- Port: `8080`

**Command Line:**
```bash
# Environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Test with curl
curl -x http://localhost:8080 https://example.com
```

**Python:**
```python
import requests
proxies = {
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080'
}
requests.get('https://api.example.com', proxies=proxies, verify='proxy-ca.crt')
```

### Command Line Options

```
-port int          Proxy port (default 8080)
-certdir string    Certificate directory (default ".")
-config string     Configuration file (default "proxy-config.ini")
-cleanup          Remove CA certificates and exit
-skip-install     Skip automatic certificate installation
```

### Cleanup

Remove CA certificate from system:
```bash
./tlsproxy -cleanup
```

## Logging Modules

The proxy includes an extensible module system for filtering and modifying traffic.

### Built-in Modules

**AllTrafficModule** - Logs all traffic (default)

**OAuthModule** - Only logs OAuth/authentication flows

**DomainFilterModule** - Filter by domain:
```go
RegisterModule(&DomainFilterModule{
    Domains: []string{"example.com", "api.github.com"},
})
```

**PathFilterModule** - Filter by URL path:
```go
RegisterModule(&PathFilterModule{
    Paths: []string{"/api/", "/v1/users"},
})
```

**RequestModifierModule** - Add/remove request headers:
```go
RegisterModule(&RequestModifierModule{
    AddHeaders: map[string]string{"X-Custom": "value"},
    RemoveHeaders: []string{"User-Agent"},
})
```

**ResponseModifierModule** - Add/remove response headers

### Enable Modules

Edit `initializeModules()` in `tlsproxy.go`:
```go
func initializeModules() {
    // Default
    RegisterModule(&AllTrafficModule{})
    
    // Or use filters
    // RegisterModule(&OAuthModule{})
    // RegisterModule(&DomainFilterModule{Domains: []string{"example.com"}})
}
```

See `MODULES.md` for creating custom modules.

## Configuration File

Optional `proxy-config.ini` for advanced settings:

```ini
[server]
port = 8080
cert_dir = .
skip_install = false

[ca_certificate]
organization = TLS Proxy CA
common_name = TLS Proxy Root CA
validity_years = 10

[certificate_extensions]
# Authority Information Access
aia_urls = http://ocsp.proxy.local|http://ca.issuer.local/ca.crt

# CRL Distribution Points
crl_distribution_points = http://crl.proxy.local/proxy-ca.crl

# OCSP Server
ocsp_url = http://ocsp.proxy.local

[host_certificates]
# Default SAN entries
default_san_entries = localhost,127.0.0.1,*.local

# Validity period (days)
validity_days = 365

# Include extensions in host certificates
include_aia_in_host_certs = false
include_cdp_in_host_certs = false
```

## Log Format

Traffic is logged to console and `proxy.log`:

```
2025/01/13 14:30:45 Proxy listening on port 8080
2025/01/13 14:30:45 CA certificate: ./proxy-ca.crt
2025/01/13 14:30:50 [CONNECTION] New connection from 127.0.0.1:54321
2025/01/13 14:30:50 [CONNECT] 127.0.0.1:54321 -> example.com:443
2025/01/13 14:30:50 [TLS] example.com:443 using TLS 1.3 with cipher TLS_AES_128_GCM_SHA256

=== 2025-01-13 14:30:45 ===
GET https://example.com/api/data
Headers:
  User-Agent: Mozilla/5.0
  Accept: application/json
```

**Output Sanitization:**
- Control characters are escaped to prevent terminal beeping
- Binary content shown as `[Binary data, N bytes]`
- Large bodies (>10KB) truncated in console
- Full raw data always in `proxy.log`

## Troubleshooting

### Certificate Errors in Chrome (Linux)

If you see certificate errors in Chrome after system installation:

1. **Install to Chrome's NSS database:**
   ```bash
   sudo apt install libnss3-tools
   certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TLSDebug CA" -i proxy-ca.crt
   ```

2. **Verify installation:**
   ```bash
   certutil -d sql:$HOME/.pki/nssdb -L | grep "TLSDebug CA"
   ```

3. **Restart Chrome completely** (close all windows and background processes)

### Other Issues

**Certificate installation failed (Windows):**
- Run `install-cert-windows.bat` as Administrator
- Or use GUI: double-click `proxy-ca.crt`

**Certificate installation failed (macOS/Linux):**
- Enter sudo password when prompted
- Check console for error messages

**Connection refused:**
- Verify proxy is running: `netstat -an | grep 8080`
- Check firewall settings
- Try different port: `./tlsproxy -port 9090`

**TLS handshake failures:**
- Check console for TLS version logs
- Proxy supports both TLS 1.2 and 1.3
- Some servers may require specific versions

**Nothing in logs:**
- Verify client proxy settings
- Check `proxy.log` permissions
- Look for connection errors in console

**Terminal beeping:**
- Console output is automatically sanitized
- Control characters shown as `\xHH`
- Binary data shown as `[Binary data, N bytes]`
- Raw data available in `proxy.log`

## Technical Details

### TLS Support

**Versions:** TLS 1.2, TLS 1.3

**Cipher Suites:**
- TLS 1.3: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- TLS 1.2: ECDHE-RSA/ECDSA with AES-GCM and ChaCha20-Poly1305

### Certificate Extensions

**SAN (Subject Alternative Names):**
- Auto-includes target hostname
- Adds wildcards (e.g., `*.example.com`)
- Supports DNS names and IP addresses

**AIA (Authority Information Access):**
- OCSP responder and CA issuer locations
- Optional for host certificates

**CDP (CRL Distribution Points):**
- Certificate revocation list URLs
- Optional for host certificates

**OCSP (Online Certificate Status Protocol):**
- Real-time revocation checking

View certificate details:
```bash
openssl x509 -in proxy-ca.crt -text -noout
```

## Security Notes

 **This tool performs averdary-in-the-middle TLS interception:**
- Only use on networks/applications you own or control
- Keep `proxy-ca.key` secure (never share)
- Remove CA certificate when done testing
- Never use in production environments

## Build for Other Platforms

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o tlsproxy-linux tlsproxy.go

# Windows
GOOS=windows GOARCH=amd64 go build -o tlsproxy.exe tlsproxy.go

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o tlsproxy-mac tlsproxy.go

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o tlsproxy-mac-arm tlsproxy.go

# Smaller Build

go build -ldflags "-s -w"
```

## Files

- `proxy-config.ini` - Configuration (optional)
- `proxy-ca.crt` - CA certificate (install this)
- `proxy-ca.key` - CA private key (keep secure)
- `proxy.log` - Traffic logs
- `install-cert-windows.bat` - Windows installer
- `MODULES.md` - Module development guide

## License

MIT - Use at your own risk for legitimate debugging/testing purposes only.
