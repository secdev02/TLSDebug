# TLS Debugging Proxy

A minimalist TLS intercepting proxy written in Go. Single file, no external dependencies, cross-platform.

A Simple TLS Intercepting Proxy - For Learning 



## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CERTIFICATE STORAGE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Working Directory:                      System Trust Store:                │
│  ┌──────────────────┐                    ┌─────────────────────┐           │
│  │ proxy-ca.crt     │ ──── install ────> │ Windows: certutil   │           │
│  │ (Public CA Cert) │                    │ macOS: Keychain     │           │
│  └──────────────────┘                    │ Linux: ca-certs     │           │
│                                           └─────────────────────┘           │
│  ┌──────────────────┐                                                       │
│  │ proxy-ca.key     │ ◄── used to sign                                      │
│  │ (Private CA Key) │     host certs                                        │
│  └──────────────────┘                                                       │
│         │                                                                    │
│         └─────────┐                                                          │
│                   ▼                                                          │
│         ┌──────────────────┐                                                │
│         │ In-Memory Cache  │                                                │
│         │ ┌──────────────┐ │                                                │
│         │ │ example.com  │ │ ◄── Dynamically generated per host            │
│         │ │   cert+key   │ │                                                │
│         │ └──────────────┘ │                                                │
│         │ ┌──────────────┐ │                                                │
│         │ │ google.com   │ │                                                │
│         │ │   cert+key   │ │                                                │
│         │ └──────────────┘ │                                                │
│         └──────────────────┘                                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROXY TRAFFIC FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────┐                                                  ┌─────────┐    │
│  │ Client │                                                  │  Real   │    │
│  │Browser │                                                  │ Server  │    │
│  │  App   │                                                  │(HTTPS)  │    │
│  └────┬───┘                                                  └────▲────┘    │
│       │                                                           │          │
│       │ 1. CONNECT example.com:443                               │          │
│       ├──────────────────────────────────────────────┐           │          │
│       │                                               │           │          │
│       │                    ┌──────────────────────────▼───────────┴─────┐   │
│       │                    │      TLS PROXY (localhost:8080)            │   │
│       │                    │                                            │   │
│       │                    │  ┌──────────────────────────────────────┐ │   │
│       │ 2. HTTP/1.1 200 OK │  │ 1. Receive CONNECT                   │ │   │
│       │◄───────────────────┤  │ 2. Send "200 Connection Established" │ │   │
│       │                    │  │ 3. Get/Generate cert for example.com │ │   │
│       │                    │  │ 4. Start TLS handshake with client   │ │   │
│       │                    │  └──────────────────────────────────────┘ │   │
│       │                    │                                            │   │
│       │ 3. TLS Handshake   │  ┌──────────────────────────────────────┐ │   │
│       │   (Client Hello)   │  │ Present dynamically generated cert   │ │   │
│       ├───────────────────>│  │ signed by proxy-ca.key               │ │   │
│       │                    │  │                                      │ │   │
│       │   (Server Hello +  │  │ Client validates against installed   │ │   │
│       │    example.com     │  │ proxy-ca.crt in trust store         │ │   │
│       │    certificate)    │  └──────────────────────────────────────┘ │   │
│       │◄───────────────────┤                                            │   │
│       │                    │                                            │   │
│       │   [TLS 1.2/1.3     │                                            │   │
│       │    Encrypted]      │                                            │   │
│       │                    └────────────────────────────────────────────┘   │
│       │                                                                     │
│       │ 4. HTTPS Request (decrypted by proxy)                              │
│       │    GET /api/data                                                    │
│       ├────────────────────────────────────┐                                │
│       │                                     │                                │
│       │              ┌──────────────────────▼────────────────────┐          │
│       │              │  PROXY LOGGING                            │          │
│       │              │  ┌─────────────────────────────────────┐  │          │
│       │              │  │ Log to console:                     │  │          │
│       │              │  │ - Connection info                   │  │          │
│       │              │  │ - TLS version & cipher             │  │          │
│       │              │  │ - HTTP method & URL                │  │          │
│       │              │  │ - Headers                          │  │          │
│       │              │  │ - POST parameters                  │  │          │
│       │              │  └─────────────────────────────────────┘  │          │
│       │              │  ┌─────────────────────────────────────┐  │          │
│       │              │  │ Write to proxy.log file             │  │          │
│       │              │  └─────────────────────────────────────┘  │          │
│       │              └───────────────────────────────────────────┘          │
│       │                                     │                                │
│       │                                     │ 5. Forward to real server      │
│       │                                     │    (establish new TLS)         │
│       │                                     └──────────────────────┐         │
│       │                                                            │         │
│       │                                                            ▼         │
│       │                                              ┌──────────────────┐    │
│       │                                              │  example.com:443 │    │
│       │                                              │                  │    │
│       │                                              │  TLS 1.2/1.3    │    │
│       │                                              │  Handshake      │    │
│       │                                              └────────┬─────────┘    │
│       │                                                       │              │
│       │                                              6. GET /api/data        │
│       │                                              ────────────────>       │
│       │                                                       │              │
│       │                                              7. Response             │
│       │                                              <────────────────       │
│       │                                                       │              │
│       │              8. Response (encrypted by proxy)        │              │
│       │◄─────────────────────────────────────────────────────┘              │
│       │                                                                      │
│       ▼                                                                      │
│  [Client receives                                                           │
│   decrypted data]                                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

KEY:
  ──>  : Unencrypted traffic
  ═══> : TLS encrypted traffic
  ┌─┐  : Component/Process
  
SECURITY MODEL:
  1. Proxy acts as Certificate Authority (CA)
  2. Client trusts proxy's CA certificate
  3. Proxy generates unique certs for each domain on-the-fly
  4. Proxy can decrypt, inspect, log, then re-encrypt traffic
  5. Real servers see normal TLS connections from proxy
```

## Features

- Automatic CA certificate generation and system installation
- TLS/HTTPS traffic interception (TLS 1.2 and TLS 1.3 support)
- Request/response logging with headers and POST parameters
- **Console output sanitization** prevents terminal beeping from control characters
- TLS version and cipher suite logging
- **Extensible logging module system** for filtering and modifying traffic
- Configurable certificate extensions (SAN, AIA, CDP, OCSP)
- Automatic SAN generation with wildcards and IP addresses
- Single binary, no dependencies
- Configuration file support for advanced settings
- Easy cleanup with automatic certificate removal
- Cross-platform (Windows, macOS, Linux)

## Build

```bash
# Build for your platform
go build tlsproxy.go

# Cross-compile for other platforms
GOOS=linux GOARCH=amd64 go build -o tlsproxy-linux tlsproxy.go
GOOS=windows GOARCH=amd64 go build -o tlsproxy.exe tlsproxy.go
GOOS=darwin GOARCH=amd64 go build -o tlsproxy-mac tlsproxy.go
GOOS=darwin GOARCH=arm64 go build -o tlsproxy-mac-arm tlsproxy.go
```

## Usage

### Start the proxy

```bash
# Default port 8080 (logs to console and file)
./tlsproxy

# Custom port
./tlsproxy -port 9090

# Custom certificate directory
./tlsproxy -certdir /path/to/certs
```

All traffic, connections, and headers are logged to both console and `proxy.log` file.

### Configure your client

Set your browser or application to use the proxy:
- Proxy: `localhost`
- Port: `8080` (or your custom port)

### Install CA Certificate

**The proxy attempts automatic certificate installation on first run.**

On first run, the proxy:
1. Generates `proxy-ca.crt`
2. Attempts to install it to your system trust store

**Platform Notes:**
- **Windows:** Installs to user store automatically. For system-wide installation, see troubleshooting below.
- **macOS/Linux:** Requires `sudo` password for system-wide installation
- If automatic installation fails, manual instructions will be displayed

**Skip automatic installation:**
```bash
./tlsproxy --skip-install
```

#### Windows Certificate Installation

If automatic installation fails on Windows, you have several options:

**Option 1 - Run the installer script (Recommended):**
```cmd
# Right-click and "Run as administrator"
install-cert-windows.bat
```

**Option 2 - Command Line (User Store):**
```cmd
certutil -addstore -user Root proxy-ca.crt
```

**Option 3 - Command Line (System Store, requires Admin):**
```cmd
certutil -addstore Root proxy-ca.crt
```

**Option 4 - GUI Method:**
1. Double-click `proxy-ca.crt`
2. Click "Install Certificate"
3. Store Location: "Current User" or "Local Machine"
4. Place in: "Trusted Root Certification Authorities"
5. Click "Next" and "Finish"

**Verify Installation:**
```cmd
certutil -user -verifystore Root "TLS Proxy Root CA"
```

#### Manual Installation - macOS/Linux

#### Windows
```bash
certutil -addstore -user Root proxy-ca.crt
```

Or: Double-click `proxy-ca.crt` → Install Certificate → Current User → Place in "Trusted Root Certification Authorities"

#### macOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy-ca.crt
```

Or: Double-click `proxy-ca.crt` → Keychain Access → Always Trust

#### Linux (Ubuntu/Debian)
```bash
sudo cp proxy-ca.crt /usr/local/share/ca-certificates/tlsproxy.crt
sudo update-ca-certificates
```

#### Firefox
Firefox uses its own certificate store:
1. Settings → Privacy & Security → Certificates → View Certificates
2. Authorities → Import → Select `proxy-ca.crt`
3. Trust for websites

### Logging Modules

The proxy includes an extensible logging module system that allows you to filter and modify traffic.

#### Built-in Modules

**AllTrafficModule (Default)**
Logs all traffic without filtering.

**OAuthModule**
Only logs OAuth and authentication flows. Detects:
- URLs containing: /oauth, /auth, /login, /token, /authorize
- Requests with Authorization headers
- OAuth parameters in URLs

**DomainFilterModule**
Only logs traffic to specific domains.
```go
RegisterModule(&DomainFilterModule{
    Domains: []string{"example.com", "api.github.com"},
})
```

**PathFilterModule**
Only logs requests to specific URL paths.
```go
RegisterModule(&PathFilterModule{
    Paths: []string{"/api/", "/v1/users"},
})
```

**RequestModifierModule**
Adds or removes headers from requests before forwarding.
```go
RegisterModule(&RequestModifierModule{
    AddHeaders: map[string]string{
        "X-Custom-Header": "value",
    },
    RemoveHeaders: []string{"User-Agent"},
})
```

**ResponseModifierModule**
Adds or removes headers from responses.
```go
RegisterModule(&ResponseModifierModule{
    AddHeaders: map[string]string{
        "X-Proxy-Modified": "true",
    },
    RemoveHeaders: []string{"Server"},
})
```

#### Enabling Modules

Edit the `initializeModules()` function in `tlsproxy.go`:

```go
func initializeModules() {
    // Default: log everything
    RegisterModule(&AllTrafficModule{})
    
    // Or use filters:
    // RegisterModule(&OAuthModule{})
    // RegisterModule(&DomainFilterModule{Domains: []string{"example.com"}})
}
```

#### Creating Custom Modules

See `MODULES.md` for detailed documentation on creating custom logging modules. The module interface allows you to:
- Filter which requests get logged
- Modify requests before they reach the server
- Modify responses before they reach the client
- Implement custom traffic analysis logic

Example custom module:
```go
type MyModule struct{}

func (m *MyModule) Name() string { return "MyModule" }
func (m *MyModule) ShouldLog(req *http.Request) bool { 
    return strings.Contains(req.URL.Path, "/api/")
}
func (m *MyModule) ProcessRequest(req *http.Request) error { return nil }
func (m *MyModule) ProcessResponse(resp *http.Response) error { return nil }
```

### Cleanup

Remove CA certificates and uninstall from system:
```bash
./tlsproxy -cleanup
```

This will:
1. Uninstall the certificate from system trust store
2. Delete `proxy-ca.crt` and `proxy-ca.key` files

**Note:** macOS/Linux will prompt for `sudo` password to remove from system store.

## Output Files

- `proxy-config.ini` - Configuration file (optional, will be created on first run)
- `proxy-ca.crt` - CA certificate (install this)
- `proxy-ca.key` - CA private key (keep secure)
- `proxy.log` - Traffic logs
- `install-cert-windows.bat` - Windows certificate installer (run as admin)
- `MODULES.md` - Module development guide

## Log Format

Console and file output:
```
2025/01/13 14:30:45 Proxy listening on port 8080
2025/01/13 14:30:45 CA certificate: ./proxy-ca.crt
2025/01/13 14:30:45 Log file: ./proxy.log
2025/01/13 14:30:45 Initializing logging modules...
2025/01/13 14:30:45 [MODULE] Registered: AllTraffic
2025/01/13 14:30:45 Total modules registered: 1
2025/01/13 14:30:50 [CONNECTION] New connection from 127.0.0.1:54321
2025/01/13 14:30:50 [CONNECT] 127.0.0.1:54321 -> example.com:443
2025/01/13 14:30:50 [TLS] example.com:443 using TLS 1.3 with cipher TLS_AES_128_GCM_SHA256

=== 2025-01-13 14:30:45 ===
GET https://example.com/api/data
Headers:
  User-Agent: Mozilla/5.0
  Accept: application/json

=== 2025-01-13 14:30:46 ===
POST https://accounts.google.com/oauth/token
Headers:
  Content-Type: application/x-www-form-urlencoded
POST Parameters:
  client_id: abc123
  grant_type: authorization_code
  code: xyz789
```

With modules enabled:
```
2025/01/13 14:30:45 [MODULE] Registered: OAuth
2025/01/13 14:30:50 [OAuth] Detected OAuth flow: https://accounts.google.com/oauth/token
2025/01/13 14:30:51 [RequestModifier] Added header: X-Debug: true
```

**Output Sanitization:**
- Console output sanitizes control characters to prevent terminal beeping
- Binary content is detected and shown as [Binary data, N bytes]
- Large request bodies (>10KB) are truncated in logs
- Raw unsanitized data is always written to proxy.log file
- Control characters are displayed as \xHH in console (e.g., \x07 for bell character)

The TLS version log shows:
- Which TLS version was negotiated (1.2 or 1.3)
- Which cipher suite is being used
- Helpful for debugging compatibility issues

## Command Line Options

```
-port int
    Proxy port (default 8080)
-certdir string
    Certificate directory (default ".")
-config string
    Configuration file path (default "proxy-config.ini")
-cleanup
    Remove CA certificates and exit
-skip-install
    Skip automatic certificate installation
```

## Configuration File

The proxy supports a configuration file (`proxy-config.ini`) for certificate extensions and advanced settings. If the file doesn't exist, defaults are used.

### Example Configuration

```ini
[server]
port = 8080
cert_dir = .
skip_install = false

[ca_certificate]
# CA Certificate settings
organization = TLS Proxy CA
common_name = TLS Proxy Root CA
validity_years = 10

[certificate_extensions]
# Authority Information Access (AIA) - Format: ocsp_url|ca_issuer_url
aia_urls = http://ocsp.proxy.local|http://ca.issuer.local/ca.crt

# CRL Distribution Points (comma-separated)
crl_distribution_points = http://crl.proxy.local/proxy-ca.crl

# OCSP Server URL
ocsp_url = http://ocsp.proxy.local

[host_certificates]
# Default SAN entries added to all generated certificates
default_san_entries = localhost,127.0.0.1,*.local

# Certificate validity for host certificates (days)
validity_days = 365

# Include AIA/CDP extensions in dynamically generated host certificates
include_aia_in_host_certs = false
include_cdp_in_host_certs = false
```

### Certificate Extensions Explained

**SAN (Subject Alternative Names):**
- Automatically includes the target hostname
- Adds default entries from `default_san_entries`
- Adds wildcard for subdomains (e.g., `*.example.com` for `api.example.com`)
- Supports both DNS names and IP addresses

**AIA (Authority Information Access):**
- Specifies OCSP responder and CA issuer certificate locations
- Format: `ocsp_url|ca_issuer_url`
- Helps clients validate certificate chain
- Enabled in CA certificate if configured
- Can be enabled in host certificates with `include_aia_in_host_certs = true`

**CDP (CRL Distribution Points):**
- URLs where Certificate Revocation Lists are published
- Multiple URLs supported (comma-separated)
- Clients can check if certificates have been revoked
- Enabled in CA certificate if configured
- Can be enabled in host certificates with `include_cdp_in_host_certs = true`

**OCSP (Online Certificate Status Protocol):**
- Real-time certificate revocation checking
- Alternative to CRL (more efficient)
- Can be specified separately or as part of AIA

### Configuration Use Cases

**Development/Testing (Default):**
```ini
# Minimal config - no extensions needed
[host_certificates]
default_san_entries = localhost,127.0.0.1
```

**Enterprise Testing:**
```ini
# Full certificate validation testing
[certificate_extensions]
aia_urls = http://ocsp.company.local|http://ca.company.local/ca.crt
crl_distribution_points = http://crl.company.local/proxy.crl

[host_certificates]
include_aia_in_host_certs = true
include_cdp_in_host_certs = true
default_san_entries = localhost,127.0.0.1,*.company.local
```

### Viewing Certificate Extensions

Check CA certificate:
```bash
openssl x509 -in proxy-ca.crt -text -noout
```

Check generated host certificate:
```bash
openssl s_client -connect localhost:8080 -servername example.com -showcerts
```

## Security Notes

⚠️ This tool performs man-in-the-middle TLS interception:
- Only use on networks and applications you own/control
- Keep the CA private key (`proxy-ca.key`) secure
- Remove the CA certificate when done testing
- Never share your CA certificate/key with others

## Example Workflows

### Test with curl
```bash
# Start proxy
./tlsproxy

# In another terminal
curl -x http://localhost:8080 https://example.com
```

### Browser testing
1. Start proxy: `./tlsproxy`
2. Configure browser proxy settings
3. Install CA certificate in browser
4. Browse HTTPS sites
5. Watch console output and check `proxy.log` for captured traffic

### API debugging
```bash
# Python
import requests
proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
requests.get('https://api.example.com', proxies=proxies, verify='/path/to/proxy-ca.crt')

# Node.js
const https = require('https');
const agent = new https.Agent({
  ca: fs.readFileSync('proxy-ca.crt'),
  proxy: 'http://localhost:8080'
});
```

## Troubleshooting

**Certificate installation failed (Windows):**
- Check the console output for detailed error messages
- Try running PowerShell/CMD as Administrator
- Use the provided `install-cert-windows.bat` script (run as admin)
- Verify certutil is available: `certutil -?`
- Try GUI installation: double-click `proxy-ca.crt`
- If still failing, use `--skip-install` flag and install manually

**Certificate installation failed (macOS/Linux):**
- Enter your password when prompted for `sudo`
- Check console for error messages
- Manual install: Follow the instructions printed by the program

**Certificate errors in browser:**
- Restart your browser after certificate installation
- Ensure CA certificate is installed in system/browser trust store
- Check certificate is valid: `openssl x509 -in proxy-ca.crt -text -noout`

**Connection refused:**
- Verify proxy is running: `netstat -an | grep 8080`
- Check firewall settings
- Try different port: `./tlsproxy -port 9090`

**TLS handshake failures:**
- Check console for TLS version logs
- Some older systems may only support TLS 1.2
- Some servers may require TLS 1.3
- The proxy supports both - check server requirements

**Nothing in logs:**
- Check console output for connection/error messages
- Verify client is using correct proxy settings
- Check proxy.log permissions

**Terminal beeping or strange characters:**
- Console output is automatically sanitized to prevent control characters
- Control characters are shown as \xHH (e.g., \x07 for bell)
- Binary content is detected and shown as [Binary data, N bytes]
- Raw unsanitized data is always available in proxy.log file

## Technical Details

### TLS Configuration

**Supported Versions:**
- TLS 1.2 (for legacy compatibility)
- TLS 1.3 (for modern security)

**Cipher Suites:**

TLS 1.3:
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

TLS 1.2:
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

The proxy negotiates the highest supported version with the client and uses forward secrecy cipher suites for maximum compatibility and security.

### Output Sanitization

**Console Protection:**
- Control characters (0x00-0x1F except newline, tab, CR) are escaped as \xHH
- Prevents terminal beeping (bell character 0x07)
- Prevents ANSI escape sequences from corrupting output
- Unicode characters are preserved

**Binary Detection:**
- Automatically detects binary content in request/response bodies
- Detection based on null byte and control character ratios
- Binary content shown as [Binary data, N bytes] in console
- First 512 bytes are sampled for detection

**Size Limits:**
- Request/response bodies >10KB are truncated in console
- Full data is always written to proxy.log file
- Truncation message shows remaining bytes

**File vs Console:**
- Console: Sanitized, safe for terminal display
- Log file: Raw unsanitized data, complete capture

## License

MIT - Use at your own risk for legitimate debugging/testing purposes only.
