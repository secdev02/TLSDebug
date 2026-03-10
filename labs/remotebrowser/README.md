# TLSDebug Remote Browser Lab

Browser-in-browser setup for testing HTTPS interception with TLSDebug. All-in-one Docker container with Chrome, noVNC, and the TLS intercepting proxy pre-configured.

## Quick Start

```bash
docker-compose up
```

Open your browser:
- **http://localhost:6080** - Chrome browser interface (proxy already configured)
- **http://localhost:4040** - Real-time traffic monitor

Browse any HTTPS site in the remote Chrome - all traffic will be intercepted and logged.

## What's Included

- **Headless Chrome** - Full browser with TLS proxy pre-configured
- **noVNC** - Web-based VNC viewer (no VNC client needed)
- **TLSDebug Proxy** - Intercepts and logs all HTTPS traffic
- **Debug Monitor** - Port 4040 shows live traffic, tokens, and sessions
- **Auto CA Trust** - Proxy certificate automatically trusted in Chrome

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 6080 | noVNC | Browser interface - start here |
| 4040 | Monitor | Real-time traffic viewer |
| 8888 | Proxy | TLS proxy (mapped from internal 8080) |
| 5900 | VNC | Raw VNC access (optional) |
| 9222 | DevTools | Chrome debugging protocol (optional) |

## Debug Monitor (Port 4040)

The monitor shows:
- **All HTTP requests/responses** with full headers
- **Session cookies** - Marked with `"session": true`
- **JWT tokens** - Automatically decoded with claims visible
- **OAuth tokens** - Access and refresh tokens
- **POST data** - Form parameters and JSON payloads

## Captured Data

All logs and tokens are saved to `./logs/` on your host:
- `proxy.log` - Full request/response logs
- `EditThisCookie_Sessions.json` - All captured cookies and sessions
- `captured_tokens.json` - JWT and OAuth tokens
- `proxy-ca.crt` - CA certificate (if you need to trust it elsewhere)

## Configuration

Edit `docker-compose.yml` to customize:
- `START_URL` - Set the browser's starting page
- Port mappings - Change if ports conflict
- `./logs` volume - Where captured data is saved

## Use Cases

- Debug OAuth/SAML flows
- Inspect JWT token contents
- Extract session cookies for testing
- Analyze API request/response patterns
- Troubleshoot TLS/HTTPS issues
