# TLSDebug Remote Browser Lab (HTTPS noVNC)

This variant exposes the browser-in-browser UI over HTTPS while keeping the
same TLSDebug proxy, Manifest V3 proxy extension, and persistent CA lifecycle
as `../remotebrowser`.

```bash
docker compose up
```

Open `https://localhost:6443` for the remote Chrome UI and
`http://localhost:4040` for captured traffic.

The build generates a CA pair inside the image. On first start it is copied to
`./logs/proxy-ca.crt` and `./logs/proxy-ca.key`; later starts reuse that pair.
The container compares the CA fingerprint with the Debian and Chrome NSS
stores before installing it. The extension routes Chrome through
`127.0.0.1:8080` and adds a floating back button in the top-left corner.

To rotate the CA, stop the container, remove both CA files from `./logs`, and
rebuild with `docker compose build --no-cache`.

The private key remains extractable from the built image and the logs volume.
Do not distribute either or trust this CA outside a controlled test system.
