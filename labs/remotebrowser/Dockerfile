# =============================================================================
# TLSDebug + Headless Chrome + noVNC  —  single self-contained Dockerfile
# =============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    VNC_PORT=5900 \
    NOVNC_PORT=6080 \
    PROXY_PORT=8080 \
    CHROME_REMOTE_DEBUGGING_PORT=9222 \
    PROXY_HOST=127.0.0.1

# ---------------------------------------------------------------------------
# 1. Base packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    git \
    xvfb \
    x11vnc \
    openbox \
    xterm \
    python3 \
    python3-pip \
    python3-websockify \
    novnc \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgdk-pixbuf2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libnss3-tools \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    libxshmfence1 \
    xdg-utils \
    openssl \
    curl \
    netcat-openbsd \
    procps \
    psmisc \
    x11-utils \
    unclutter \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 2. Install browser
#    amd64 -> Google Chrome stable (official Google .deb)
#    arm64 -> Chromium from Debian bookworm (native deb, no snap)
#
#    Base image is debian:bookworm-slim which has real chromium packages
#    on all architectures — no snap wrappers.
# ---------------------------------------------------------------------------
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "${ARCH}" = "amd64" ]; then \
        echo "[browser] amd64: installing Google Chrome ..." && \
        wget -q -O /tmp/chrome.deb \
            "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" && \
        apt-get update && \
        apt-get install -y --no-install-recommends /tmp/chrome.deb && \
        rm /tmp/chrome.deb && \
        rm -rf /var/lib/apt/lists/* && \
        ln -sf /usr/bin/google-chrome /usr/local/bin/browser && \
        echo "[browser] installed: $(google-chrome --version)"; \
    elif [ "${ARCH}" = "arm64" ]; then \
        echo "[browser] arm64: installing Chromium from Debian bookworm ..." && \
        apt-get update && \
        apt-get install -y --no-install-recommends chromium && \
        rm -rf /var/lib/apt/lists/* && \
        ln -sf /usr/bin/chromium /usr/local/bin/browser && \
        echo "[browser] installed: $(chromium --version)"; \
    else \
        echo "[browser] ERROR: unsupported arch ${ARCH}" && exit 1; \
    fi

# ---------------------------------------------------------------------------
# 3. Build TLSDebug from source
#    AllTrafficModule is already active by default and logs every request,
#    response, headers and body — no source patching needed.
#    We set log flags via the LOG_FLAGS env var at runtime instead.
# ---------------------------------------------------------------------------
WORKDIR /build
RUN git clone --depth 1 https://github.com/secdev02/TLSDebug.git . \
    && CGO_ENABLED=0 go build -ldflags "-s -w" -o /usr/local/bin/tlsproxy tlsproxy.go \
    && chmod +x /usr/local/bin/tlsproxy \
    && rm -rf /build

# 4. Locate noVNC web root and write kiosk index.html
#    Kiosk mode: auto-connects, scales to fill browser window, hides toolbar,
#    no password prompt, no connection dialog — just the desktop.
# ---------------------------------------------------------------------------
RUN find /usr -name "vnc.html" 2>/dev/null | head -1 | xargs -I{} dirname {} > /opt/novnc_path \
    && NOVNC_WEB=$(cat /opt/novnc_path) \
    && echo "noVNC web root: ${NOVNC_WEB}" \
    && ls -la "${NOVNC_WEB}"

RUN NOVNC_WEB=$(cat /opt/novnc_path) && cat > "${NOVNC_WEB}/index.html" << 'HTML'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>TLSDebug</title>
  <style>
    html, body { margin:0; padding:0; width:100%; height:100%;
                 overflow:hidden; background:#000; }
    #screen    { position:fixed; top:0; left:0;
                 width:100vw; height:100vh; background:#000; }
    /* Nuke every noVNC chrome element by ID and class */
    #noVNC_control_bar_anchor, #noVNC_control_bar,
    #noVNC_control_bar_handle, #noVNC_hint_anchor,
    #noVNC_transition_dim, #noVNC_bell, #noVNC_status,
    #noVNC_connect_dlg, #noVNC_credentials_dlg,
    .noVNC_status, .noVNC_control_bar { display:none!important; }
    #pip { position:fixed; bottom:14px; left:50%; transform:translateX(-50%);
           background:rgba(0,0,0,.7); color:#58a6ff;
           font:12px/1 'SF Mono',monospace; padding:4px 14px;
           border-radius:20px; pointer-events:none;
           transition:opacity .8s; z-index:9999; }
  </style>
</head>
<body>
  <div id="screen"></div>
  <div id="pip">Connecting...</div>
  <script type="module">
    import RFB from './core/rfb.js';

    const pip  = document.getElementById('pip');
    const scrn = document.getElementById('screen');
    let rfb, t;

    function msg(s, keep) {
      pip.style.opacity = '1';
      pip.textContent   = s;
      clearTimeout(t);
      if (!keep) t = setTimeout(() => { pip.style.opacity = '0'; }, 2500);
    }

    // Remove any noVNC-injected elements immediately and keep watching
    function strip() {
      ['noVNC_control_bar_anchor','noVNC_control_bar','noVNC_control_bar_handle',
       'noVNC_hint_anchor','noVNC_transition_dim','noVNC_bell',
       'noVNC_status','noVNC_connect_dlg'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.parentNode.removeChild(el);
      });
    }
    new MutationObserver(strip).observe(document.documentElement,
                                        {childList:true, subtree:true});

    function connect() {
      strip();
      msg('Connecting...', true);
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = proto + '//' + location.hostname + ':' + (location.port||'6080');
      rfb = new RFB(scrn, url, { credentials: {password:''} });
      rfb.scaleViewport = true;
      rfb.resizeSession = true;
      rfb.clipViewport  = false;
      rfb.showDotCursor = false;
      rfb.background    = '#000000';
      rfb.addEventListener('connect',    ()  => { strip(); msg('TLSDebug Active'); });
      rfb.addEventListener('disconnect', ()  => { msg('Reconnecting...', true); setTimeout(connect, 3000); });
      rfb.addEventListener('credentialsrequired', () => rfb.sendCredentials({password:''}));
    }

    connect();
  </script>
</body>
</html>
HTML

# Also overwrite vnc.html so any direct /vnc.html request shows our kiosk too
RUN NOVNC_WEB=$(cat /opt/novnc_path) && cp "${NOVNC_WEB}/index.html" "${NOVNC_WEB}/vnc.html"

# ---------------------------------------------------------------------------
# 5. Working directories
# ---------------------------------------------------------------------------
RUN mkdir -p /opt/tlsdebug /opt/chrome-profile /var/log/tlsdebug /root/.config

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 4b. Openbox config — fullscreen enforcement + black desktop, no decorations
# ---------------------------------------------------------------------------
RUN mkdir -p /root/.config/openbox

# rc.xml — force every window fullscreen, no decorations, black desktop
RUN cat > /root/.config/openbox/rc.xml << 'RCXML'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <theme>
    <name>Clearlooks</name>
    <titleLayout></titleLayout>
    <keepBorder>no</keepBorder>
    <animateIconify>no</animateIconify>
  </theme>
  <desktops><number>1</number></desktops>
  <applications>
    <application class="*" name="*" role="*" type="normal">
      <fullscreen>yes</fullscreen>
      <maximized>yes</maximized>
      <decorations>no</decorations>
      <focus>yes</focus>
    </application>
  </applications>
</openbox_config>
RCXML

# autostart — black root window, hide idle cursor
RUN cat > /root/.config/openbox/autostart << 'OBSTART'
xsetroot -solid black
unclutter -idle 0 -root -noevents &
OBSTART

# ---------------------------------------------------------------------------
# 5b. Log viewer — real-time web UI on port 4040
# ---------------------------------------------------------------------------
RUN echo 'aW1wb3J0IGh0dHAuc2VydmVyLCBvcywganNvbgpmcm9tIGh0dHAuc2VydmVyIGltcG9ydCBCYXNlSFRUUFJlcXVlc3RIYW5kbGVyLCBIVFRQU2VydmVyCmZyb20gdXJsbGliLnBhcnNlIGltcG9ydCB1cmxwYXJzZSwgcGFyc2VfcXMKCkxPR19ESVIgPSBvcy5lbnZpcm9uLmdldCgiTE9HX0RJUiIsICIvdmFyL2xvZy90bHNkZWJ1ZyIpClBPUlQgICAgPSA0MDQwCgpMT0dfRklMRVMgPSBbInRsc3Byb3h5LmxvZyIsICJjYXB0dXJlZF90b2tlbnMuanNvbiIsICJjaHJvbWUubG9nIiwKICAgICAgICAgICAgICJ4MTF2bmMubG9nIiwgIm5vdm5jLmxvZyIsICJ4dmZiLmxvZyIsICJvcGVuYm94LmxvZyJdCgpkZWYgYnVpbGRfcGFnZSgpOgogICAgZmlsZXNfanMgPSBqc29uLmR1bXBzKExPR19GSUxFUykKICAgIHJldHVybiBmIiIiPCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCxpbml0aWFsLXNjYWxlPTEiPgo8dGl0bGU+VExTRGVidWcgTG9nIFZpZXdlcjwvdGl0bGU+CjxzdHlsZT4KICA6cm9vdHt7LS1iZzojMGQxMTE3Oy0tcGFuZWw6IzE2MWIyMjstLWJvcmRlcjojMzAzNjNkOy0tYWNjZW50OiM1OGE2ZmY7CiAgICAgICAgLS1ncmVlbjojM2ZiOTUwOy0tdGV4dDojYzlkMWQ5Oy0tbXV0ZWQ6IzhiOTQ5ZX19CiAgKnt7Ym94LXNpemluZzpib3JkZXItYm94O21hcmdpbjowO3BhZGRpbmc6MH19CiAgYm9keXt7YmFja2dyb3VuZDp2YXIoLS1iZyk7Y29sb3I6dmFyKC0tdGV4dCk7Zm9udC1mYW1pbHk6J1NGIE1vbm8nLE1vbmFjbyxtb25vc3BhY2U7CiAgICAgICBmb250LXNpemU6MTNweDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2hlaWdodDoxMDB2aH19CiAgaGVhZGVye3tiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgICAgICAgcGFkZGluZzoxMnB4IDIwcHg7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTZweDtmbGV4LXNocmluazowfX0KICBoZWFkZXIgaDF7e2ZvbnQtc2l6ZToxNXB4O2ZvbnQtd2VpZ2h0OjYwMDtjb2xvcjp2YXIoLS1hY2NlbnQpfX0KICAuYmFkZ2V7e2JhY2tncm91bmQ6dmFyKC0tZ3JlZW4pO2NvbG9yOiMwMDA7Zm9udC1zaXplOjEwcHg7Zm9udC13ZWlnaHQ6NzAwOwogICAgICAgICAgcGFkZGluZzoycHggOHB4O2JvcmRlci1yYWRpdXM6MTBweH19CiAgI3N0YXR1c2Jhcnt7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tbXV0ZWQpO21hcmdpbi1sZWZ0OmF1dG99fQogIC50YWJze3tkaXNwbGF5OmZsZXg7Z2FwOjRweDtvdmVyZmxvdy14OmF1dG87YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7CiAgICAgICAgIHBhZGRpbmc6OHB4IDE2cHggMDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2ZsZXgtc2hyaW5rOjB9fQogIC50YWJ7e3BhZGRpbmc6NnB4IDE0cHg7Ym9yZGVyLXJhZGl1czo2cHggNnB4IDAgMDtjdXJzb3I6cG9pbnRlcjtjb2xvcjp2YXIoLS1tdXRlZCk7CiAgICAgICAgYm9yZGVyOjFweCBzb2xpZCB0cmFuc3BhcmVudDtib3JkZXItYm90dG9tOm5vbmU7Zm9udC1zaXplOjEycHg7d2hpdGUtc3BhY2U6bm93cmFwfX0KICAudGFiOmhvdmVye3tjb2xvcjp2YXIoLS10ZXh0KTtiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsLjA1KX19CiAgLnRhYi5hY3RpdmV7e2NvbG9yOnZhcigtLWFjY2VudCk7YmFja2dyb3VuZDp2YXIoLS1iZyk7Ym9yZGVyLWNvbG9yOnZhcigtLWJvcmRlcil9fQogIC50b29sYmFye3tkaXNwbGF5OmZsZXg7Z2FwOjhweDtwYWRkaW5nOjhweCAxNnB4O2JhY2tncm91bmQ6dmFyKC0tYmcpOwogICAgICAgICAgICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2ZsZXgtc2hyaW5rOjA7YWxpZ24taXRlbXM6Y2VudGVyfX0KICAudG9vbGJhciBpbnB1dHt7ZmxleDoxO2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICAgICAgICAgICAgICAgICAgY29sb3I6dmFyKC0tdGV4dCk7cGFkZGluZzo1cHggMTBweDtib3JkZXItcmFkaXVzOjZweDtmb250LWZhbWlseTppbmhlcml0fX0KICAudG9vbGJhciBsYWJlbHt7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtc2l6ZToxMnB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjVweH19CiAgLnRvb2xiYXIgYnV0dG9ue3tiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Y29sb3I6dmFyKC0tdGV4dCk7CiAgICAgICAgICAgICAgICAgICBwYWRkaW5nOjVweCAxMnB4O2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpwb2ludGVyO2ZvbnQtZmFtaWx5OmluaGVyaXR9fQogIC50b29sYmFyIGJ1dHRvbjpob3Zlcnt7Ym9yZGVyLWNvbG9yOnZhcigtLWFjY2VudCk7Y29sb3I6dmFyKC0tYWNjZW50KX19CiAgI2xvZ3ZpZXd7e2ZsZXg6MTtvdmVyZmxvdy15OmF1dG87cGFkZGluZzoxMnB4IDE2cHg7d2hpdGUtc3BhY2U6cHJlLXdyYXA7CiAgICAgICAgICAgIHdvcmQtYnJlYWs6YnJlYWstYWxsO2xpbmUtaGVpZ2h0OjEuNn19CiAgLmxue3twYWRkaW5nOjFweCAwfX0gLmxuOmhvdmVye3tiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsLjA0KX19CiAgLm1hdGNoe3tiYWNrZ3JvdW5kOnJnYmEoODgsMTY2LDI1NSwuMTIpfX0gLmhse3tiYWNrZ3JvdW5kOiNlM2IzNDE0NDtib3JkZXItcmFkaXVzOjJweH19Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CjxoZWFkZXI+CiAgPGgxPiYjeDFGNTBEOyBUTFNEZWJ1ZyBMb2cgVmlld2VyPC9oMT4KICA8c3BhbiBjbGFzcz0iYmFkZ2UiPkxJVkU8L3NwYW4+CiAgPHNwYW4gaWQ9InN0YXR1c2JhciI+Q29ubmVjdGluZy4uLjwvc3Bhbj4KPC9oZWFkZXI+CjxkaXYgY2xhc3M9InRhYnMiIGlkPSJ0YWJzIj48L2Rpdj4KPGRpdiBjbGFzcz0idG9vbGJhciI+CiAgPGlucHV0IGlkPSJmaWx0ZXIiIHBsYWNlaG9sZGVyPSJGaWx0ZXIgbGluZXMuLi4iIG9uaW5wdXQ9ImFwcGx5RmlsdGVyKCkiPgogIDxsYWJlbD48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJhdXRvIiBjaGVja2VkPiBBdXRvLXNjcm9sbDwvbGFiZWw+CiAgPGJ1dHRvbiBvbmNsaWNrPSJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZmlsdGVyJykudmFsdWU9Jyc7YXBwbHlGaWx0ZXIoKSI+Q2xlYXI8L2J1dHRvbj4KICA8YnV0dG9uIG9uY2xpY2s9ImxvY2F0aW9uLmhyZWY9Jy9hcGkvZG93bmxvYWQ/ZmlsZT0nK2N1ciI+RG93bmxvYWQ8L2J1dHRvbj4KPC9kaXY+CjxkaXYgaWQ9ImxvZ3ZpZXciPjwvZGl2Pgo8c2NyaXB0Pgpjb25zdCBMT0dTPXtmaWxlc19qc307CmxldCBjdXI9TE9HU1swXSxvZmY9MCxyYXc9W107CmZ1bmN0aW9uIGluaXQoKXt7CiAgY29uc3QgdD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFicycpOwogIExPR1MuZm9yRWFjaChmPT57ewogICAgY29uc3QgZD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGQuY2xhc3NOYW1lPSd0YWInKyhmPT09Y3VyPycgYWN0aXZlJzonJyk7CiAgICBkLnRleHRDb250ZW50PWY7ZC5vbmNsaWNrPSgpPT5zdyhmKTt0LmFwcGVuZENoaWxkKGQpOwogIH19KTsKICBwb2xsKCk7c2V0SW50ZXJ2YWwocG9sbCwxNTAwKTsKfX0KZnVuY3Rpb24gc3coZil7e2N1cj1mO29mZj0wO3Jhdz1bXTsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudGFiJykuZm9yRWFjaCh0PT50LmNsYXNzTmFtZT0ndGFiJysodC50ZXh0Q29udGVudD09PWY/JyBhY3RpdmUnOicnKSk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ3ZpZXcnKS5pbm5lckhUTUw9Jyc7cG9sbCgpO319CmFzeW5jIGZ1bmN0aW9uIHBvbGwoKXt7CiAgdHJ5e3sKICAgIGNvbnN0IHI9YXdhaXQgZmV0Y2goJy9hcGkvbG9nP2ZpbGU9JytlbmNvZGVVUklDb21wb25lbnQoY3VyKSsnJm9mZnNldD0nK29mZik7CiAgICBpZighci5vaylyZXR1cm47CiAgICBjb25zdCBkPWF3YWl0IHIuanNvbigpO29mZj1kLnNpemU7CiAgICBpZihkLmxpbmVzJiZkLmxpbmVzLmxlbmd0aCl7e3Jhdz1yYXcuY29uY2F0KGQubGluZXMpO2lmKHJhdy5sZW5ndGg+NTAwMClyYXc9cmF3LnNsaWNlKC01MDAwKTthcHBseUZpbHRlcigpO319CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdHVzYmFyJykudGV4dENvbnRlbnQ9J1VwZGF0ZWQgJytuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygpOwogIH19Y2F0Y2goZSl7e2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0dXNiYXInKS50ZXh0Q29udGVudD0nRXJyb3I6ICcrZTt9fQp9fQpmdW5jdGlvbiBhcHBseUZpbHRlcigpe3sKICBjb25zdCBmdj1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZmlsdGVyJykudmFsdWUudG9Mb3dlckNhc2UoKTsKICBjb25zdCBsdj1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9ndmlldycpOwogIGNvbnN0IHJvd3M9ZnY/cmF3LmZpbHRlcihsPT5sLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoZnYpKTpyYXc7CiAgbHYuaW5uZXJIVE1MPXJvd3MubWFwKGw9Pnt7CiAgICBjb25zdCBlPWwucmVwbGFjZSgvJi9nLCcmYW1wOycpLnJlcGxhY2UoLzwvZywnJmx0OycpLnJlcGxhY2UoLz4vZywnJmd0OycpOwogICAgY29uc3QgaD1mdj9lLnJlcGxhY2UobmV3IFJlZ0V4cChmdi5yZXBsYWNlKC9bLiorP14ke3t9fSgpfFtcXF1cXFxcXS9nLCdcXFxcJCYnKSwnZ2knKSxtPT4nPHNwYW4gY2xhc3M9ImhsIj4nK20rJzwvc3Bhbj4nKTplOwogICAgcmV0dXJuICc8ZGl2IGNsYXNzPSJsbicrKGZ2JiZsLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoZnYpPycgbWF0Y2gnOicnKSsnIj4nK2grJzwvZGl2Pic7CiAgfX0pLmpvaW4oJycpOwogIGlmKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhdXRvJykuY2hlY2tlZClsdi5zY3JvbGxUb3A9bHYuc2Nyb2xsSGVpZ2h0Owp9fQppbml0KCk7Cjwvc2NyaXB0Pgo8L2JvZHk+PC9odG1sPiIiIgoKUEFHRSA9IGJ1aWxkX3BhZ2UoKQoKY2xhc3MgSGFuZGxlcihCYXNlSFRUUFJlcXVlc3RIYW5kbGVyKToKICAgIGRlZiBsb2dfbWVzc2FnZShzZWxmLCBmbXQsICphcmdzKTogcGFzcwogICAgZGVmIGRvX0dFVChzZWxmKToKICAgICAgICBwID0gc2VsZi5wYXRoLnNwbGl0KCc/JylbMF0KICAgICAgICBpZiBwIGluICgnLycsICcvaW5kZXguaHRtbCcpOgogICAgICAgICAgICBib2R5ID0gUEFHRS5lbmNvZGUoKQogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoMjAwKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCdDb250ZW50LVR5cGUnLCd0ZXh0L2h0bWw7IGNoYXJzZXQ9dXRmLTgnKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCdDb250ZW50LUxlbmd0aCcsIHN0cihsZW4oYm9keSkpKQogICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCk7IHNlbGYud2ZpbGUud3JpdGUoYm9keSkKICAgICAgICBlbGlmIHAgPT0gJy9hcGkvbG9nJzoKICAgICAgICAgICAgcSA9IHBhcnNlX3FzKHVybHBhcnNlKHNlbGYucGF0aCkucXVlcnkpCiAgICAgICAgICAgIGZuYW1lID0gb3MucGF0aC5iYXNlbmFtZShxLmdldCgnZmlsZScsWyd0bHNwcm94eS5sb2cnXSlbMF0pCiAgICAgICAgICAgIG9mZnNldCA9IGludChxLmdldCgnb2Zmc2V0JyxbJzAnXSlbMF0pCiAgICAgICAgICAgIGZwYXRoID0gb3MucGF0aC5qb2luKExPR19ESVIsIGZuYW1lKQogICAgICAgICAgICBsaW5lcyA9IFtdOyBzaXplID0gb2Zmc2V0CiAgICAgICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKGZwYXRoKToKICAgICAgICAgICAgICAgIHdpdGggb3BlbihmcGF0aCwncmInKSBhcyBmOgogICAgICAgICAgICAgICAgICAgIGYuc2VlayhvZmZzZXQpOyBjaHVuayA9IGYucmVhZCgpCiAgICAgICAgICAgICAgICAgICAgc2l6ZSA9IG9mZnNldCArIGxlbihjaHVuaykKICAgICAgICAgICAgICAgICAgICByYXdfdGV4dCA9IGNodW5rLmRlY29kZSgndXRmLTgnLCBlcnJvcnM9J3JlcGxhY2UnKQogICAgICAgICAgICAgICAgICAgIGlmIGZuYW1lLmVuZHN3aXRoKCcuanNvbicpOgogICAgICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBvcnQganNvbiBhcyBfanNvbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFyc2VkID0gX2pzb24ubG9hZHMob3BlbihmcGF0aCkucmVhZCgpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJldHR5ID0gX2pzb24uZHVtcHMocGFyc2VkLCBpbmRlbnQ9MikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzICA9IHByZXR0eS5zcGxpdGxpbmVzKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNpemUgICA9IG9zLnBhdGguZ2V0c2l6ZShmcGF0aCkKICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmVzID0gcmF3X3RleHQuc3BsaXRsaW5lcygpCiAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgbGluZXMgPSByYXdfdGV4dC5zcGxpdGxpbmVzKCkKICAgICAgICAgICAgYm9keSA9IGpzb24uZHVtcHMoeydsaW5lcyc6bGluZXMsJ3NpemUnOnNpemV9KS5lbmNvZGUoKQogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoMjAwKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCdDb250ZW50LVR5cGUnLCdhcHBsaWNhdGlvbi9qc29uJykKICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcignQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJywnKicpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKTsgc2VsZi53ZmlsZS53cml0ZShib2R5KQogICAgICAgIGVsaWYgcCA9PSAnL2FwaS9kb3dubG9hZCc6CiAgICAgICAgICAgIHEgPSBwYXJzZV9xcyh1cmxwYXJzZShzZWxmLnBhdGgpLnF1ZXJ5KQogICAgICAgICAgICBmbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUocS5nZXQoJ2ZpbGUnLFsndGxzcHJveHkubG9nJ10pWzBdKQogICAgICAgICAgICBmcGF0aCA9IG9zLnBhdGguam9pbihMT0dfRElSLCBmbmFtZSkKICAgICAgICAgICAgaWYgb3MucGF0aC5leGlzdHMoZnBhdGgpOgogICAgICAgICAgICAgICAgd2l0aCBvcGVuKGZwYXRoLCdyYicpIGFzIGY6IGRhdGEgPSBmLnJlYWQoKQogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDIwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoJ0NvbnRlbnQtVHlwZScsJ3RleHQvcGxhaW4nKQogICAgICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcignQ29udGVudC1EaXNwb3NpdGlvbicsJ2F0dGFjaG1lbnQ7IGZpbGVuYW1lPScrZm5hbWUpCiAgICAgICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCk7IHNlbGYud2ZpbGUud3JpdGUoZGF0YSkKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZSg0MDQpOyBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDA0KTsgc2VsZi5lbmRfaGVhZGVycygpCgpvcy5tYWtlZGlycyhMT0dfRElSLCBleGlzdF9vaz1UcnVlKQpwcmludChmIltsb2d2aWV3ZXJdIDAuMC4wLjA6e1BPUlR9ICBsb2dzPXtMT0dfRElSfSIpCkhUVFBTZXJ2ZXIoKCcwLjAuMC4wJywgUE9SVCksIEhhbmRsZXIpLnNlcnZlX2ZvcmV2ZXIoKQo=' | base64 -d > /opt/logviewer.py

# ---------------------------------------------------------------------------
# 6. install-ca.sh
#    Installs TLSDebug CA into:
#      (a) Debian/OS system trust store
#      (b) ~/.pki/nssdb  — where Chromium/Chrome actually looks on Linux
#      (c) Chrome profile NSS db  — belt-and-suspenders
# ---------------------------------------------------------------------------
RUN cat > /opt/install-ca.sh << 'SCRIPT'
#!/bin/bash
set -e
CA_CERT="${1:-/opt/tlsdebug/proxy-ca.crt}"
CA_NAME="TLSDebug CA"
HOME_NSS="/root/.pki/nssdb"
PROFILE_NSS="/opt/chrome-profile/nssdb"

log() { echo "[CA] $*"; }

if [ ! -f "${CA_CERT}" ]; then
    log "ERROR: cert not found at ${CA_CERT}"; exit 1
fi

log "=== Installing TLSDebug CA ==="
log "Subject : $(openssl x509 -noout -subject -in "${CA_CERT}" 2>/dev/null)"
log "Expires : $(openssl x509 -noout -enddate  -in "${CA_CERT}" 2>/dev/null)"

# ------------------------------------------------------------------
# (a) OS / system trust store
# ------------------------------------------------------------------
log "--- System trust store ---"
cp "${CA_CERT}" /usr/local/share/ca-certificates/tlsdebug.crt
update-ca-certificates --fresh
log "System store updated."

# ------------------------------------------------------------------
# (b) ~/.pki/nssdb  (THIS is where Chromium on Linux actually looks)
# ------------------------------------------------------------------
log "--- ~/.pki/nssdb (Chromium default location) ---"
mkdir -p "${HOME_NSS}"
if [ ! -f "${HOME_NSS}/cert9.db" ]; then
    certutil -N -d "sql:${HOME_NSS}" --empty-password
    log "Created new NSS db at ${HOME_NSS}"
fi
certutil -d "sql:${HOME_NSS}" -D -n "${CA_NAME}" 2>/dev/null || true
certutil -d "sql:${HOME_NSS}" -A -t "CT,C,C" -n "${CA_NAME}" -i "${CA_CERT}"
log "Installed into ${HOME_NSS}"

# Verify
if certutil -d "sql:${HOME_NSS}" -L -n "${CA_NAME}" 2>/dev/null | grep -q "CT"; then
    log "OK: ${HOME_NSS} verification passed."
else
    log "WARNING: cert not found in ${HOME_NSS} after install"
fi

# ------------------------------------------------------------------
# (c) Chrome profile NSS db (belt-and-suspenders)
# ------------------------------------------------------------------
log "--- Chrome profile NSS db ---"
mkdir -p "${PROFILE_NSS}"
if [ ! -f "${PROFILE_NSS}/cert9.db" ]; then
    certutil -N -d "sql:${PROFILE_NSS}" --empty-password
    log "Created new NSS db at ${PROFILE_NSS}"
fi
certutil -d "sql:${PROFILE_NSS}" -D -n "${CA_NAME}" 2>/dev/null || true
certutil -d "sql:${PROFILE_NSS}" -A -t "CT,C,C" -n "${CA_NAME}" -i "${CA_CERT}"
log "Installed into ${PROFILE_NSS}"

log "=== CA installation complete ==="
SCRIPT
RUN chmod +x /opt/install-ca.sh

# 7. start-chrome.sh
# ---------------------------------------------------------------------------
RUN cat > /opt/start-chrome.sh << 'SCRIPT'
#!/bin/bash
export DISPLAY="${DISPLAY:-:99}"
export HOME=/root

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"
REMOTE_DEBUG_PORT="${CHROME_REMOTE_DEBUGGING_PORT:-9222}"
START_URL="${START_URL:-https://www.google.com}"

echo "[Browser] $(browser --version 2>/dev/null || echo unknown)"
echo "[Browser] DISPLAY=${DISPLAY} proxy=${PROXY_HOST}:${PROXY_PORT}"

exec browser \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --disable-software-rasterizer \
    --use-gl=swiftshader \
    --use-angle=swiftshader \
    --enable-unsafe-swiftshader \
    --in-process-gpu \
    --disable-setuid-sandbox \
    --user-data-dir="/opt/chrome-profile" \
    --proxy-server="http://${PROXY_HOST}:${PROXY_PORT}" \
    --ignore-certificate-errors \
    --ignore-certificate-errors-spki-list \
    --test-type \
    --remote-debugging-port="${REMOTE_DEBUG_PORT}" \
    --remote-debugging-address=0.0.0.0 \
    --window-size=1920,1080 \
    --start-fullscreen \
    --kiosk \
    --disable-extensions \
    --no-first-run \
    --no-default-browser-check \
    --password-store=basic \
    --use-mock-keychain \
    --enable-logging=stderr \
    --v=1 \
    "${START_URL}" 2>&1
SCRIPT
RUN chmod +x /opt/start-chrome.sh


# ---------------------------------------------------------------------------
# 8. entrypoint.sh
# ---------------------------------------------------------------------------
RUN cat > /entrypoint.sh << 'SCRIPT'
#!/bin/bash
set -e

export HOME=/root
PROXY_PORT="${PROXY_PORT:-8080}"
VNC_PORT="${VNC_PORT:-5900}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
DISPLAY="${DISPLAY:-:99}"
# LOG_DIR is bind-mounted to ./logs/ on the host.
# CERTDIR is set to the same path so tlsproxy writes captured_tokens.json,
# session files, and the CA cert directly into the host-visible logs folder.
LOG_DIR="/var/log/tlsdebug"
CERTDIR="${LOG_DIR}"
NOVNC_WEB=$(cat /opt/novnc_path 2>/dev/null || echo "/usr/share/novnc")

mkdir -p "${LOG_DIR}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
wait_port() {
    local port=$1 label=$2 tries=${3:-30}
    for i in $(seq 1 "${tries}"); do
        if nc -z 127.0.0.1 "${port}" 2>/dev/null; then
            log "[+] ${label} ready on port ${port}."
            return 0
        fi
        sleep 0.5
    done
    log "[!] TIMEOUT waiting for ${label} on port ${port}."
    return 1
}

log "============================================"
log "  TLSDebug + Headless Chrome Container"
log "  noVNC Web UI : http://localhost:${NOVNC_PORT}"
log "  TLS Proxy    : localhost:${PROXY_PORT}"
log "  noVNC root   : ${NOVNC_WEB}"
log "============================================"

# ---- Diagnostics -----------------------------------------------------------
log "[diag] novnc web root contents:"
ls -la "${NOVNC_WEB}" 2>&1 | head -20 || log "  (none)"
log "[diag] websockify location: $(which websockify 2>/dev/null || echo NOT FOUND)"
log "[diag] x11vnc location:     $(which x11vnc 2>/dev/null || echo NOT FOUND)"
log "[diag] browser symlink:      $(which browser 2>/dev/null || echo NOT FOUND) -> $(readlink /usr/local/bin/browser 2>/dev/null || echo none)"
log "[diag] tlsproxy location:   $(which tlsproxy 2>/dev/null || echo NOT FOUND)"

# ---- 1. Xvfb ---------------------------------------------------------------
log "[*] Starting Xvfb on ${DISPLAY} ..."
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb "${DISPLAY}" \
    -screen 0 1920x1080x24 \
    -ac \
    +extension GLX \
    +extension RANDR \
    +render \
    -noreset \
    >> "${LOG_DIR}/xvfb.log" 2>&1 &
XVFB_PID=$!

log "[*] Waiting for Xvfb ..."
for i in $(seq 1 30); do
    if DISPLAY="${DISPLAY}" xdpyinfo >/dev/null 2>&1; then
        log "[+] Xvfb ready."
        break
    fi
    sleep 0.5
done
export DISPLAY="${DISPLAY}"

# ---- 2. Openbox window manager ---------------------------------------------
log "[*] Starting openbox ..."
openbox --config-file /root/.config/openbox/rc.xml --display "${DISPLAY}" >> "${LOG_DIR}/openbox.log" 2>&1 &
sleep 1

# ---- 3. TLSDebug proxy -----------------------------------------------------
log "[*] Starting TLSDebug proxy on port ${PROXY_PORT} ..."
cd "${CERTDIR}"
tlsproxy \
    -port "${PROXY_PORT}" \
    -certdir "${CERTDIR}" \
    -skip-install \
    2>&1 | tee -a "${LOG_DIR}/tlsproxy.log" &
PROXY_PID=$!

log "[*] Waiting for CA certificate ..."
for i in $(seq 1 30); do
    if [ -f "${CERTDIR}/proxy-ca.crt" ]; then
        log "[+] CA certificate ready."
        break
    fi
    sleep 1
done
# Install CA before Chrome launches — must succeed
if [ -f "${CERTDIR}/proxy-ca.crt" ]; then
    if /opt/install-ca.sh "${CERTDIR}/proxy-ca.crt"; then
        log "[+] CA trusted by OS and Chrome NSS."
    else
        log "[!] CA install failed — Chrome may show cert errors."
    fi
else
    log "[!] proxy-ca.crt missing — Chrome may show cert errors."
fi

# ---- 4. x11vnc -------------------------------------------------------------
log "[*] Starting x11vnc on port ${VNC_PORT} ..."
x11vnc \
    -display "${DISPLAY}" \
    -forever \
    -shared \
    -nopw \
    -rfbport "${VNC_PORT}" \
    -o "${LOG_DIR}/x11vnc.log" \
    -bg \
    -noipv6 \
    -xkb \
    -noxrecord \
    -noxfixes \
    -noxdamage \
    -cursor arrow \
    -wait 5 \
    -defer 5

wait_port "${VNC_PORT}" "x11vnc" 40

# ---- 5. noVNC --------------------------------------------------------------
log "[*] Starting noVNC websockify on port ${NOVNC_PORT} ..."
log "[*]   web root : ${NOVNC_WEB}"
log "[*]   target   : 127.0.0.1:${VNC_PORT}"

websockify \
    --web "${NOVNC_WEB}" \
    --heartbeat 30 \
    --log-file "${LOG_DIR}/novnc.log" \
    "${NOVNC_PORT}" \
    "127.0.0.1:${VNC_PORT}" &
NOVNC_PID=$!

wait_port "${NOVNC_PORT}" "noVNC" 40

# Confirm websockify process
log "[diag] websockify process: $(pgrep -a websockify 2>/dev/null || echo NOT RUNNING)"
log "[diag] listening ports:    $(ss -tlnp 2>/dev/null | grep -E '5900|6080|8080' || echo none)"

# ---- 6. Chrome -------------------------------------------------------------
log "[*] Starting Chrome ..."
/opt/start-chrome.sh >> "${LOG_DIR}/chrome.log" 2>&1 &
CHROME_PID=$!

# ---- 7. Log viewer on port 4040 --------------------------------------------
log "[*] Starting log viewer on port 4040 ..."
python3 /opt/logviewer.py >> "${LOG_DIR}/logviewer.log" 2>&1 &
LOGVIEWER_PID=$!
wait_port 4040 "log viewer" 20

log ""
log "[+] All services started."
log "[+] Browser (noVNC) : http://localhost:${NOVNC_PORT}"
log "[+] Log viewer      : http://localhost:4040"
log "[+] TLS proxy       : localhost:${PROXY_PORT}"
log "[+] Host logs dir   : ${LOG_DIR}  (mounted to ./logs/ on host)"
log ""

cleanup() {
    log "[*] Shutting down ..."
    kill "${CHROME_PID}" "${NOVNC_PID}" "${PROXY_PID}" "${XVFB_PID}" "${LOGVIEWER_PID}" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Stream proxy traffic to docker logs so 'docker logs -f tlsdebug' shows live traffic
tail -f "${LOG_DIR}/tlsproxy.log"
SCRIPT
RUN chmod +x /entrypoint.sh

# ---------------------------------------------------------------------------
# 9. Ports
# ---------------------------------------------------------------------------
EXPOSE 6080 5900 8080 4040 9222

WORKDIR /opt/tlsdebug
ENTRYPOINT ["/entrypoint.sh"]
