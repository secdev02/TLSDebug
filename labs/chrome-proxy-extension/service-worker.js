const DEFAULT_PROXY = Object.freeze({
  host: "127.0.0.1",
  port: 8080,
});

async function configureProxy() {
  const { proxyHost, proxyPort } = await chrome.storage.local.get({
    proxyHost: DEFAULT_PROXY.host,
    proxyPort: DEFAULT_PROXY.port,
  });

  const port = Number(proxyPort);
  if (!proxyHost || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid TLSDebug proxy endpoint: ${proxyHost}:${proxyPort}`);
  }

  await chrome.proxy.settings.set({
    scope: "regular",
    value: {
      mode: "fixed_servers",
      rules: {
        singleProxy: {
          scheme: "http",
          host: proxyHost,
          port,
        },
        // Chrome normally bypasses loopback addresses. This special rule
        // removes that implicit bypass so 127.0.0.1:8080 can be the proxy.
        bypassList: ["<-loopback>"],
      },
    },
  });

  console.info(`TLSDebug proxy configured at ${proxyHost}:${port}`);
}

chrome.runtime.onInstalled.addListener(() => {
  configureProxy().catch(console.error);
});

chrome.runtime.onStartup.addListener(() => {
  configureProxy().catch(console.error);
});

configureProxy().catch(console.error);
