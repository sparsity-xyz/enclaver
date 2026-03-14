const express = require("express");
const axios = require("axios");
const { HttpsProxyAgent } = require("https-proxy-agent");

const app = express();
const port = Number(process.env.PORT || 8000);
const upstreamUrl = "https://news.ycombinator.com";

function buildUpstreamRequestConfig() {
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  const config = {
    timeout: 15000,
    responseType: "text",
    validateStatus: () => true,
    headers: {
      "user-agent": "hn-fetcher-example/1.0",
    },
  };

  if (!httpsProxy) {
    return config;
  }

  config.httpsAgent = new HttpsProxyAgent(httpsProxy);
  // When a custom agent is used, disable axios' own proxy handling to avoid
  // applying proxy configuration twice.
  config.proxy = false;
  return config;
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    upstream: upstreamUrl,
  });
});

app.get("/", async (_req, res) => {
  console.log(`Forwarding request to ${upstreamUrl}`);

  try {
    const upstream = await axios.get(upstreamUrl, buildUpstreamRequestConfig());
    const contentType = upstream.headers["content-type"];

    res.status(upstream.status);
    if (contentType) {
      res.set("content-type", contentType);
    }
    res.send(upstream.data);
  } catch (err) {
    console.error("Fetch failed:", err && err.stack ? err.stack : err);
    res.status(502).json({
      error: "upstream_fetch_failed",
    });
  }
});

app.listen(port, () => {
  console.log(`hn-fetcher listening on port ${port}`);
});
