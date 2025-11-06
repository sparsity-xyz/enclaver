const express = require('express');
const axios = require('axios');
const https_proxy_agent = require("https-proxy-agent");

const app = express();
const port = 8000;

app.get('/', (req, resOuter) => {
  console.log('Request received!');
  // Only construct the proxy agent if HTTPS_PROXY is set. Passing undefined to
  // HttpsProxyAgent causes a TypeError (cannot read 'href').
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  const opts = {};

  if (httpsProxy) {
    const agent = new https_proxy_agent.HttpsProxyAgent(httpsProxy);
    opts.httpsAgent = agent;
    // when using a custom agent, disable axios' proxy option so it doesn't try
    // to use the proxy setting again
    opts.proxy = false;
  }

  axios.get('https://news.ycombinator.com', opts)
    .then((resInner) => {
      const status = resInner.status;
      const contentType = resInner.headers['content-type'];
      const data = resInner.data;

      resOuter.status(status);
      resOuter.set('content-type', contentType);
      resOuter.send(data);
    })
    .catch((err) => {
      console.error('Fetch failed:', err && err.stack ? err.stack : err);
      resOuter.status(502).send('Bad gateway');
    });
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
