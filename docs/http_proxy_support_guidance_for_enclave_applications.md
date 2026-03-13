# HTTP(S) Proxy Support Guidance for Enclave Applications

## Scope and assumptions

- applications run inside an enclave
- Enclaver's built-in outbound path is an HTTP(S) proxy, not arbitrary raw TCP egress
- when `egress.allow` is non-empty, Odyn sets:
  - `http_proxy`
  - `https_proxy`
  - `HTTP_PROXY`
  - `HTTPS_PROXY`
  - `no_proxy`
  - `NO_PROXY`
- `no_proxy` and `NO_PROXY` are currently `localhost,127.0.0.1`

This document intentionally focuses on Enclaver's runtime contract, not on an
exhaustive survey of every third-party HTTP library.

## Runtime contract

For outbound HTTP/HTTPS to work inside the enclave:

- your client stack must support HTTP proxying
- it must either honor the proxy environment variables above or be configured explicitly to use `http://127.0.0.1:<egress.proxy_port>`
- enclave-local traffic such as `127.0.0.1:<api.listen_port>` must stay direct instead of being sent through the proxy
- the destination host must still pass the manifest's `egress.allow` / `egress.deny` policy

If a client ignores proxy configuration, it may work outside the enclave but
fail once the same code runs inside the enclave.

## What to verify in your application

- whether the library supports HTTP proxying for both HTTP and HTTPS requests
- whether env-based proxy configuration is enough, or whether your code must attach an explicit transport, connector, or agent
- whether custom transport code preserves proxy configuration instead of silently dropping it
- whether localhost traffic bypasses the proxy as intended
- whether startup checks fail fast when the proxy path or egress policy blocks a required dependency

## Repo-backed example

The repo's `examples/hn-fetcher/app.js` reads `HTTPS_PROXY` / `https_proxy`
and, when present, constructs an explicit proxy-aware agent before making
outbound requests. Use that style when your chosen client stack does not
automatically pick up proxy environment variables.

## Suggested startup self-tests

- request one allowed external URL through the same application HTTP client used in production
- request one enclave-local URL such as `http://127.0.0.1:<api_port>/v1/eth/address` and confirm it is still reachable locally
- fail startup early if either path behaves unexpectedly

## Common failure modes

- the manifest does not allow the destination host
- the client ignores proxy configuration
- custom transport or agent code accidentally removes proxy behavior
- localhost traffic is incorrectly sent through the proxy
- the application assumes arbitrary outbound TCP, but Enclaver only provides documented HTTP/HTTPS proxy egress

## Final guidance

Use an outbound HTTP client stack only when you have verified one of these two
behaviors:

- it correctly honors the proxy environment variables that Odyn sets
- your application configures the proxy explicitly

Anything else is outside Enclaver's documented outbound contract.
