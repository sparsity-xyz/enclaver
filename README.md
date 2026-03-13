<p align="center">
  <img src="docs/img/enclaver-logo-color.png" width="350" />
</p>


Enclaver is an open source toolkit that simplifies packaging and running applications inside [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). It handles the complexity of enclave networking (ingress/egress proxies), cryptographic attestation, secure key management (KMS integration), host-backed directory mounts, and application lifecycle management, so you can focus on building your application.

This is the **Sparsity edition** of Enclaver. It significantly extends the original project with new enclave runtime capabilities, including a built-in Internal API, Ethereum signing, P-384 ECDH encryption, S3-backed storage, trustless Helios RPC, host-backed directory mounts, and KMS-backed key management. See [enclaver-io/enclaver](https://github.com/enclaver-io/enclaver) for the original project.

## Enclaver Highlights

- **Secure Internal API**: Gives enclave apps built-in APIs for attestation, randomness, signing, encryption, and storage operations, so application code can call localhost HTTP endpoints instead of integrating the AWS NSM SDK directly. See [Internal API Reference](docs/internal_api.md) and [Internal API Mock Service](docs/internal_api_mockup.md).
- **Ingress and egress control**: Routes inbound traffic into the enclave and outbound HTTP/HTTPS traffic through explicit proxy and policy layers. See [Enclaver CLI Reference](docs/enclaver-cli.md), [Port Handling](docs/port_handling.md), and [HTTP(S) Proxy Support Guidance](docs/http_proxy_support_guidance_for_enclave_applications.md).
- **Host-backed storage**: Exposes host-backed directory mounts inside the enclave as normal filesystem paths for application code. See [Host-Backed Directory Mounts Guide](docs/host_backed_mounts_design.md).
- **Runtime supervision**: Starts the app, streams logs, reports exit status, and keeps the enclave wall clock synchronized with the host. See [Odyn User Guide](docs/odyn.md), [Odyn Implementation Details](docs/odyn_details.md), and [Clock Drift & Time Sync](docs/nitro_enclave_clock_drift.md).
- **Ethereum signing**: Adds secp256k1-based signing flows for enclave applications and internal APIs. See [Internal API Reference](docs/internal_api.md).
- **Trustless Helios RPC**: Runs Helios light-client RPC inside the enclave for Ethereum and OP Stack workloads. See [Helios RPC Integration](docs/helios_rpc.md).
- **S3-backed storage**: Supports encrypted object storage flows for enclave applications. See [Internal API Reference](docs/internal_api.md).
- **KMS-backed key management**: Integrates external KMS-backed signing and derivation flows into the enclave runtime. See [Internal API Reference](docs/internal_api.md).

## Enclaver Runtime Architecture

The diagram below shows the runtime component relationships across the host container, the enclave, Odyn, and the main integrations.

For architecture details, see [Runtime Architecture](docs/architecture.md) and [Detailed Architecture](docs/enclaver-architecture.md).

![Enclaver runtime architecture](docs/img/diagram-enclaver-components.svg)

## Installation

Run this command to install the latest version of the `enclaver` CLI tool:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/sparsity-xyz/enclaver/refs/heads/sparsity/install.sh)"
```

## Quick Start

See [examples/hn-fetcher/readme.md](examples/hn-fetcher/readme.md) for a quick start example of building and running an enclave application with Enclaver.

For runtime configuration and feature-specific guides, use the links in the documentation section below.

## Important: HTTP(S) Proxy Support for Enclave Apps

Applications running **inside the enclave** have no direct outbound network access. Any external HTTP/HTTPS traffic must go through Enclaver/Odyn's egress proxy.

- Your application (and the HTTP client library it uses) **must** support proxy routing via `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` (or be explicitly configured to use a proxy).
- Some popular client APIs intentionally **ignore** these environment variables by default (e.g. Node.js `fetch` / undici without a proxy agent). In that case the app may work outside the enclave but **fail inside**.

See [docs/http_proxy_support_guidance_for_enclave_applications.md](docs/http_proxy_support_guidance_for_enclave_applications.md) for language/library-specific guidance and common pitfalls.

## Documentation

Core feature docs are linked from [Enclaver Highlights](#enclaver-highlights). Additional references:

- [enclaver.yaml Reference](docs/enclaver.yaml) — Complete manifest configuration with parameter usage annotations
- [Base Images](docs/base-images.md) — What the odyn / sleeve base images contain and how to inspect them
- [Building Images](docs/BUILDING_IMAGES.md) — Local build flow for odyn, sleeve, and nitro-cli images
- [VSOCK Runtime Model](docs/vsock_runtime.md) — How CID-derived VSOCK ports work, including multiple Enclaver instances on one EC2
- [Nitro CLI FUSE Image](docs/nitro_cli_fuse_image.md) — Why and how the Nitro CLI image rebuilds enclave blobs with FUSE enabled
- [CI and Release Workflows](docs/ci.md) — How repository CI and release pipelines are structured


## Container and EIF Layout

The ASCII view below keeps the original file/layout-oriented perspective: what the release image contains, how `enclaver-run` launches the EIF, and what is embedded inside the enclave image.

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Docker Image (release) - runs as a single container                          │
│                                                                              │
│  entrypoint: /usr/local/bin/enclaver-run                                     │
│  includes:                                                                   │
│    - /bin/nitro-cli                                                          │
│    - /enclave/enclaver.yaml   (unified config)                               │
│    - /enclave/application.eif                                                │
│                                                                              │
│  Image layers (top -> bottom):                                               │
│    [L3] /enclave/application.eif                                             │
│    [L2] /enclave/enclaver.yaml                                               │
│    [L1] Sleeve image (contains enclaver-run, nitro-cli)                      │
│                                                                              │
│  Runtime control flow:                                                       │
│    enclaver-run --> nitro-cli run-enclave --eif /enclave/application.eif     │
│                  \-> passes config from /enclave/enclaver.yaml to enclave    │
└──────────────────────────────────────────────────────────────────────────────┘

                     | launches enclave with EIF
                     v
┌─────────────────────────── Enclave (application.eif) ────────────────────────┐
│ /etc/enclaver/enclaver.yaml (config, also inside EIF)                        │
│                                                                              │
│ /sbin/odyn (supervisor)                                                      │
│   Runtime services                                                           │
│   - launcher:   start and monitor the application                            │
│   - ingress:    inbound traffic --> app                                      │
│   - egress:     app --> outbound traffic                                     │
│   - clock-sync: keep enclave wall clock aligned with host time               │
│   - helios:     trustless Ethereum / OP Stack light client RPC               │
│   - console:    collect app stdout/stderr --> container logs                 │
│                                                                              │
│   Internal API (`/v1/*`)                                                     │
│   - core:       attestation, signing, random                                 │
│   - encryption: `/v1/encryption/*` (P-384 ECDH)                              │
│   - storage:    `/v1/s3/*` persistent storage integration                    │
│   - kms:        `/v1/kms/*` + `/v1/app-wallet/*` backed by Nova KMS          │
│                                                                              │
│ [User Application] (started and supervised by odyn)                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

Data paths overview:

- External clients -> container networking -> `odyn.ingress` -> app
- App -> `odyn.egress` -> container networking -> external services
- `odyn.clock-sync` <-> host vsock time server <-> host wall clock
- `odyn` Internal API (`/v1/kms/*`) <-> Nova KMS cluster via registry discovery
- App stdout/stderr -> `odyn.console` -> Docker container logs
