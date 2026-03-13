# Building Enclaver Images

This document covers the image-building paths that exist in the repository today:

- local developer images via `scripts/build-docker-images.sh`
- release-style images via `dockerfiles/*-release.dockerfile`
- Nitro CLI image rebuilds with a FUSE-enabled enclave kernel

## Prerequisites

- Docker with `buildx`
- Rust toolchain
- `cross` for musl cross-compilation

Typical setup:

```bash
cargo install cross
docker buildx create --use
```

If `cargo install cross` fails because `cc` is missing, install a C toolchain first.

## One-command local builds

From the repository root:

```bash
./scripts/build-docker-images.sh
```

This default mode:

- currently requires an `x86_64` host
- builds `odyn` and `enclaver-run` for `x86_64-unknown-linux-musl`
- uses `dockerfiles/odyn-dev.dockerfile`
- uses `dockerfiles/sleeve-dev.dockerfile`
- produces:
  - `odyn-dev:latest`
  - `sleeve-dev:latest`

The helper is currently `x86_64`-only because the default Sleeve Dockerfiles
copy `nitro-cli` from the self-hosted Nitro CLI image, and that image is
currently published only for `linux/amd64`.

Release-style local tags:

```bash
./scripts/build-docker-images.sh --release
```

This produces:

- `odyn:latest`
- `sleeve:latest`

## What the helper script actually does

`scripts/build-docker-images.sh`:

1. maps host architecture to:
   - `x86_64` -> `x86_64-unknown-linux-musl`
   - `aarch64` -> unsupported in the default helper
2. runs:
   ```bash
   cross build --target <target> --features run_enclave,odyn [--release]
   ```
3. copies `odyn` and `enclaver-run` into a temporary Docker build context
4. builds Odyn and Sleeve images from the selected Dockerfiles

## Manual developer-image build

Example for `x86_64` debug builds:

```bash
cd enclaver
cross build --target x86_64-unknown-linux-musl --features run_enclave,odyn

tmpdir="$(mktemp -d)"
cp target/x86_64-unknown-linux-musl/debug/odyn "$tmpdir/"
docker buildx build -f ../dockerfiles/odyn-dev.dockerfile -t odyn-dev:latest "$tmpdir"

cp target/x86_64-unknown-linux-musl/debug/enclaver-run "$tmpdir/"
docker buildx build -f ../dockerfiles/sleeve-dev.dockerfile -t sleeve-dev:latest "$tmpdir"

rm -rf "$tmpdir"
```

For release binaries, switch `debug` to `release` and add `--release` to `cross build`.

## Release Dockerfiles

The release Dockerfiles are designed around the layout used by `.github/workflows/release.yaml`.

Expected artifact layout before building the currently published release images:

```text
./amd64/odyn
./amd64/enclaver-run
```

Local release-image build example:

```bash
docker buildx build \
  --file dockerfiles/odyn-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64 \
  -t odyn:local .

docker buildx build \
  --file dockerfiles/sleeve-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64 \
  -t sleeve:local .
```

How those Dockerfiles work:

- `odyn-release.dockerfile` copies `${TARGETARCH}/odyn` from the `artifacts` build context
- `sleeve-release.dockerfile` copies `${TARGETARCH}/enclaver-run` from the `artifacts` build context
- `sleeve-release.dockerfile` also copies `nitro-cli` and required runtime libraries from the default Nitro CLI image
- `odyn-release.dockerfile` is currently published only for `linux/amd64`
- `sleeve-release.dockerfile` is currently published only for `linux/amd64`

## Nitro CLI image

This repository includes `dockerfiles/nitro-cli.dockerfile`, `scripts/build-and-publish-nitro-cli.sh`, and `scripts/validate-nitro-cli-image.sh`.

Detailed background on the Nitro CLI kernel/blob rebuild flow lives in
[`docs/nitro_cli_fuse_image.md`](nitro_cli_fuse_image.md).

Build it locally:

```bash
docker buildx build -f dockerfiles/nitro-cli.dockerfile -t nitro-cli:latest .
```

Or use the helper script:

```bash
./scripts/build-and-publish-nitro-cli.sh --tag latest
```

The nitro-cli Dockerfile now rewrites the upstream kernel config in place to set `CONFIG_FUSE_FS=y` before rebuilding the official Nitro Enclaves blobs. The helper script then builds a local `linux/amd64` validation image, checks that the rebuilt enclave kernel exposes `CONFIG_FUSE_FS`, performs a smoke `nitro-cli build-enclave`, and only then pushes the `linux/amd64` image. Enclaver uses `public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest` by default.
That self-hosted Nitro CLI image is what gives Enclaver EIFs the FUSE support required for host-backed directory mounts and the hostfs file proxy.

To smoke-test the full `enclaver build` path itself, including the local Docker-context handoff to `nitro-cli build-enclave --docker-dir`, run:

```bash
cargo build --manifest-path enclaver/Cargo.toml --bin enclaver
ENCLAVER_BIN=./enclaver/target/debug/enclaver ./scripts/enclaver-build-smoke-test.sh
```

## Troubleshooting

- Missing `cross`: `cargo install cross`
- Missing `buildx`: `docker buildx create --use`
- Missing `protoc` during cross builds: provide `PROTOC` or use a build image that includes it
- On macOS, remember these images target Linux musl; build and runtime validation should happen on Linux

## Related files

- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`
- `scripts/enclaver-build-smoke-test.sh`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `.github/workflows/release.yaml`
