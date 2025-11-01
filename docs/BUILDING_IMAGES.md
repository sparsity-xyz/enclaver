## Building the base images (nitro-cli/runtimebase, odyn, sleeve)

This document shows the exact local steps used by the repository to build the development base images used by Enclaver: the `odyn` supervisor image and the `enclaver-wrapper-base` (sleeve) dev image. It also explains how the release Dockerfiles are intended to be used in a multi-stage pipeline.

Prerequisites
- Docker with BuildKit / buildx enabled (or an alternative builder that supports multi-arch and build stages).
- Rust toolchain and musl targets available for your architecture (the helper script chooses a target based on `uname -m`).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo install cross

sudo apt install protobuf-compiler
```

Quick (one-command) local build

Run this from the repository root:

```bash
./scripts/build-dev-images.sh
```

What the script does
- Compiles `odyn` and `enclaver-run` for your machine architecture (using musl targets).
- Creates a temporary docker build context containing the compiled binaries.
- Builds the dev images using these Dockerfiles:
  - `build/dockerfiles/odyn-dev.dockerfile`
  - `build/dockerfiles/runtimebase-dev.dockerfile`

After running the helper, you will have these images locally:

- `odyn-dev:latest` — development odyn image that contains the compiled `odyn` binary at `/usr/local/bin/odyn`.
- `enclaver-wrapper-base:latest` — development sleeve image that contains `enclaver-run` as the container entrypoint and uses the upstream `nitro-cli` image as the source for runtime libs and `/usr/bin/nitro-cli`.

Manual steps (if you want to run each step yourself)

1) Build the Rust binaries (example for x86_64):

```bash
cd enclaver
cargo build --target x86_64-unknown-linux-musl --features run_enclave,odyn
```

2) Build `odyn-dev` (create a small context and build):

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/debug/odyn "${docker_build_dir}/"
docker buildx build \
  -f build/dockerfiles/odyn-dev.dockerfile \
  -t odyn-dev:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

3) Build `enclaver-wrapper-base` (dev):

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/debug/enclaver-run "${docker_build_dir}/"
docker buildx build \
  -f build/dockerfiles/runtimebase-dev.dockerfile \
  -t enclaver-wrapper-base:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

Notes about release Dockerfiles
- The release Dockerfiles are written for multi-stage CI builds where an `artifacts` stage provides `${TARGETARCH}/odyn` and `${TARGETARCH}/enclaver-run`.
  - `build/dockerfiles/runtimebase.dockerfile` uses `FROM public.ecr.aws/.../nitro-cli:latest AS nitro_cli` to copy necessary runtime libraries and `/usr/bin/nitro-cli` into the final image stage. It then expects an `artifacts` stage with `${TARGETARCH}/enclaver-run`.
  - `build/dockerfiles/odyn-release.dockerfile` similarly expects `${TARGETARCH}/odyn` from the `artifacts` stage.

If you want to produce release images locally, you need to create a multi-stage build that defines the `artifacts` stage (for example, using a small Dockerfile or `docker buildx build` with an appropriate context and stages).

About nitro-cli
- The `nitro-cli` image is NOT included in this repository. The runtime Dockerfiles rely on the public image:

```
public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
```

If you need to rebuild nitro-cli from source, obtain the upstream sources and build/publish that image separately.

Tips & troubleshooting
- If `docker buildx` fails, ensure you have BuildKit enabled. On Docker Desktop, enable experimental features or create a buildx builder:

```bash
docker buildx create --use
```

- On macOS with Apple Silicon, ensure you build for the correct `--platform` or run the helper script from an x86_64 runner if you need x86 images.

Questions or next steps
- I can add CI-ready multi-arch Docker build examples or a release `Makefile` if you'd like.
