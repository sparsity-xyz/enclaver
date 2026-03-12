# Building A FUSE-Enabled Nitro CLI Image

This document explains why Enclaver rebuilds the Nitro CLI image, where the
original enclave kernel blobs come from, how the kernel config is modified to
enable FUSE, and how the rebuilt blobs are swapped into the final image.

## Why We Do This

Enclaver supports host-backed directory mounts inside the enclave. This is the
same capability Nova Platform describes as a Host-Backed Temporary Directory
Mount. In Enclaver, the same mechanism can be temporary or persistent depending
on whether you reuse the bound host state directory across runs.

That flow depends on FUSE being available inside the EIF kernel so `odyn` can
mount host-backed storage through `/dev/fuse`.

The stock Nitro CLI packages ship prebuilt enclave blobs whose kernel config
does not enable `CONFIG_FUSE_FS`. If we build EIFs from those defaults, the
resulting enclave boots without FUSE support and the hostfs file proxy cannot
be mounted inside the enclave.

Because `nitro-cli build-enclave` reads its kernel and bootstrap artifacts from
the Nitro CLI image itself, the fix has to happen in the Nitro CLI image build
pipeline, before EIFs are generated.

## Where The Original Blobs Come From

The Nitro CLI image installs these Amazon Linux packages:

- `aws-nitro-enclaves-cli`
- `aws-nitro-enclaves-cli-devel`

The main CLI package provides user-facing tools such as:

- `/usr/bin/nitro-cli`
- `/usr/bin/vsock-proxy`
- `/usr/bin/nitro-enclaves-allocator`

The `-devel` package provides the prebuilt enclave blobs used by
`nitro-cli build-enclave`. Those files are stored under:

```text
/usr/share/nitro_enclaves/blobs/
```

For `x86_64`, the important files are:

- `bzImage`
- `bzImage.config`
- `cmdline`
- `init`
- `linuxkit`
- `nsm.ko`

For `aarch64`, the same role is served by:

- `Image`
- `Image.config`
- `cmdline`
- `init`
- `linuxkit`
- `nsm.ko`

These are the exact inputs Nitro CLI uses when building an EIF.

## What Nitro CLI Reads During `build-enclave`

The Nitro CLI `build-enclave` implementation reads:

- the current-architecture kernel image from `/usr/share/nitro_enclaves/blobs`
- the matching kernel config from the same directory
- `cmdline`
- `init`
- `linuxkit`
- `nsm.ko`

So the Nitro CLI image is not just a wrapper around the `nitro-cli` binary. It
also defines the default kernel and bootstrap environment that every EIF build
will embed.

## How We Rebuild The Kernel Blobs

The rebuild happens in `dockerfiles/nitro-cli.dockerfile`.

The first stage clones the official
`aws-nitro-enclaves-sdk-bootstrap` repository and runs:

```bash
nix-build -A all
```

That upstream repository contains the kernel build definitions and the source
configs used to produce the enclave blobs. Before running `nix-build`, we patch
the upstream kernel config files in place:

- `kernel/microvm-kernel-config-x86_64`
- `kernel/microvm-kernel-config-aarch64`

The Dockerfile rewrites `CONFIG_FUSE_FS` to `y` in both files. It handles the
two upstream shapes that may appear:

- `# CONFIG_FUSE_FS is not set`
- `CONFIG_FUSE_FS=<value>`

and normalizes either one to:

```text
CONFIG_FUSE_FS=y
```

That means the kernel we rebuild is still the upstream Nitro Enclaves bootstrap
kernel, but with one explicit config override applied before compilation.

## How The Rebuilt Blobs Replace The Original Ones

After the bootstrap stage finishes, the Dockerfile installs the Amazon Linux
Nitro CLI packages as usual. At that point the image already contains the stock
package-provided blobs under:

```text
/usr/share/nitro_enclaves/blobs/
```

The Dockerfile then:

1. copies the rebuilt artifacts from the bootstrap stage into `/tmp/nitro-bootstrap`
2. selects `x86_64` or `aarch64` based on `uname -m`
3. removes the original package-provided blobs
4. copies the rebuilt blobs into `/usr/share/nitro_enclaves/blobs/`
5. verifies that the expected files exist
6. verifies that the installed kernel config now contains `CONFIG_FUSE_FS=y` or `m`

This is the point where the image stops using AWS's stock prebuilt blobs and
starts using the rebuilt FUSE-enabled ones.

## End-To-End Build Flow

The full flow for producing the final image is:

1. build the upstream Nitro Enclaves bootstrap artifacts with FUSE enabled in the kernel config
2. install `aws-nitro-enclaves-cli` and `aws-nitro-enclaves-cli-devel`
3. replace `/usr/share/nitro_enclaves/blobs/*` with the rebuilt artifacts
4. build the final Nitro CLI Docker image
5. validate the image with `scripts/validate-nitro-cli-image.sh`
6. optionally publish the image with `scripts/build-and-publish-nitro-cli.sh` or the manual GitHub workflow

The validation script checks two things:

- the rebuilt blob set is present and the installed kernel config exposes `CONFIG_FUSE_FS`
- the image can complete a smoke `nitro-cli build-enclave` and produce an EIF

## Local Build Commands

The commands below assume the current working directory is the repository root.

Build the image locally:

```bash
docker buildx build -f dockerfiles/nitro-cli.dockerfile -t nitro-cli:latest .
```

Validate it locally:

```bash
scripts/validate-nitro-cli-image.sh nitro-cli:latest
```

Build and publish with validation:

```bash
scripts/build-and-publish-nitro-cli.sh --tag latest
```

## Publishing Model

The repository does not publish Nitro CLI from the main release workflow.

Nitro CLI is published only when explicitly requested, through:

- `scripts/build-and-publish-nitro-cli.sh`
- `.github/workflows/nitro-cli.yaml`

That keeps the normal release path small while still allowing us to refresh the
Nitro CLI image whenever we intentionally update the bootstrap kernel or its
config. The current publish path is intentionally limited to `linux/amd64`;
`arm64` publishing remains disabled until the bootstrap build is reliable in
that environment.

## Files To Inspect

- `dockerfiles/nitro-cli.dockerfile`
- `scripts/validate-nitro-cli-image.sh`
- `scripts/build-and-publish-nitro-cli.sh`
- `.github/workflows/nitro-cli.yaml`
