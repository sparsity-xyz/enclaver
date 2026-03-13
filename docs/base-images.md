# Enclaver Base Images

Enclaver uses three important images in its build and runtime flow. The defaults live in `enclaver/src/build.rs`:

- Nitro CLI: `public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest`
- Odyn: `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest`
- Sleeve: `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest`

## What each image does

### Nitro CLI image

Purpose:

- provides `nitro-cli`
- provides the runtime libraries copied into sleeve images
- is used as the build environment for `nitro-cli build-enclave`

Relevant files:

- `dockerfiles/sleeve-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `scripts/build-and-publish-nitro-cli.sh`

The repository now publishes a self-hosted `nitro-cli` image through the manual `nitro-cli.yaml` workflow, and Enclaver consumes that image by default. The nitro-cli build rewrites the upstream kernel config to set `CONFIG_FUSE_FS=y`, then replaces the stock enclave blobs with rebuilt bootstrap artifacts.
That rebuilt kernel support is what allows Odyn to mount host-backed directories through `/dev/fuse` inside the enclave. The publish flow for this image is manual and currently targets `linux/amd64` only.

### Odyn image

Purpose:

- supplies the `odyn` supervisor binary at `/usr/local/bin/odyn`
- is read at build time, then copied into the amended app image as `/sbin/odyn`

Relevant files:

- `enclaver/src/build.rs`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`

Local tags used by repository tooling:

- debug helper build: `odyn-dev:latest`
- release-style local build: `odyn:latest`

The published Odyn image is currently `linux/amd64` only to match the current
release-image publish policy.

### Sleeve image

Purpose:

- provides the host-side runtime container entrypoint `enclaver-run`
- provides `nitro-cli` and its runtime libraries
- receives `/enclave/application.eif` and `/enclave/enclaver.yaml` as appended layers during `enclaver build`

Relevant files:

- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `enclaver/src/build.rs`
- `enclaver/src/run_container.rs`

Local tags used by repository tooling:

- debug helper build: `sleeve-dev:latest`
- release-style local build: `sleeve:latest`

The published Sleeve image is currently `linux/amd64` only. Sleeve embeds
`nitro-cli` and its runtime libraries from the self-hosted Nitro CLI image, so
its published platforms currently follow the Nitro CLI image's `linux/amd64`
limit.

## How the images are used

Build time:

1. resolve the app image
2. read the Odyn binary from the Odyn image
3. amend the app image with:
   - `/etc/enclaver/enclaver.yaml`
   - `/sbin/odyn`
4. tag the amended image locally and write a tiny temporary Docker context whose `Dockerfile` is `FROM <local-tag>`
5. run `nitro-cli build-enclave --docker-dir <that-context>` inside the Nitro CLI image to produce `application.eif`
6. append `application.eif` and `enclaver.yaml` to the Sleeve image

Runtime:

- the final release image is a Sleeve image plus `/enclave/application.eif` and `/enclave/enclaver.yaml`
- `enclaver-run` reads `/enclave/enclaver.yaml` for host-side runtime behavior and uses `nitro-cli` to launch the enclave
- inside the EIF, `odyn` reads the matching manifest copy at `/etc/enclaver/enclaver.yaml`

## Local inspection commands

```bash
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest

docker image inspect public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest
docker history public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest

docker run --rm --entrypoint ls \
  public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest \
  -la /usr/bin /lib64
```

After building a release image locally:

```bash
docker inspect my-release:latest
docker history my-release:latest
docker run --rm --entrypoint ls my-release:latest -la /enclave
```

## Related files

- `enclaver/src/build.rs`
- `dockerfiles/nitro-cli.dockerfile`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`
