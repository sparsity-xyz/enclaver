#!/bin/bash

set -euo pipefail

IMAGE_REF="${1:-}"
SMOKE_TAG="nitro-cli-smoke-app:${RANDOM}-$$"
SCRIPT_TMPDIR="$(mktemp -d)"

cleanup() {
    docker image rm -f "${SMOKE_TAG}" >/dev/null 2>&1 || true
    rm -rf "${SCRIPT_TMPDIR}"
}

trap cleanup EXIT

if [[ -z "${IMAGE_REF}" ]]; then
    echo "Usage: $0 <image-ref>" >&2
    exit 1
fi

cat > "${SCRIPT_TMPDIR}/Dockerfile" <<'EOF'
FROM public.ecr.aws/docker/library/alpine:3.20
CMD ["echo", "nitro-cli smoke test"]
EOF

docker build -t "${SMOKE_TAG}" "${SCRIPT_TMPDIR}" >/dev/null

docker run --rm --entrypoint /bin/bash "${IMAGE_REF}" -lc '
set -euo pipefail

arch="$(uname -m)"
blobs_dir="/usr/share/nitro_enclaves/blobs"

case "${arch}" in
    x86_64)
        kernel_path="${blobs_dir}/bzImage"
        kernel_cfg="${blobs_dir}/bzImage.config"
        ;;
    aarch64)
        kernel_path="${blobs_dir}/Image"
        kernel_cfg="${blobs_dir}/Image.config"
        ;;
    *)
        echo "unsupported architecture: ${arch}" >&2
        exit 1
        ;;
esac

for required_path in \
    /usr/bin/nitro-cli \
    "${blobs_dir}/init" \
    "${blobs_dir}/linuxkit" \
    "${blobs_dir}/cmdline" \
    "${blobs_dir}/nsm.ko" \
    "${kernel_path}" \
    "${kernel_cfg}"
do
    test -s "${required_path}"
done

grep -Eq "^CONFIG_FUSE_FS=(y|m)$" "${kernel_cfg}"
'

mkdir -p "${SCRIPT_TMPDIR}/output"

docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${SCRIPT_TMPDIR}/output:/build" \
    "${IMAGE_REF}" \
    build-enclave \
    --docker-uri "${SMOKE_TAG}" \
    --output-file /build/smoke.eif >/dev/null

test -s "${SCRIPT_TMPDIR}/output/smoke.eif"
