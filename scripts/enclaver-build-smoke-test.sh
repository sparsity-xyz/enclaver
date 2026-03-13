#!/bin/bash

set -euo pipefail

unique_suffix() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8
    else
        printf '%s-%s' "${RANDOM}" "$$"
    fi
}

TAG_SUFFIX="$(unique_suffix)"
TMP_DIR="$(mktemp -d)"
APP_DIR="${TMP_DIR}/app"
MANIFEST_PATH="${TMP_DIR}/enclaver.yaml"
BUILD_STDOUT="${TMP_DIR}/build-summary.json"
BUILD_STDERR="${TMP_DIR}/build.log"
APP_IMAGE_TAG="enclaver-build-smoke-app:${TAG_SUFFIX}"
RELEASE_IMAGE_TAG="enclaver-build-smoke-release:${TAG_SUFFIX}"
ODYN_IMAGE_TAG="enclaver-build-smoke-odyn:${TAG_SUFFIX}"
SLEEVE_IMAGE_TAG="enclaver-build-smoke-sleeve:${TAG_SUFFIX}"
# Fixture mode intentionally reuses the real published nitro-cli tag because the
# builder still resolves that default image from a fixed tag with no manifest
# override. This is acceptable on fresh CI runners; the guard below refuses to
# overwrite any pre-existing local copy.
NITRO_CLI_FIXTURE_TAG="public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest"
ENCLAVER_BIN="${ENCLAVER_BIN:-enclaver}"
ENCLAVER_SMOKE_MODE="${ENCLAVER_SMOKE_MODE:-official}"
PROBE_CONTAINER_ID=""
FIXTURE_NITRO_CLI_CREATED=0

on_exit() {
    status=$?
    if [[ ${status} -ne 0 ]]; then
        echo "--- enclaver build stdout ---" >&2
        [[ -f "${BUILD_STDOUT}" ]] && cat "${BUILD_STDOUT}" >&2
        echo "--- enclaver build stderr ---" >&2
        [[ -f "${BUILD_STDERR}" ]] && cat "${BUILD_STDERR}" >&2
    fi

    docker image rm -f \
        "${APP_IMAGE_TAG}" \
        "${RELEASE_IMAGE_TAG}" \
        "${ODYN_IMAGE_TAG}" \
        "${SLEEVE_IMAGE_TAG}" >/dev/null 2>&1 || true
    if [[ "${FIXTURE_NITRO_CLI_CREATED}" == "1" ]]; then
        docker image rm -f "${NITRO_CLI_FIXTURE_TAG}" >/dev/null 2>&1 || true
    fi
    [[ -n "${PROBE_CONTAINER_ID}" ]] && docker rm -f "${PROBE_CONTAINER_ID}" >/dev/null 2>&1 || true
    rm -rf "${TMP_DIR}"
}

trap on_exit EXIT

build_fixture_images() {
    local odyn_dir="${TMP_DIR}/odyn-fixture"
    local sleeve_dir="${TMP_DIR}/sleeve-fixture"
    local nitro_dir="${TMP_DIR}/nitro-cli-fixture"
    local nitro_rootfs_dir="${nitro_dir}/rootfs"
    local busybox_path=""

    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "fixture smoke mode currently requires a Linux host" >&2
        exit 1
    fi

    busybox_path="$(command -v busybox || true)"
    if [[ -z "${busybox_path}" ]]; then
        echo "fixture smoke mode requires a local busybox binary on Linux" >&2
        exit 1
    fi

    if docker image inspect "${NITRO_CLI_FIXTURE_TAG}" >/dev/null 2>&1; then
        echo "fixture smoke mode refuses to overwrite existing local image tag: ${NITRO_CLI_FIXTURE_TAG}" >&2
        exit 1
    fi

    mkdir -p "${odyn_dir}" "${sleeve_dir}" "${nitro_rootfs_dir}/bin" "${nitro_rootfs_dir}/usr/bin"

    cat > "${odyn_dir}/odyn" <<'EOF'
#!/bin/sh
echo fixture-odyn
EOF
    chmod +x "${odyn_dir}/odyn"

    cat > "${odyn_dir}/Dockerfile" <<'EOF'
FROM scratch
COPY odyn /usr/local/bin/odyn
CMD ["/usr/local/bin/odyn"]
EOF

    cat > "${sleeve_dir}/nitro-cli" <<'EOF'
fixture sleeve nitro-cli placeholder
EOF
    chmod +x "${sleeve_dir}/nitro-cli"

    cat > "${sleeve_dir}/Dockerfile" <<'EOF'
FROM scratch
COPY nitro-cli /bin/nitro-cli
CMD ["/bin/nitro-cli"]
EOF

    cp "${busybox_path}" "${nitro_rootfs_dir}/bin/busybox"

    cat > "${nitro_rootfs_dir}/usr/bin/nitro-cli" <<'EOF'
#!/bin/sh
set -eu

[ "${1:-}" = "build-enclave" ] || {
    echo "unsupported fixture nitro-cli command: ${1:-}" >&2
    exit 1
}

shift

docker_uri=""
docker_dir=""
output_file=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --docker-uri)
            docker_uri="${2:-}"
            shift 2
            ;;
        --docker-dir)
            docker_dir="${2:-}"
            shift 2
            ;;
        --output-file)
            output_file="${2:-}"
            shift 2
            ;;
        --signing-certificate|--private-key)
            shift 2
            ;;
        *)
            echo "unexpected fixture nitro-cli arg: $1" >&2
            exit 1
            ;;
    esac
done

[ -n "${docker_uri}" ] || { echo "missing --docker-uri" >&2; exit 1; }
[ -n "${docker_dir}" ] || { echo "missing --docker-dir" >&2; exit 1; }
[ -n "${output_file}" ] || { echo "missing --output-file" >&2; exit 1; }
[ -f "${docker_dir}/Dockerfile" ] || { echo "missing Dockerfile under ${docker_dir}" >&2; exit 1; }

read -r first_line < "${docker_dir}/Dockerfile"
if ! printf '%s\n' "${first_line}" | grep -Eq '^FROM enclaver-intermediate-[^[:space:]]+:latest$'; then
    echo "unexpected docker context line: ${first_line}" >&2
    exit 1
fi

printf 'fixture EIF for %s\n' "${docker_uri}" > "${output_file}"
printf '{"Measurements":{"PCR0":"fixture-pcr0","PCR1":"fixture-pcr1","PCR2":"fixture-pcr2"}}'
EOF
    chmod +x "${nitro_rootfs_dir}/usr/bin/nitro-cli"

    cat > "${nitro_dir}/Dockerfile" <<'EOF'
FROM scratch
COPY rootfs/ /
WORKDIR /build
ENTRYPOINT ["/bin/busybox", "sh", "/usr/bin/nitro-cli"]
EOF

    docker build -t "${ODYN_IMAGE_TAG}" "${odyn_dir}" >/dev/null
    docker build -t "${SLEEVE_IMAGE_TAG}" "${sleeve_dir}" >/dev/null
    docker build -t "${NITRO_CLI_FIXTURE_TAG}" "${nitro_dir}" >/dev/null
    FIXTURE_NITRO_CLI_CREATED=1
}

write_manifest() {
    cat > "${MANIFEST_PATH}" <<EOF
version: "v1"
name: "enclaver-build-smoke"
target: "${RELEASE_IMAGE_TAG}"
sources:
  app: "${APP_IMAGE_TAG}"
EOF

    if [[ "${ENCLAVER_SMOKE_MODE}" == "fixture" ]]; then
        cat >> "${MANIFEST_PATH}" <<EOF
  odyn: "${ODYN_IMAGE_TAG}"
  sleeve: "${SLEEVE_IMAGE_TAG}"
EOF
    fi
}

if [[ -x "${ENCLAVER_BIN}" ]]; then
    true
elif ! command -v "${ENCLAVER_BIN}" >/dev/null 2>&1; then
    echo "enclaver binary not found: ${ENCLAVER_BIN}" >&2
    exit 1
fi

case "${ENCLAVER_SMOKE_MODE}" in
    official|fixture)
        ;;
    *)
        echo "unsupported ENCLAVER_SMOKE_MODE: ${ENCLAVER_SMOKE_MODE}" >&2
        exit 1
        ;;
esac

docker info >/dev/null
mkdir -p "${APP_DIR}"

cat > "${APP_DIR}/Dockerfile" <<'EOF'
FROM scratch
CMD ["/smoke-test-placeholder"]
EOF

if [[ "${ENCLAVER_SMOKE_MODE}" == "fixture" ]]; then
    echo "Preparing local fixture images for smoke mode"
    build_fixture_images
fi

write_manifest

echo "[1/5] building app image ${APP_IMAGE_TAG}"
docker build -t "${APP_IMAGE_TAG}" "${APP_DIR}" >/dev/null

echo "[2/5] running enclaver build"
"${ENCLAVER_BIN}" -v build -f "${MANIFEST_PATH}" >"${BUILD_STDOUT}" 2>"${BUILD_STDERR}"

echo "[3/5] verifying build summary and docker-dir path"
grep -q '"Measurements"' "${BUILD_STDOUT}"
grep -q '"PCR0"' "${BUILD_STDOUT}"
grep -q '"Image"' "${BUILD_STDOUT}"
grep -q 'wrote docker context' "${BUILD_STDERR}"
grep -q 'started nitro-cli build-eif in container' "${BUILD_STDERR}"

echo "[4/5] verifying release image ${RELEASE_IMAGE_TAG}"
docker image inspect "${RELEASE_IMAGE_TAG}" >/dev/null
PROBE_CONTAINER_ID="$(docker create "${RELEASE_IMAGE_TAG}")"
docker cp "${PROBE_CONTAINER_ID}:/enclave/application.eif" "${TMP_DIR}/application.eif"
docker cp "${PROBE_CONTAINER_ID}:/enclave/enclaver.yaml" "${TMP_DIR}/embedded-enclaver.yaml"
docker cp "${PROBE_CONTAINER_ID}:/bin/nitro-cli" "${TMP_DIR}/nitro-cli"
test -s "${TMP_DIR}/application.eif"
test -s "${TMP_DIR}/embedded-enclaver.yaml"
test -x "${TMP_DIR}/nitro-cli"
grep -q 'name: "enclaver-build-smoke"' "${TMP_DIR}/embedded-enclaver.yaml"

echo "[5/5] enclaver build smoke test passed"
