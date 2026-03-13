#!/bin/bash

set -euo pipefail

TMP_DIR="$(mktemp -d)"
APP_DIR="${TMP_DIR}/app"
MANIFEST_PATH="${TMP_DIR}/enclaver.yaml"
BUILD_STDOUT="${TMP_DIR}/build-summary.json"
BUILD_STDERR="${TMP_DIR}/build.log"
APP_IMAGE_TAG="enclaver-build-smoke-app:${RANDOM}-$$"
RELEASE_IMAGE_TAG="enclaver-build-smoke-release:${RANDOM}-$$"
ENCLAVER_BIN="${ENCLAVER_BIN:-enclaver}"
PROBE_CONTAINER_ID=""

on_exit() {
    status=$?
    if [[ ${status} -ne 0 ]]; then
        echo "--- enclaver build stdout ---" >&2
        [[ -f "${BUILD_STDOUT}" ]] && cat "${BUILD_STDOUT}" >&2
        echo "--- enclaver build stderr ---" >&2
        [[ -f "${BUILD_STDERR}" ]] && cat "${BUILD_STDERR}" >&2
    fi

    docker image rm -f "${APP_IMAGE_TAG}" "${RELEASE_IMAGE_TAG}" >/dev/null 2>&1 || true
    [[ -n "${PROBE_CONTAINER_ID}" ]] && docker rm -f "${PROBE_CONTAINER_ID}" >/dev/null 2>&1 || true
    rm -rf "${TMP_DIR}"
}

trap on_exit EXIT

if [[ -x "${ENCLAVER_BIN}" ]]; then
    true
elif ! command -v "${ENCLAVER_BIN}" >/dev/null 2>&1; then
    echo "enclaver binary not found: ${ENCLAVER_BIN}" >&2
    exit 1
fi

docker info >/dev/null
mkdir -p "${APP_DIR}"

cat > "${APP_DIR}/Dockerfile" <<'EOF'
FROM scratch
CMD ["/smoke-test-placeholder"]
EOF

cat > "${MANIFEST_PATH}" <<EOF
version: "v1"
name: "enclaver-build-smoke"
target: "${RELEASE_IMAGE_TAG}"
sources:
  app: "${APP_IMAGE_TAG}"
EOF

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
