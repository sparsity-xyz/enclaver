#!/bin/bash
# ---------------------------------------------------------------------------
# build-and-publish-nitro-cli.sh
#
# Build and publish the nitro-cli Docker image to AWS Public ECR.
#
# This script:
#   1. Authenticates Docker to AWS Public ECR
#   2. Creates the ECR repository if it doesn't exist
#   3. Builds a local validation image for linux/amd64
#   4. Verifies the image ships a FUSE-enabled enclave kernel
#   5. Builds the nitro-cli image for linux/amd64
#   6. Pushes the amd64 image to ECR
#
# We rebuild Nitro CLI because the stock AWS blobs do not enable FUSE in the
# enclave kernel, which means Odyn cannot mount host-backed directories through
# the hostfs file proxy. Publishing is currently limited to linux/amd64 because
# the bootstrap build is not yet reliable in the arm64 release path.
#
# Prerequisites:
#   - AWS CLI configured with appropriate credentials
#   - Docker with buildx support
#   - Permissions to push to the target ECR repository
#
# Usage:
#   ./scripts/build-and-publish-nitro-cli.sh [--tag TAG]
#
# Options:
#   --tag TAG    Tag to use for the image (default: latest)
#   --help       Show this help message
# ---------------------------------------------------------------------------

set -euo pipefail

# Configuration
REGISTRY="public.ecr.aws/d4t4u8d2"
REPO_NAME="sparsity-ai/nitro-cli"
DOCKERFILE_PATH="dockerfiles/nitro-cli.dockerfile"
TAG="${TAG:-latest}"

# Script directory for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build and publish the nitro-cli Docker image to AWS Public ECR."
    echo ""
    echo "Options:"
    echo "  --tag TAG    Tag to use for the image (default: latest)"
    echo "  --help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  TAG          Alternative way to set the image tag"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build and push with 'latest' tag"
    echo "  $0 --tag v1.4.2       # Build and push with 'v1.4.2' tag"
    echo "  TAG=dev $0            # Build and push with 'dev' tag"
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Run '$0 --help' for usage information."
            exit 1
            ;;
    esac
done

FULL_IMAGE_URI="${REGISTRY}/${REPO_NAME}"
VALIDATION_IMAGE_URI="${FULL_IMAGE_URI}:validate-${TAG}"
VALIDATION_PLATFORM="linux/amd64"
PUBLISH_PLATFORM="linux/amd64"
BUILD_CACHE_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "${BUILD_CACHE_DIR}"
}

trap cleanup EXIT

local_arch=$(uname -m)
if [[ "${local_arch}" != "x86_64" ]]; then
    log_error "nitro-cli publishing is currently supported only on x86_64 hosts."
    log_error "The published nitro-cli image is restricted to ${PUBLISH_PLATFORM}."
    exit 1
fi

log_info "Building nitro-cli image..."
log_info "  Dockerfile: ${DOCKERFILE_PATH}"
log_info "  Target: ${FULL_IMAGE_URI}:${TAG}"

# Change to repository root
cd "$REPO_ROOT"

# Check prerequisites
if ! command -v aws &> /dev/null; then
    log_error "AWS CLI is not installed. Please install it first."
    exit 1
fi

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install it first."
    exit 1
fi

if ! docker buildx version &> /dev/null; then
    log_error "Docker buildx is not available. Please install/enable it."
    exit 1
fi

# Step 1: Authenticate Docker to AWS Public ECR
log_info "Authenticating Docker to AWS Public ECR..."
aws ecr-public get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin public.ecr.aws

# Step 2: Create repository if it doesn't exist
log_info "Ensuring ECR repository exists..."
if ! aws ecr-public describe-repositories \
    --repository-names "${REPO_NAME}" \
    --region us-east-1 &> /dev/null; then
    log_info "Creating repository: ${REPO_NAME}"
    aws ecr-public create-repository \
        --repository-name "${REPO_NAME}" \
        --region us-east-1
else
    log_info "Repository already exists: ${REPO_NAME}"
fi

# Step 3: Set up buildx builder
BUILDER_NAME="nitro-cli-builder"
if ! docker buildx inspect "${BUILDER_NAME}" &> /dev/null; then
    log_info "Creating buildx builder: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --use
else
    docker buildx use "${BUILDER_NAME}"
fi

# Step 4: Build and validate the amd64 image locally
log_info "Building local validation image for ${VALIDATION_PLATFORM}..."
docker buildx build \
    --platform "${VALIDATION_PLATFORM}" \
    --file "${DOCKERFILE_PATH}" \
    --tag "${VALIDATION_IMAGE_URI}" \
    --cache-to "type=local,dest=${BUILD_CACHE_DIR},mode=max" \
    --load \
    .

log_info "Validating nitro-cli image contents..."
"${REPO_ROOT}/scripts/validate-nitro-cli-image.sh" "${VALIDATION_IMAGE_URI}"

# Step 5: Build and push the amd64 image, reusing the validated build cache so
# the expensive bootstrap kernel rebuild does not run twice in one publish flow.
log_info "Building and pushing ${PUBLISH_PLATFORM} image with cached layers..."
docker buildx build \
    --platform "${PUBLISH_PLATFORM}" \
    --file "${DOCKERFILE_PATH}" \
    --tag "${FULL_IMAGE_URI}:${TAG}" \
    --cache-from "type=local,src=${BUILD_CACHE_DIR}" \
    --push \
    .

# Step 6: Verify the push
log_info "Verifying image was pushed..."
if docker buildx imagetools inspect "${FULL_IMAGE_URI}:${TAG}" &> /dev/null; then
    log_info "✅ Successfully pushed: ${FULL_IMAGE_URI}:${TAG}"
else
    log_warn "Could not verify image. It may still be processing."
fi

# Print summary
echo ""
echo "=========================================="
echo "Image published successfully!"
echo "=========================================="
echo ""
echo "Image URI: ${FULL_IMAGE_URI}:${TAG}"
echo ""
echo "Validated local image: ${VALIDATION_IMAGE_URI}"
echo ""
