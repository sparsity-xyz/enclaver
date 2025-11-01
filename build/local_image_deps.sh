#!/bin/bash

set -eu

# ---------------------------------------------------------------------------
# local_image_deps.sh - developer helper to build dev Docker images with
#                      enclave binaries (odyn, enclaver-run)
#
# High-level goal:
#   Build Rust artifacts for the selected musl target, collect resulting
#   binaries into a temporary docker build context and produce two dev
#   images used by the project.
#
# Steps (what the script does) and details
#  0) Preconditions
#     - Docker (with buildx) available when building images
#     - Either 'cross' installed (recommended) OR host has musl cross toolchain
#       (e.g. x86_64-linux-musl-gcc) available
#     - curl and unzip available if the script needs to download protoc (earlier
#       versions of this script attempted that). If you rely on protobufs at
#       build time, ensure protoc is available inside the build environment.
#
#  1) Detect local architecture and map it to a Rust musl target.
#     - Command used: uname -m
#     - Example mapping: x86_64 -> x86_64-unknown-linux-musl
#     - Result: the variable $rust_target (strings like x86_64-unknown-linux-musl)
#
#  2) Compute important paths and Docker tag names.
#     - Key variables populated:
#         enclaver_dir       -> project/enclaver directory (script base)
#         rust_target_dir    -> ./target/${rust_target}/debug (where artifacts appear)
#         docker_build_dir   -> temporary directory used for docker build context
#         odyn_tag           -> odyn-dev:latest
#         wrapper_base_tag   -> enclaver-wrapper-base:latest
#
#  3) Ensure host has necessary C cross-compiler for musl target (if building
#     locally) OR prefer running builds with 'cross'.
#     - Why: some crates (aws-lc-sys, other C bindings) compile C code and require
#       a target cross-compiler like x86_64-linux-musl-gcc to be on PATH.
#     - What script does: tries to detect the expected target compiler name
#       (e.g. x86_64-linux-musl-gcc) and if missing and apt-get is present, it
#       attempts to install `musl-tools` via sudo. If automatic install isn't
#       possible it prints instructions and exits.
#     - Environment variables exported for build scripts:
#         CC_x86_64_unknown_linux_musl, CC_x86_64-unknown-linux-musl, CC
#
#  4) Build Rust artifacts for the target
#     - Prefer using: cross build --target ${rust_target} --features run_enclave,odyn
#         * cross runs the build inside a container and usually contains the
#           required tooling for musl targets.
#     - Fallback: cargo build --target ${rust_target} --features run_enclave,odyn
#         * Only works if the host has the required musl cross toolchain
#
#     Expected results:
#       - After success, binaries should exist at:
#           ./target/${rust_target}/debug/odyn
#           ./target/${rust_target}/debug/enclaver-run
#       - Build failures commonly occur because of missing `protoc` or missing
#         musl C compiler. See troubleshooting below.
#
#  5) Copy built binaries into a temporary docker build context
#     - Commands used (example):
#         cp ${rust_target_dir}/odyn ${docker_build_dir}/
#         cp ${rust_target_dir}/enclaver-run ${docker_build_dir}/
#     - Result: docker build context contains the runtime executables used by
#       the Dockerfiles.
#
#  6) Build Docker images using docker buildx
#     - Example commands:
#         docker buildx build -f ../build/dockerfiles/odyn-dev.dockerfile -t ${odyn_tag} ${docker_build_dir}
#         docker buildx build -f ../build/dockerfiles/runtimebase-dev.dockerfile -t ${wrapper_base_tag} ${docker_build_dir}
#
#  7) Output
#     - The script prints a snippet to merge into `enclaver.yaml` that references
#       the built dev images (odyn-dev:latest and enclaver-wrapper-base:latest)
#
# Troubleshooting tips
#  - Missing protoc/protobuf errors (prost-build):
#      * Ensure `protoc` is available to the build container. One approach is to
#        place an executable `protoc` under `enclaver/build/protoc/protoc` and
#        set PROTOC to /project/enclaver/build/protoc/protoc when building with
#        `cross` (the script previously included logic to do this). Alternatively
#        install `protobuf-compiler` on Debian: `sudo apt-get install -y protobuf-compiler`.
#  - Missing musl cross-compiler (x86_64-linux-musl-gcc):
#      * On Debian/Ubuntu: `sudo apt-get update && sudo apt-get install -y musl-tools`
#      * Or install appropriate cross toolchain that provides a compiler named
#        `x86_64-linux-musl-gcc` (or the arch-specific equivalent).
#  - If you prefer hermetic CI builds, add musl toolchain/protoc to the build
#    Docker image used by `cross` (or build a custom image with those tools baked in).
#
# Notes
#  - The script attempts to be helpful by auto-detecting and (if possible)
#    installing required host deps, but auto-installation requires `apt-get` and
#    `sudo` privileges. If you want a non-interactive or CI-friendly variant,
#    consider disabling auto-install and instead documenting the dependencies
#    in your CI image.
# ---------------------------------------------------------------------------

local_arch=$(uname -m)
case $local_arch in
	x86_64)
		rust_target="x86_64-unknown-linux-musl"
		;;
	aarch64)
		rust_target="aarch64-unknown-linux-musl"
		;;
	*)
		echo "Unsupported architecture: $local_arch"
		exit 1
		;;
esac

odyn_tag="odyn-dev:latest"

enclaver_dir="$(dirname $(dirname ${BASH_SOURCE[0]}))/enclaver"
rust_target_dir="./target/${rust_target}/debug"

odyn_tag="odyn-dev:latest"
wrapper_base_tag="enclaver-wrapper-base:latest"

cd $enclaver_dir

docker_build_dir=$(mktemp -d)
trap "rm --force --recursive ${docker_build_dir}" EXIT

# Require 'cross' to perform the cross-compilation. Do not attempt to fall
# back to building on the host or auto-install host musl compilers. This keeps
# the script deterministic and avoids modifying the developer host.
if ! command -v cross >/dev/null 2>&1; then
    echo "'cross' is required but not found in PATH."
    echo "Install it with: cargo install cross"
    echo "Also ensure Docker is running and you have permission to use it."
    exit 1
fi

# Use 'cross' to perform the build (required earlier). This script will not
# fall back to building on the host.
echo "Building Rust artifacts with 'cross' for target: $rust_target"
echo "  Command: cross build --target $rust_target --features run_enclave,odyn"
cross build --target "$rust_target" --features run_enclave,odyn

cp $rust_target_dir/odyn $docker_build_dir/
cp $rust_target_dir/enclaver-run $docker_build_dir/

docker buildx build \
	-f ../build/dockerfiles/odyn-dev.dockerfile \
	-t ${odyn_tag} \
	${docker_build_dir}

docker buildx build \
	-f ../build/dockerfiles/runtimebase-dev.dockerfile \
	-t ${wrapper_base_tag} \
	${docker_build_dir}

echo "To use dev images, merge the following into enclaver.yaml:"
echo ""
echo "sources:"
echo "   supervisor: \"${odyn_tag}\""
echo "   wrapper: \"${wrapper_base_tag}\""
