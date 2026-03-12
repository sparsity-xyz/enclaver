# Dockerfile for building the nitro-cli image.
#
# This image installs the AWS Nitro Enclaves CLI packages from Amazon Linux,
# then replaces the default enclave blobs with artifacts rebuilt from the
# official aws-nitro-enclaves-sdk-bootstrap sources. We do that so the enclave
# kernel and matching NSM module ship with FUSE enabled.

ARG NITRO_BOOTSTRAP_REF=v6.6.79

FROM nixos/nix:2.21.4 AS nitro_bootstrap
ARG NITRO_BOOTSTRAP_REF

RUN nix-env -f '<nixpkgs>' -iA git

WORKDIR /build

RUN git clone --depth 1 --branch "${NITRO_BOOTSTRAP_REF}" \
        https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap.git sdk-bootstrap

WORKDIR /build/sdk-bootstrap

RUN nix-build -A all

FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install the Nitro CLI binaries and runtime libraries from Amazon Linux.
RUN dnf install -y \
        aws-nitro-enclaves-cli \
        aws-nitro-enclaves-cli-devel \
    && dnf clean all \
    && rm -rf /var/cache/yum /var/cache/dnf

# Replace the package-provided blobs with a freshly built, FUSE-enabled set so
# build-enclave produces EIF kernels that can mount hostfs via /dev/fuse.
COPY --from=nitro_bootstrap /build/sdk-bootstrap/result/. /tmp/nitro-bootstrap/

RUN arch="$(uname -m)" \
    && case "$arch" in \
        x86_64) \
            src_dir="/tmp/nitro-bootstrap/x86_64"; \
            kernel_cfg="/usr/share/nitro_enclaves/blobs/bzImage.config"; \
            ;; \
        aarch64) \
            src_dir="/tmp/nitro-bootstrap/aarch64"; \
            kernel_cfg="/usr/share/nitro_enclaves/blobs/Image.config"; \
            ;; \
        *) \
            echo "unsupported architecture: ${arch}" >&2; \
            exit 1; \
            ;; \
    esac \
    && rm -rf /usr/share/nitro_enclaves/blobs/* \
    && cp -r "${src_dir}"/. /usr/share/nitro_enclaves/blobs/ \
    && test -s /usr/share/nitro_enclaves/blobs/init \
    && test -s /usr/share/nitro_enclaves/blobs/linuxkit \
    && test -s /usr/share/nitro_enclaves/blobs/cmdline \
    && test -s /usr/share/nitro_enclaves/blobs/nsm.ko \
    && grep -Eq '^CONFIG_FUSE_FS=(y|m)$' "${kernel_cfg}" \
    && rm -rf /tmp/nitro-bootstrap

WORKDIR /build

ENTRYPOINT ["nitro-cli"]
