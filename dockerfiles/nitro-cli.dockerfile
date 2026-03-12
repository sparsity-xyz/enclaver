# Dockerfile for building the nitro-cli image.
#
# This image installs the AWS Nitro Enclaves CLI packages from Amazon Linux,
# then replaces the default enclave blobs with artifacts rebuilt from the
# official aws-nitro-enclaves-sdk-bootstrap sources. We do that so the enclave
# kernel and matching NSM module ship with FUSE enabled.

ARG NITRO_BOOTSTRAP_REF=v6.6.79

FROM nixos/nix:2.21.4 AS nitro_bootstrap
ARG NITRO_BOOTSTRAP_REF

# The Nix base image is intentionally minimal, so install the tools used to
# patch the upstream kernel config before rebuilding the blobs.
RUN nix-env -f '<nixpkgs>' -iA git gnused

WORKDIR /build

RUN git clone --depth 1 --branch "${NITRO_BOOTSTRAP_REF}" \
        https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap.git sdk-bootstrap

WORKDIR /build/sdk-bootstrap

# Nitro CLI's build-enclave flow bakes whatever kernel blobs live under
# /usr/share/nitro_enclaves/blobs into the EIF. The upstream bootstrap repo
# still ships microvm kernel configs with FUSE disabled, which breaks odyn's
# host-backed directory mounts inside the enclave. We patch the upstream config
# files before rebuilding so the generated bzImage/Image artifacts include
# CONFIG_FUSE_FS=y for both supported architectures.
#
# The sed expression handles both upstream forms we may encounter:
# - "# CONFIG_FUSE_FS is not set"
# - "CONFIG_FUSE_FS=<value>"
# and normalizes either one to "CONFIG_FUSE_FS=y".
RUN for cfg in kernel/microvm-kernel-config-x86_64 kernel/microvm-kernel-config-aarch64; do \
        grep -Eq '^# CONFIG_FUSE_FS is not set$|^CONFIG_FUSE_FS=' "${cfg}"; \
        sed -i -E 's|^# CONFIG_FUSE_FS is not set$|CONFIG_FUSE_FS=y|; s|^CONFIG_FUSE_FS=.*$|CONFIG_FUSE_FS=y|' "${cfg}"; \
        grep -Eq '^CONFIG_FUSE_FS=y$' "${cfg}"; \
    done

RUN nix-build -A all

FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install the Nitro CLI binaries and runtime libraries from Amazon Linux.
RUN dnf install -y \
        aws-nitro-enclaves-cli \
        aws-nitro-enclaves-cli-devel \
    && dnf clean all \
    && rm -rf /var/cache/yum /var/cache/dnf

# Replace the package-provided blobs with the rebuilt set from the patched
# bootstrap stage. This is the point where we swap Nitro CLI off the stock AWS
# blobs and onto our FUSE-enabled kernel/init/linuxkit artifacts so every later
# "nitro-cli build-enclave" invocation in this image produces EIFs with FUSE
# support available inside the enclave.
COPY --from=nitro_bootstrap /build/sdk-bootstrap/result/. /tmp/nitro-bootstrap/

RUN arch="$(uname -m)" \
    && case "$arch" in \
        x86_64) \
            src_dir="/tmp/nitro-bootstrap/x86_64"; \
            kernel_image="/usr/share/nitro_enclaves/blobs/bzImage"; \
            kernel_cfg="/usr/share/nitro_enclaves/blobs/bzImage.config"; \
            ;; \
        aarch64) \
            src_dir="/tmp/nitro-bootstrap/aarch64"; \
            kernel_image="/usr/share/nitro_enclaves/blobs/Image"; \
            kernel_cfg="/usr/share/nitro_enclaves/blobs/Image.config"; \
            ;; \
        *) \
            echo "unsupported architecture: ${arch}" >&2; \
            exit 1; \
            ;; \
    esac \
    && rm -rf /usr/share/nitro_enclaves/blobs/* \
    && cp -r "${src_dir}"/. /usr/share/nitro_enclaves/blobs/ \
    && test -s "${kernel_image}" \
    && test -s "${kernel_cfg}" \
    && test -s /usr/share/nitro_enclaves/blobs/init \
    && test -s /usr/share/nitro_enclaves/blobs/linuxkit \
    && test -s /usr/share/nitro_enclaves/blobs/cmdline \
    && test -s /usr/share/nitro_enclaves/blobs/nsm.ko \
    && grep -Eq '^CONFIG_FUSE_FS=(y|m)$' "${kernel_cfg}" \
    && rm -rf /tmp/nitro-bootstrap

WORKDIR /build

ENTRYPOINT ["nitro-cli"]
