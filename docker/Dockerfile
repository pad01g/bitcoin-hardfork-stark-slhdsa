# BHSS build/test image. linux/amd64 on purpose: RISC Zero ships prebuilt
# Linux toolchains for x86_64 only. On Apple Silicon this runs under Rosetta.
FROM --platform=linux/amd64 rust:1.98.1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang pkg-config libssl-dev curl git ca-certificates \
        jq python3 \
    && rm -rf /var/lib/apt/lists/*

# RISC Zero toolchain manager. Versions are pinned below; bump deliberately.
ARG RISC0_VERSION=3.0.6
ENV RISC0_HOME=/root/.risc0
ENV PATH=/root/.risc0/bin:$PATH
RUN curl -L https://risczero.com/install | bash \
    && rzup install cargo-risczero ${RISC0_VERSION} \
    && rzup install r0vm ${RISC0_VERSION} \
    && rzup install rust \
    && rzup show

# risc0-circuit-recursion's build script downloads this archive and verifies
# its SHA-256; the in-build downloader is flaky under emulation, so fetch it
# once here and point the build script at it (RECURSION_SRC_PATH).
ARG RECURSION_ZKR_SHA256=744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849
RUN mkdir -p /opt/risc0 \
    && curl -fL --retry 5 -o /opt/risc0/recursion_zkr.zip \
       https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/${RECURSION_ZKR_SHA256}.zip \
    && echo "${RECURSION_ZKR_SHA256}  /opt/risc0/recursion_zkr.zip" | sha256sum -c -
ENV RECURSION_SRC_PATH=/opt/risc0/recursion_zkr.zip

WORKDIR /work
