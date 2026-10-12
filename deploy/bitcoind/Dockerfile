# The deployment's node: stock Bitcoin Core for regtest, signet and
# testnet4; benthecarman's patched build (30 s signet blocks) for
# mutinynet. Each release tarball is pinned by its SHA-256: Core's from
# its SHA256SUMS (fetched over TLS, not GPG-checked here); the Mutinynet
# build's as observed on 2026-10-12 (its release publishes none).
FROM debian:bookworm-slim
ARG NETWORK
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in amd64) triplet=x86_64-linux-gnu ;; arm64) triplet=aarch64-linux-gnu ;; *) echo "no build for $arch" >&2; exit 1 ;; esac; \
    case "$NETWORK/$triplet" in \
        mutinynet/x86_64-linux-gnu) url=https://github.com/benthecarman/bitcoin/releases/download/paircommit/bitcoin-d4a86277ed8a-x86_64-linux-gnu.tar.gz; sha=e7323dae628f48676fe59b5caa36bd36cf7973e98b7753b965811b61fbd33ced ;; \
        mutinynet/aarch64-linux-gnu) url=https://github.com/benthecarman/bitcoin/releases/download/paircommit/bitcoin-d4a86277ed8a-aarch64-linux-gnu.tar.gz; sha=df9360e302c6a46ae60faf31bc28713874b16767ab8a012f21c744257aeafad4 ;; \
        */x86_64-linux-gnu) url=https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz; sha=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e ;; \
        */aarch64-linux-gnu) url=https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-aarch64-linux-gnu.tar.gz; sha=dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004 ;; \
    esac; \
    curl -fsSL -o /tmp/bitcoin.tar.gz "$url"; \
    echo "$sha  /tmp/bitcoin.tar.gz" | sha256sum -c -; \
    mkdir /tmp/b && tar -xzf /tmp/bitcoin.tar.gz -C /tmp/b --strip-components=1; \
    cp /tmp/b/bin/bitcoind /tmp/b/bin/bitcoin-cli /usr/local/bin/; \
    rm -rf /tmp/b /tmp/bitcoin.tar.gz
ENV NETWORK=$NETWORK
COPY entry.sh /usr/local/bin/bitcoind-entry
ENTRYPOINT ["/usr/local/bin/bitcoind-entry"]
