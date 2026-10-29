# The deployment's node: stock Bitcoin Core for regtest, signet and
# testnet4; benthecarman's patched build (30 s signet blocks) for
# mutinynet, the one MutinyWallet/mutiny-net's own node runs (v29.0 +
# Template Hash, 2026-10-29). Before it, a 25.99 build rejected TRUC
# (version 3), which BABE's `wrongly_challenged` is. Each release tarball
# is pinned by its SHA-256, from its SHA256SUMS (fetched over TLS, not
# GPG-checked here).
FROM debian:bookworm-slim
ARG NETWORK
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in amd64) triplet=x86_64-linux-gnu ;; arm64) triplet=aarch64-linux-gnu ;; *) echo "no build for $arch" >&2; exit 1 ;; esac; \
    case "$NETWORK/$triplet" in \
        mutinynet/x86_64-linux-gnu) url=https://github.com/benthecarman/bitcoin/releases/download/mutinynet-inq-template-hash/bitcoin-2fda7bfc027e-x86_64-linux-gnu.tar.gz; sha=c76b58a078e3e5fcc4597f50d9f9d15da8d11a5d8cf0831ab62970329bfb6115 ;; \
        mutinynet/aarch64-linux-gnu) url=https://github.com/benthecarman/bitcoin/releases/download/mutinynet-inq-template-hash/bitcoin-2fda7bfc027e-aarch64-linux-gnu.tar.gz; sha=c18705e9e98202e095e13bbc5546b5f34fbb4df9bf8bc34ef4553f6d2d1d68bc ;; \
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
