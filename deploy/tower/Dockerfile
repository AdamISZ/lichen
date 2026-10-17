# A turnkey tower's image (docs/TOWER_PLAN.md): the `lichen` wallet (its
# `tower` command), BitVMX's verifier ELF, and the prover: ln-gap's
# `lngap-r0` with RISC Zero's r0vm 3.0.6. The Groth16 wrap runs RISC
# Zero's prover image, through the host's Docker (its socket mounted:
# deploy/tower/docker-compose.yml). x86_64 only (the wrap's image is).
# Build context: a directory holding lichen/ and ln-gap/ side by side
# (deploy/tower/build.sh makes it).
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY ln-gap ln-gap
COPY lichen lichen
WORKDIR /src/lichen
RUN cargo build --release -p lichen-wallet
# BitVMX's Groth16 verifier (GPL; shipped as the separate file it is), from
# the BitVMX-CPU checkout cargo just made; its SHA-256 is checked at start
RUN mkdir -p /out && cp target/release/lichen /out/ \
    && cp "$(ls /usr/local/cargo/git/checkouts/bitvmx-cpu-*/*/docker-riscv32/verifier/build/zkverifier-new-mul.elf | head -1)" /out/zkverifier.elf
# the prover: RISC Zero's own workspace in ln-gap (the guest is committed,
# so building the host needs no guest toolchain)
WORKDIR /src/ln-gap/crates/apps/sessions/r0
RUN cargo build --release -p lngap-r0 && cp target/release/lngap-r0 /out/
# r0vm, which the host proves through (client mode)
RUN curl -sSfL https://risczero.com/install | bash \
    && /root/.risc0/bin/rzup install r0vm 3.0.6 \
    && mkdir -p /out/risc0 && cp -r /root/.risc0 /out/risc0/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl docker.io && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/lichen /out/lngap-r0 /usr/local/bin/
COPY --from=build /out/zkverifier.elf /opt/lichen/zkverifier.elf
COPY --from=build /out/risc0/.risc0 /root/.risc0
COPY lichen/deploy/tower/entry.sh /usr/local/bin/tower-entry
ENV LICHEN_VERIFIER_ELF=/opt/lichen/zkverifier.elf
ENV PATH="/root/.risc0/bin:${PATH}"
ENTRYPOINT ["/usr/local/bin/tower-entry"]
