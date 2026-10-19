# A turnkey tower's image (docs/TOWER_PLAN.md): the `lichen` wallet (its
# `tower` command), BitVMX's verifier ELF, and the prover: `lichen-r0`
# (RISC Zero 3.0.6, in process) with the committed guests it reads. The
# Groth16 wrap runs RISC Zero's prover image, through the host's Docker
# (its socket mounted: deploy/tower/docker-compose.yml). x86_64 only (the
# wrap's image is).
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
# the prover: lichen's RISC Zero workspace (the guests are committed, so
# building the host needs no guest toolchain)
RUN apt-get update && apt-get install -y --no-install-recommends clang && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --locked --manifest-path r0/Cargo.toml -p lichen-r0 && cp r0/target/release/lichen-r0 /out/ \
    && /out/lichen-r0 check-id

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl docker.io && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/lichen /out/lichen-r0 /usr/local/bin/
COPY --from=build /out/zkverifier.elf /opt/lichen/zkverifier.elf
# lichen-r0 reads the committed guests from its source tree's path
COPY --from=build /src/lichen/r0/guests /src/lichen/r0/guests
COPY lichen/deploy/tower/entry.sh /usr/local/bin/tower-entry
ENV LICHEN_VERIFIER_ELF=/opt/lichen/zkverifier.elf
ENTRYPOINT ["/usr/local/bin/tower-entry"]
