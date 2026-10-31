# The operator's image, one for every service but the node
# (deploy/docker-compose.yml): the hub (`lichen-hub`), the L2's sequencer
# (`lichen-sequencer`), the wallet (`lichen`, for deploy/smoke.sh),
# BitVMX's verifier ELF, and the prover `lichen-r0` (RISC Zero 3.0.6, in
# process) with the committed guests it reads, which proves the chain
# (r0/chain-prover.sh) and the hub's counters to exit claims. The Groth16
# wrap runs RISC Zero's prover image, through the host's Docker (its
# socket mounted). Build context: a directory holding lichen/ and ln-gap/
# side by side (deploy/build.sh makes it).
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY ln-gap ln-gap
COPY lichen lichen
WORKDIR /src/lichen
RUN cargo build --release -p lichen-hub -p lichen-wallet -p lichen-sequencer
# BitVMX's Groth16 verifier (GPL; shipped as the separate file it is), from
# the BitVMX-CPU checkout cargo just made; its SHA-256 is checked at start
RUN mkdir -p /out && cp target/release/lichen-hub target/release/lichen target/release/lichen-sequencer /out/ \
    && cp "$(ls /usr/local/cargo/git/checkouts/bitvmx-cpu-*/*/docker-riscv32/verifier/build/zkverifier-new-mul.elf | head -1)" /out/zkverifier.elf
# the prover: lichen's RISC Zero workspace (the guests are committed, so
# building the host needs no guest toolchain)
RUN apt-get update && apt-get install -y --no-install-recommends clang && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --locked --manifest-path r0/Cargo.toml -p lichen-r0 && cp r0/target/release/lichen-r0 /out/ \
    && /out/lichen-r0 check-id

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
# the docker CLI for the wrap (static; bookworm's docker.io speaks an API
# older than a current daemon's minimum)
COPY --from=docker:28.5.1-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /out/lichen-hub /out/lichen /out/lichen-sequencer /out/lichen-r0 /usr/local/bin/
COPY --from=build /out/zkverifier.elf /opt/lichen/zkverifier.elf
# lichen-r0 reads the committed guests from its source tree's path,
# r0/host/../guests: r0/host has to exist for that to resolve
COPY --from=build /src/lichen/r0/guests /src/lichen/r0/guests
RUN mkdir -p /src/lichen/r0/host
COPY lichen/r0/chain-prover.sh /usr/local/bin/lichen-chain-prover
COPY lichen/deploy/entry.sh /usr/local/bin/lichen-entry
ENV LICHEN_VERIFIER_ELF=/opt/lichen/zkverifier.elf
ENTRYPOINT ["/usr/local/bin/lichen-entry"]
