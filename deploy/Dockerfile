# The hub's and the sequencer's image. Build context: a directory holding
# lichen/ and ln-gap/ side by side (deploy/build.sh makes it).
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY ln-gap ln-gap
COPY lichen lichen
WORKDIR /src/lichen
RUN cargo build --release -p lichen-hub -p lichen-sequencer -p lichen-wallet
# BitVMX's Groth16 verifier (GPL; shipped as the separate file it is), from
# the BitVMX-CPU checkout cargo just made; its SHA-256 is checked at start
RUN mkdir -p /out && cp target/release/lichen-hub target/release/lichen-sequencer target/release/lichen /out/ \
    && cp "$(ls /usr/local/cargo/git/checkouts/bitvmx-cpu-*/*/docker-riscv32/verifier/build/zkverifier-new-mul.elf | head -1)" /out/zkverifier.elf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/lichen-hub /out/lichen-sequencer /out/lichen /usr/local/bin/
COPY --from=build /out/zkverifier.elf /opt/lichen/zkverifier.elf
COPY lichen/deploy/entry.sh /usr/local/bin/lichen-entry
ENV LICHEN_VERIFIER_ELF=/opt/lichen/zkverifier.elf
ENTRYPOINT ["/usr/local/bin/lichen-entry"]
