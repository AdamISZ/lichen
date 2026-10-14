# The sequencer's image: `lichen-sequencer` alone. It has no chain: no
# node, no BitVMX, no verifier. Build context: a directory holding lichen/
# and ln-gap/ side by side (deploy/sequencer/build.sh makes it; cargo needs
# ln-gap's tree to read the workspace, though the sequencer uses only the
# withdrawal statement's data structures from it).
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY ln-gap ln-gap
COPY lichen lichen
WORKDIR /src/lichen
RUN cargo build --release -p lichen-sequencer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/lichen/target/release/lichen-sequencer /usr/local/bin/
ENTRYPOINT ["lichen-sequencer"]
