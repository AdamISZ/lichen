# lichen-r0, the spend guest's prover, on Linux (Apple silicon: arm64,
# native). Context: lichen's root. Run by r0/spend-prover.sh.
FROM rust:1.96-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends clang && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY crates/shielded crates/shielded
COPY crates/validity crates/validity
COPY r0/Cargo.toml r0/Cargo.lock r0/
COPY r0/host r0/host
RUN cargo build --release --locked --manifest-path r0/Cargo.toml -p lichen-r0
COPY r0/guests r0/guests
# the committed image id must be the committed binary's
ARG NO_ID_CHECK=
RUN [ -n "$NO_ID_CHECK" ] || /src/r0/target/release/lichen-r0 check-id
ENTRYPOINT ["/src/r0/target/release/lichen-r0"]
