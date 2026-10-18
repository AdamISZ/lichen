#!/usr/bin/env bash
# Build the spend guest and commit it, in two steps:
#
#   r0/build-guest.sh elf    on x86_64 Linux (RISC Zero's pinned builder
#                            image is x86; emulated on Apple silicon its
#                            linker has crashed): writes r0/guests/spend.elf
#   r0/build-guest.sh pack   anywhere with Docker: packs it with RISC Zero's
#                            kernel in the prover image (r0/Dockerfile),
#                            writes r0/guests/spend.bin and spend.id
#
# Commit spend.bin and spend.id (not the ELF), and record the build in
# r0/guests/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
elf)
    [ "$(uname -m)" = x86_64 ] || { echo "the guest builder image is x86_64: build the ELF on an x86 machine" >&2; exit 1; }
    flags="$(printf -- '-Cpasses=lower-atomic\x1f-Clink-arg=-Ttext=0x00200800\x1f-Clink-arg=--fatal-warnings\x1f-Cpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"')"
    docker build --build-arg FLAGS="$flags" -f r0/Dockerfile.guest -t lichen-spend-guest .
    id=$(docker create lichen-spend-guest)
    docker cp "$id:/src/target/riscv32im-risc0-zkvm-elf/release/spend" r0/guests/spend.elf
    docker rm "$id" >/dev/null
    sha256sum r0/guests/spend.elf
    ;;
pack)
    [ -f r0/guests/spend.elf ] || { echo "no r0/guests/spend.elf: build it first (elf)" >&2; exit 1; }
    # the prover image without a guest to check yet
    docker build --build-arg NO_ID_CHECK=1 -f r0/Dockerfile -t lichen-r0 .
    docker run --rm -i --entrypoint sh lichen-r0 -c 'cat > /tmp/spend.elf && /src/r0/target/release/lichen-r0 pack /tmp/spend.elf /tmp/spend.bin >&2 && cat /tmp/spend.bin' < r0/guests/spend.elf > r0/guests/spend.bin
    docker run --rm -i --entrypoint sh lichen-r0 -c 'cat > /tmp/spend.bin && /src/r0/target/release/lichen-r0 pack-id /tmp/spend.bin' < r0/guests/spend.bin > r0/guests/spend.id
    rm r0/guests/spend.elf
    cat r0/guests/spend.id
    shasum -a 256 r0/guests/spend.bin
    docker build -f r0/Dockerfile -t lichen-r0 .
    ;;
*)
    echo "usage: $0 elf | pack" >&2
    exit 2
    ;;
esac
