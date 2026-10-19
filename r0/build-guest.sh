#!/usr/bin/env bash
# Build a guest (spend, the default, chain or withdraw) and commit it, in two
# steps:
#
#   r0/build-guest.sh elf [g]   on x86_64 Linux (RISC Zero's pinned builder
#                               image is x86; emulated on Apple silicon its
#                               linker has crashed): writes r0/guests/<g>.elf
#   r0/build-guest.sh pack [g]  anywhere with Docker: packs it with RISC
#                               Zero's kernel in the prover image
#                               (r0/Dockerfile), writes r0/guests/<g>.bin
#                               and <g>.id
#
# Commit <g>.bin and <g>.id (not the ELF), and record the build in
# r0/guests/README.md. The chain guest holds the spend guest's image id,
# the withdrawal guest the chain guest's: rebuild each after the one it
# holds.
set -euo pipefail
cd "$(dirname "$0")/.."
g="${2:-spend}"
case "$g" in
spend) dir=r0/guest ;;
chain) dir=r0/chain-guest ;;
withdraw) dir=r0/withdraw-guest ;;
*) echo "no guest $g (spend, chain, withdraw)" >&2; exit 2 ;;
esac
case "${1:-}" in
elf)
    [ "$(uname -m)" = x86_64 ] || { echo "the guest builder image is x86_64: build the ELF on an x86 machine" >&2; exit 1; }
    flags="$(printf -- '-Cpasses=lower-atomic\x1f-Clink-arg=-Ttext=0x00200800\x1f-Clink-arg=--fatal-warnings\x1f-Cpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"')"
    docker build --build-arg FLAGS="$flags" --build-arg GUEST_DIR="$dir" -f r0/Dockerfile.guest -t "lichen-$g-guest" .
    id=$(docker create "lichen-$g-guest")
    docker cp "$id:/src/target/riscv32im-risc0-zkvm-elf/release/$g" "r0/guests/$g.elf"
    docker rm "$id" >/dev/null
    sha256sum "r0/guests/$g.elf"
    ;;
pack)
    [ -f "r0/guests/$g.elf" ] || { echo "no r0/guests/$g.elf: build it first (elf $g)" >&2; exit 1; }
    # the prover image without a guest to check yet
    docker build --build-arg NO_ID_CHECK=1 -f r0/Dockerfile -t lichen-r0 .
    docker run --rm -i --entrypoint sh lichen-r0 -c 'cat > /tmp/g.elf && /src/r0/target/release/lichen-r0 pack /tmp/g.elf /tmp/g.bin >&2 && cat /tmp/g.bin' < "r0/guests/$g.elf" > "r0/guests/$g.bin"
    docker run --rm -i --entrypoint sh lichen-r0 -c 'cat > /tmp/g.bin && /src/r0/target/release/lichen-r0 pack-id /tmp/g.bin' < "r0/guests/$g.bin" > "r0/guests/$g.id"
    rm "r0/guests/$g.elf"
    cat "r0/guests/$g.id"
    shasum -a 256 "r0/guests/$g.bin"
    docker build -f r0/Dockerfile -t lichen-r0 .
    ;;
*)
    echo "usage: $0 elf|pack [spend|chain|withdraw]" >&2
    exit 2
    ;;
esac
