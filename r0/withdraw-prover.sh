#!/bin/sh
# The withdrawal prover on a Mac (docs/SHIELDED_PLAN.md, phase 2, step 4):
# lichen-r0 in its Docker image (docker build -f r0/Dockerfile -t lichen-r0
# .), the files in as a tar stream and the result out on stdout, as
# r0/chain-prover.sh. Or, with LICHEN_R0 naming lichen-r0 itself (Linux),
# that. The Groth16 wrap (`claim`) is x86 Linux's only: RISC Zero's prover
# image runs as a sibling container through the host's Docker (the socket
# mounted here), with its files in RISC0_WORK_DIR at the same path on the
# host and in the container.
#
#   withdraw-prover.sh withdraw|exec-withdraw|claim <withdraw input> <chain receipt> <out>
set -eu
[ $# -eq 4 ] || { echo "usage: $0 withdraw|exec-withdraw|claim <withdraw input> <chain receipt> <out>" >&2; exit 2; }
cmd=$1 json=$2 chain=$3 out=$4
if [ -n "${LICHEN_R0:-}" ]; then
    exec "$LICHEN_R0" "$cmd" "$json" "$chain" "$out"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$json" "$tmp/input.json"
cp "$chain" "$tmp/chain.receipt"
wrap=
if [ "$cmd" = claim ]; then
    mkdir "$tmp/r0work"
    wrap="-v /var/run/docker.sock:/var/run/docker.sock -v $tmp/r0work:$tmp/r0work -e RISC0_WORK_DIR=$tmp/r0work"
fi
tar cf - -C "$tmp" input.json chain.receipt | docker run --rm -i $wrap --entrypoint sh lichen-r0 -c \
    "mkdir /w && cd /w && tar xf - && /src/r0/target/release/lichen-r0 $cmd input.json chain.receipt /w/out >&2 && { [ ! -e /w/out ] || cat /w/out; }" > "$tmp/out"
[ "$cmd" = exec-withdraw ] || mv "$tmp/out" "$out"
