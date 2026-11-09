#!/bin/sh
# The hub's prover (docs/HUB_PROVES_PLAN.md): the hub's statement on its
# input (HubInput's bytes) and the chain receipt at A*'s chain height
# (`none` for a malformed claim), by lichen-r0 in its Docker image (docker
# build -f r0/Dockerfile -t lichen-r0 .), the files in as a tar stream and
# the result out on stdout, as r0/chain-prover.sh. Or, with LICHEN_R0
# naming lichen-r0 itself (Linux), that. The Groth16 wrap (`hp-proof`) is
# x86 Linux's only: RISC Zero's prover image runs as a sibling container
# through the host's Docker (the socket mounted here), with its files in
# RISC0_WORK_DIR at the same path on the host and in the container.
#
#   hp-prover.sh hp-proof|hp|exec-hp <hub input> <chain receipt|none> <out>
set -eu
[ $# -eq 4 ] || { echo "usage: $0 hp-proof|hp|exec-hp <hub input> <chain receipt|none> <out>" >&2; exit 2; }
cmd=$1 input=$2 chain=$3 out=$4
if [ -n "${LICHEN_R0:-}" ]; then
    if [ "$cmd" = exec-hp ]; then
        [ "$chain" = none ] && exec "$LICHEN_R0" exec-hp "$input"
        exec "$LICHEN_R0" exec-hp "$input" "$chain"
    fi
    exec "$LICHEN_R0" "$cmd" "$input" "$chain" "$out"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$input" "$tmp/input.bin"
files=input.bin
c=none
if [ "$chain" != none ]; then
    cp "$chain" "$tmp/chain.receipt"
    files="$files chain.receipt"
    c=chain.receipt
fi
case "$cmd" in
exec-hp) run="exec-hp input.bin $([ "$c" = none ] || echo "$c")" ;;
*) run="$cmd input.bin $c /w/out" ;;
esac
wrap=
if [ "$cmd" = hp-proof ]; then
    mkdir "$tmp/r0work"
    wrap="-v /var/run/docker.sock:/var/run/docker.sock -v $tmp/r0work:$tmp/r0work -e RISC0_WORK_DIR=$tmp/r0work"
fi
# shellcheck disable=SC2086 # file names without spaces, ours
tar cf - -C "$tmp" $files | docker run --rm -i --init $wrap --entrypoint sh "${LICHEN_R0_IMAGE:-lichen-r0}" -c \
    "mkdir /w && cd /w && tar xf - && /src/r0/target/release/lichen-r0 $run >&2 && { [ ! -e /w/out ] || cat /w/out; }" > "$tmp/out"
[ "$cmd" = exec-hp ] || mv "$tmp/out" "$out"
