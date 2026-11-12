#!/bin/sh
# The hub's prover (docs/GRANTS_PLAN.md, milestone 3): the hub's statement
# on its input (GrantsInput's bytes), by lichen-r0 in its Docker image
# (docker build -f r0/Dockerfile -t lichen-r0 .), the input in as a tar
# stream and the result out on stdout. Or, with LICHEN_R0 naming lichen-r0
# itself (Linux), that. The Groth16 wrap (`hp-proof`) is x86 Linux's only:
# RISC Zero's prover image runs as a sibling container through the host's
# Docker (the socket mounted here), with its files in RISC0_WORK_DIR at
# the same path on the host and in the container.
#
#   hp-prover.sh hp-proof|hp|exec-hp <hub input> <out>
set -eu
[ $# -eq 3 ] || { echo "usage: $0 hp-proof|hp|exec-hp <hub input> <out>" >&2; exit 2; }
cmd=$1 input=$2 out=$3
if [ -n "${LICHEN_R0:-}" ]; then
    [ "$cmd" = exec-hp ] && exec "$LICHEN_R0" exec-hp "$input"
    exec "$LICHEN_R0" "$cmd" "$input" "$out"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$input" "$tmp/input.bin"
case "$cmd" in
exec-hp) run="exec-hp input.bin" ;;
*) run="$cmd input.bin /w/out" ;;
esac
wrap=
if [ "$cmd" = hp-proof ]; then
    mkdir "$tmp/r0work"
    wrap="-v /var/run/docker.sock:/var/run/docker.sock -v $tmp/r0work:$tmp/r0work -e RISC0_WORK_DIR=$tmp/r0work"
fi
# shellcheck disable=SC2086 # file names without spaces, ours
tar cf - -C "$tmp" input.bin | docker run --rm -i --init $wrap --entrypoint sh "${LICHEN_R0_IMAGE:-lichen-r0}" -c \
    "mkdir /w && cd /w && tar xf - && /src/r0/target/release/lichen-r0 $run >&2 && { [ ! -e /w/out ] || cat /w/out; }" > "$tmp/out"
[ "$cmd" = exec-hp ] || mv "$tmp/out" "$out"
