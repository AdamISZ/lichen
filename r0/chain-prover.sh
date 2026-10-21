#!/bin/sh
# The chain prover (docs/SHIELDED_PLAN.md, phase 2): proves each height
# the sequencer records (<ledger>.blocks/<h>.input and its spend receipts
# <h>.<k>.receipt), in order, each from the last, writing <h>.chain: the
# succinct receipt that heights 1..h are valid from genesis. In the prover
# image (docker build -f r0/Dockerfile -t lichen-r0 .), or with LICHEN_R0
# naming lichen-r0 itself (Linux).
#
#   chain-prover.sh <blocks dir> [--once]   --once: stop at the last height
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <blocks dir> [--once]" >&2; exit 2; }
dir=$(cd "$1" && pwd)
once=${2:-}

# prove height h: lichen-r0 chain <h>.input <out> [--prev <h-1>.chain]
# <h>.<k>.receipt..., run in $dir
prove() {
    h=$1
    files="$h.input"
    args="$h.input OUT"
    if [ "$h" -gt 1 ]; then
        files="$files $((h - 1)).chain"
        args="$args --prev $((h - 1)).chain"
    fi
    for r in "$dir/$h".*.receipt; do
        [ -e "$r" ] || continue
        files="$files $(basename "$r")"
        args="$args $(basename "$r")"
    done
    cd "$dir"
    if [ -n "${LICHEN_R0:-}" ]; then
        # shellcheck disable=SC2086 # file names without spaces, ours
        "$LICHEN_R0" chain $(echo "$args" | sed "s|OUT|$h.chain.tmp|")
    else
        # Docker without shared folders (as r0/spend-prover.sh): the files
        # in as a tar stream, the receipt out on stdout
        # shellcheck disable=SC2086
        tar cf - $files | docker run --rm -i --init --entrypoint sh "${LICHEN_R0_IMAGE:-lichen-r0}" -c \
            "mkdir /b && cd /b && tar xf - && /src/r0/target/release/lichen-r0 chain $(echo "$args" | sed 's|OUT|/b/out|') >&2 && cat /b/out" > "$h.chain.tmp"
    fi
    cd - >/dev/null
}

h=1
while :; do
    if [ -f "$dir/$h.chain" ]; then
        h=$((h + 1))
        continue
    fi
    if [ ! -f "$dir/$h.input" ]; then
        [ -z "$once" ] || exit 0
        sleep 5
        continue
    fi
    # the sequencer records a height again (and clears its old files) if
    # it restarted after recording a block it never kept: a proof of the
    # input that was there is then thrown away
    sum=$(cksum < "$dir/$h.input")
    prove "$h"
    if [ ! -f "$dir/$h.input" ] || [ "$(cksum < "$dir/$h.input")" != "$sum" ]; then
        rm -f "$dir/$h.chain.tmp"
        echo "chain-prover: height $h was recorded again while proving; proving it again"
        continue
    fi
    mv "$dir/$h.chain.tmp" "$dir/$h.chain"
    echo "chain-prover: height $h proved"
done
