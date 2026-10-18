#!/bin/sh
# The wallet's --spend-prover on a Mac: lichen-r0 in its Docker image
# (docker build -f r0/Dockerfile -t lichen-r0 .), the input and the receipt
# through stdin and stdout. Called as: spend-prover.sh spend <input> <receipt>
set -eu
[ "$1" = spend ] || { echo "usage: $0 spend <input> <receipt>" >&2; exit 2; }
docker run --rm -i lichen-r0 spend - - < "$2" > "$3"
