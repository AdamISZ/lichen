#!/usr/bin/env bash
# Build the tower's image, lichen-tower:latest, from committed sources
# (deploy/context.sh), on an x86_64 machine:
#   deploy/tower/build.sh      (in a lichen checkout, ln-gap beside it)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/../context.sh"
[ "$(uname -m)" = x86_64 ] || echo "note: building for linux/amd64 on $(uname -m) (emulated: slow)" >&2
make_context
docker build --platform linux/amd64 -t lichen-tower:latest -f "$here/Dockerfile" "$ctx"
echo "== built lichen-tower:latest"
# RISC Zero's Groth16 prover, which the wrap runs by tag (risc0-groth16's
# prove/docker.rs): pulled by digest and given that tag, so that the tag
# names these contents. A RISC Zero upgrade changes both.
prover=risczero/risc0-groth16-prover
digest=sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee
docker pull --platform linux/amd64 "$prover@$digest"
docker tag "$prover@$digest" "$prover:v2025-04-03.1"
echo "== pulled $prover:v2025-04-03.1 ($digest)"
