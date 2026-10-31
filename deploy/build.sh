#!/usr/bin/env bash
# Build the deployment's two images from committed sources
# (deploy/context.sh):
#   deploy/build.sh            (in a lichen checkout, ln-gap beside it)
# - lichen: the hub, the sequencer, the chain prover, the wallet;
# - lichen-bitcoind: the node for NETWORK (deploy/.env, or ENV_FILE),
#   from a release tarball checked by SHA-256.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/context.sh"
env_file="${ENV_FILE:-$here/.env}"
[ -f "$env_file" ] || die "no $env_file (copy .env.example and set NETWORK)"
# shellcheck disable=SC1090
. "$env_file"
make_context
docker build -t lichen:latest -f "$here/Dockerfile" "$ctx"
docker build -t "lichen-bitcoind:$NETWORK" --build-arg "NETWORK=$NETWORK" "$here/bitcoind"
echo "== built lichen:latest and lichen-bitcoind:$NETWORK"
