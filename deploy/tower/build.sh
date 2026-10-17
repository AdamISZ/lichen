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
