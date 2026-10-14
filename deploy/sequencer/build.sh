#!/usr/bin/env bash
# Build the sequencer's image, lichen-sequencer:latest, from committed
# sources (deploy/context.sh):
#   deploy/sequencer/build.sh      (in a lichen checkout, ln-gap beside it)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/../context.sh"
make_context
docker build -t lichen-sequencer:latest -f "$here/Dockerfile" "$ctx"
echo "== built lichen-sequencer:latest"
