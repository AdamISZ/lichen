#!/bin/sh
# The tower's entry: play the dispute of /tower/package.json to its end
# (resumable: run again after a restart). NETWORK and ESPLORA (two
# servers, comma-separated) from deploy/tower/.env.
set -eu
[ -f /tower/package.json ] || { echo "no /tower/package.json: put the package from 'lichen export-dispute' there"; exit 1; }
exec lichen --network "${NETWORK:?}" ${ESPLORA:+--esplora "$ESPLORA"} --statement "${STATEMENT:-babe}" \
    tower --package /tower/package.json --prover lichen-r0
