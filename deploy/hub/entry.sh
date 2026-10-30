#!/bin/sh
# The hub image's roles (deploy/hub/docker-compose.yml):
#   key   make the hub's keys (in /hub) if needed, and print its L2 key:
#         the sequencer's operator sets it as their ISSUER
#   hub   the hub, on NETWORK's node (its cookie in /bitcoind), once the
#         sequencer at SEQUENCER_URL answers; on the real BABE statement
#         it proves counters to exit claims with lichen-r0
set -eu
NETWORK="${NETWORK:?set NETWORK}"
case "$NETWORK" in
    regtest) chaindir=regtest ;;
    mutinynet | signet) chaindir=signet ;;
    testnet4) chaindir=testnet4 ;;
    *) echo "unknown NETWORK $NETWORK" >&2; exit 1 ;;
esac

case "${1:-}" in
    key)
        exec lichen-hub --dir /hub --print-key
        ;;
    hub)
        seq="${SEQUENCER_URL:?set SEQUENCER_URL in deploy/hub/.env}"
        cookie="/bitcoind/$chaindir/.cookie"
        # the node writes its cookie when its RPC is up
        while [ ! -f "$cookie" ]; do echo "waiting for $cookie"; sleep 2; done
        until curl -fsS "$seq/info" >/dev/null 2>&1; do echo "waiting for the sequencer at $seq"; sleep 5; done
        prover=
        [ "${STATEMENT:-babe}" = babe ] && prover=/usr/local/bin/lichen-r0
        exec lichen-hub --network "$NETWORK" --listen 0.0.0.0:18310 --sequencer "$seq" \
            --rpc-url http://bitcoind:8332 --cookie "$cookie" --chain-wallet hub --dir /hub \
            --statement "${STATEMENT:-babe}" --reserve-ppm "${RESERVE_PPM:-20000}" --max-bits "${MAX_BITS:-24}" \
            ${DURATION:+--duration "$DURATION"} ${WINDOWS:+--windows "$WINDOWS"} ${HOSTILE:+--hostile} ${REFUSE_FOLDS:+--refuse-folds} ${prover:+--prover "$prover"}
        ;;
    *)
        exec "$@"
        ;;
esac
