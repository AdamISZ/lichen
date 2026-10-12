#!/bin/sh
# The lichen image's roles (deploy/docker-compose.yml):
#   hub-key    make the hub's keys (in /hub) if needed; its L2 key to /shared/hub.pub
#   sequencer  the sequencer, minting by the hub's key; its key in /seq
#   hub        the hub, on NETWORK's node (its cookie in /bitcoind)
set -eu
NETWORK="${NETWORK:?set NETWORK}"
case "$NETWORK" in
    regtest) chaindir=regtest ;;
    mutinynet | signet) chaindir=signet ;;
    testnet4) chaindir=testnet4 ;;
    *) echo "unknown NETWORK $NETWORK" >&2; exit 1 ;;
esac

case "${1:-}" in
    hub-key)
        lichen-hub --dir /hub --print-key > /shared/hub.pub.tmp
        mv /shared/hub.pub.tmp /shared/hub.pub
        echo "the hub's L2 key: $(cat /shared/hub.pub)"
        ;;
    sequencer)
        exec lichen-sequencer --listen 0.0.0.0:18300 --ledger /seq/ledger.json --key /seq/sequencer.key \
            --issuer "$(cat /shared/hub.pub)" --seal-every "${SEAL_EVERY:-5}"
        ;;
    hub)
        cookie="/bitcoind/$chaindir/.cookie"
        # the node writes its cookie when its RPC is up
        while [ ! -f "$cookie" ]; do echo "waiting for $cookie"; sleep 2; done
        exec lichen-hub --network "$NETWORK" --listen 0.0.0.0:18310 --sequencer http://sequencer:18300 \
            --rpc-url http://bitcoind:8332 --cookie "$cookie" --chain-wallet hub --dir /hub \
            --statement "${STATEMENT:-groth16}" --reserve-ppm "${RESERVE_PPM:-20000}" --max-bits "${MAX_BITS:-24}" \
            ${DURATION:+--duration "$DURATION"}
        ;;
    *)
        exec "$@"
        ;;
esac
