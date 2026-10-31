#!/bin/sh
# The image's roles (deploy/docker-compose.yml):
#   key           make the hub's keys (in /hub) if needed, and print its
#                 L2 key: the key that mints, and the sequencer's issuer
#   sequencer     the L2's sequencer (its key and ledger in /seq), the hub's
#                 key its issuer; unless ANCHOR=off, anchoring its history
#                 through NETWORK's node (its cookie in /bitcoind), paid
#                 from the node's wallet ANCHOR_WALLET. A new ledger's
#                 genesis seal is paid first, so it waits for that wallet
#                 to be funded, and logs an address to pay
#   chain-prover  prove each height the sequencer seals, in order
#                 (r0/chain-prover.sh), with lichen-r0
#   hub           the hub, on NETWORK's node, once the sequencer answers;
#                 on the real BABE statement it proves counters to exit
#                 claims with lichen-r0
set -eu
NETWORK="${NETWORK:?set NETWORK}"
case "$NETWORK" in
    regtest) chaindir=regtest ;;
    mutinynet | signet) chaindir=signet ;;
    testnet4) chaindir=testnet4 ;;
    *) echo "unknown NETWORK $NETWORK" >&2; exit 1 ;;
esac
cookie="/bitcoind/$chaindir/.cookie"
node=http://bitcoind:8332

# the node writes its cookie when its RPC is up
wait_node() {
    while [ ! -f "$cookie" ]; do echo "waiting for $cookie"; sleep 2; done
}
# a JSON-RPC call to the node: rpc <path> <method> <params>
rpc() {
    curl -sS --user "$(cat "$cookie")" -H 'content-type: text/plain' \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":0,\"method\":\"$2\",\"params\":$3}" "$node$1"
}

case "${1:-}" in
    key)
        exec lichen-hub --dir /hub --print-key
        ;;
    sequencer)
        issuer="$(lichen-hub --dir /hub --print-key)"
        set -- --listen 0.0.0.0:18300 --ledger /seq/ledger.json --key /seq/sequencer.key \
            --issuer "$issuer" --seal-every "${SEAL_EVERY:-5}"
        [ "${ANCHOR:-on}" = off ] && exec lichen-sequencer "$@"
        wait_node
        wallet="${ANCHOR_WALLET:-sequencer}"
        if [ ! -f /seq/ledger.json ]; then
            # a new ledger: its genesis seal is paid from the wallet
            rpc / loadwallet "[\"$wallet\"]" >/dev/null
            rpc / createwallet "[\"$wallet\"]" >/dev/null
            addr=
            until rpc "/wallet/$wallet" getbalance '["*",0]' | grep -q '"result":[0-9.]*[1-9]'; do
                [ -n "$addr" ] || addr="$(rpc "/wallet/$wallet" getnewaddress '[]' | sed 's/.*"result":"\([^"]*\)".*/\1/')"
                echo "waiting for the sequencer's wallet ($wallet) to be funded, for its genesis seal and anchors: pay $addr"
                sleep 10
            done
        fi
        exec lichen-sequencer "$@" --network "$NETWORK" --anchor-rpc "$node" --anchor-cookie "$cookie" \
            --anchor-wallet "$wallet" --anchor-confirmations "${ANCHOR_CONFIRMATIONS:-1}" --anchor-feerate "${ANCHOR_FEERATE:-2}"
        ;;
    chain-prover)
        blocks=/seq/ledger.json.blocks
        until [ -d "$blocks" ]; do echo "waiting for the sequencer's first block"; sleep 5; done
        LICHEN_R0=/usr/local/bin/lichen-r0 exec lichen-chain-prover "$blocks"
        ;;
    hub)
        seq="${SEQUENCER_URL:-http://sequencer:18300}"
        wait_node
        until curl -fsS "$seq/info" >/dev/null 2>&1; do echo "waiting for the sequencer at $seq"; sleep 5; done
        prover=
        [ "${STATEMENT:-babe}" = babe ] && prover=/usr/local/bin/lichen-r0
        exec lichen-hub --network "$NETWORK" --listen 0.0.0.0:18310 --sequencer "$seq" \
            --rpc-url "$node" --cookie "$cookie" --chain-wallet hub --dir /hub \
            --statement "${STATEMENT:-babe}" --reserve-ppm "${RESERVE_PPM:-20000}" --max-bits "${MAX_BITS:-24}" \
            ${DURATION:+--duration "$DURATION"} ${WINDOWS:+--windows "$WINDOWS"} ${HOSTILE:+--hostile} ${REFUSE_FOLDS:+--refuse-folds} ${prover:+--prover "$prover"}
        ;;
    *)
        exec "$@"
        ;;
esac
