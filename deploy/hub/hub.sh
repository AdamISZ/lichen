#!/usr/bin/env bash
# The hub operator's commands (deploy/hub/.env, or ENV_FILE):
#   deploy/hub/hub.sh key           make the hub's keys if needed; print its L2 key (give it to the sequencer's operator)
#   deploy/hub/hub.sh info          the hub's key, the deployment it pinned, the sequencer, the chain
#   deploy/hub/hub.sh address       an address of the hub's wallet (fund it: a faucet, or `fund`)
#   deploy/hub/hub.sh balance       the hub's wallet balance
#   deploy/hub/hub.sh coins         the hub's coins: address, amount, confirmations
#   deploy/hub/hub.sh fund <btc>    regtest: pay the hub from the miner's coins
#   deploy/hub/hub.sh cli <args>    bitcoin-cli on the hub's node
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file="${ENV_FILE:-$here/.env}"
# shellcheck disable=SC1090
. "$env_file"
data="$here/data/$NETWORK"
dc() { docker compose --env-file "$env_file" -f "$here/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli -datadir=/data "$@"; }

case "${1:-}" in
    key)
        mkdir -p "$data/hub"
        docker run --rm -e NETWORK="$NETWORK" -v "$data/hub:/hub" lichen-hub:latest key
        ;;
    info)
        hubrun() { docker run --rm -e NETWORK="$NETWORK" -v "$data/hub:/hub" lichen-hub:latest "$@"; }
        echo "hub L2 key:  $(hubrun key)"
        echo "pinned:      $(hubrun sh -c 'tr -d " \n" < /hub/deployment.json' 2>/dev/null || echo "nothing yet (the hub pins the sequencer's key on first start)")"
        echo "sequencer:   $SEQUENCER_URL says $(dc exec -T hub curl -fsS "$SEQUENCER_URL/info" 2>/dev/null || echo '(no answer)')"
        cli getblockchaininfo | grep -E '"(chain|blocks|headers|initialblockdownload)"'
        ;;
    address) cli -rpcwallet=hub getnewaddress ;;
    balance) cli -rpcwallet=hub getbalance ;;
    coins)
        cli -rpcwallet=hub listunspent 0 | tr -d ' ",' | awk -F: '$1=="address"{a=$2} $1=="amount"{v=$2} $1=="confirmations"{print a"  "v" BTC  ("$2" conf)"}'
        ;;
    fund)
        addr="$(cli -rpcwallet=hub getnewaddress)"
        cli -rpcwallet=miner sendtoaddress "$addr" "${2:?amount in BTC}"
        ;;
    cli) shift; cli "$@" ;;
    *) sed -n '2,9p' "$0"; exit 1 ;;
esac
