#!/usr/bin/env bash
# The operator's commands for a running deployment (NETWORK from deploy/.env):
#   deploy/lichen.sh info          the deployment: the hub's and the sequencer's keys, the chain
#   deploy/lichen.sh address       an address of the hub's wallet (fund it: a faucet, or `fund`)
#   deploy/lichen.sh balance       the hub's wallet balance
#   deploy/lichen.sh coins         the hub's coins: address, amount, confirmations
#   deploy/lichen.sh fund <btc>    regtest: pay the hub from the miner's coins
#   deploy/lichen.sh cli <args>    bitcoin-cli on the deployment's node
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dc() { docker compose -f "$here/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli -datadir=/data "$@"; }

case "${1:-}" in
    info)
        echo "hub L2 key:  $(cat "$here/data/$(. "$here/.env"; echo "$NETWORK")/shared/hub.pub")"
        curl -fsS "http://127.0.0.1:${SEQUENCER_PORT:-18300}/info" | tr -d '{}"' | tr ',' '\n' | sed 's/:/:  /; s/^/sequencer says /'; echo
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
