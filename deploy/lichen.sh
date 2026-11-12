#!/usr/bin/env bash
# The operator's commands (deploy/.env, or ENV_FILE):
#   deploy/lichen.sh up                 start the deployment (or bring it up to date after a build)
#   deploy/lichen.sh down               stop it
#   deploy/lichen.sh info               the keys, the deployment, the L2's heights, proving and anchoring, the chain
#   deploy/lichen.sh address [wallet]   an address of the node's wallet `hub` (the hub's coins)
#   deploy/lichen.sh balance [wallet]   that wallet's balance
#   deploy/lichen.sh coins [wallet]     its coins: address, amount, confirmations
#   deploy/lichen.sh fund <btc> [wallet]  regtest: pay that wallet from the miner's coins
#   deploy/lichen.sh logs [service]     follow the logs (bitcoind, hub)
#   deploy/lichen.sh cli <args>         bitcoin-cli on the node
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file="${ENV_FILE:-$here/.env}"
# shellcheck disable=SC1090
. "$env_file"
data="$here/state/$NETWORK"
# the wrap's working files, at the same path on the host and in the hub
export R0WORK="${R0WORK:-$data/r0work}"
dc() { docker compose --env-file "$env_file" -f "$here/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli -datadir=/data "$@"; }

case "${1:-}" in
    up)
        mkdir -p "$data/bitcoind" "$data/hub" "$R0WORK"
        dc up -d
        ;;
    down) dc down ;;
    info)
        echo "hub L2 key:    $(docker run --rm -e NETWORK="$NETWORK" -v "$data/hub:/hub" "${LICHEN_IMAGE:-lichen:latest}" key)"
        echo "pinned:        $(tr -d ' \n' < "$data/hub/deployment.json" 2>/dev/null || echo "nothing yet (the hub pins the deployment on its first start)")"
        echo "hub:           $(curl -fsS "http://127.0.0.1:${HUB_PORT:-18310}/info" 2>/dev/null || echo '(no answer yet: deploy/lichen.sh logs hub)')"
        cli getblockchaininfo | grep -E '"(chain|blocks|headers|initialblockdownload)"'
        ;;
    address) cli -rpcwallet="${2:-hub}" getnewaddress ;;
    balance) cli -rpcwallet="${2:-hub}" getbalance ;;
    coins)
        cli -rpcwallet="${2:-hub}" listunspent 0 | tr -d ' ",' | awk -F: '$1=="address"{a=$2} $1=="amount"{v=$2} $1=="confirmations"{print a"  "v" BTC  ("$2" conf)"}'
        ;;
    fund)
        addr="$(cli -rpcwallet="${3:-hub}" getnewaddress)"
        cli -rpcwallet=miner sendtoaddress "$addr" "${2:?amount in BTC}"
        ;;
    logs) shift; dc logs -f "$@" ;;
    cli) shift; cli "$@" ;;
    *) sed -n '2,11p' "$0"; exit 1 ;;
esac
