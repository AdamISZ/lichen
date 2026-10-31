#!/usr/bin/env bash
# A smoke test of a running regtest deployment (COMPOSE_PROFILES=regtest):
# a user's wallet, as a one-off container on the deployment's compose
# network, opens a contract (its deposit paid from the miner's coins),
# waits for the deposit to be minted on the L2, withdraws cooperatively,
# and checks the payout address received it.
#   deploy/smoke.sh              (deploy/.env, or ENV_FILE)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file="${ENV_FILE:-$here/.env}"
# shellcheck disable=SC1090
. "$env_file"
[ "$NETWORK" = regtest ] || { echo "the smoke test is for regtest" >&2; exit 1; }
export R0WORK="${R0WORK:-$here/state/$NETWORK/r0work}"
dc() { docker compose --env-file "$env_file" -f "$here/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli -datadir=/data "$@"; }
ops() { ENV_FILE="$env_file" "$here/lichen.sh" "$@"; }
smoke="$here/state/regtest/smoke"
w=/w/smoke-$$.json
wallet() {
    dc run --rm --no-deps -T -v "$smoke:/w" -v "$here/state/regtest/bitcoind:/bitcoind:ro" --entrypoint lichen hub \
        --network regtest --wallet "$w" --sequencer http://sequencer:18300 --hub http://hub:18310 \
        --rpc-url http://bitcoind:8332 --cookie /bitcoind/regtest/.cookie --chain-wallet smoke --statement "${STATEMENT:-babe}" "$@"
}
mkdir -p "$smoke"

# the sequencer first: a new ledger waits for its wallet's funds (for the
# genesis seal), and the hub, which makes its wallet when it starts, waits
# for the sequencer
echo "== the sequencer's and the hub's funds"
until cli -rpcwallet=miner getbalance >/dev/null 2>&1; do sleep 2; done
if [ "${ANCHOR:-on}" != off ]; then
    until cli -rpcwallet="${ANCHOR_WALLET:-sequencer}" getbalance >/dev/null 2>&1; do sleep 2; done
    [ "$(cli -rpcwallet="${ANCHOR_WALLET:-sequencer}" getbalance | cut -d. -f1)" -ge 1 ] || ops fund 1 "${ANCHOR_WALLET:-sequencer}" >/dev/null
fi
until cli -rpcwallet=hub getbalance >/dev/null 2>&1; do sleep 2; done
[ "$(cli -rpcwallet=hub getbalance | cut -d. -f1)" -ge 5 ] || { ops fund 10 >/dev/null; sleep 5; }
cli -rpcwallet=hub getbalance

echo "== the sequencer and the hub answer"
until curl -fsS "http://127.0.0.1:${SEQUENCER_PORT:-18300}/info" >/dev/null 2>&1; do sleep 2; done
until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HUB_PORT:-18310}/" || true)" != 000 ]; do sleep 2; done

echo "== a wallet, pinned to the deployment"
wallet init
payout="$(cli -rpcwallet=miner getnewaddress)"

echo "== open: pay the deposit when it is asked for"
log="$(mktemp)"
wallet open 400000 --payout "$payout" > "$log" 2>&1 &
opener=$!
until grep -q "^pay " "$log"; do
    kill -0 "$opener" 2>/dev/null || { cat "$log"; exit 1; }
    sleep 1
done
read -r _ amount _ _ addr < <(grep "^pay " "$log")
echo "paying $amount sats to $addr"
cli -rpcwallet=miner sendtoaddress "$addr" "$(printf '%d.%08d' $((amount / 100000000)) $((amount % 100000000)))" >/dev/null
wait "$opener" || { cat "$log"; exit 1; }
cat "$log"
cid="$(grep -o '^contract [0-9]*' "$log" | cut -d' ' -f2)"

echo "== minted on the L2"
for _ in $(seq 60); do
    [ "$(wallet balance | head -1 | cut -d" " -f1)" -ge 400000 ] && break
    sleep 2
done
wallet balance

echo "== withdraw 300000 cooperatively"
wallet withdraw "$cid" 300000
sleep "$((MINE_EVERY + 3))"
got="$(cli -rpcwallet=miner listreceivedbyaddress 0 | grep -A3 "\"$payout\"" | grep amount | tr -dc '0-9.')"
echo "the payout address received $got BTC (300000 sats and the reserve)"
[ "$got" = "0.00320000" ] || { echo "FAIL" >&2; exit 1; }
echo "OK"
