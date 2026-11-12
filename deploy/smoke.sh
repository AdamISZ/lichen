#!/usr/bin/env bash
# A smoke test of a running regtest deployment (COMPOSE_PROFILES=regtest):
# a user's wallet, as a one-off container on the deployment's compose
# network, opens a contract with inbound liquidity (its deposit paid from
# the miner's coins), finds the deposit less the hub's fee issued to it as
# a note, withdraws cooperatively (in the contract's units), and checks the
# payout address received it.
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
        --network regtest --wallet "$w" --hub http://hub:18310 \
        --rpc-url http://bitcoind:8332 --cookie /bitcoind/regtest/.cookie --chain-wallet smoke --statement "${STATEMENT:-hub-proves-mock}" "$@"
}
mkdir -p "$smoke"

echo "== the hub's funds"
until cli -rpcwallet=miner getbalance >/dev/null 2>&1; do sleep 2; done
until cli -rpcwallet=hub getbalance >/dev/null 2>&1; do sleep 2; done
[ "$(cli -rpcwallet=hub getbalance | cut -d. -f1)" -ge 5 ] || { ops fund 10 >/dev/null; sleep 5; }
cli -rpcwallet=hub getbalance

echo "== the hub answers"
until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HUB_PORT:-18310}/" || true)" != 000 ]; do sleep 2; done

echo "== a wallet, pinned to the deployment"
wallet init
payout="$(cli -rpcwallet=miner getnewaddress)"

echo "== open, with 200000 of liquidity: pay the deposit when it is asked for"
log="$(mktemp)"
wallet open 400000 --liquidity 200000 --reserve 20000 --payout "$payout" > "$log" 2>&1 &
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
minted="$(grep -o "you'll be minted [0-9]*" "$log" | grep -o '[0-9]*$')"

echo "== issued: the deposit less the hub's fee, $minted sats, a note"
wallet balance
[ "$(wallet balance | awk 'NR == 1 {print $1}')" = "$minted" ] || { echo "FAIL: not $minted issued" >&2; exit 1; }

echo "== withdraw 300000 cooperatively (rounded down to the contract's unit)"
wlog="$(mktemp)"
wallet withdraw "$cid" 300000 | tee "$wlog"
withdrawn="$(grep -o '^withdrew [0-9]*' "$wlog" | cut -d' ' -f2)"
[ -n "$withdrawn" ] || { echo "FAIL: no withdrawal" >&2; exit 1; }
sleep "$((MINE_EVERY + 3))"
got="$(cli -rpcwallet=miner listreceivedbyaddress 0 | grep -A3 "\"$payout\"" | grep amount | tr -dc '0-9.')"
want="$(printf '0.%08d' $((withdrawn + 20000)))"
echo "the payout address received $got BTC ($withdrawn sats and the reserve)"
[ "$got" = "$want" ] || { echo "FAIL: expected $want" >&2; exit 1; }
echo "OK"
