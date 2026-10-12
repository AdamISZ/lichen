#!/usr/bin/env bash
# A smoke test of a running regtest deployment (`--profile regtest`): a
# user's wallet, as a one-off container on the compose network, opens a
# contract (its deposit paid from the miner's coins), waits for the
# deposit to be minted on the L2, withdraws cooperatively, and checks the
# payout address received it.
#   deploy/smoke.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/.env"
[ "$NETWORK" = regtest ] || { echo "the smoke test is for regtest" >&2; exit 1; }
dc() { docker compose -f "$here/docker-compose.yml" "$@"; }
cli() { dc exec -T bitcoind bitcoin-cli -datadir=/data "$@"; }
w=/w/smoke-$$.json
wallet() {
    dc run --rm --no-deps -T -v "$here/data/regtest/smoke:/w" -v "$here/data/regtest/bitcoind:/bitcoind:ro" --entrypoint lichen hub \
        --network regtest --wallet "$w" --sequencer http://sequencer:18300 --hub http://hub:18310 \
        --rpc-url http://bitcoind:8332 --cookie /bitcoind/regtest/.cookie --chain-wallet smoke --statement "${STATEMENT:-groth16}" "$@"
}
mkdir -p "$here/data/regtest/smoke"

echo "== the hub's funds"
[ "$(cli -rpcwallet=hub getbalance | cut -d. -f1)" -ge 5 ] || { "$here/lichen.sh" fund 10 >/dev/null; sleep 5; }
cli -rpcwallet=hub getbalance

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
    [ "$(wallet balance)" -ge 400000 ] && break
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
