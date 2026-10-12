#!/bin/sh
# Write bitcoin.conf for NETWORK and run the node (datadir /data).
#   bitcoind           the node
#   miner <seconds>    regtest only: a block every <seconds> to the
#                      `miner` wallet (after 101 to start with)
#   <anything else>    run it (e.g. bitcoin-cli ...)
set -eu
NETWORK="${NETWORK:?set NETWORK}"
conf=/data/bitcoin.conf
mkdir -p /data

common="txindex=1
server=1
fallbackfee=0.0002
rpccookieperms=all"
# per chain: RPC on 8332 inside the compose network, for every chain
section() {
    printf '[%s]\nrpcport=8332\nrpcbind=0.0.0.0\nrpcallowip=0.0.0.0/0\n' "$1"
}
case "$NETWORK" in
    regtest) printf 'regtest=1\n%s\n%s\n' "$common" "$(section regtest)" > "$conf" ;;
    signet) printf 'signet=1\n%s\n%s\n' "$common" "$(section signet)" > "$conf" ;;
    testnet4) printf 'testnet4=1\n%s\n%s\n' "$common" "$(section testnet4)" > "$conf" ;;
    mutinynet)
        # MutinyWallet/mutiny-net's .env.mutinynet, 2026-10-12
        printf 'signet=1\n%s\ndnsseed=0\n%s\nsignetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae\nsignetblocktime=30\naddnode=45.79.52.207:38333\n' "$common" "$(section signet)" > "$conf"
        ;;
    *) echo "unknown NETWORK $NETWORK" >&2; exit 1 ;;
esac

cli() { bitcoin-cli -datadir=/data "$@"; }

case "${1:-bitcoind}" in
    bitcoind)
        exec bitcoind -datadir=/data -printtoconsole
        ;;
    miner)
        [ "$NETWORK" = regtest ] || { echo "the miner is for regtest" >&2; exit 1; }
        until cli getblockchaininfo >/dev/null 2>&1; do sleep 1; done
        cli -named createwallet wallet_name=miner load_on_startup=true >/dev/null 2>&1 || cli loadwallet miner >/dev/null 2>&1 || true
        addr="$(cli -rpcwallet=miner getnewaddress)"
        [ "$(cli getblockcount)" -ge 101 ] || cli generatetoaddress 101 "$addr" >/dev/null
        while true; do cli generatetoaddress 1 "$addr" >/dev/null; sleep "${2:-5}"; done
        ;;
    *)
        exec "$@"
        ;;
esac
