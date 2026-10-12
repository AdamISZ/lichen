# Deploying a lichen hub

One Docker Compose deployment: a node for the network, the sequencer and
the hub. Testers run only the `lichen` wallet, on their own machines,
with no node: it reads Bitcoin from a public Esplora (mutinynet.com,
mempool.space) and is paid into, and pays out to, addresses of any
wallet they like.

## A machine

x86-64 or arm64 Linux with Docker (Compose v2). 16 GB of memory is
comfortable (the image's build compiles the Rust tree; a Groth16 wrap
service, later, needs ~10 GB); a few GB of disk for Mutinynet, more for
signet or testnet4 (`txindex`). Open the hub's and the sequencer's ports
(18310, 18300) to testers; the node's RPC stays inside the compose
network.

## Build

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
cd lichen && cp deploy/.env.example deploy/.env    # set NETWORK
deploy/build.sh
```

`build.sh` builds from committed sources only: lichen's HEAD, and ln-gap
at the commit in `LNGAP_REV` (lichen depends on ln-gap by path, so this
file is what pins it; bump it when lichen moves to a newer ln-gap). The
node image is the network's: stock Bitcoin Core 31.1 for regtest, signet
and testnet4, benthecarman's patched build (Core 25.99 with 30 s signet
blocks) for Mutinynet, each tarball pinned by SHA-256.

## Run

```sh
docker compose -f deploy/docker-compose.yml up -d          # regtest: add --profile regtest
deploy/lichen.sh info                                      # the hub's key, the deployment, the chain
deploy/lichen.sh address                                   # fund the hub here (a faucet)
```

First start: `hub-key` makes the hub's keys (`data/<network>/hub/`: its
L2 key and contract seed, secrets: back them up), the sequencer starts
with the hub's public key as its issuer and makes its own key
(`data/<network>/sequencer/`), the hub starts once the node answers. The
node syncs before the hub should open contracts: watch
`deploy/lichen.sh info` until `initialblockdownload` is false.

The hub needs coins: its share of every cap (`V_max − D` plus its
reserve). Fund `deploy/lichen.sh address` from the network's faucet
(regtest: `deploy/lichen.sh fund 10`).

## Testers

```sh
lichen --network mutinynet --wallet alice.json --sequencer http://<host>:18300 init
lichen --network mutinynet --wallet alice.json --sequencer http://<host>:18300 --hub http://<host>:18310 \
  --statement groth16 open 400000 --payout <an address of hers>
```

`init` pins the deployment the sequencer announces. `open` prints a
deposit address and an amount; she pays it from any wallet or faucet.

## Layout

| path | what |
|---|---|
| `Dockerfile` | the lichen image: `lichen-hub`, `lichen-sequencer`, `lichen`, BitVMX's verifier ELF |
| `entry.sh` | its roles: `hub-key`, `sequencer`, `hub` |
| `bitcoind/` | the node image and its `bitcoin.conf` per network |
| `docker-compose.yml`, `.env.example` | the deployment |
| `lichen.sh` | the operator's commands |
| `data/<network>/` | everything kept (not in git) |

Not here yet: TLS (test coins only), the wrap service (TESTNET_PLAN.md T4).
