# Running a lichen hub

The hub issues the L2's tokens, opens a contract on Bitcoin with each
user, pays withdrawals cooperatively (the fold), and answers disputes.
It runs its own Bitcoin node and wallet. The L2's sequencer is a
separate party, normally on another machine
([RUN_A_SEQUENCER.md](RUN_A_SEQUENCER.md)). The hub reaches it by URL,
as a wallet does.

With a real statement (`babe` or `groth16`), the hub folds only what the user could win by dispute. It checks the withdrawal
statement natively, with the sequencer's chain receipt at the return's
height ([SHIELDED.md](SHIELDED.md)), so the sequencer must run its chain
prover.

Setting the two up together takes four steps, alternating:

1. **The hub's operator** builds, and makes the hub's key (steps 1–2 here).
2. **The sequencer's operator** starts the sequencer with that key as its
   issuer, then sends back its URL and key ([RUN_A_SEQUENCER.md](RUN_A_SEQUENCER.md)).
3. **The hub's operator** sets the URL, starts the hub, and funds it
   (steps 3–5 here).
4. **Testers** get both URLs (the end of this guide).

## A machine

Linux, x86-64 or arm64, with Docker (Compose v2):

- **Memory:** 16 GB is comfortable. Building the image compiles the
  whole Rust tree, and a Groth16 wrap service, later, needs about 10 GB.
- **Disk:** a few GB for Mutinynet, more for signet or testnet4 (the
  node keeps a `txindex`).
- **Ports:** open the hub's port, 18310 by default, to testers. The
  node's RPC stays inside the compose network.

The hub must reach the sequencer's URL. The sequencer doesn't connect
to the hub.

## 1. Build

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
cd lichen && cp deploy/hub/.env.example deploy/hub/.env    # set NETWORK
deploy/hub/build.sh
```

`build.sh` builds two images, from committed sources only: lichen's HEAD,
and ln-gap at the commit in `LNGAP_REV`.

- **`lichen-hub`:** the hub, BitVMX's Groth16 verifier ELF, and the
  `lichen` wallet, for the smoke test.
- **`lichen-bitcoind:<network>`:** the node.
  - For regtest, signet and testnet4: stock Bitcoin Core 31.1.
  - For Mutinynet: benthecarman's patched build, the one Mutinynet's
    own node runs: Core 29.2 (Inquisition) with 30-second signet blocks.
    It relays TRUC, which BABE's `wrongly_challenged` is. The earlier
    build, 25.99, refuses TRUC. To move a node off it, rebuild the image
    and recreate the `bitcoind` container. The datadir upgrades in place.
  - Each release tarball is pinned by SHA-256.

## 2. The hub's key

```sh
deploy/hub/hub.sh key
```

This makes the hub's keys on first use and prints its L2 key, 64 hex
characters: the key that mints, and that returns are paid to. Send it
to the sequencer's operator, who sets it as their `ISSUER`. They send
back the sequencer's URL and its key.

The keys are in `deploy/hub/data/<network>/hub/`: `l2.key` and `seed`,
the seed every contract's keys come from. **They are secrets: back them
up.**

## 3. Configure

In `deploy/hub/.env`:

| setting | what |
|---|---|
| `NETWORK` | `regtest`, `mutinynet`, `signet` or `testnet4` |
| `SEQUENCER_URL` | the sequencer, as the hub's container reaches it. If the sequencer is on this same machine: `http://host.docker.internal:<its port>` |
| `STATEMENT` | what disputes run: `babe` (the real statement, on BABE) or `babe-mock`; `groth16` (the real statement, on BitVMX) or `mock` |
| `RESERVE_PPM`, `MAX_BITS`, `DURATION` | the hub's terms: its reserve (ppm of the cap), the largest cap (2^bits − 1 sats), a contract's life in blocks (empty: the network's default) |
| `WINDOWS` | the dispute's windows in blocks, `<user>,<hub>,<path>`: the user's for each of her moves, the hub's for its choices, the hub's for its heavy moves (empty: the network's default; wallets refuse a user window under it). The heavy ones bound how many contracts the hub can hold safely when blocks are full (the paper's congestion table) |
| `HOSTILE` | trials on test networks only (the hub refuses it on any other): any value makes the hub refuse every cooperative withdrawal and dispute every claim, true ones too, so that each withdrawal is played on chain to its end; a valid last step whose proof doesn't come in the user's window is taken by the hub's timeout (a tower's test: [RUN_A_TOWER.md](RUN_A_TOWER.md)). Empty by default |
| `HUB_PORT` | the published port (default 18310) |
| `MINE_EVERY` | regtest only: seconds between the miner's blocks |

## 4. Run

```sh
docker compose -f deploy/hub/docker-compose.yml up -d     # regtest: add --profile regtest
deploy/hub/hub.sh info
```

The hub starts once two things are true:

- its node answers;
- the sequencer answers at `SEQUENCER_URL`. Until then its log says
  `waiting for the sequencer`.

On first start the hub checks that the sequencer's issuer is its own
key. It then pins the sequencer's key in `data/<network>/hub/deployment.json`,
and refuses any other sequencer key after that. `info` shows the pin.
Check it against the key the sequencer's operator sent.

Let the node sync before opening contracts: watch `deploy/hub/hub.sh info`
until `initialblockdownload` is false.

## 5. Fund it

The hub puts up its share of every cap (`V_max − D` plus its reserve),
so it needs coins:

```sh
deploy/hub/hub.sh address        # pay this from the network's faucet
deploy/hub/hub.sh balance
deploy/hub/hub.sh fund 10        # regtest: from the miner's coins
```

## Testers

Testers run only the `lichen` wallet, on their own machines, with no
node. It reads Bitcoin from a public Esplora server (mutinynet.com,
mempool.space). Users are paid into, and pay out to, addresses of any
wallet they like. They need both URLs:

```sh
lichen --network mutinynet --wallet alice.json --sequencer http://<sequencer host>:18300 init
lichen --network mutinynet --wallet alice.json --sequencer http://<sequencer host>:18300 --hub http://<hub host>:18310 \
  --statement babe open 400000 --payout <an address of hers>
```

`init` pins the deployment the sequencer announces. `open` prints a
deposit address and an amount, which she pays from any wallet or
faucet.

## Keeping it

Everything is in `deploy/hub/data/<network>/`:

| directory | what |
|---|---|
| `hub/` | the keys (`l2.key`, `seed`); `deployment.json`; a record per contract and per deposit asked for; the disputes' working state |
| `bitcoind/` | the node, and the hub's wallet (`hub`) |

Back up `hub/`, and the node's `hub` wallet. Both hold secrets. Losing
the contract records would leave the hub unable to answer disputes.

To update: pull, `deploy/hub/build.sh`, then `docker compose -f deploy/hub/docker-compose.yml up -d`.

## A smoke test (regtest)

With a regtest hub and its sequencer running, this runs a wallet in a
one-off container. It deposits, waits for the mint, withdraws
cooperatively, and checks the payout:

```sh
deploy/hub/smoke.sh
```

## Both on one machine

For tests, the sequencer can run beside the hub. The sequencer runs as
in its guide. Here, set `SEQUENCER_URL=http://host.docker.internal:18300`.
The two stay separate compose projects, talking through the published
port, as they would between machines. Other `NETWORK`s, with their own
ports, can run beside them: pass `--env-file` to compose, and `ENV_FILE`
to the scripts.

Not here yet: TLS (test coins only); a proving service, for users
without an x86 machine of their own.
