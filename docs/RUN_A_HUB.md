# Running a lichen hub

The hub keeps the L2's notes (its book), opens a contract on Bitcoin
with each user, takes part in every payment, pays withdrawals
cooperatively (the fold), and corrects false exit claims, proving its
correction if contested ([the design](../papers/lichen-grants.pdf)).
One operator, one deployment (`deploy/`), in one Docker Compose project
per network:

| service | what it does |
|---|---|
| `bitcoind` | the node, with the hub's wallet (`hub`) |
| `hub` | the book, the contracts, payments, folds and exits; users' wallets talk to it over HTTP ([its API](hub-api.yaml)) |
| `miner` | regtest only: a block every few seconds |

Users run only the `lichen` wallet, with no node:
[USE_A_WALLET.md](USE_A_WALLET.md).

## A machine

Linux or macOS, x86-64 or arm64, with Docker (Compose v2):

- **Memory:** 16 GB. Building the image compiles the whole Rust tree;
  the hub's proof, with its Groth16 wrap, takes about 10 GB at peak.
- **Disk:** a few GB for Mutinynet, more for signet or testnet4 (the
  node keeps a `txindex`), and about 250 MB a contract for the garbled
  instances the hub keeps.
- **Ports:** open the hub's (18310) to users. The node's RPC stays
  inside the compose network.

## 1. Build

```sh
git clone -b grants https://github.com/lichenbtc-org/lichen
cd lichen && cp deploy/.env.example deploy/.env    # set NETWORK
deploy/build.sh
```

`build.sh` builds two images, from committed sources only: lichen's HEAD
(and lichen-btc at the commit `Cargo.lock` pins).

- **`lichen`:** the hub, the prover (`lichen-r0`, through
  `lichen-hp-prover`), and the `lichen` wallet, for the smoke test.
- **`lichen-bitcoind:<network>`:** the node.
  - For regtest, signet and testnet4: stock Bitcoin Core 31.1.
  - For Mutinynet: benthecarman's patched build, the one Mutinynet's
    own node runs, with 30-second signet blocks. It relays TRUC, which
    the hub's `wrongly_challenged` answers are.
  - Each release tarball is pinned by SHA-256.

## 2. Configure

In `deploy/.env`:

| setting | what |
|---|---|
| `NETWORK` | `regtest`, `mutinynet`, `signet` or `testnet4` |
| `COMPOSE_PROFILES` | `regtest` on regtest, for the miner (a block every `MINE_EVERY` seconds); empty otherwise |
| `STATEMENT` | what an exit's dispute runs: `hub-proves-mock` (a toy circuit's proof, for trials) or `hub-proves` (the hub's statement, a real Groth16 proof checked by BABE). The image doesn't yet run the real prover for the hub, so deployments run the mock |
| `R0WORK` | where the Groth16 wrap keeps its files: an absolute path, mounted at the same path in the hub's container. Empty: `deploy/state/<network>/r0work` |
| `RESERVE_PPM`, `DURATION` | the hub's reserve (ppm of the cap), and a contract's life in blocks (empty: the network's default) |
| `FEE_PPM`, `MAX_LIQUIDITY` | what the hub charges for the liquidity a user asks (inbound: what she can receive beyond her deposit), in ppm of it, 1% by default; and the most a contract may ask, in sats. The fee is kept out of the deposit the hub mints her; the hub puts in the liquidity less the fee |
| `HUB_WALLET` | the node's wallet holding the hub's coins (`hub`) |
| `HOSTILE` | trials on test networks only: the hub refuses every cooperative withdrawal and asserts a forged proof against every exit claim, true ones too, so that users challenge and win |
| `REFUSE_FOLDS` | trials on test networks only: the hub refuses every cooperative withdrawal but asserts only against false claims |
| `HUB_PORT` | the published port (18310) |

## 3. Start

```sh
deploy/lichen.sh up
deploy/lichen.sh logs hub
deploy/lichen.sh info
```

On first start the hub makes its keys: its issuer key, which signs
every note, and the seed of its contract keys. `info` shows the issuer
key, the hub's `/info` and the node. Let the node sync before opening
contracts: wait until `initialblockdownload` is false.

## 4. Fund the hub

The hub puts up its share of every cap (`V_max − D` plus its reserve),
so it needs coins:

```sh
deploy/lichen.sh address        # pay this from the network's faucet
deploy/lichen.sh balance
deploy/lichen.sh fund 10        # regtest: from the miner's coins
```

Then give users the URL, `http://<this host>:18310`, and the issuer key
from `info`, which their wallets pin at `init`.

Wallets read the hub's offer, `GET /info`: its network and keys, its
statement, its terms (`FEE_PPM`, `MAX_LIQUIDITY`, `RESERVE_PPM`,
`DURATION`), the lichen version it runs with the commit its image was
built from (`git describe`: the tag, if it is one), and the image ids of
its guests. A wallet refuses a hub whose guests aren't its own: a
contract's statement pins them.

A wallet tells the hub what it will ask when it asks for a deposit
address, and the hub refuses one its coins couldn't fund, before the user
pays anything. The check counts all the hub wallet's coins, unconfirmed
and those held for offers pending, so keep a margin.

## What runs

**Payments.** Each payment moves the payer's and the payee's notes
together: the hub checks both, pre-signs both new notes under one
adaptor point, and releases the seed once both have signed. The hub
must be online for payments; it keeps each account's live note and the
payment that made it, in `book.json`.

**Exits.** A user whose withdrawal the hub won't fold, or whose
operator has gone, exits (`lichen exit`): she posts a claim of a note.
The hub watches the chain, and within `w_H` (two hours on Mutinynet)
either lets the claim stand, or posts its correction, citing a later
payment of hers. If she contests, it must prove the correction within
`w_H`: in the background (`lichen-hp-prover`: the STARK, then its
Groth16 wrap in RISC Zero's prover image on the host's Docker), its
files in `state/<network>/hub/hp/<contract>/`. The STARK took 179 s on
a 14-core laptop, and the wrap 264 s on a 4-vCPU x86 server.

## Keeping it

Everything is in `deploy/state/<network>/`:

| directory | what |
|---|---|
| `hub/` | the hub's keys (`l2.key`, the issuer key; `seed`, the seed every contract's keys come from); `book.json`, the L2's notes; a record per contract and per deposit; the kept garbled instances (`hp/<contract>/`, about 240 MB a contract) and the prover's files |
| `bitcoind/` | the node, and its wallet `hub` |

Back up `hub/` and the node's wallet. **Both hold secrets.** Losing the
book loses the L2's state: it has a single copy. Losing the contract
records, or a contract's kept instances, leaves the hub unable to answer
a challenge of its proof. Losing `l2.key` ends the deployment: a new key
is a new deployment, which every wallet refuses.

To update: pull, `deploy/build.sh`, then `deploy/lichen.sh up`. Keys,
book and contracts carry over. Deploy tagged versions, so that `info`
names one. A build compiles everything again whenever lichen's source
has changed, RISC Zero's libraries included, which takes a long while.
Each build leaves several GB of cache behind; `docker builder prune -f`
frees it. The services' logs are rotated (10 MB a file, three kept), so
`deploy/lichen.sh logs` shows recent history only.

An update that changes the hub's guest (`r0/guests/`) is different. A
contract's statement pins the guest it opened with, so the hub could no
longer prove a correction for a contract open across the change, and
users' wallets must change version to open new contracts. So, with
contracts open:

- stop opening contracts (lichen has no switch for it yet) and tell
  users the switch's date;
- let them withdraw, or let their contracts reach `T_close`;
- then update, and tell users the version their wallets need.

## A smoke test (regtest)

With a regtest deployment running, this runs a wallet in a one-off
container. It funds the hub from the miner, deposits, finds the deposit
issued as a note, withdraws cooperatively, and checks the payout:

```sh
deploy/smoke.sh
```

## Several networks on one machine

Each network has its own data directory and compose project
(`lichen-<network>`). Give each its own env file, with another
`NETWORK` and another port, and pass it as `ENV_FILE`:

```sh
ENV_FILE=deploy/regtest.env deploy/lichen.sh up
```

Not here yet: TLS (test coins only).
