# Running a lichen hub

The hub issues the L2's tokens, opens a contract on Bitcoin with each
user, pays withdrawals cooperatively (the fold), and answers disputes.
In lichen the hub also runs the L2 itself: one operator, one deployment
(`deploy/`), in one Docker Compose project per network:

| service | what it does |
|---|---|
| `bitcoind` | the node, with the hub's wallet (`hub`) and the one that pays the anchors (`sequencer`) |
| `sequencer` | orders the L2's transactions, and every few seconds seals a height: it signs the state root. Wallets and the hub talk to it over HTTP. It anchors its history on Bitcoin through the node |
| `chain-prover` | proves each sealed height valid from genesis, in order (a RISC Zero receipt per height) |
| `hub` | the contracts, folds and disputes; it checks a withdrawal against the chain prover's receipt before it folds |
| `miner` | regtest only: a block every few seconds |

Users run only the `lichen` wallet, with no node:
[USE_A_WALLET.md](USE_A_WALLET.md).

## A machine

Linux or macOS, x86-64 or arm64, with Docker (Compose v2):

- **Memory:** 16 GB. Building the image compiles the whole Rust tree;
  the chain prover proves each height on the CPU, and the hub's proof of
  a counter to an exit claim, with its Groth16 wrap, takes about 10 GB
  at peak.
- **Disk:** a few GB for Mutinynet, more for signet or testnet4 (the
  node keeps a `txindex`).
- **Ports:** open the sequencer's (18300) and the hub's (18310) to
  users. The node's RPC stays inside the compose network.

## 1. Build

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
cd lichen && cp deploy/.env.example deploy/.env    # set NETWORK
deploy/build.sh
```

`build.sh` builds two images, from committed sources only: lichen's HEAD,
and ln-gap at the commit in `LNGAP_REV`.

- **`lichen`:** the hub, the sequencer, the chain prover (`lichen-r0`,
  which also proves the hub's counters), BitVMX's Groth16 verifier ELF,
  and the `lichen` wallet, for the smoke test.
- **`lichen-bitcoind:<network>`:** the node.
  - For regtest, signet and testnet4: stock Bitcoin Core 31.1.
  - For Mutinynet: benthecarman's patched build, the one Mutinynet's
    own node runs, with 30-second signet blocks. It relays TRUC, which
    BABE's `wrongly_challenged` is.
  - Each release tarball is pinned by SHA-256.

## 2. Configure

In `deploy/.env`:

| setting | what |
|---|---|
| `NETWORK` | `regtest`, `mutinynet`, `signet` or `testnet4` |
| `COMPOSE_PROFILES` | `regtest` on regtest, for the miner (a block every `MINE_EVERY` seconds); empty otherwise |
| `STATEMENT` | what disputes run: `babe` (the real statement, on BABE) or `babe-mock`; `bitvmx` (the real statement, on BitVMX) or `bitvmx-mock` |
| `R0WORK` | where the Groth16 wrap of a counter keeps its files: an absolute path, mounted at the same path in the hub's container (the wrap runs RISC Zero's prover image on the host's Docker). Empty: `deploy/state/<network>/r0work` |
| `RESERVE_PPM`, `MAX_BITS`, `DURATION` | the hub's terms: its reserve (ppm of the cap), the largest cap (2^bits − 1 sats), a contract's life in blocks (empty: the network's default) |
| `WINDOWS` | the dispute's windows in blocks, `<user>,<hub>,<path>` (empty: the network's default; wallets refuse a user window under it). The heavy ones bound how many contracts the hub can hold safely when blocks are full |
| `SEAL_EVERY` | seconds between sealed heights (default 5) |
| `ANCHOR`, `ANCHOR_WALLET`, `ANCHOR_FEERATE` | anchoring (below): `on` by default, paid from the node's wallet `sequencer`, at 2 sat/vB. `off` runs the L2 unanchored, and a ledger started so can never be anchored |
| `HOSTILE` | trials on test networks only: the hub refuses every cooperative withdrawal and disputes every claim, true ones too, so each is played on chain to its end |
| `REFUSE_FOLDS` | trials on test networks only: the hub refuses every cooperative withdrawal but disputes only false claims |
| `HUB_PORT`, `SEQUENCER_PORT` | the published ports (18310, 18300) |

## 3. Start

```sh
deploy/lichen.sh up
deploy/lichen.sh logs sequencer
```

On first start the sequencer makes the hub's keys and its own. It then
waits for its wallet to be funded, because a new ledger's first act is
to pay its **genesis seal** (below), and logs an address to pay:

```
waiting for the sequencer's wallet (sequencer) to be funded, for its genesis seal and anchors: pay tb1q...
```

Pay it a few thousand sats from the network's faucet
(`deploy/lichen.sh fund 1 sequencer` on regtest). The sequencer then
starts, and the hub, which waits for it, starts too. On its first start
the hub pins the deployment, the sequencer's key and its own, in
`state/<network>/hub/deployment.json`, and refuses any other sequencer
after that.

```sh
deploy/lichen.sh info
```

shows the keys, the deployment, the heights sealed and proved, the
anchoring wallet's balance, and the node. Let the node sync before
opening contracts: wait until `initialblockdownload` is false.

## 4. Fund the hub

The hub puts up its share of every cap (`V_max − D` plus its reserve),
so it needs coins:

```sh
deploy/lichen.sh address        # pay this from the network's faucet
deploy/lichen.sh balance
deploy/lichen.sh fund 10        # regtest: from the miner's coins
```

Then give users the two URLs, `http://<this host>:18300` (the
sequencer) and `http://<this host>:18310` (the hub), and the sequencer's
key from `info`, so they can check the deployment their wallet pins.

## What runs

**The sequencer** is trusted for the L2's inclusion and availability,
and nothing else: every client checks each signed root, the chain
prover proves every height valid, and anchoring makes a second history
impossible to use. Shielded transactions carry a RISC Zero receipt of
the spend guest, which it checks against the committed guest's image
id; it never proves anything itself.

**Anchoring.** So that it can't sign two histories unseen, the
sequencer commits its history to Bitcoin:

- on a new ledger, before its first height, it pays 1,000 sats to the
  genesis seal (a P2TR output of its own key), which the deployment
  names from then on;
- whenever something has changed since the last anchor and none is in
  flight, it sends an anchor: a transaction spending the seal, making
  the next, and committing the history to the last sealed height (about
  270 vB);
- once the anchor confirms, it records it on the L2, in the next
  height's block, for the chain prover.

A withdrawal needs its return anchored, with ten blocks' work on the
anchor, so keep the `sequencer` wallet funded: a few thousand sats a day
at most on a test network. The anchor in flight is kept beside the
ledger, so a restart carries on.

**The chain prover** proves each height the sequencer records
(`ledger.json.blocks/<h>.input`), each from the last, to
`<h>.chain`, which the sequencer serves at `GET /chain/<h>`. Every
withdrawal needs the receipt at its return's height: a disputed one's
proof checks its root ends a valid history, and the hub checks the same
before it folds. A small height takes under a minute on a laptop; the
prover runs behind the seals, so a withdrawal waits for it.

**Exits.** A user whose withdrawal the hub won't fold can exit instead:
claim her notes from a state already anchored (`lichen exit`; [the
explainer](explainers/exit.md)). The hub answers each claim in its
`respond`: plainly, holding the claimed notes and recording the exit on
the L2, or with a counter, when one of the notes was spent at an
anchored state before the claim, or claimed through another contract.
On the real statement a counter is a RISC Zero proof, wrapped in
Groth16, which the hub makes itself with `lichen-r0`. The response
window `w_H` is long enough for it: two hours on Mutinynet.

## Keeping it

Everything is in `deploy/state/<network>/`:

| directory | what |
|---|---|
| `hub/` | the hub's keys (`l2.key`, `seed`, the seed every contract's keys come from); `deployment.json`; a record per contract and per deposit; the disputes' working state |
| `sequencer/` | `sequencer.key`, the sequencer's key, which also spends the seal; `ledger.json`, the L2's state; `ledger.json.blocks/`, the heights' blocks and the chain prover's receipts |
| `bitcoind/` | the node, and its wallets `hub` and `sequencer` |

Back up `hub/`, `sequencer/sequencer.key`, `sequencer/ledger.json` and
the node's two wallets. **All hold secrets.** Losing the contract
records leaves the hub unable to answer disputes. Losing the sequencer's
key ends the deployment: a new key is a new deployment, which every
wallet and the hub refuse, and the seal can no longer be spent. Losing
the ledger loses the L2's state: it has a single copy, and anchoring
commits to its history but doesn't keep its data.

To update: pull, `deploy/build.sh`, then `deploy/lichen.sh up`. Keys,
ledger and contracts carry over.

## A smoke test (regtest)

With a regtest deployment running, this runs a wallet in a one-off
container. It funds the hub and the anchors from the miner, deposits,
waits for the mint, withdraws cooperatively, and checks the payout:

```sh
deploy/smoke.sh
```

## Several networks on one machine

Each network has its own data directory and compose project
(`lichen-<network>`). Give each its own env file, with another
`NETWORK` and other ports, and pass it as `ENV_FILE`:

```sh
ENV_FILE=deploy/regtest.env deploy/lichen.sh up
```

## Moving from the two-project layout

Until 2026-10-31 the hub (`deploy/hub/`) and the sequencer
(`deploy/sequencer/`) were two compose projects, with their data in
`deploy/hub/data/<network>/` and `deploy/sequencer/data/<network>/`.
The data moves unchanged, so the deployment keeps its keys, its ledger,
its contracts and the node's wallets. For `NETWORK=mutinynet`:

```sh
# 1. stop the two projects (their compose files are gone; by name), and
#    a chain prover run by hand
docker compose -p lichen-hub-mutinynet down
docker compose -p lichen-sequencer-mutinynet down
# 2. back up the secrets, with the node stopped
mkdir -p ~/lichen-backup
cp -a deploy/hub/data/mutinynet/hub ~/lichen-backup/hub
cp -a deploy/hub/data/mutinynet/bitcoind/signet/wallets ~/lichen-backup/wallets
cp -a deploy/sequencer/data/mutinynet/sequencer.key deploy/sequencer/data/mutinynet/ledger.json ~/lichen-backup/
# 3. move the data
mkdir -p deploy/state/mutinynet
mv deploy/hub/data/mutinynet/bitcoind deploy/hub/data/mutinynet/hub deploy/state/mutinynet/
mv deploy/sequencer/data/mutinynet deploy/state/mutinynet/sequencer
# 4. one settings file
cp deploy/.env.example deploy/.env
```

In `deploy/.env`, set `NETWORK` and copy the hub's settings from
`deploy/hub/.env` (`STATEMENT`, `RESERVE_PPM`, `MAX_BITS`, `DURATION`,
`WINDOWS`, `HUB_PORT`) and the sequencer's from `deploy/sequencer/.env`
(`SEAL_EVERY`, `SEQUENCER_PORT`). Leave `R0WORK` empty. Anchoring is on,
through the same node and its wallet `sequencer`, as `anchor.yml` had
it. Then:

```sh
deploy/build.sh && deploy/lichen.sh up && deploy/lichen.sh info
```

The ports are as they were, so wallets need no change. The chain prover
carries on from the last height it proved. Anything else in the old
data directories (a trial wallet's files, the old `r0work`) stays where
it was.

Not here yet: TLS (test coins only); more than one hub per L2.
