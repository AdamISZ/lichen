# Running a lichen hub

The hub issues the L2's tokens, opens a contract on Bitcoin with each
user, pays withdrawals cooperatively (the fold), and proves false exit
claims false.
In lichen the hub also runs the L2 itself: one operator, one deployment
(`deploy/`), in one Docker Compose project per network:

| service | what it does |
|---|---|
| `bitcoind` | the node, with the hub's wallet (`hub`) and the one that pays the anchors (`sequencer`) |
| `sequencer` | orders the L2's transactions, and every few seconds seals a height: it signs the state root. Wallets and the hub talk to it over HTTP. It anchors its history on Bitcoin through the node |
| `chain-prover` | proves each sealed height valid from genesis, in order (a RISC Zero receipt per height) |
| `hub` | the contracts, folds and exits; it checks a withdrawal's claim against the ledger before it folds, and proves its statement against a false exit claim |
| `miner` | regtest only: a block every few seconds |

Users run only the `lichen` wallet, with no node:
[USE_A_WALLET.md](USE_A_WALLET.md).

## A machine

Linux or macOS, x86-64 or arm64, with Docker (Compose v2):

- **Memory:** 16 GB. Building the image compiles the whole Rust tree;
  the chain prover proves each height on the CPU, and the hub's proof
  that an exit claim is false, with its Groth16 wrap, takes about 10 GB
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
  which also proves the hub's statement, through `lichen-hp-prover`), and
  the `lichen` wallet, for the smoke test.
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
| `STATEMENT` | what an exit's dispute runs: `hub-proves` (the hub's statement, a real Groth16 proof checked by BABE) or `hub-proves-mock` (a toy circuit's proof, for trials) |
| `R0WORK` | where the Groth16 wrap of the hub's proof keeps its files: an absolute path, mounted at the same path in the hub's container (the wrap runs RISC Zero's prover image on the host's Docker). Empty: `deploy/state/<network>/r0work` |
| `RESERVE_PPM`, `DURATION` | the hub's reserve (ppm of the cap), and a contract's life in blocks (empty: the network's default) |
| `FEE_PPM`, `MAX_LIQUIDITY` | what the hub charges for the liquidity a user asks (inbound: what she can receive beyond her deposit), in ppm of it, 1% by default; and the most a contract may ask, in sats. The fee is kept out of the deposit the hub mints her, so it is paid whatever happens later; the hub puts in the liquidity less the fee |
| `SEAL_EVERY` | seconds between sealed heights (default 5) |
| `ANCHOR`, `ANCHOR_WALLET`, `ANCHOR_FEERATE` | anchoring (below): `on` by default, paid from the node's wallet `sequencer`, at 2 sat/vB. `off` runs the L2 unanchored, and a ledger started so can never be anchored |
| `ANCHOR_CONFIRMATIONS` | how deep an anchor is before the sequencer records it on the L2. Empty (the default): the network's margin, 20 on Mutinynet, 6 on mainnet, which an acknowledgment waits for; set it only to anchor deeper |
| `HOSTILE` | trials on test networks only: the hub refuses every cooperative withdrawal and asserts a forged proof against every exit claim, true ones too, so that users challenge and win |
| `REFUSE_FOLDS` | trials on test networks only: the hub refuses every cooperative withdrawal but asserts only against false claims |
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

Wallets read the hub's offer, `GET /info`: its network and deployment,
its statement, its terms (`FEE_PPM`, `MAX_LIQUIDITY`, `RESERVE_PPM`,
`DURATION`), the lichen version it runs with the commit its image was
built from (`git describe`: the tag, if it is one), and the image ids of
its guests. A wallet refuses a hub whose guests aren't its own: a
contract's statement pins them, and a wallet proves with its own.

A wallet tells the hub what it will ask when it asks for a deposit
address, and the hub refuses one its coins couldn't fund, before the user
pays anything. The check counts all the hub wallet's coins, unconfirmed
and those held for offers pending, so keep a margin.

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
- once the anchor is the margin deep (20 blocks on Mutinynet), it
  records it on the L2, in the next height's block, for the chain
  prover.

Every user's spend counts only once its sender acknowledges it against
a recorded anchor ([payments](explainers/payments.md)), so payments wait
for anchoring: keep the `sequencer` wallet funded, a few thousand sats
a day at most on a test network. The anchor in flight is kept beside
the ledger, so a restart carries on.

**The chain prover** proves each height the sequencer records
(`ledger.json.blocks/<h>.input`), each from the last, to
`<h>.chain`, which the sequencer serves at `GET /chain/<h>` (and the
last height proved, at `GET /chain`). The hub's proof against a false
exit claim stands on the receipt at the claim's state, so the prover
must not fall far behind: a small height takes under a minute on a
laptop's CPU, and a couple of seconds on a GPU.

**Exits.** A user whose withdrawal the hub won't fold, or whose
operator has gone, exits (`lichen exit`; [the
explainer](explainers/exit.md)): she claims her notes, and the hub must
prove the claim false within `w_H` (two hours on Mutinynet), or her
timeout pays her. The hub decides natively, from the L2's state and the
chain; a claim that holds it lets stand, holding the claimed notes and
recording the exit on the L2. A false one it proves false, in the
background (`lichen-hp-prover`: the STARK, then its Groth16 wrap in
RISC Zero's prover image on the host's Docker), and asserts; its files
are in `state/<network>/hub/hp/<contract>/`. Keep the machine able to
prove within `w_H`: on a 16-vCPU server a proof took about 9
minutes and its wrap 2, after its chain prover had caught up with the
claim's state.

## Keeping it

Everything is in `deploy/state/<network>/`:

| directory | what |
|---|---|
| `hub/` | the hub's keys (`l2.key`, `seed`, the seed every contract's keys come from); `deployment.json`; a record per contract and per deposit; the kept garbled instances (`hp/<contract>/`, about 240 MB a contract) and the prover's files |
| `sequencer/` | `sequencer.key`, the sequencer's key, which also spends the seal; `ledger.json`, the L2's state; `ledger.json.blocks/`, the heights' blocks and the chain prover's receipts |
| `bitcoind/` | the node, and its wallets `hub` and `sequencer` |

Back up `hub/`, `sequencer/sequencer.key`, `sequencer/ledger.json` and
the node's two wallets. **All hold secrets.** Losing the contract
records, or a contract's kept instances, leaves the hub unable to
answer a challenge of its proof. Losing the sequencer's
key ends the deployment: a new key is a new deployment, which every
wallet and the hub refuse, and the seal can no longer be spent. Losing
the ledger loses the L2's state: it has a single copy, and anchoring
commits to its history but doesn't keep its data.

To update: pull, `deploy/build.sh`, then `deploy/lichen.sh up`. Keys,
ledger and contracts carry over. Deploy tagged versions, so that `info`
names one. A build compiles everything again whenever lichen's source
has changed, RISC Zero's libraries included, which takes a long while:
the image copies the source in before building, so Docker's cache keeps
only the steps before that. Each build leaves several GB of cache behind;
`docker builder prune -f` frees it. The services' logs are rotated (10 MB
a file, three kept), so `deploy/lichen.sh logs` shows recent history only.

If the sequencer or the hub fails to accept a connection (a client
gone before it was accepted, or too many open files), it logs "the
listener stopped", listens again on the same port, and logs "listening
again". Before v0.4.4 the listener stayed closed after such an error while
the service went on running: the sequencer then sealed nothing new, and
its log repeated `seal: … Connection refused`. Restarting the service
recovers it.

An update that changes a guest (`r0/guests/`) is different. A contract's
statement pins the guests it opened with, and the chain guest proves the
whole history under its own image id, so the hub could no longer prove a
false claim false for a contract open across the change. Users' wallets
must also change version to open new contracts.
So, with contracts open:

- stop opening contracts (lichen has no switch for it yet) and tell
  users the switch's date;
- let them withdraw, or let their contracts reach `T_close`;
- then update, and tell users the version their wallets need.

A change that only tightens the ledger's rules can be made without the
wait, by keeping the old chain guest proving alongside the new: every
new block is still valid to it. lichen doesn't do this yet.

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

Not here yet: TLS (test coins only); more than one hub per L2.
