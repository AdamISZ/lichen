# Running a lichen sequencer

The sequencer orders the L2's transactions, applies them to the ledger,
and every few seconds seals a height: it signs the state root. Wallets
and the hub talk to it over HTTP. It is a separate party from the hub,
and runs on its own machine: this guide is all it needs.
[RUN_A_HUB.md](RUN_A_HUB.md) is the hub's.

What the sequencer is trusted for: the L2's finality, inclusion and
availability. Nothing else: every client checks each signed root, and a
withdrawal's proof checks the sequencer's signature on the root it uses.

It has no chain. It runs no Bitcoin node and holds no coins, and it never
runs a dispute. It needs one fact from the hub: the hub's L2 key, which
it treats as the only key allowed to mint.

## A machine

Linux, x86-64 or arm64, with Docker (Compose v2). The image compiles a
small part of the Rust tree, so 2 GB of memory and a few GB of disk for
the build are enough. Running it takes little. Open one port, 18300 by
default, to the hub and to the testers' wallets.

## 1. Build

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
cd lichen && cp deploy/sequencer/.env.example deploy/sequencer/.env
deploy/sequencer/build.sh
```

This builds the image `lichen-sequencer:latest`, from committed sources
only: lichen's HEAD, and ln-gap at the commit in `LNGAP_REV`. lichen's
workspace refers to ln-gap by path, so the checkout must be there, but
the sequencer uses only the withdrawal statement's data structures from
it.

## 2. Configure: the hub's key

Ask the hub's operator for the hub's L2 key: 64 hex characters, from
`deploy/hub/hub.sh key` on their machine ([RUN_A_HUB.md](RUN_A_HUB.md),
step 2). Set it in `deploy/sequencer/.env`:

| setting | what |
|---|---|
| `NETWORK` | the hub's network (`regtest`, `mutinynet`, `signet`, `testnet4`). A label only: it names the data directory and the compose project. |
| `ISSUER` | the hub's L2 key |
| `SEAL_EVERY` | seconds between sealed heights (default 5) |
| `SEQUENCER_PORT` | the published port (default 18300) |

## 3. Run

```sh
docker compose -f deploy/sequencer/docker-compose.yml up -d
deploy/sequencer/sequencer.sh info
```

On first start the sequencer makes its key. `info` prints:

- its key and the hub's;
- the **deployment id**, which commits to both keys.

The withdrawal statement takes these keys as input, so a contract and
its disputes are bound to this deployment.

Give the hub's operator and the testers the sequencer's URL,
`http://<this host>:18300`, and its key. A wallet pins the deployment the
first time it connects (`lichen init`), and the hub pins it on its first
start. If they check the key against the one you sent, the first contact
can't be spoofed.

## Keeping it

Everything is in `deploy/sequencer/data/<network>/`:

| file | what |
|---|---|
| `sequencer.key` | the sequencer's signing key. **Secret.** Losing it ends the deployment: a new key is a new deployment, and every wallet and the hub refuse it. |
| `ledger.json` | the ledger: every note, nullifier and sealed height. Written after every change. Losing it loses the L2's state. |

Back up both. Nothing else in this setup protects the ledger: it has a
single copy, and no roots are published to Bitcoin yet (README, "Things
not implemented yet").

Day to day:

```sh
deploy/sequencer/sequencer.sh heights     # sealed heights, notes, spent
deploy/sequencer/sequencer.sh logs        # follow its log
docker compose -f deploy/sequencer/docker-compose.yml restart
```

To update: pull, `deploy/sequencer/build.sh`, then
`docker compose -f deploy/sequencer/docker-compose.yml up -d`. The key
and the ledger carry over.

If the sequencer keeps restarting, check its log. The usual
cause is a changed `ISSUER`: a ledger belongs to one deployment, and the
sequencer refuses to open it for another hub.

## Several on one machine

Each network gets its own data directory and compose project. To run a
second sequencer beside the first, give it its own env file with another
`NETWORK` and port:

```sh
docker compose --env-file my-regtest.env -f deploy/sequencer/docker-compose.yml up -d
ENV_FILE=my-regtest.env deploy/sequencer/sequencer.sh info
```

Not here yet: TLS (test coins only); more than one hub per sequencer.
