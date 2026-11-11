# lichen

**L**2 **I**n **CH**annels, **EN**forced on Bitcoin.

A layer 2 ledger whose tokens a hub issues, each user's holdings up to a cap collateralised in her own contract with the hub, and withdrawable on Bitcoin without trusting the hub for anything: not its honesty, not its liveness.

## Introduction

CAVEAT: Do not use with real money. Most importantly, the code is unaudited either by humans or LLMs, almost all written by one LLM (extensively *tested* but not *audited*).

To follow an evolving tradition: the Introduction section here, is written by me, as is the [main design paper](./papers/lichen-v0.5.0.pdf) and also a no-frills, no maths or complex diagrams or algorithms description in a md file [here](docs/1000-ft-view.md). Most of the lower level documentation and instructions are LLM generated.

*Want to try it* - with a wallet, against a hub someone is running (a test network only): see [Using a wallet](#using-a-wallet). Or run your own hub and sequencer: see [Running a hub](#running-a-hub).

*Want to understand the mechanics, in more detail than covered in the paper* - look at the growing set of [explainers](./docs/explainers/README.md); these are AI generated and have lots of nice diagrams to take you through the steps of all the component parts. They vary from completely high level with no code/math to the guts of the dispute mechanism, the ZKP generation etc.

-------

## Using a wallet

A user runs only `lichen`, the wallet: no Bitcoin node, and no coins held
in it. It reads Bitcoin from the network's public Esplora server, and
talks to a running deployment's two services, its sequencer and its hub.
From the hub's operator you need their two URLs and the sequencer's key.

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
cd lichen && cargo build --release -p lichen-wallet       # target/release/lichen

alias lw='target/release/lichen --network mutinynet --wallet alice.json \
  --sequencer http://<host>:18300 --hub http://<host>:18310 --statement hub-proves'

lw init                              # a fresh key; check the sequencer key it prints
lw open 100000 --liquidity 100000    # prints the hub's fee and a deposit address to pay
lw balance
lw send <address> <amount>           # on the L2
lw ack --wait                        # a payment counts once you acknowledge it
lw withdraw <contract> <amount>      # cooperatively: a claim, and the hub folds
lw exit <contract>                   # if the hub won't: the claim on Bitcoin
```

The deposit is paid from any Bitcoin wallet or faucet, and withdrawals go
to an address of yours. Opening uploads about 240 MB (the garbled
circuits the hub keeps). Shielded payments need a prover for the spend
guest. [Using a wallet](docs/USE_A_WALLET.md) has every step, and what
each costs and waits for.

## Running a hub

In our example L2, the hub runs its own sequencer. [Running a
hub](docs/RUN_A_HUB.md) deploys the Bitcoin node, the sequencer (with
its chain prover) and the hub, with Docker Compose, and makes them
reachable to users: one deployment per network, its keys made on first
start. To try the stack on your own machine first, on regtest:

```sh
cp deploy/.env.example deploy/.env    # set NETWORK=regtest, COMPOSE_PROFILES=regtest
deploy/build.sh
deploy/lichen.sh up
deploy/smoke.sh     # a wallet opens a contract, is minted its deposit, and withdraws cooperatively
```

The hub proves a claim false only in a dispute, with RISC Zero and a
Groth16 wrap, which needs x86 Linux with Docker and about 8 GB:
[the pipeline](docs/explainers/pipeline.md) covers it, and
[the exit](docs/explainers/exit.md) every ending of a dispute, played on
Mutinynet.

## The code

[docs/CODE.md](docs/CODE.md) maps the crates; [deploy/README.md](deploy/README.md)
the deployment's files. The private L2, with every block proved valid,
is described in [Shielded transfers](docs/SHIELDED.md). Tests run on
regtest (`cargo test`, with `bitcoind` on the PATH); `crates/hub/tests/hp_real.rs`
(opt-in, `--ignored`) proves the hub's statement for real.
