# lichen

**L**2 **I**n **CH**annels, **EN**forced on Bitcoin.

A layer 2 ledger whose tokens a hub issues, each user's holdings up to a cap collateralised in her own contract with the hub, and withdrawable on Bitcoin without trusting the hub for anything: not its honesty, not its liveness.

## Introduction

CAVEAT: Do not use with real money. Most importantly, the code is unaudited either by humans or LLMs, almost all written by one LLM (extensively *tested* but not *audited*).

To follow an evolving tradition: the Introduction section here, is written by me, as is the [main design paper](./papers/lichen-v0.5.0.pdf) and, for this branch's L2, the [grants paper](./papers/lichen-grants.pdf). Most of the lower level documentation and instructions are LLM generated.

*Want to try it* - with a wallet, against a hub someone is running (a test network only): see [Using a wallet](#using-a-wallet). Or run your own hub: see [Running a hub](#running-a-hub).

-------

## Using a wallet

A user runs only `lichen`, the wallet: no Bitcoin node, and no coins held
in it. It reads Bitcoin from the network's public Esplora server, and
talks to a running deployment's hub.
From the hub's operator you need its URL and its key.

```sh
git clone -b grants https://github.com/lichenbtc-org/lichen
cd lichen && cargo build --release -p lichen-wallet       # target/release/lichen

alias lw='target/release/lichen --network mutinynet --wallet alice.json --hub <URL>'

lw init                              # a fresh key; check the hub's key it prints
lw open 100000 --liquidity 100000    # prints the hub's fee and a deposit address to pay
lw balance
lw address                           # yours, to be paid to (tlc1…)
lw receive                           # take payments, for a minute
lw send <address> <amount>           # on the L2, while the payee runs receive
lw withdraw <contract> <amount>      # cooperatively: a claim, and the hub folds
lw exit <contract>                   # if the hub won't: the claim on Bitcoin
```

The deposit is paid from any Bitcoin wallet or faucet, and withdrawals go
to an address of yours. Opening uploads about 240 MB (the garbled
circuits the hub keeps). [Using a wallet](docs/USE_A_WALLET.md) has every step, and what
each costs and waits for.

## Running a hub

[Running a
hub](docs/RUN_A_HUB.md) deploys the Bitcoin node and the hub, with Docker Compose, and makes them
reachable to users: one deployment per network, its keys made on first
start. To try the stack on your own machine first, on regtest:

```sh
cp deploy/.env.example deploy/.env    # set NETWORK=regtest, COMPOSE_PROFILES=regtest
deploy/build.sh
deploy/lichen.sh up
deploy/smoke.sh     # a wallet opens a contract, is minted its deposit, and withdraws cooperatively
```

The hub proves only in a dispute, with RISC Zero and a
Groth16 wrap, which needs x86 Linux with Docker and about 8 GB.

## The code

[docs/CODE.md](docs/CODE.md) maps the crates; [deploy/README.md](deploy/README.md)
the deployment's files. Tests run on
regtest (`cargo test`, with `bitcoind` on the PATH).
