# lichen

**L**2 **I**n **CH**annels, **EN**forced on Bitcoin.

A layer 2 ledger whose tokens a hub issues, each user's holdings up to a cap collateralised in her own contract with the hub, and withdrawable on Bitcoin without trusting the hub for anything: not its honesty, not its liveness.

## Introduction

CAVEAT: Do not use with real money. Most importantly, the code is unaudited either by humans or LLMs, almost all written by one LLM (extensively *tested* but not *audited*).

To follow an evolving tradition: the Introduction section here, is written by me, as is the [main design paper](./papers/lichen-v0.5.0.pdf) and also a no-frills, no maths or complex diagrams or algorithms description in a md file [here](docs/1000-ft-view.md). Most of the lower level documentation and instructions are LLM generated.

*Want to run the web demo* - that is, running the stack on regtest locally and playing with it in the browser to see how it operates: go [here](#the-demo).

*Want to understand the mechanics, in more detail than covered in the paper* - look at the growing set of [explainers](./docs/explainers/README.md); these are AI generated and have lots of nice diagrams to take you through the steps of all the component parts. They vary from completely high level with no code/math to the guts of the dispute mechanism, the ZKP generation etc.

-------

## The demo

```sh
docker build -f r0/Dockerfile -t lichen-r0 .   # the prover image, once
cargo build --release -p lichen-demo
./target/release/lichen-demo        # then open http://127.0.0.1:18330
```

It starts its own regtest bitcoind (`bitcoind` on the PATH, or
`LNGAP_BITCOIND`), the sequencer, a hub and two wallets, opens a contract
each for Alice and Bob (2M sats deposited, a cap of about 16.8M sats),
and mines a block a second. Each deposit, once minted, is shielded.
Payments between them are shielded too, each proved for real on your
machine (RISC Zero, in Docker) and checked by the sequencer: 15 to 25
seconds a payment on a recent Mac.

Four panes. Alice and Bob each see their balance and their own notes.
The ledger shows what anyone sees: the deposits and withdrawals in full,
since they touch Bitcoin, and for each payment only its nullifiers,
commitments and proof, with no amounts or parties. Beside it, the chain
prover proves each sealed height valid from genesis as it goes, a minute
or two a height, so it runs a little behind (`--no-chain-prover` turns
it off and leaves the CPU to the payments). The hub's pane has its
contracts and two switches. To show it on a screen, open each pane in a
window of its own, larger: `/alice`, `/bob`, `/ledger` and `/hub`.

Pay each other and withdraw cooperatively. Then switch the hub to refuse
withdrawals, and withdraw: the dispute plays out on Bitcoin, BABE's, in
a few transactions. Alice requests, the hub responds, she asserts her
proof, and `success` pays her once the hub's window to challenge has
passed (about half a minute). Switch the hub to dispute true claims as
well, and it challenges: her wallet answers with one of the garbled
circuits it kept when the contract opened, and she is paid ([a true
claim challenged, on Mutinynet](docs/explainers/babe-challenged.md)).
Disputes run on BABE's mock statement, where each claim's proof is of a
toy circuit, so every claim is true (the contract's memo check still
applies). It stands in for the real withdrawal proof, which takes
a few minutes ([Disputes on the real statement](#disputes-on-the-real-statement)).

## Running a hub (and sequencer)

In our example L2, the hub runs its own sequencer for the L2.

- [Running a hub](docs/RUN_A_HUB.md): deploying the bitcoin node, hub
and sequencer and making them accessible to clients/users.

Usage for clients/users is explained in [Using a wallet](docs/USE_A_WALLET.md).

The L2 has private payments, with every block proved valid: what is
hidden, how long things take and what a dispute costs are in [Shielded
transfers](docs/SHIELDED.md).

[deploy/README.md](deploy/README.md) lays out the files;
[docs/CODE.md](docs/CODE.md) the crates, for working on lichen's code.

## Try it

The quickest look is [the demo](#the-demo). To run the stack as it is
deployed, on regtest:

```sh
cp deploy/.env.example deploy/.env    # NETWORK=regtest, COMPOSE_PROFILES=regtest
deploy/build.sh
deploy/lichen.sh up
deploy/smoke.sh     # funds the sequencer and the hub from the miner, deposits, withdraws cooperatively
```

On a test network such as Mutinynet, the hub's operator follows
[Running a hub](docs/RUN_A_HUB.md), and users run only the `lichen`
wallet ([Using a wallet](docs/USE_A_WALLET.md)), reading Bitcoin from
the network's public Esplora server: no node, and no coins held by the
wallet. Deposits are paid from any wallet or faucet; withdrawals go to
an address of any wallet.

Each deployment has its own keys, made on first start: the hub's L2 key
(it mints; returns are paid to it) and its contract seed, and the
sequencer's key. The withdrawal statement takes the keys as input and
its journal commits to them (the deployment id), so one guest serves
every deployment, and each contract checks its own. A wallet pins the
deployment the sequencer announces when it is made, and won't open a
contract with a hub in another. `--toy` (sequencer and hub) runs the toy
deployment instead, whose keys anyone can derive (`lngap-toy/sequencer`,
`lngap-toy/hub`): the tests and the demo use it, so that a proof made in
advance is valid for them.

## Disputes on the real statement

TODO (needs to be updated for 0.5)