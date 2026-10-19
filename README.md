# lichen

**L**2 **I**n **CH**annels, **EN**forced on Bitcoin.

## Introduction

CAVEAT: Do not use with real money. Currently missing a number of features that could bring that within reach, and more importantly, the code is unaudited either by humans or LLMs, all written by one LLM with only peripheral oversight by me.

To follow an evolving tradition: the Introduction section here, is written by me. Most of the lower level documentation and instructions are LLM generated.

Choose your adventure:

*New to the concept and want to understand it* - read this short intro, then go to the main [design paper](./papers/lichen-v0.1.1.pdf)

*Want to run the web demo* - that is, running the stack on regtest locally and playing with it in the browser to see how it operates: go [here](#the-demo).

*Want to understand the mechanics, in more detail than covered in the paper* - look at the growing set of [explainers](./docs/explainers/README.md); these are AI generated and have lots of nice diagrams to take you through the steps of, e.g. the dispute mechanism onchain, the ZKP, etc.

### General concepts in a few words

A layer 2 ledger whose tokens a hub issues, each user's holdings up to a cap collateralised in her own contract with the hub, and withdrawable on Bitcoin without trusting the hub for anything: not its honesty, not its liveness. A withdrawal is a
return of tokens to the hub on the ledger; the hub pays it out in btc in the contract, on the bitcoin blockchain, cooperatively, and if it refuses (or is gone), the user proves the return (RISC Zero, wrapped in Groth16) and enforces it on Bitcoin by BitVMX's search over a Groth16 verifier. No change to Bitcoin is needed.

The contracts and the dispute machinery are in [ln-gap](https://github.com/AdamISZ/ln-gap) (`crates/apps/sessions`); think of that as the backend including both all the bitcoin side and also all the ZKP dispute management side. This repository is the software the parties run.

### A few operational details that are mostly PoC limitations

Worth mentioning these as idiosyncracies: first, this was built without a user-side bitcoin wallet as that's probably the right choice anyway: you fund an intermediate joint-control address and then from there the contract is funded. Explained in the procedures below. Second: in case you actually want to test *disputes*, and not normal usage, you'll have to create proofs to do withdrawals. The instructions are [here](#disputes-on-the-real-statement), and note that this involves running a proving step on x86 architecture that might take about 5 minutes. Notably, this step is partly delegatable but it will remain a point of interest in making this a usable system.

### Things not implemented yet:

* Any L2 consensus development. No finality through publishing roots on bitcoin; no distribution of the sequencer (just a single entity's key). See the [paper](./papers/lichen-v0.1.1.pdf) for discussion of what could be done here.
* Any watchtower infrastructure: a turnkey deployment for a VPS (like a docker instance), that a user could deploy at the time when a dispute occurs.
* Shielded instead of transparent notes on the L2. This is the intended first application of the idea.

### High level plan of work to do:

* Completing documentation of all the internal steps for normal operation and dispute, in the Bitcoin contracts

* Building extra support functionality - a turnkey watchtower, so there is a realistic path for a constrained user to dispute correctly.

* Creating a useful feature for the L2: shielded transfers.

* Making the ZKP prove validity and not only sequencer authorization.

* Creating a commitment mechanism (seals) for the L2 sequencer to gain finality from the Bitcoin chain (on a slower timescale)

* As per the above, but further strengthening against malicious or disruptive sequencer behavior.

* LONG TERM: potential replacement of BitVMX with a BABE-style construction.

-------

## Components

| crate | binary | who runs it |
|---|---|---|
| `ledger` | | everyone: notes, transfers, mints, signed roots (the withdrawal statement's own data structures) |
| `sequencer` | `lichen-sequencer` | the L2's sequencer: orders transactions, seals and signs heights |
| `l2` | | wallet and hub: the sequencer's API and its client |
| `wallet` | `lichen` | the user |
| `chain` | | each party: its own bitcoind wallet over RPC |
| `proto` | | wallet and hub: the opening messages, the contract record |
| `hub` | `lichen-hub` | the hub: opens contracts, issues tokens, folds withdrawals, answers disputes |
| `demo` | `lichen-demo` | a local web demo of all of the above |

## The demo

```sh
cargo build --release -p lichen-demo
./target/release/lichen-demo        # then open http://127.0.0.1:18330
```

It starts its own regtest bitcoind (`bitcoind` on the PATH, or
`LNGAP_BITCOIND`), the sequencer, a hub and two wallets, opens a contract
each for Alice and Bob (2M sats deposited, a cap of about 16.8M
sats), and mines a block a second. Four panes: Alice and Bob (balances,
address, send, withdraw), the ledger (what the sequencer ordered and
sealed, and what happened on Bitcoin), and the hub (its contracts,
headroom, and two switches). Pay each other, withdraw cooperatively, then
switch the hub to refuse withdrawals and dispute true claims, and
withdraw: the dispute plays out move by move (about a minute). Disputes
run on the mock statement set so that every claim is true (the
contract's memo check still applies), a stand-in for the proof of the
return that the real statement checks.

## Running a sequencer or a hub

The sequencer and the hub are separate parties, deployed separately,
normally on different machines. Each has its own Docker image, settings
and data, and its own guide:

- [Running a sequencer](docs/RUN_A_SEQUENCER.md): the L2's sequencer.
  It has no node and no coins, and needs only the hub's key.
- [Running a hub](docs/RUN_A_HUB.md): the hub and its Bitcoin node. It
  reaches the sequencer by URL. The guide also covers setting the two up
  together, and what testers need.

A user whose withdrawal is refused can hand the dispute to a machine she
rents, a tower that proves and plays it while she is away:
[Running a tower](docs/RUN_A_TOWER.md).

[deploy/README.md](deploy/README.md) lays out the files.

## Try it

Each deployment has its own keys, made on first start: the hub's L2 key
(it mints; returns are paid to it) and its contract seed, in the hub's
data directory, and the sequencer's key. The withdrawal statement takes
the keys as input and its journal commits to them (the deployment id),
so one guest serves every deployment; each contract checks its own.

```sh
cargo build
./target/debug/lichen-hub --dir hub-data --print-key          # the hub's L2 key
./target/debug/lichen-sequencer --ledger ledger.json --issuer <that key> &
./target/debug/lichen-hub --dir hub-data --rpc-url ... --cookie ... &
./target/debug/lichen --wallet alice.json init                 # pins the deployment
./target/debug/lichen --wallet alice.json balance
```

A wallet pins the deployment the sequencer announces when it is made,
and won't open a contract with a hub in another.

## Networks, and no wallet of the user's

`--network regtest|mutinynet|signet|testnet4` (hub and wallet): each a
whole profile, the addresses and the contracts' timing in blocks (see
[docs/TESTNET_PLAN.md](docs/TESTNET_PLAN.md)). The hub runs a node and
its wallet. The user runs neither: `lichen` reads Bitcoin from an
Esplora server (`--esplora`, by default the network's public one) and
holds keys, not coins. Opening a contract:

```sh
lichen --network mutinynet --wallet alice.json open 400000 --payout <an address of yours>
# pay 571000 sats to tb1p... (from any wallet, or a faucet); it waits
```

The deposit address is the hub's and yours together, or yours alone
after about a day: if the contract never opens, `lichen refund
<contract>` takes it back. It carries `D + r_A`, a share of the funding
fee, and a fee budget for a dispute, which the funding transaction pays
to a key of yours; `lichen sweep-fees <contract>` returns what is left
once the contract is closed. Withdrawals and dispute payouts go to the
payout address. `--toy` (sequencer and
hub) runs the toy deployment instead, whose keys anyone can derive
(`lngap-toy/sequencer`, `lngap-toy/hub`): the tests and the demo use it,
so that a proof made in advance is valid for them.

## Disputes on the real statement

A withdrawal the hub refuses is enforced with a proof of the return, made
with RISC Zero and wrapped in Groth16 (the wrap runs on x86 Linux). On
branch `shielded` the proof also shows that the return's root ends a valid
history, with the sequencer's chain receipt at its height
([SHIELDED_PLAN.md](docs/SHIELDED_PLAN.md), phase 2):

```sh
# 1. the claim: the return note, its path, the sequencer's signed root;
#    and the chain receipt at that root's height
lichen --wallet alice.json withdraw-input <memo> > withdraw-input.json
lichen --wallet alice.json chain-receipt <memo> chain.receipt
# 2. on x86 Linux with Docker, lichen-r0 (r0/host; or the prover image,
#    docker build -f r0/Dockerfile -t lichen-r0 ., with r0/withdraw-prover.sh,
#    which gives it the host's Docker for the wrap). 4 vCPUs, 32 GB: 6 min
#    to prove, 4.5 to wrap
lichen-r0 claim withdraw-input.json chain.receipt claim.hex
#    (on a Mac, r0/withdraw-prover.sh withdraw ... proves the STARK only)
# 3. the dispute, on the Groth16 verifier
lichen --wallet alice.json --statement groth16 dispute <contract> <amount> --input claim.hex
```

`--statement groth16` finds BitVMX's verifier in the cargo checkout (by
its SHA-256; `LICHEN_VERIFIER_ELF` overrides). The wallet checks the
claim's words against the contract (memo, image id, deployment, journal
length) before escalating; a dispute in progress resumes
when the command is run again (`lichen dispute <contract>`).

