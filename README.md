# lichen

**L**2 **I**n **CH**annels, **EN**forced on Bitcoin.

## Introduction

CAVEAT: Do not use with real money. Most importantly, the code is unaudited either by humans or LLMs, all written by one LLM with only peripheral oversight by me.

To follow an evolving tradition: the Introduction section here, is written by me. Most of the lower level documentation and instructions are LLM generated.

Just want the idea, no maths, no complex diagrams, no code or demo or blah blah? [Here you go](docs/1000-ft-view.md).

Choose your adventure:

*Want the full design* - read this short intro, then go to the main [design paper](./papers/lichen-v0.4.0.pdf)

*Want to run the web demo* - that is, running the stack on regtest locally and playing with it in the browser to see how it operates: go [here](#the-demo).

*Want to understand the mechanics, in more detail than covered in the paper* - look at the growing set of [explainers](./docs/explainers/README.md); these are AI generated and have lots of nice diagrams to take you through the steps of all the component parts. They vary from completely high level with no code/math to the guts of the dispute mechanism, the ZKP generation etc.

### General concepts in a few words

A layer 2 ledger whose tokens a hub issues, each user's holdings up to a cap collateralised in her own contract with the hub, and withdrawable on Bitcoin without trusting the hub for anything: not its honesty, not its liveness. A withdrawal is a return of tokens to the hub on the ledger; the hub pays it out in btc in the contract, on the bitcoin blockchain, cooperatively, and if it refuses (or is gone), the user proves the return (RISC Zero, wrapped in Groth16) and enforces it on Bitcoin with a verification gadget (currently using a variant of BABE, but BitVMX is also built) over a Groth16 verifier. No change to Bitcoin is needed. In case you didn't spot the point: the tokens *are* bitcoin because of the 1-1 backing, permissionlessly claimable.

The contracts and the dispute machinery are in [ln-gap](https://github.com/AdamISZ/ln-gap) (`crates/apps/sessions`); think of that as the backend including both all the bitcoin side and also all the ZKP dispute management side. This repository is the software the parties run.

### A few operational details that are mostly PoC limitations

Worth mentioning these as idiosyncracies: first, this was built without a user-side bitcoin wallet as that's probably the right choice anyway: you fund an intermediate joint-control address and then from there the contract is funded. Explained in the procedures below. Second: in case you actually want to test *disputes*, and not normal usage, you'll have to create proofs to do withdrawals. The instructions are [here](#disputes-on-the-real-statement), and note that this involves running a proving step that might take about 5 minutes. Notably, this step is delegatable, and that is addressed with the idea of [watchtowers](docs/RUN_A_TOWER.md).

### High level plan of work to do:

* Completing documentation of all the internal steps for normal operation and dispute, in the Bitcoin contracts. (Ongoing as the design is not yet 100% bedded down)

* Building extra support functionality - a turnkey watchtower, so there is a realistic path for a constrained user to dispute correctly. Note that this is now **keyless** using the BABE verification gadget. :white_check_mark:

* Creating a useful feature for the L2: shielded transfers. :white_check_mark:

* Making the ZKP prove validity and not only sequencer authorization. :white_check_mark:

* Creating a commitment mechanism (seals) for the L2 sequencer to gain finality from the Bitcoin chain (on a slower timescale) :white_check_mark:

* As per the above, but further strengthening against malicious or disruptive sequencer behavior. :white_check_mark: (see the [exit explainer](docs/explainers/exit.md))

* Replacement of BitVMX with a BABE-style construction. Done; vastly improves the onchain dispute case scalability. :white_check_mark:

Note that what is still to do is related to L2 security guarantees/claims; the Lichen part is already complete.

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

Deploying a watchtower for handling disputes is in [running a tower](docs/RUN_A_TOWER.md).

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

A withdrawal the hub refuses is enforced with a proof of the return, made
with RISC Zero and wrapped in Groth16. The proof also shows that the
return's root ends a valid history, with the sequencer's chain receipt
at its height, and that the root is anchored on Bitcoin
([Shielded transfers](docs/SHIELDED.md)). It is made with `lichen-r0`:

```sh
cargo build --release --manifest-path r0/Cargo.toml -p lichen-r0
```

on Linux, or on a Mac with Xcode and its Metal toolchain
(`xcodebuild -downloadComponent MetalToolchain`; build with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`). Either way
it proves on the CPU, and the wrap runs RISC Zero's prover image on
Docker, its files in `RISC0_WORK_DIR`. On a Mac, set that to a directory
under your home folder, which Docker Desktop shares. The proof needs no
secret of the user's, so anyone can make it for her.

### Under BABE

With `--statement babe` (the hub's too), the proof also covers the hub's
signature on the amount, which the hub gives only when it responds on
chain. So the dispute has two steps. First, `lichen dispute <contract>
<amount>` requests, waits for the hub's `respond`, writes its signature
to `<wallet>.d/babe-<contract>/hub-auth.json` and stops: the proof is
due by `T_A`, shortly before the contract closes (on Mutinynet, a week
after it opened). Then:

```sh
lichen --wallet alice.json withdraw-input <contract> > withdraw-input.json
lichen --wallet alice.json chain-receipt <contract> chain.receipt
# a minute or so to prove and two to wrap on an M4 Pro laptop (est.);
# 11 and 4 minutes on a 4-vCPU server
lichen-r0 babe-claim withdraw-input.json alice.d/babe-<contract>/hub-auth.json chain.receipt claim.hex
lichen --wallet alice.json --statement babe dispute <contract> --input claim.hex
```

Or, with the proof made, hand the rest to a tower: `lichen export-dispute
<contract> --input claim.hex --out package.json`
([Running a tower](docs/RUN_A_TOWER.md)). The wallet checks the claim's
journal and verifies its proof before it asserts. If the hub challenges
a true claim, the wallet (or the tower) answers it from the garbled
circuits kept when the contract opened ([a true claim challenged, on
Mutinynet](docs/explainers/babe-challenged.md)). If the operator won't
even take the return on the L2, the wallet exits instead: `lichen exit
<contract>` ([the exit](docs/explainers/exit.md)).

### Under BitVMX

BitVMX, lichen's first gadget, is still built. Its proof covers the
amount itself, so it is made before the dispute starts:

```sh
lichen --wallet alice.json withdraw-input <memo> > withdraw-input.json
lichen --wallet alice.json chain-receipt <memo> chain.receipt
# 6 minutes to prove and 4.5 to wrap on a 4-vCPU server
lichen-r0 claim withdraw-input.json chain.receipt claim.hex
lichen --wallet alice.json --statement bitvmx dispute <contract> <amount> --input claim.hex
```

`--statement bitvmx` finds BitVMX's verifier in the cargo checkout (by
its SHA-256; `LICHEN_VERIFIER_ELF` overrides). The wallet checks the
claim's words against the contract (memo, image id, deployment, journal
length) before escalating; a dispute in progress resumes when the
command is run again (`lichen dispute <contract>`).
