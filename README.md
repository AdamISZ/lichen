# lichen

**L**2 **I**n **CH**annels, **EN**forced: a layer 2 ledger whose tokens a
hub issues, each user's holdings up to a cap collateralised in her own
contract with the hub, and withdrawable on Bitcoin without trusting the
hub for anything: not its honesty, not its liveness. A withdrawal is a
return of tokens to the hub on the ledger; the hub pays it out
cooperatively, and if it refuses (or is gone), the user proves the return
(RISC Zero, wrapped in Groth16) and enforces it on Bitcoin by BitVMX's
search over a Groth16 verifier. No change to Bitcoin is needed.

The protocol and its proof of concept are in
[ln-gap](../ln-gap) (the LN-GAP v3 paper, `crates/apps/sessions`); this
repository is the software the parties run.

Amounts are in sats throughout: what the ledger carries is bitcoin, not
a separate asset.

## Components

| crate | binary | who runs it |
|---|---|---|
| `ledger` | | everyone: notes, transfers, mints, signed roots (the withdrawal statement's own data structures) |
| `sequencer` | `lichen-sequencer` | the L2's sequencer: orders transactions, seals and signs heights |
| `wallet` | `lichen` | the user |
| `chain` | | each party: its own bitcoind wallet over RPC |
| `proto` | | wallet and hub: the opening messages, the contract record |
| `hub` | `lichen-hub` | the hub: opens contracts, issues tokens, folds withdrawals, answers disputes |
| `demo` | `lichen-demo` | a local web demo of all of the above |

## Status

Milestone 1, the ledger: a single sequencer; the hub mints; wallets pay
each other and return to the hub with a contract's memo; the wallet
builds the withdrawal statement's input for a return, checked against the
statement. Milestone 2, contracts: a wallet opens a contract with the
hub, both pre-sign every transaction a dispute could need, and the hub
mints the deposit once the funding confirms. Milestone 3, the cooperative
withdrawal: return tokens on the L2, and the hub folds the contract (the
default after `T_close` otherwise). Milestone 4, disputes: when the hub
won't fold, the wallet enforces the withdrawal on Bitcoin, the hub
daemon answering from the chain. See
[docs/PLAN.md](docs/PLAN.md).

## The demo

```sh
cargo build --release -p lichen-demo
./target/release/lichen-demo        # then open http://127.0.0.1:18330
```

It starts its own regtest bitcoind (`bitcoind` on the PATH, or
`LNGAP_BITCOIND`), the sequencer, a hub and two wallets, opens a contract
each for Alice and Bob (400,000 sats deposited, a cap of about 2.1M
sats), and mines a block a second. Four panes: Alice and Bob (balances,
address, send, withdraw), the ledger (what the sequencer ordered and
sealed, and what happened on Bitcoin), and the hub (its contracts,
headroom, and two switches). Pay each other, withdraw cooperatively, then
switch the hub to refuse withdrawals and dispute true claims, and
withdraw with Alice: the dispute plays out move by move (about a minute).
The dispute runs on the mock statement, whose true returns are a fixed
table for Alice's first contract, so in a dispute she withdraws one of
its amounts.

## Try it (regtest keys)

```sh
cargo build
./target/debug/lichen-sequencer --ledger /tmp/ledger.json &
./target/debug/lichen --wallet /tmp/alice.json init
./target/debug/lichen --wallet /tmp/alice.json balance
```

The sequencer's and the hub's keys are the regtest deployment's
(`lngap-toy/sequencer`, `lngap-toy/hub`): the withdrawal statement pins
them, so a proof made with the committed guest is valid for them only.

## Disputes on the real statement

A withdrawal the hub refuses is enforced with a proof of the return, made
with RISC Zero and wrapped in Groth16 (the wrap runs on x86 Linux):

```sh
# 1. the claim: the return note, its path, the sequencer's signed root
lichen --wallet alice.json withdraw-input <memo> > withdraw-input.json
# 2. on x86 Linux, in ln-gap/crates/apps/sessions/r0 (see WRAP_ON_LINUX.md):
scripts/linux-claim.sh withdraw-input.json claim.hex
#    (or on a Mac: lngap-r0 prove-input ... for the STARK, then wrap on Linux)
# 3. the dispute, on the Groth16 verifier
lichen --wallet alice.json --statement groth16:<path to groth16.yaml> \
  dispute <contract> <amount> --input claim.hex
```

The wallet checks the claim's words against the contract (memo, image
id, journal length) before escalating; a dispute in progress resumes
when the command is run again (`lichen dispute <contract>`).

