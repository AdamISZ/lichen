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
