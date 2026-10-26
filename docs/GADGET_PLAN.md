# The verification gadget, abstracted: plan

2026-10-27, branch `gadget` (lichen) and `gadget` (ln-gap).

## The goal

lichen's dispute is BitVMX: a search on the ladder, input words under
one-time keys, a jump-list tail. BABE (lichen-babe-v0.1, BABE_DISPUTE_PLAN.md)
is a second gadget for the same contract: the same funding, fold, default
and payout, a different graph behind `escalate`. The aim is to add it
without copying the parts the two share. So first, with nothing else
changing, separate those parts from BitVMX; then add BABE beside it.

## What the surveys found (2026-10-27)

**The shared parts exist, but are reached only through BitVMX.**

- ln-gap's `sessions/src/session.rs` is gadget-neutral already: `Terms`,
  `fold_leaf`, `default_leaf`, `default_outputs`, the payout
  (`payout_less`, `bit_tree`, `equiv_b_leaf`, `reserve_tree`).
- But ln-gap's `sessions/src/contract.rs` builds them inside the BitVMX
  `Contract`:
  - `tree()` hard-wires the third leaf to the ladder's `escalate`, so the
    contract's address, and with it the funding checks, the fold and
    the default, need a loaded BitVMX `Program`;
  - `presign()` builds the default, the links and the payouts in one
    BitVMX loop;
  - the link builder is private and dispatches on BitVMX names
    (`poster`, `link_wire_shape`): a link named `respond` would panic;
  - `Presign::new` and `new_multi` are private; terminal transactions
    have one input (BABE's `failure` has two).
- The payout's `b` key is "input word `b_word`" (`Contract::b_key`),
  BitVMX's layout. BABE signs `b` in `request` under its own key.

**In lichen, BitVMX is in:**

- proto:
  - `Record` and the wire (`OpenRequest`, `OpenOffer`, `Info`) carry
    `moves`, `inputs`, `hops`/`tail`, `path`, `depths`, `windows`
    (`Windows.path` is the tail's);
  - `Statement` mixes what is proved (the real withdrawal or the mock)
    with the BitVMX program (pdf, ELF, the 51-word layout);
  - `Disputed`, `move_wire`, `sign_move`, `link_name`, `tail_keys`,
    `check_request_keys`;
  - `terminal_need` and `fee_budget` are sized by BitVMX's heaviest
    terminal (`prove_*`).
- hub:
  - `dispute.rs` is the BitVMX verifier, apart from `Conceded`,
    `Collect`, `Done`, the collection of the hub's bit outputs and the
    chain helpers;
  - the reserve's floor is one constant measured from the first
    contract's BitVMX set.
- wallet:
  - `engine.rs` is the BitVMX prover around neutral helpers (`post`,
    `wait_link`, `terminal`, `paid`, `lost`);
  - the `Signer` trait mixes neutral (fees, anchor) and BitVMX (moves,
    input words, hops) secrets;
  - `dispute.rs`'s `won()` signs `b` with the input-word key, and picks
    up her anchors by BitVMX link names;
  - the tower package carries the BitVMX secrets.
- the withdrawal's journal `b ‖ c ‖ D` matches BitVMX's public input.
  BABE fixes the statement at setup, so `b` moves into the witness
  (BABE_DISPUTE_PLAN §2): a second journal, a second guest. That's
  BABE's step, not this refactor's.

## The design

### ln-gap: a skeleton under the BitVMX contract

A new module `sessions::skeleton`, gadget-neutral:

- `Core<'a>`, a borrowed view of what every contract has: `terms`,
  `params`, `pubs`. It builds:
  - `ctx()`, `value()`;
  - `tree(escalate: Leaf)`: `[fold, default, escalate]`, the third
    leaf the gadget's;
  - `fold(tree, funding, b, fee)`, `default_tx(tree, funding)`;
  - `pay_alice(b_key, available)`, `pay_hub(available)`;
  - `link(name, poster, wire_shape, prev, next)`: a link with its floor
    and its poster's anchor, the poster and the witness's shape given,
    not looked up by name.
- `Presign`, `Signed`, `sign_all`, `sig_name`, `anchor_tree(_for)`, the
  constants (`SEQ`, `FLOOR_RATE`, `ANCHOR`, `POST_CSV`) and
  `slack_vbytes`, moved from `contract.rs`, with `Presign::new` and
  `new_multi` public. (Multi-input terminals wait for BABE.)

`contract::Contract` (BitVMX) keeps its API and delegates: lichen
compiles unchanged. `contract` re-exports what moved.

**Invariant: byte-identical.** Every script, txid and sighash of the
pre-signed set and the fold is unchanged, or every open contract's
address and signatures break. A fingerprint test over the mock
contract, with the tail and windows, is written first, on today's
code, and must still pass after.

### lichen: a gadget layer

- **proto**
  - `gadget`: the enum `Gadget { BitVmx }`, what a contract's dispute
    is. Today's `Statement` stays what is proved (`Groth16` or `Mock`)
    and, for BitVMX, which program.
  - `bitvmx`: everything BitVMX moves here: `Disputed`, move and word
    wires, `link_name`, `tail_keys`, `check_request_keys`, the input
    layout, `terminal_need`.
  - `Record`: the neutral fields stay, the BitVMX ones go into a
    `BitVmxKeys { moves, inputs, tail, windows }`, flattened, so a
    record written today reads back unchanged. Likewise `OpenRequest`
    and `OpenOffer`.
  - `Record::core()` and the funding checks build the contract's tree
    through the gadget.
- **hub**
  - `dispute/mod.rs`: the tick, the neutral states (`Conceded`,
    `Collect`, `Done`), collecting the hub's bit outputs, the chain
    helpers;
  - `dispute/bitvmx.rs`: the verifier as now;
  - the floors: per gadget, not one constant.
- **wallet**
  - `engine/mod.rs` neutral, `engine/bitvmx.rs` the prover;
  - `Signer` split into neutral secrets (fees, anchor, `b`) and the
    gadget's;
  - `won()` and the anchor sweep through the gadget, not BitVMX names.

**Invariant: compatible.** Old wallet files, hub records and tower
packages load. A fixture of each, written by today's code, is
deserialized by the new code in a test.

## What the refactor doesn't do

- Change any script, transaction, message or file format.
- Add BABE: no new journal, guest, graph or keys. Those follow, on top.
- Persist the hub's dispute state (it re-emulates after a restart):
  a separate question.

## Steps

1. ln-gap, branch `gadget`:
   1. the fingerprint test, on today's code;
   2. `sessions::skeleton`, and `Contract` delegating to it; the
      fingerprint unchanged; ln-gap's offline tests pass.
2. lichen, branch `gadget`:
   1. fixtures: a `Record`, an `OpenRequest`, an `OpenOffer` and a tower
      package written by today's code, and a test that reads them;
   2. proto: `gadget` and `bitvmx` modules, the flattened `BitVmxKeys`;
      fixtures read; proto's tests pass;
   3. hub: `dispute/{mod,bitvmx}.rs`, per-gadget floors;
   4. wallet: `engine/{mod,bitvmx}.rs`, the `Signer` split, `won()`;
   5. the whole suite on regtest (`cargo test --workspace`), clippy.
3. `LNGAP_REV`: point it at ln-gap's `gadget` commit. CI checks out
   ln-gap at that revision, so it must be pushed before CI can run.
4. BABE, planned on the abstraction: below, then its own plan.

## BABE on this layer (outline)

To be written after step 2, as BABE_GADGET_PLAN.md: what it reuses
(`Core`, the payout, the link builder, `Presign`, Lamport and WOTS
checks, adaptor signatures, the neutral drivers), what it adds (its
graph and windows, an absolute deadline for `assert`, multi-input
`failure`, the label reveal, the garbler, the fixed statement's guest),
and in what order.

## Status

- [ ] 1.1 fingerprint
- [ ] 1.2 skeleton
- [ ] 2.1 fixtures
- [ ] 2.2 proto
- [ ] 2.3 hub
- [ ] 2.4 wallet
- [ ] 2.5 suite
- [ ] 3 LNGAP_REV
- [ ] 4 BABE plan
