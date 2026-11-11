# Lichen as a library: plan

2026-11-11. Working notes, not built. The aim (the user, with the
lichen-ecash author): an L2 other than ours, such as ecash, reuses
Lichen's contract, gadget and exit machinery through a clean interface,
so that effort on hardening and performance lands in one place. Not
every L2 will fit everything; the interface should make most of the code
reusable for most of them.

## What is already L2-agnostic

| layer | where | what |
|---|---|---|
| the contract | ln-gap `sessions` | the skeleton (fold, default, the links' floors and anchors), the payout in units, the bit and reserve leaves |
| Bitcoin access | `chain` | a node over RPC or Esplora (several, cross-checked), fee children, terminals |
| the gadget | `babe` | garbling, VSSS, the reveal by adaptor signatures, the swapped graph (`hp`): `request`, `assert`, `challenge_assert`, the answers and terminals |
| the opening | `proto` (most of it) | terms and units, the deposit address and refund, the cut-and-choose exchange (`/hp/setup`, `/hp/commit`, uploads, opening), the pre-signed set and its checks |
| the play | wallet `engine` and hub `dispute` (the parts that move transactions) | posting links and terminals, waiting on the other side, checking an assertion, challenging, answering with a kept instance, sweeping bits and reserves |

## What an L2 must supply

1. **The claim.** Bytes posted in `request`'s witness (raw, 80-byte
   items, at most the posting budget), the user's signed `b`, and the
   digest `E` binding the claim to the contract and `b`.
2. **The deployment's identity `D`,** and whatever else the statement's
   journal must fix at opening (ours: the contract's funding coin and the
   margin).
3. **The statement:** a guest that refutes a claim, its image id fixed
   at opening. Lichen supplies the generic half (below); the L2 the
   refutation (`Ref_L`: intrinsic, signed, or stateful).
4. **The hub's side:** deciding a claim natively (holds, wait, or a
   refutation with its witness); holding claimed funds on the L2 once a
   request is seen; recording a paid claim (retiring what it claims);
   checking a cooperative withdrawal's claim before the fold; issuing the
   deposit's funds at opening, locked to the funding.
5. **The user's side:** planning a claim (which funds, up to the cap and
   the posting budget, with whatever evidence its refutations need);
   keeping what an exit needs without the operator; receiving the mint.

## The generic half of the statement

A crate the L2's guest links: read `request` (from Bitcoin, with its
inclusion and the contract's work, when the L2's refutations are
stateful; otherwise the user's one-time signatures checked directly),
take the posted claim and `b` from its witness, recompute `E`, and emit
the journal. The L2's guest then calls its own refutation on
`(claim, b, ρ, state)`.

## Coupling to cut, today

- **`babe` depends on `withdraw`** for the claim's posting format
  (`posted_items`, `POSTED_ITEM`, `POSTED_ITEMS`). The format is
  Lichen's, not the L2's: move it to `babe` or `proto`.
- **`proto` reaches into our L2:** the journal (`withdraw::hp::journal`),
  `D` (`ledger::lichen_withdraw_contract_id`, the deployment, the
  checkpoint's work), the guests' image ids, `request`'s inclusion proof
  type (`withdraw::Request`), the claim's type in a withdrawal request,
  and the mint's locked key (`ledger::mint_key`). Each becomes a type or
  a value the L2 supplies.
- **The hub's `dispute::hp` mixes the play with our L2:** `hp_decide`,
  `hp_hold`, `hp_record` and the statement's input assembly are ours;
  `hp_tick`'s state machine, `hp_assert`, `hp_proof`'s prover call,
  `hp_answer` and the collection of bits are generic. Split along that
  line, behind a trait the L2 implements.
- **The wallet's `hp` (claim planning, acknowledgments, shielded claims)
  is ours;** `engine` and `dispute` (the sweep) are generic. Its
  `Signer` and `Store` traits are already the right shape for the
  generic side.

## A sketch

```rust
/// What an L2 gives Lichen.
pub trait L2 {
    /// The deployment's identity, in the journal.
    fn deployment(&self) -> Hash;
    /// The journal's L2 part, fixed at opening.
    fn journal_extra(&self, contract: &Record) -> Vec<u8>;
    /// The hub's statement's image id.
    fn statement_id(&self) -> [u8; 32];
}

/// The hub's side.
pub trait L2Hub: L2 {
    fn issue(&self, contract: &Record, amount: u64, locked_to: &PublicKey) -> Result<Issued>;
    fn decide(&self, contract: &Record, claim: &[u8], b: u32, request: &Requested) -> Result<Decision>;
    fn hold(&self, claim: &[u8]) -> Result<()>;
    fn record(&self, contract: &Record, claim: &[u8], b: u32) -> Result<()>;
}

/// The user's side.
pub trait L2Wallet: L2 {
    fn plan_claim(&self, contract: &Record, cap_units: u32, budget: usize) -> Result<(u32, Vec<u8>)>;
}
```

`Decision` is `Holds`, `Wait(why)` or `Refute(input)`, the input the
generic prover hands the L2's guest.

## Order, if we do it

1. Move the posting format out of `withdraw` (`babe` loses that
   dependency).
2. Split the hub's `dispute::hp` into the generic play and our
   decision, behind `L2Hub`; the same in the wallet behind `L2Wallet`.
3. Make `proto`'s journal and `D` generic.
4. A second implementation, even a toy one (a transparent ledger with no
   anchors and only signed refutations), to prove the boundary: ecash's
   shape without its cryptography.

Each step is behaviour-preserving for our L2, so the regtest suites
check it. The guests are untouched until the generic statement crate,
which is a new deployment.
