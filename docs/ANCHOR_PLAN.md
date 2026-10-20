# Anchoring the L2's history on Bitcoin: plan

2026-10-20, branch `shielded`. After the Mutinynet trial of the
shielded L2 with the tower (SHIELDED_PLAN.md).

## The problem

A withdrawal rests on: a return to the hub (`b`, memo `c`) in the tree
of a root the sequencer signed, and a chain receipt showing that root
ends a valid history from genesis. Valid, not unique, and not latest.
The sequencer can sign two valid histories that split at a height:

- **The receiver robbed** (a double spend): Alice pays Bob in history A
  and returns the same money to the hub in B; the sequencer continues
  only B. Bob's note is in a signed root of A, but the statement takes
  only a return, which needs a later height of A the sequencer never
  seals. Needs only the payer and the sequencer; the hub never notices.
- **The hub robbed** (inflation through a fork): both branches served,
  Alice withdraws from B and Bob from A. Each contract holds its own
  cap, so both are paid, out of the hub's collateral. The chain proof
  stops inflation within one history, not across two.

So a payment's finality at sealing is trust in the sequencer, and so is
the hub's protection from inflation.

The second threat, a sequencer that stops (balances not withdrawn by
`T_close` go to the hub by the default), and data availability are not
this plan's; anchoring is the ground a later answer to the first would
stand on (a freeze, below).

## The principle

A 10-block fork of Bitcoin at today's difficulty is unheard of and
enormously expensive. So: prove that a root was committed on Bitcoin by
the sequencer's single-use seal, from a checkpoint fixed at the
contract's opening, and allow no withdrawal until that commitment is at
least 10 blocks deep. A quasi-proof that we use the canonical history,
enforced by Bitcoin's proof of work. Start there; a freeze proof and a
counter-proof of a heavier chain can come later.

## The design

**Seal chain.** The deployment's genesis names an outpoint, the first
seal (P2TR, the sequencer's key). An anchor spends the current seal and
has outputs: the new seal (same script) and an OP_RETURN `lichen-anchor
‖ h ‖ root(h)`. Bitcoin lets the seal be spent once, so there is one
chain of anchors. OP_RETURN rather than a key tweak: the guest parses
bytes and does no curve arithmetic. It need not check the spend's
signature: Bitcoin did, and we trust its proof of work anyway.

**Anchors inside the history.** A chain of seals is linear; the roots
it commits need not be: the sequencer could anchor a root of A, then
one of B, both valid from genesis. So each anchor must extend the
history the last committed to. The way: anchors become part of the
history the chain prover proves. Once an anchor confirms, the sequencer
records it on the L2, an anchor record: the transaction, its Merkle
path, and the Bitcoin headers since the last record. The chain guest
checks:

- the headers extend the Bitcoin tip it tracks, each meeting the work
  rule (below);
- the transaction is in one of those blocks (txid, Merkle path to the
  header's root);
- it spends the seal the journal names;
- it commits a root of this history: `root(h)` at a height `h` the
  guest can check (one of the recent roots it already carries, or an
  accumulator of all roots if the window is too short).

The chain journal gains: the current seal, the last anchored height and
the Bitcoin tip (its hash and height). A history forked from A can hold
no anchor after the fork point: the only spend of the seal is A's
anchor, and it commits A's root.

**The withdrawal statement** additionally requires:

- the return at or below the last anchored height, under the chain
  receipt (the one that recorded the anchor, or any later one);
- at least `k = 10` headers on top of the anchor's block, supplied by
  the withdrawer (any Bitcoin node or Esplora has them), each meeting
  the work rule, the first's parent the anchor's block.

**The checkpoint at opening.** Bounds how far back a fake branch could
start and fixes the difficulty to compare with. The contract record
already pins its own eight deployment words of the journal
(`crates/proto/src/lib.rs`, `layout`), so `D` becomes per contract,
`H(deployment ‖ checkpoint)`, with no change to ln-gap's layout or
scripts: only the guests and the opening. The anchor's block must
descend from the checkpoint (the guest's tracked header chain passes
through it).

**The work rule.** Not Bitcoin's retargeting: each header's target at
most the checkpoint's × 4 (a week-long contract crosses at most one
retarget). Per network: on Mutinynet (a signet: blocks authorized by a
signature, the work trivial) and regtest the rule holds trivially, so
they test the mechanics, not the security. A fork test belongs on
regtest, where both sides can be mined.

**The fold.** The hub by default requires the same depth before
folding, so it still pays only what a dispute could win. A hub that
trusts its sequencer may fold sooner at its own risk.

**Receivers.** A payment is trustless once its height is anchored 10
deep. The wallet shows both: sealed, and anchored (and how deep).

**Costs.** One anchor of about 150 vB per Bitcoin block at most, only
when there's activity. A withdrawal waits for: sealing, the anchor,
its confirmation, 9 more blocks, the anchor record proved. About two
hours on mainnet at best; minutes on Mutinynet. It must fit inside
`T_close` with the dispute.

## Later, not now

- A freeze: each seal also spendable after N blocks unspent (CSV), so a
  stopped sequencer is a fact on Bitcoin; then a forced exit, a note
  proved unspent under the frozen root, in place of the default's
  windfall to the hub. Contracts are pre-signed at opening and can't
  name a future freeze's txid, so it would be a statement about the
  freeze, not a pre-signed spend of it.
- A counter-proof of a heavier chain, for the hub in a dispute.
- A penalty for signing two roots at one height (committed nonces
  reveal the key; a bond). Who the bond pays, and front-running by the
  sequencer, are open.

## Steps

0. **Housekeeping** (independent of anchoring):
   - the wallet keeps a return's withdrawal input and chain receipt as
     soon as they exist, and `export-dispute` packs them, so a
     sequencer gone after that blocks nothing and the tower needs no
     tunnel;
   - signed roots kept and compared, so an equivocation is visible:
     the wallet records every signed root it checks and alarms on a
     second root at a height it has; a command to compare with another
     source.
1. The sequencer's anchoring loop on regtest: the genesis seal, an
   anchor per Bitcoin block when there's something new, the anchor
   record once it confirms.
2. The chain guest checks anchor records and headers; its journal
   gains the seal, the last anchored height, the Bitcoin tip.
3. The withdrawal statement requires `k` headers on top; the checkpoint
   into `D`; the wallet and the tower fetch headers (Esplora or
   bitcoind); the hub's fold check the same. New guests, so a new
   deployment.
4. Tests: a regtest fork, the sequencer signing two histories, the
   second unable to withdraw; then a Mutinynet trial.

## Status

Step 0 in progress.
