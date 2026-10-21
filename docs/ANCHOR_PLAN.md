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

**Costs.** One anchor of about 270 vB per Bitcoin block at most, only
when there's activity. A withdrawal waits for: sealing, the anchor,
its confirmation, 9 more blocks, the anchor record proved. About two
hours on mainnet at best; minutes on Mutinynet. It must fit inside
`T_close` with the dispute.

## The design, in detail (2026-10-20)

Worked out while building it; it refines the sketch above.

**The history hash.** `hist_0 = 0`, `hist_h = H("lichen/hist" ‖
hist_{h-1} ‖ root_h)`, `root_h` the state root signed at `h`. The block
statement carries it from height to height beside the recent roots. An
anchor commits `hist_at`, not a root: it then commits the whole history
to `at`, and the chain guest can check it is an ancestor of the current
one by hashing forward (the record supplies `hist_{at-1}` and the roots
`at..i`, a hash each: a few hundred between anchors, cheap next to a
signature).

**The anchor transaction.** Input 0 spends the seal; any other inputs
pay the fee. Output 0 is the next seal, P2TR with the sequencer's key as
the output key itself (untweaked: no curve arithmetic in the guest to
check it; Bitcoin doesn't require the tweak). Output 1 is `OP_RETURN
"lichen" ‖ at ‖ hist_at` (46 bytes). The guest reads the
non-witness serialization (the txid's), refuses 64 bytes (a Merkle
node's length), and checks the Merkle path to the header's root. The
seal's script is checked so no one else can spend it: anyone could
otherwise stop the anchoring by spending it with a commitment the
sequencer's history doesn't hold.

**The anchor state**, in the chain journal: the genesis seal and the
sequencer's key (constant, fixed at height 0), the current seal, the
anchored height `at`, its root `root_at`, and the anchor's block hash.
A record needs `at` above the last anchored height.

**No proof of work in the chain guest.** The withdrawal statement
checks it, on top of the anchor's block. A forked history's anchor can
only be in a block off Bitcoin's real chain (the real chain's spend of
that seal commits the other history), so it costs the work on top of it
whatever the chain guest checked. The chain guest checks only that the
transaction is in the block it names.

**The withdrawal statement**, changed:
- the return under the anchored root: `SR = root_at`, the sequencer's
  signature on it (`input.height = at`; a note not yet in the tree at
  `at` has no path to it), the chain receipt at any height whose anchor
  state has that root;
- headers: the first's parent the anchor's block, each linked, each
  hash within its own target, their work summed (`2^256/target`,
  computed from the compact bits) at least the contract's `W`;
- `D = H("lichen/contract" ‖ deployment id ‖ genesis seal ‖ W)`.

**Per contract:** `W = k · work(bits at the checkpoint)`, `k = 10`
(blocks on top of the anchor's; a work sum, so fewer if difficulty
rises, more if it falls, never stuck). The checkpoint (height, hash,
bits) is in the contract's terms; hub and wallet each check it against
their own view of the chain. A hub has reason to set `W` high, which
would make the user's withdrawals unprovable, so the wallet checks.
On regtest each block's work is about 2, so `W` is tiny: mechanics only.

**The sequencer** with Bitcoin access (a bitcoind wallet): makes the
genesis seal before its first seal (a ledger sealed without one can't be
anchored); while sealed heights are newer than the last anchored and no
anchor is in flight, broadcasts one for the last sealed height; once it
has `n` confirmations (1 on test networks), applies its record as an L2
transaction (`Tx::Anchor`), which the next block carries to the chain
prover.

**Receivers** don't need a proof: the wallet has every signed root
(the root records above), so it computes `hist` itself, finds the anchor
on Bitcoin, compares, and counts confirmations.

## Later, not now

- A deployment with no shielding (decided 2026-10-20: after the MVP):
  validity proofs and anchoring over transparent notes only, so that
  clients can be light (no spend proofs, no scanning, hardware signers).
  The sequencer's cost is unchanged (the chain prover proves every
  block either way). Today the chain statement depends on
  `lichen-shielded`; the refactor makes shielding a deployment's option
  on top of validity and anchoring.

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

**Step 0 done** (2026-10-20):
- the wallet keeps each return's withdrawal input and chain receipt
  (`Kept`) as soon as the sequencer has them; `export-dispute` packs
  them and the tower uses them, asking the sequencer only for what's
  missing (`96013a7`);
- signed roots recorded and compared (`lichen_l2::Seen`, `Equivocation`):
  the wallet records every root it checks and refuses to go on, with
  the evidence in `<wallet>.equivocation.json`, if shown a second root
  at a height; the hub the same before folding (`seen.json`,
  `equivocation.json`); `lichen roots`, `compare-roots`,
  `check-equivocation`. Test: two ledgers under one key
  (`crates/wallet/tests/l2.rs`). Every root is kept, about 300 bytes a
  height: fine at this scale, to prune later (keep from the oldest open
  contract's opening). Publishing roots somewhere public (nostr, say) is
  left to whoever runs a watcher.

**Steps 1–3 done** (2026-10-20, branch `anchor`), natively and then with
the guests: chain `04debc77…`, withdraw `9a7b0b40…` (x86 Linux). The
real-receipt test anchors on regtest and proves the withdrawal under the
anchor, ten blocks on it: on the Mac 392,631 user cycles, 75 s (before
anchoring 332k, 75 s: one segment either way); on the GCE `n2-highmem-4`
proved in 361 s, wrapped in 258 s, the same as before. The chain guest:
about 3% more a block (the history hash: a mint 395,543 cycles, was
384,061); a block holding only an anchor's record about 130k cycles, 50 s
on the Mac. Tests: the statements', the sequencer anchoring on regtest
(a restart with an anchor in flight), a fork (of two histories under one
key and one genesis seal, only one is ever anchored), an anchored
contract's withdrawal checked by the statement natively.

**The Mutinynet trial** (2026-10-20/21), a fresh deployment (`8c971e86…`:
a new sequencer key, genesis seal `415a16c7…:0`; the last one,
`3d40fd9a…`, archived), the sequencer anchoring through the hub's node
(`deploy/sequencer/anchor.yml`), the chain prover on the Mac. Each
anchor 269 vB; one a block at most, only when something changed.

- **Opening:** Alice and Bob open at once (1011, 1010), each with a
  checkpoint both sides checked; `D` the contract's. Shield 13 s, a
  payment 30 s, as before.
- **A, the fold under an anchor:** Bob withdraws 35,000: his return at
  height 13, anchored at 13, the chain receipt at 14 carrying it, the
  headers on the anchor from the hub's own node: folded (`70cdf2d8…`).
  The wait was the chain prover's (the Mac also running the Groth16
  test), not the anchor's.
- **B, the tower:** the hub hostile; Alice's return at 15 refused after
  its anchor and chain receipt (3 minutes). Her package carried the
  input, the chain receipt and the anchor, so the tower (GCE) never
  reached the sequencer: no tunnel. Proved 405 s, wrapped 263 s,
  escalated at 3,522,157, move 21 after 14 minutes, the last step proved
  after the hub's window: the payout `5b03d690…`, 74 minutes from the
  tower's start. Swept on the Mac after δ: 146,064 sats (`c00e4d15…`).

Found and fixed: `withdraw` kept the input straight after sealing, which
in an anchored deployment needs the anchor, so Bob's first try failed at
once (`863bfbd`, with a test); the anchor's size, estimated at 220 vB,
is 269 (its fee now at the rate asked).

Then: the Groth16 dispute tests pass on the new claim, on an idle Mac
(G1 conceded, G2 proved after the whole search in 782 s, G3's lie of 61
disproved in 551 s; G2 had missed its 3-minute window on a Mac also
proving). The receiver's view: `lichen balance` (and the demo's panes)
split what's held into final (anchored, ten blocks deep), anchored, and
sealed only, each anchor checked by the wallet on Bitcoin, once
(`crates/wallet/src/finality.rs`); in the demo, at a block a second, a
payment is final about nine seconds after it's sealed.

TODO: the guest builds' speed: `build-guest.sh pack` with any prover
image there (packing doesn't depend on the statements), the prover image
rebuilt once after the guests; BuildKit cache mounts for cargo's
registry and `target/` in r0/Dockerfile and the guest builder. The demo
leaves its bitcoind and chain prover running when stopped (no signal
handler).
