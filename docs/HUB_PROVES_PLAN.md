# The exit where only the hub proves: plan

2026-11-09. A design in progress, not built. It would replace the
counter design of EXIT_PLAN.md ("Under BABE") and the withdrawal by
return's dispute with one dispute: Alice claims, and only the hub
proves, if it can, that her claim is false.

**Status, 2026-11-09.** Built on branch `hub-proves` on the mock
statement, transparent notes only: the hub's statement natively
(`lichen_withdraw::hp`), the swapped graph (`lichen_babe::hp`), the
setup in which Alice garbles and uploads (`lichen_proto::hp`), both
sides' play, and a regtest test of seven cases (`hp_exit.rs`); the
leaf's kind and claims by position; the cooperative withdrawal by claim
(`withdraw.rs`). The only contract kind (`hub-proves-mock`): the old
exit, the return, and the babe and BitVMX contracts are removed (build
order, steps 9 and 10). Not yet: sender acknowledgment (decided, "Data
availability"), the hub's statement as a guest, real proofs, shielded
notes. Being thought through with the user:
"Open questions" is the live part; where a question is settled, it moves
to "Decided".

## Why

Today's exit makes both sides prove. Alice proves her claim (her notes
in `T_S`, unspent in `N_S`, `S` anchored), the hub may counter with a
proof of its own, and Alice may then have to prove the counter false:
a Groth16 verification inside RISC Zero, 56.3M cycles, about an hour on
a laptop's CPU. Even in the honest case, a user who exits needs a
prover: the STARK, then the Groth16 wrap, on x86 Linux with Docker and
about 8 GB.

The usual optimistic shape is cheaper for the side that's right: claim,
and let the other side prove the claim false. Every way an exit claim
can be false can be shown from data the operator holds, and the hub
holds it, since one operator runs both. So the hub carries the whole
proof. This is the counter's own logic ("the burden falls on whoever
holds the newer data") taken all the way: the hub holds all of it.

EXIT_PLAN's role-reversed game (BABE_DISPUTE_PLAN §9) put the hub's
counter in a second BABE instance, garbled by Alice, beside her own,
which doubled the setup. Here it's the only instance.

## The claim

Alice claims a definite set of her notes, and `b`, their value (at most
`V_max`), one fixed amount. `request` carries, in its witness:

- **the notes, by their positions in the commitment tree and their
  openings:** 80 bytes each. The opening can't be left out (found while
  building): shielded commitments share the tree, the hub doesn't know
  their openings, and it couldn't show that a leaf isn't a transparent
  note's. Without the opening, Alice could claim someone's shielded leaf
  for any `b`;
- **one signature on `E` per owner key** (usually one), not per note.
  Transparent notes are public, so without it anyone who knows hers, the
  operator included, could claim them through their own contract;
- **`b`,** under her one-time Winternitz key, as today, with today's
  digit decomposition;
- **`E`,** under a second one, as today: today's fingerprint with no
  state named (`h_S` 0) and the positions' digest in place of `SR_S`,
  over the notes' nullifiers. Script can't check the claim's bytes, so
  without this a relayer could swap them. The hub's statement checks
  that the posted claim hashes to the signed `E`. Being today's
  fingerprint, the hub's exit record retires the notes under today's
  chain statement: no guest change.

At most 8 notes for now, an exit record's most (a chain-guest change
would raise it; today's fifteen 80-byte items hold about 14).

Her claim: **"these notes are mine, live at `A*`, and worth at least
`b`."** `A*` is the last anchor confirmed at or before `m` blocks before
`request`'s block (the margin, below). A note is live if it's in the
tree and its nullifier isn't in the spent set.

- **No state named.** Today she names `S` because her proof starts from
  a kit there. Here she proves nothing, so the claim is about one
  objective state. The tree only grows, and a spend is permanent, so
  `A*` answers both "was it created" and "is it spent".
- **The margin `m`** is EXIT_PLAN's, and it's for censorship. The
  operator holds a payment of hers, unsequenced, and serves data
  honestly. At the tip she sees the payment not included, so she
  claims its inputs. Without a margin, the operator could include the
  payment in an anchor that confirms before her `request` does, making
  her claim false. So `A*` ignores anchors in the last `m` blocks
  before `request`'s: what she saw at the tip when she broadcast is
  what counts, provided `request` confirms within `m` blocks. `m`
  covers its confirmation, and she fee-bumps if it takes longer.

## The hub's statement

"The claim posted in `request` is false." Fixed at the contract's
opening, journal `c ‖ D ‖ H(O_D ‖ margin)`. It reads `request` from
Bitcoin, in a block with the contract's work on it, as Alice's
statement does today, and reads `b` and `E` from her signatures'
digits: Bitcoin checked the signatures, in `request`'s script, so her
keys needn't be in the journal.

It holds on any of these grounds:

| ground | shown by |
|---|---|
| malformed | the claim doesn't parse, doesn't hash to `E`, repeats a note, or `b` exceeds `V_max` |
| not hers | a signature on `E` doesn't verify, or a note's owner isn't a signing key |
| too much | `b` exceeds the notes' value |
| not live | at `A*`, the leaf at a note's position isn't its commitment (an empty one past the tree's end, too), or its nullifier is spent by a spend that counts (with acknowledgment: "Data availability") |
| locked | at `A*`, a note is an output of an unacknowledged spend, and the claim carries no acknowledgment of it |
| voided | at `A*`, a note is an output of a spend an exit record voided |
| a second claim | her signature on a claim of one of these notes through another contract |

"Not live" is today's "later spend", plus "no such note", which Alice
used to disprove herself, with her kit.

- **Her own return to this contract doesn't count as a spend,** of
  notes worth at least `b`, as today's exclusion: the hub holds those
  tokens. So an exit after a refused return (case R) is a claim of the
  notes the return spent. The withdrawal by return then needs no
  dispute of its own.
- **Another contract's exit record** spends a note like any spend.
  Concurrent claims are caught by the second-claim ground.

**`A*` is the last anchor before the cutoff.** The hub shows `A*`'s
anchor confirmed by the cutoff, and the transaction spending `A*`'s
seal confirmed after it. Only the sequencer's key spends the seal, and
Bitcoin allows one spend, so this is objective. If nothing has spent
the seal yet, the hub spends it (an anchor), which it can always do,
since the operator holds the key. Today's counter shows only that a
state was final; this also shows that no later one was.

## On chain

```
request (Alice: b, E, the claim)
 ├─ request_timeout (after w_H)      → Alice: b
 └─ assert (the hub: π1, Lamport)
     ├─ hub_wins (after Δ_c)         → the hub: the contract
     └─ challenge_assert (Alice)
         ├─ wrongly_challenged_k     → the hub (its proof was valid)
         └─ challenge_timeout        → Alice: b and the hub's reserve
```

- **No `respond`.** The hub signs nothing. It either lets
  `request_timeout` pay her or asserts a proof that her claim is false.
- **An honest exit is two transactions:** `request`, then
  `request_timeout`, `w_H` later. Today's honest exit, against a hub
  that won't fold, is `request`, `respond`, Alice's proof (minutes to
  an hour), `assert` and `success` after `Δ2`.
- **`Δ_c`, her window to challenge,** can be long (days). Only a lying
  hub, or a lying Alice, ever gets there, and only the hub that
  countered a liar waits for it.
- **`w_H` must cover the hub's proving,** including the chain receipt
  at `A*` if its prover is behind. It's also the honest Alice's wait.

## BABE's roles swap

The prover is now the hub, and Alice garbles.

| | today | swapped |
|---|---|---|
| garbles 78 instances | the hub (9.5 s) | Alice (9.5 s on a laptop) |
| the 10 kept instances, 243 MB | Alice downloads them | Alice uploads them; the hub keeps them (240 MiB a contract) |
| checks the 68 opened | Alice | the hub |
| Lamport key for π1, adaptor pre-signatures on `challenge_assert` | Alice's, to the hub | the hub's, to Alice |
| completes them to challenge, revealing `f(0)` | the hub | Alice |
| evaluates the kept instances to answer | Alice | the hub |
| keeps | Alice: the instances | Alice: a seed for her `f`s |

## What goes away

- **Alice's claim proof,** and her prover: no STARK, no Groth16 wrap,
  no Docker, for any withdrawal or exit. A user proves only her
  shielded spends.
- **The failed-counter branch:** the 56.3M cycles, `K`, and the
  countering leaf of `respond` (12.3 kvB).
- **`respond`** altogether, plain (4.5 kvB) or countering.
- **The exit set's chain receipt** (230 kB). She needs only her notes'
  openings and positions, which her wallet has anyway. Kits, about
  0.7 kB a note, still let it check against the anchored root that a
  claim will hold.
- **The withdrawal by return's statement,** and `lichen dispute` as a
  separate path: a refused return is exited (R above).

## What it costs

- **Alice uploads 243 MB at opening.** That's two to three minutes on a
  10–20 Mbit/s uplink: fine at home, poor on mobile data.
- **A tower to challenge would hold her secrets.** Her challenge
  completes the hub's adaptor pre-signatures with her `f(0)`s, one
  digit at a time. A tower must hold all of them, to complete whichever
  π1 the hub asserts, and all of them are every input label, which is
  enough for the hub to answer any challenge. So that tower is trusted.
  Mitigations: she has to challenge only a lying hub, and `Δ_c` can be
  days. Today's exit has no tower at all; the return's keyless tower
  goes with the return's dispute.
- **Her heavy move is the challenge,** about 17–21 kvB, against
  today's 7.7 kvB `assert`. It's paid from the contract, as the hub's
  challenge is today. Against a hub that asserts falsely against every
  user, that sets the block-space bound: about 8,300 a day-window
  (BABE_DISPUTE_PLAN §9). Each false assert also costs the hub its
  7.7 kvB and the contract.
- **The hub proves every false claim within `w_H`.** It does today, for
  its counters. Liars lose their contracts. But a coordinated wave of
  them could outrun the hub's prover, and each liar the hub fails to
  answer is paid. `w_H` and the hub's proving capacity have to be sized
  for that (open question 3).

## Data availability: sender acknowledgment

Decided (the user, 2026-11-09): every spend counts against its sender
only once she has acknowledged it, and she acknowledges only a history
that is fixed on Bitcoin and that she holds the data for. With it,
withholding data can stall payments but never take funds. This replaces
the earlier acceptance of an in-flight risk, kept below as "Without
acknowledgment" for the reasoning.

### The problem it closes

Without it, the exposure is an unresolved spend. From signing a spend
until she has seen, at an anchored state, whether it's included, Alice
can't safely claim the notes it touches:

- **its inputs:** if an anchor before the cutoff included it, they're
  spent, and the claim is false;
- **its outputs to her:** if no anchor did, they don't exist, and the
  claim is false.

The root of each anchor is on Bitcoin; the data under it isn't. An
operator that anchors a busy block and serves none of its data leaves
every sender in it unable to choose, and their stuck value defaults to
the hub at `T_close`: the motive.

No succinct accumulator lets a member prove membership without data
about the others; Camacho and Hevia (2010) show the update data after
deletions is at least proportional to them, which is what an anchor's
blob is. So the fix can't be a better structure. It's an order:
inclusion first, unconditional and without effect; then the sender's
signature, given only once she holds her witness, which makes the
spend count. A Merkle path against a fixed root never expires, and
the commitment tree only grows, so she needs it once.

### The design

The simple version first (the user, 2026-11-09: walk before run). Its
gist: **a payee who waits for full finality before counting a payment
can't be robbed by any collusion**; the sender is safe throughout if she
acknowledges only with her data in hand; the hub protects itself by
what it sequences.

- **Every spend names a one-time key `ak`.** The sender's, for this
  spend only (unlinkable, for shielded spends; a public input of the
  spend's proof). Hub-signed transactions acknowledge themselves.
- **The sequencer seals as now,** at any height. A sealed spend spends
  its inputs and appends its outputs, but its outputs are **locked**:
  nobody spends them, the sender's change included, until the spend is
  acknowledged on the L2.
- **At the next anchor,** once it's broadcast (`hist_a` public in the
  mempool), the sequencer sends each sender whose spends were sealed
  since the last one her data: her outputs' positions and paths against
  her block's root `R_h`, `hist_{h-1}`, and the roots `R_{h+1}..R_a`.
- **She checks and signs:** her paths against `R_h`, and that
  `hist_{h-1}`, `R_h..R_a` hash-chain (`hist_next`) to the `hist_a` the
  anchor commits. Then the acknowledgment, her signature under `ak` on
  `H("lichen/ack" ‖ txid ‖ a ‖ hist_a)`, to the sequencer and to her
  payee, with the payee's position, opening and path.
- **If anchor `a` never confirms** (replaced, or reorged out), her
  acknowledgment is void; she signs another for the anchor that does
  confirm, once she has the roots to it. An acknowledgment may name any
  anchor at or above the spend's height.

The ack names the anchor, not her block, so seals stay as frequent as
today. An exact-height rule (the ack names `hist_h`, valid only if
height `h` is itself anchored) would force a seal per anchor.

### The chain guest's rules

State, beyond today's (the commitment tree, the spent set, the
anchoring state):

- `Pending`: txid → (`ak`, height `h`, output positions), the
  unacknowledged spends;
- `Locked`: their outputs' positions;
- `Void`: spends voided by an exit;
- `Anchors`: each applied anchor's height `a` → `hist_a`.

Rules:

1. **A user's spend:** as today (inputs in the tree, nullifiers
   unspent, the owners' authority), and no input's position in
   `Locked`. It names `ak`. Effect: nullifiers spent and outputs
   appended as today; `Pending[txid]` set; its outputs into `Locked`.
2. **A hub-signed transaction** (an exit record, the hub's own spend or
   mint) is acknowledged by its signature: its outputs aren't locked.
3. **An acknowledgment** `(txid, a, hist_a, sig)`: `txid` in `Pending`
   and not in `Void`; `Anchors[a] = hist_a` (the anchor's record
   applied); `h ≤ a`; `sig` under `ak` on
   `H("lichen/ack" ‖ txid ‖ a ‖ hist_a)`. Effect: `txid` leaves
   `Pending`, its outputs leave `Locked`.
4. **An anchor record:** as today, and `Anchors[a] = hist_a`.
5. **An exit record** retires its notes' nullifiers. A nullifier
   already spent by a spend in `Pending` puts that spend in `Void`
   (its outputs locked for good, a later acknowledgment rejected); one
   spent by an acknowledged spend rejects the record.

**The sequencer's policy** (the hub's protection, not a guest rule): it
sequences an acknowledgment only once the anchor it names is the margin
deep, and no claim of the spend's inputs is pending. Otherwise Alice
could acknowledge, claim her inputs at once with a cutoff before the
anchor, and have the hub pay her while her payee's outputs were already
unlocked.

### The representation (for building, 2026-11-09)

All in the existing spent-set SMT, under domain-separated keys, insert
only (nothing is ever deleted; "unlocked" is "acknowledged"):

| key | leaf | inserted by |
|---|---|---|
| `nf` (a nullifier, as now) | `spent(txid)` for a user's spend, `exited(c)` for an exit record | the spend, the record |
| `H("lichen/k/tx" ‖ txid)` | `H("lichen/pending" ‖ ak ‖ h)` | a user's spend, sealed at `h` |
| `H("lichen/k/lock" ‖ i)` | `txid` | each of its outputs, at position `i` |
| `H("lichen/k/acked" ‖ txid)` | `H("lichen/acked" ‖ a)` | its acknowledgment |
| `H("lichen/k/void" ‖ txid)` | `H("lichen/void")` | an exit record retiring its inputs |
| `H("lichen/k/anchor" ‖ a)` | `hist_a` | the anchor record of height `a` |

- **`txid`** is the digest the spend's authority signs: `transfer_digest`
  (now over `ak` too), or `shielded_digest` (its journal now carries `ak`).
  The nullifier's leaf `spent(txid)` names the spend, so an exit record
  can void it, and the hub's statement can tell which spend spent a note.
- **An acknowledgment** `(txid, ak, h, a, hist_a, sig)`: the pending
  leaf recomputed from `ak` and `h`, not void, not acknowledged
  (inserted), `anchor(a) = hist_a`, `h ≤ a`, `sig` under `ak` on
  `H("lichen/ack" ‖ txid ‖ a ‖ hist_a)`.
- **A transparent input** at `i`: `lock(i)` absent, or `lock(i) = txid`
  and `acked(txid)` present. (A shielded input's position is private: its
  lock is the wallet's and the sequencer's to keep, until shielded exits
  are built.)
- **The exit record** carries the claim's acknowledgments and applies them
  first; `E` covers them (`E = H(c ‖ O_D ‖ b ‖ positions ‖ H(acks))`), so
  a relayer can't strip them from `request`. A claimed note already spent
  by a pending spend `T` (its leaf `spent(T)`) voids `T`: `acked(T)` absent,
  `void(T)` inserted once.
- **The hub's statement** judges spends, locks and voids at `A*`'s state
  (height `h*`), and an acknowledgment's anchor in the state where `A*`'s
  own anchor record is applied (the chain receipt's height): anchor
  records are applied in seal order, so every anchor up to `A*` is there,
  each confirmed before the cutoff.

### The hub's guest's rules: "this claim is false"

Its input: `request` from Bitcoin, `A*` and its proof of being last,
the chain state at `A*`, and the claim (notes by position and opening,
signatures on `E`, and an acknowledgment for each claimed note still
locked at `A*`). Any one ground suffices:

1. **Malformed;** 2. **not hers;** 3. **too much:** as before.
4. **Not in the tree:** the leaf at a note's position at `A*` isn't its
   commitment.
5. **Spent:** its nullifier is spent at `A*` by a spend `T` that counts:
   hub-signed, or acknowledged at `A*`, or pending at `A*` with an
   acknowledgment of `T`, shown by the hub from anywhere (the L2,
   another claim on Bitcoin), whose anchor confirmed before the cutoff.
   Excepted, as before: her own return of at least `b` to this
   contract, and this contract's exit record.
6. **Locked:** the note is an output of a spend pending at `A*`, and the
   claim carries no valid acknowledgment of it (the signature under
   `ak`, `a ≥ h`, anchor `a` confirmed before the cutoff).
7. **Voided:** the note is an output of a spend in `Void` at `A*`.
8. **A second claim:** as before.

Claiming both sides of one spend (her inputs through one contract, her
change with the acknowledgment through another) fails: the
acknowledgment posted in the one is the hub's evidence under ground 5
against the other.

### The collusions

- **Alice and the operator against Bob.** The operator never sequences
  Alice's acknowledgment and lets her claim her inputs; the exit record
  voids her spend, and Bob's output with it. Bob never counted the
  payment: it wasn't firm. A stall, not a theft.
- **Alice and Bob against the hub.** Alice gives her acknowledgment to
  Bob alone and claims her inputs. The hub can't refute her and pays,
  then records the exit, which voids the spend: Bob's claim of his
  output fails on ground 7. The hub pays once.
- **The operator against Alice.** It can't use a spend she hasn't
  acknowledged, and she acknowledges only with her data. Withholding
  stalls her payments.

### Finality

- **The payee:** firm once the acknowledgment is sequenced in a block
  anchored the margin deep, which he can show with a path from it to
  that anchor. Rule 5 then forbids voiding the spend. Before that he
  holds a soft payment: the sequencer's word, then Alice's
  acknowledgment (which leaves him trusting Alice and the operator not
  to collude).
- **Spending what he received** waits for the same: the sequencer
  sequences the acknowledgment only once its anchor is the margin deep.
  About ten minutes on Mutinynet, an hour or more on mainnet. An
  important limitation of this version: no fast onward transfers.
- **The sender:** online until the next anchor's broadcast, to
  acknowledge. If she goes away first, her spend waits: it counts for
  nothing, her inputs stay claimable, and she can acknowledge on her
  return against whatever anchor is then confirmed. Her change is
  locked like any output.

**Later, not now:** softer finality. Spends of locked outputs made
conditional rather than forbidden (an output's spend counts only if
its ancestors' do, as with unconfirmed Bitcoin outputs), so payments
chain at the sequencer's speed; and a hub-signed receipt for an
acknowledgment, letting a payee be firm before it's sequenced. Both
need analysis first.

### What it costs

- **Chain guest, after the compact spent set (2026-11-10, profiled):**
  the spent set is a compact sparse Merkle tree, a key's path as deep as
  its keys' common prefixes, so an access is some twenty compressions at
  a million keys, not 256 levels (512 compressions an insert). The ledger
  test's block of a transfer and its acknowledgment went from 2.84M user
  cycles to 0.84M, three segments to one; the spent set from about 70% of
  it to about 10%. A payment and its acknowledgment now cost about two
  BIP340 signatures (260k each) and some 0.1M of the spent set: the
  acknowledgment's own cost about one signature. The trims below no
  longer matter much. Before it:
- **Chain guest, measured (2026-11-10):** every spent set access is a
  256-level path, about 300k cycles. A transparent spend now reads each
  input's lock and inserts its pending leaf and a lock per output; its
  acknowledgment checks a signature (about 260k) and reads four keys
  and inserts one. A payment of one input and two outputs and its
  acknowledgment: about 2.7M cycles more than before, against about
  0.6M for the spend alone then, so some 4 to 5 times the chain guest's
  work per payment. Negligible beside a shielded spend's proof, which
  dominates there. To trim later: one lock per spend instead of per
  output (the lock keyed by the spend, the output's position mapped to
  it by the tree), the acknowledged state in the pending leaf itself
  (one insert fewer), and batching the reads of one block. The rebuilt
  chain guest runs the ledger test's first block (three mints and a
  transfer) in 2,384k user cycles.
- **The shielded spend proof:** `ak` as one more public input. The
  acknowledgment is a plain signature outside it.
- **The hub's guest:** grounds 5–7, a signature check and lookups.
- **On chain:** nothing in normal operation. In an exit, about 70 bytes
  of witness a spend whose outputs are claimed while locked: under
  20 vB.
- **The wallet:** no proving. It stays online to the next anchor's
  broadcast after a payment, and keeps its paths and acknowledgments
  with its notes.

### Assumptions left

Not gaps in the DA picture, but what it rests on:

- the operator can stop anchoring or not sequence acknowledgments:
  payments stall;
- Bitcoin: a user exits before `T_close` less the windows, challenges
  a lying hub within its window, and a mass exit needs block space;
- the cut-and-choose is sound and the hub's statement correct (its
  guest is still to build);
- a user exits at most her contract's value;
- the hub must be online to refute false claims; if it isn't, the loss
  is its own.

### Without acknowledgment (superseded)

The state before this decision, for the reasoning. Money at rest was
safe: only her keys spend her notes, and a note no transaction of hers
spends is live at `A*` whatever is withheld. A spend in flight when the
operator turned could lose the notes it spent: a payment of 30 from a
note of 100 put the 100 at risk. The wallet's rules then: sign only
while the sequencer serves anchored data promptly, stop when it
doesn't, and leave notes touched by an unresolved spend out of a
claim. Rejected alternatives: fixed denominations (they multiply
inputs, outputs, and shielded proving time), publishing each anchor's
nullifiers and commitments (about 24 vB per L2 transaction), and
ambiguous claims (the user prefers definite ones).

## Precedents

How other designs handle a hostile operator, and where lichen's choices
differ (surveyed 2026-11-09; the Intmax2 paper's own text couldn't be
fetched, so its sign-off semantics are from its docs and Nethermind's
formalization).

| | data | when it's withheld | sender sign-off | who proves at exit | what L1 enforces |
|---|---|---|---|---|---|
| Plasma (2017) | off-chain, headers on L1 | mass exit, coordinated | §5.4: both parties acknowledge after inclusion; unacknowledged stays withdrawable | the exiter (inclusion); challengers (spends) | bonds, challenge games |
| Plasma MVP (2018) | off-chain | exit within 7 days | confirmation signatures: a spend counts only once its owner confirms | the exiter, with confirm signatures | priority queue, 14-day exits |
| More Viable Plasma (2018) | off-chain | in-flight exits: post the transaction, piggyback with bonds, the canonical side exits | dropped: an extra step, operator griefing, the sender's free option | the exiter, plus a canonicity game | youngest-input priority, two-period games |
| Validium (StarkEx) | a committee signs each update | forced withdrawal, freeze, escape with a path against the frozen root (needs the data) | none | the user | committee signatures, freeze, escape hatch |
| Adamantium (StarkWare, 2021) | the committee; power users keep their own | a power user signs each state update touching her, or the operator posts her funds back on L1 | per state update, an availability attestation | none needed | no update without her signature or her withdrawal |
| Vitalik 2023, Plasma Free | off-chain, validity-proven | forced inclusion; if not served, L1 reverts blocks | none | the user (a branch) | forced-inclusion queue, reversion |
| Intmax2 | client-side; root, aggregate signature, signer IDs on L1 | unsigned is nothing; signed and unavailable counts as the sender's worst case | BLS-signs the root after receiving her proof, before posting | the user (a ZK balance proof) | the signer set, balance proofs |
| lichen | off-chain; a hash chain of roots anchored on Bitcoin | she claims; the hub proves the claim false or pays | signs `(txid, a, hist_a)` after the anchor's broadcast; counted by existence; outputs locked until then | the hub only | nothing: an anchor is an `OP_RETURN` Bitcoin can't reject |

**Where lichen differs, and why:**

1. **Bitcoin enforces nothing about the L2, so every rule is applied
   after the fact, in a dispute.** The precedents use L1 to stop a bad
   state or rescue funds: committee signatures, "sign or be withdrawn",
   forced inclusion and reversion, signer sets, priority queues.
   Bitcoin can't reject an anchor, freeze, or revert. So lichen never
   prevents a bad anchor; its exit statement decides which anchored
   facts count. "A spend counts only with an acknowledgment" is applied
   at a claim's cutoff, not at anchoring.
2. **Per-user collateral, not a shared pool.** A Plasma exit draws on
   one contract, so a double exit steals from everyone, hence
   priorities and mass-exit coordination. Here each exit is a dispute
   against the hub's collateral for one contract: no queue, no ordering
   among users, and a double payment would cost the hub, which is why
   the sequencer's policy and the voiding rule are the hub's to keep.
3. **The burden on the data holder.** Everywhere else the exiter proves
   something: inclusion, a Merkle path, a balance proof. Here she claims
   and the operator proves, since one operator runs the sequencer and
   the hub: it holds all the data and pays the exits.
4. **The acknowledgment is Plasma 2017 and MVP's, with three changes:**
   - it binds to a history fixed on Bitcoin, `(a, hist_a)`, not to a
     block, so a spend's fate is public (Intmax2 gets this by posting
     the signatures with the block; Bitcoin's space rules that out);
   - it counts by existence and claims carry it, so the operator can't
     suppress it by censoring;
   - outputs locked until it's sequenced, and an exit voiding a spend
     still unacknowledged, so a payee who waits for that is firm.
5. **No in-flight exits.** MoreVP's in-flight exit is the ambiguous
   claim rejected above ("the inputs or the outputs, whichever is
   canonical"), with bonded games of several parties. On Bitcoin each
   party in a game is another garbled-circuit setup. Acknowledgment
   keeps claims definite and disputes two-party.
6. **Validity proofs throughout,** as in Vitalik 2023, Intmax2, Plasma
   Free and Plasma Next: no exit argues about an invalid history.

**MoreVP's objections still apply, and are accepted:** the extra
interactive step (the sender online to the next anchor's broadcast);
griefing by withholding (payments stall, nothing taken); the sender's
free option (until she signs she can take the payment back, a window
of at most an anchor cycle, which the payee closes by waiting for the
acknowledgment sequenced). MoreVP's alternative needs the L1
machinery Bitcoin lacks.

**Related:** Ark's hArk variant locks a new VTXO until the user signs
the forfeit, the same shape as locked outputs. Plasma Next (2024) has
sender and operator co-sign, the operator handing the receiver its
path. Plasma Cash binds each transaction to a block number, which
removes in-flight ambiguity at the price of indivisible coins.

Sources:

- Plasma: https://www.plasma.io/plasma.pdf (§5.4, §5.7)
- Plasma MVP: https://ethresear.ch/t/minimal-viable-plasma/426
- More Viable Plasma: https://ethresear.ch/t/more-viable-plasma/2160
- Plasma Cash: https://ethresear.ch/t/plasma-cash-plasma-with-much-less-per-user-data-checking/1298
- Exit games for EVM validiums: https://vitalik.eth.limo/general/2023/11/14/neoplasma.html
- Plasma Free: https://ethresear.ch/t/plasma-free/16570
- Plasma Next: https://ethresear.ch/t/plasma-next-plasma-without-online-requirements/18786
- Intmax2: https://eprint.iacr.org/2023/1082; https://docs.network.intmax.io/developers-hub/payment-lifecycle; https://nethermind.io/blog/formally-verifying-the-security-properties-of-intmax2
- Validium: https://ethereum.org/developers/docs/scaling/validium/; https://docs.starkware.co/starkex/con_data_availability.html; https://docs.starkware.co/starkex/spot/full-withdrawal_reference.html
- Adamantium: https://ethresear.ch/t/adamantium-power-users/9600
- Ark forfeits: https://docs.second.tech/ark-protocol/forfeits-connectors; https://blog.second.tech/hark-explained/
- Camacho and Hevia, "On the impossibility of batch update for cryptographic accumulators" (LATINCRYPT 2010)

## Shielded notes

The exit must claim shielded notes directly. Unshielding is an L2
transaction, so it needs the sequencer, which is what an exit can't
count on.

Today (crates/shielded):

```text
owner = H("lichen/owner" ‖ nk)
cm    = H("lichen/snote" ‖ owner ‖ value ‖ rho)
nf    = H("lichen/snf" ‖ nk ‖ rho)
rho_i = H("lichen/rho" ‖ nf_0 ‖ i)
```

and spend authority is knowing `nk`, inside the spend proof. The hub
knows no shielded opening, and to check that a note is unspent it needs
the note's `nf`, which needs `nk`. So Alice must supply:

1. **the opening,** so the hub can check the leaf at her position;
2. **the nullifier, verifiably linked** to that note. She could
   otherwise post an unspent nullifier for a spent note;
3. **authority bound to this contract,** not a bearer secret. Otherwise
   a copy of her claim through another contract, posted first, is a
   second claim, and she loses.

**The options:**

- **A. Split the keys; reveal the nullifier key at exit.**
  `owner = H(H(ask) ‖ nk ‖ X)`. `ask` authorizes spends inside the
  proof and is never revealed. `nk` derives nullifiers and is revealed
  at exit. `X` is a Schnorr key that signs `E` and nothing else. The
  spend proof gains one hash input: negligible. The hub checks
  everything natively. Revealing `nk` doesn't let anyone spend, which
  needs `ask`.
- **B. Key-image nullifiers** (Monero's): `nf = H(nk·H_p(rho))`, the
  owner committing `nk·G`. Per note she posts the image and a DLEQ
  proof with `E` in its challenge, about 100 bytes, verified natively,
  revealing nothing else. But each shielded spend proof then does
  elliptic-curve multiplications. Two BIP340 verifications took a
  2-in-2-out spend from 2^17 cycles to 2^20 (about 23 s to 110 s on the
  Mac; shielded-pool costs), and key images need about as many. A
  cost on every payment, for an exit that should be rare.
- **C. Alice proves the link,** in a small proof. That's what this
  design removes.

**The plan: A, with a trapdoor in the nullifier** (decided; built after
the transparent exit). Revealing `nk` exposes,
to anyone who can compute `H(nk ‖ rho)`, every spend of hers under that
owner. Today every note's `rho` is public: it's derived from its
transaction's first nullifier. So add a trapdoor `r`, chosen by the
sender and encrypted to the receiver with the value:

```text
owner = H("lichen/owner" ‖ H(ask) ‖ nk ‖ X)
cm    = H("lichen/snote" ‖ owner ‖ value ‖ rho ‖ r)
nf    = H("lichen/snf" ‖ nk ‖ rho ‖ r)
```

- **After an exit,** only a note's sender (who knows its `rho` and `r`)
  can then link its spend to her.
- **`nf` stays unique:** `rho` is still derived in the proof.
- **The claim, per note:** position, value, `rho` and `r`, 76 bytes.
  Once per owner: `H(ask)`, `nk`, `X` and a signature, 160 bytes. 13
  notes in today's witness space. (Built 2026-11-10 with `rho` in the
  claim, not the hub's to supply: the statement can't recompute `rho`
  from the tree, so a hub that chose it could show any claimed note "not
  a note". One shielded owner a claim: a wallet has one.)
- **The grounds are as for transparent notes.** "Not hers" is now: the
  owner isn't `H(H(ask) ‖ nk ‖ X)` of what she posted, or `X`'s
  signature doesn't verify.
- **It's a guest change** (the spend and chain guests), so a new
  deployment.

**Found while designing this: today's commitment isn't hiding.** An
address is `(owner, enc)`, and `rho` is public, so anyone with Bob's
address can test each leaf against `H(owner ‖ v ‖ rho)` for every
value `v`. Payments are small enough to search, so they find Bob's
notes and amounts. SHIELDED.md says "who pays whom, and how much" and
"your balance" are hidden from everyone: against anyone who knows the
address, they aren't. The trapdoor `r` in `cm` fixes that too, exit or
not.

## Open questions

1. **The margin `m`.** EXIT_PLAN's `e`: 6 blocks on mainnet, 20 on
   Mutinynet. Check against `request`'s fee-bumping (TRUC).
2. **One `A*` for everything.** A spend is permanent and the tree only
   grows, so one state at `A*` answers every ground, and the hub's proof
   needs one chain receipt. Check nothing needs an earlier one, such as
   the return exclusion.
3. **Mass false claims against the hub.** Sybils open contracts, spend
   their tokens to each other, and all exit on the same day. Is `w_H`
   (two hours on Mutinynet) enough for the hub to prove every one? One
   proof per contract, since each journal is its contract's. Options:
   - a batched STARK, with a small composing guest and a wrap per
     contract;
   - a longer `w_H`, which is the honest user's wait too;
   - a cap on contracts opened per window.
4. **The upload.** 243 MB, or fewer instances with soldering or VSSS
   (BABE_DISPUTE_PLAN).
5. **A tower for the challenge.** A threshold of towers holding her
   `f(0)`s, so that only a quorum colluding with the hub could steal?
   Or accept that challenging is hers, in a window of days.
6. **The seal's other spenders.** If the seal gains a freeze path
   (END_PLAN's CSV path), the first spend of `A*`'s seal might be the
   freeze rather than an anchor. The last-anchor proof needs only some
   spend of the seal after the cutoff, so it shouldn't matter which.
   Check it against the freeze's design.
7. **Shielded notes:** decided (Decided, and "Shielded notes"); built
   after the transparent exit.
8. **The exit record.** After `request_timeout` pays her, the hub
   records the exit on the L2, retiring the claimed notes, with her
   signatures on `E`, as today.
9. **The cap.** A claim of whole notes above `V_max` forfeits the
   excess, as today. With hundreds of notes in a claim, the wallet can
   pick a subset close to `V_max`.

## Decided

- Only the hub proves. Alice's statement and the failed-counter branch
  go (the user, 2026-11-09).
- No expiry, of notes or of transactions: it breaks lichen's promise
  that a user need do nothing until `T_close − Δ` (the user,
  2026-11-09).
- Definite claims: a fixed set of notes and one `b`, under today's
  digit decomposition. No candidates, no reduction of `b` (the user,
  2026-11-09).
- Sender acknowledgment, mandatory for every spend, naming the next
  anchor (not the spend's own height), counted by existence; outputs
  locked until it's sequenced, which the sequencer does once its anchor
  is the margin deep; an exit voiding a spend still unacknowledged. The
  simple version first: a payee counts a payment only at full
  finality, and softer finality (conditional spends of locked outputs,
  a hub's receipt) is for later analysis. See "Data availability:
  sender acknowledgment" (the user, 2026-11-09). It replaces accepting
  the in-flight risk (decided earlier the same day).
- No fixed denominations to shrink it: they multiply inputs and
  outputs, and shielded proving time with them (the user, 2026-11-09).

- Shielded notes: option A, split keys (`ask`, `nk`, `X`) with a
  trapdoor `r` in `cm` and `nf`. A sender learning, after Alice's exit,
  when she spent its notes is acceptable; the wallet moves to a fresh
  shielded address after an exit. Planned, built after the transparent
  exit; the trapdoor also fixes today's non-hiding commitment (the
  user, 2026-11-09).
- Build the transparent exit first, on a branch, on the mock statement
  (the user, 2026-11-09).
- Withdraw by claim; no return transaction (the user, 2026-11-09). A
  cooperative withdrawal is Alice's claim for the contract, the same
  object her `request` would post: the hub checks it against its ledger,
  sequences its exit record (hub-signed, so it counts at once: no
  acknowledgment needed), and folds at once, with no anchor wait. If the
  hub records it and won't fold, her exit posts the same claim, which
  this contract's own record doesn't refute (Own); if it never recorded
  it, the notes are live: either way she is paid, so she needn't know
  which. Reusing the notes through another contract is a second claim.
  Whole notes only: a note to size is split off first. Gone with it: the
  return note with a contract's memo, `smt::returned`, the return
  exclusion (`Spent::Return`), the withdrawal statement and its guest.
- babe and BitVMX contracts removed, leaving hub-proves the only
  contract kind (the user, 2026-11-09): their dispute was over a refused
  return. With them went BABE's return graph and its keyless tower (a
  hub-proves exit has no tower), BitVMX's search and the BABE guest.

## Decided while building (2026-11-09)

Where these differ from the sections above, they hold.

- **The claim posts each note's opening,** with its position (80 bytes):
  see "The claim". So at most 8 notes, an exit record's most, until a
  chain-guest change.
- **Next: commit each leaf's kind.** The kind is public already (a transaction shows which
  outputs are transparent), so it costs no privacy, and a claim goes
  back to positions alone, 4 bytes a note. Lean: a bit of the leaf
  itself, today's commitment with its top bit set to the kind (0
  transparent, 1 shielded), enforced by the chain guest at insertion.
  No extra hash and no extra data in any proof: the statement reads the
  kind off the leaf its path already carries; 255-bit commitments
  instead of 256. Alternatives: `leaf = H(kind ‖ inner)` (one more
  compression per leaf hashed, and the hub reveals `inner` to show a
  leaf shielded), or two trees (a second root in the state, every spend
  naming its tree). With it, raise the exit record's 8 notes.
- **`E` is today's fingerprint** with `h_S` 0 and the positions' digest
  for `SR_S`: the hub's exit record retires the notes under today's
  chain statement, no guest change.
- **The journal is `c ‖ D ‖ H(O_D ‖ margin)`:** the statement reads `b`
  and `E` from her signatures' digits, which Bitcoin checked.
- **Her wallet waits** until her notes' anchor is the margin deep before
  it claims: a note newer than `A*` isn't in its tree, and the hub
  rightly asserts it isn't live (the first run of the test did exactly
  that).
- **No anchor after `A*` yet:** the hub mints a sat to itself, once a
  contract, so that the sequencer seals and anchors, spending `A*`'s
  seal.
- **After finding a claim holds,** the hub records the exit and keeps
  looking for a second claim of its notes until a quarter of `w_H` is
  left.
- **Two claims of one note, requested together, are both asserted
  false:** each is the other's second claim. The double claimer loses
  both contracts (EXIT_PLAN's "the first is paid" was an artefact of
  responding before the second request).
- **No tower:** a hub-proves contract's dispute can't be handed to one
  (her challenge reveals her dealing's secrets).
- **The hub keeps its signatures on `wrongly_challenged`;** she gives
  hers.
- **Windows** (`lichen_proto::hp::windows`): `w_H` 80 blocks on regtest,
  240 on Mutinynet (2 h); `Δ2` (her challenge) 40 and 2,880 (a day);
  `Δ1` (its answer) 40 and 240. The margin: 6 blocks on regtest, 20 on
  Mutinynet.
- **Measured on regtest** (`hp_exit.rs`, a laptop): she garbles 4
  instances in 1.3 s and uploads 2 of 23 MB; the hub checks the 2
  opened in 1.2 s. `request` is about 2.1 kvB with one or two notes,
  `assert` 7,725 vB, her `challenge_assert` 20,717 vB.

## Build order

Done (2026-11-09), on the mock statement:

1. The hub's statement, natively (`withdraw::hp`), with unit tests.
2. The swapped graph (`babe::hp`).
3. The swapped setup (`proto::hp`; the hub's `/hp/setup`, `/hp/commit`,
   `/hp/instance/<cid>/<i>`).
4. Both sides' play (the hub's `dispute::hp`, the wallet's `hp`,
   `engine::hp`), and `hp_exit.rs`: an honest exit paid by timeout; a
   stale claim asserted false and conceded; the same challenged and
   answered; a note through two contracts, both asserted false; a lying
   hub refuted; an exit after a withdrawal recorded but not folded,
   paid; the operator gone, paid by timeout.

Next:

5. One chain-guest change, built natively and tested on regtest first,
   then one rebuild of the guests and their fixtures:
   - done natively (2026-11-09): the leaf's kind (its commitment's top
     bit, set by the chain statement as it appends: `t_leaf`, `s_leaf`);
     claims by position alone, `E = H(c ‖ O_D ‖ b ‖ i_1 ‖ … ‖ i_n)`; the
     exit record carrying its notes and positions (shown in the tree) and
     one signature per owner, at most 64 notes; the hub's statement as
     malformed, or false at `A*` (not a note, not hers, too much, spent,
     a second claim), the hub opening each note a ground needs. The
     ledger's return check is its own, on leaves, no longer ln-gap's;
   - the guests rebuilt (2026-11-10, lichen-vps): spend `755aa218`,
     chain `0bcd188d` (r0/guests/README.md); no fixture left to prove
     again (the withdraw and BABE guests and their fixtures went with the
     return);
   - done natively (2026-11-09): sender acknowledgment ("The
     representation"). Decided while building:
     - locks only in an anchored deployment (a genesis seal): without
       anchors there is no exit and nothing to acknowledge against;
     - the margin is structural: the sequencer records an anchor only
       its margin deep (anchoring confirmations = the margin, 6 on
       regtest, 20 on Mutinynet), and an acknowledgment must name a
       recorded anchor;
     - the hub holds a claim's notes as soon as it sees the request, and
       the sequencer refuses an acknowledgment of a spend whose inputs
       are held (the earlier of an exit and a spend wins);
     - a claim carries the wallet's acknowledgments of every claimed
       output of its own spends, locked or not when it claims: a note
       unlocked now may be locked at `A*`. An exit record skips one whose
       spend is acknowledged already;
     - the sequencer serves acknowledgments with their signatures (`GET
       /ack/<txid>`), for the hub's statement; the hub also takes them
       from other contracts' claims on chain;
     - the wallet: a one-time `ak` per spend (derived from its key and
       the spend's first nullifier); `lichen ack [--wait]`; `balance`
       counts locked notes, `spendable` doesn't; a withdrawal
       acknowledges the wallet's spends first. A shielded input's lock
       is the wallet's to keep (its position is private), until shielded
       exits;
     - regtest: `hp_exit` cases U (never acknowledged: its input claimed,
       paid, the payment voided, the payee's note locked for good) and W
       (acknowledged, the acknowledgment withheld: the locked change
       claimed carrying it, paid, the payee's note unlocked).
6. Done (2026-11-10): the hub's statement as a guest (`r0/hp-guest`, hp
   `a71fe1ef`, holding the chain guest's id; the chain receipt at `A*` an
   assumption), and the real statement (`hub-proves`: BABE's
   `Kind::Risc0` on `hp.id`, the Groth16 seal read by
   `lichen_babe::risc0::proof_from_seal`). The hub proves in the
   background (`r0/hp-prover.sh hp-proof`, `LICHEN_HP_PROVER`): the
   sequencer's chain receipt at `A*`'s chain height first, its files in
   `hp/<cid>/`. In the guest, hp_exit's inputs (`LICHEN_DUMP_HP`): a
   spent note 1.68M user cycles, a second claim 1.0M, 2 segments each.
7. Real proofs on regtest, then Mutinynet. Done (2026-11-10), a first:
   `hp_real.rs` (opt-in), a malformed claim proved false for real (no
   chain receipt needed), proved and wrapped on lichen-vps through
   `r0/hp-remote.sh`, asserted (7,725 vB), the proof checked by the
   wallet, which concedes; the exit 442 s on regtest, the proving
   included. Left: a ground at `A*` for real, which needs every chain
   height to `A*` proved (on lichen-vps some ten minutes a segment: hours
   for a test's heights), so best on Mutinynet, whose chain prover runs
   anyway; that needs a fresh ledger there (this branch's state and
   guests are incompatible with the deployed ones).
8. Shielded notes ("Shielded notes"). Natively, done (2026-11-10):
   the split keys and the trapdoor (`lichen_shielded`: `auth`, `owner`,
   `cm` and `nf` with `r`, the value and `r` encrypted to the recipient);
   claims of shielded notes (`lichen_validity::exit::SClaim`, in `E`; the
   exit record retires them; the hub's grounds over transparent then
   shielded notes, a shielded note's opening the claim's); the wallet
   keeps them in its exit sets and claims them, signed by its exit key;
   `shielded_exit.rs` (an exit of a shielded note paid; a stale one
   asserted spent). Left: the guests rebuilt; a shielded input's lock is
   still the wallet's to keep.
9. Done (2026-11-09): the old exit removed (the hub's counter,
   `respond`'s countering leaf, the failed-counter branch and its
   in-guest Groth16 check, the counter guest, Alice's claim proof and
   its exit set's kits and chain receipts).
10. Done (2026-11-09): withdraw by claim (`POST /withdraw`: the claim,
    recorded on the L2, then the fold at once; `withdraw.rs`), and the
    return removed with the babe and BitVMX contracts, their disputes,
    the tower, the withdrawal and BABE guests. Step 5's guest rebuild is
    then the spend and chain guests only.
