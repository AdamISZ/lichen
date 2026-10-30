# Exits from anchored state, with a counter: plan

2026-10-21, branch `anchor`. Replaces END_PLAN.md for a deployment
whose hub and sequencer are one operator.

2026-10-30: revised for BABE, now lichen's gadget. "The game" below is
the BitVMX design and is superseded by "Under BABE", which follows it.
The steps at the end are the BABE ones.

## The assumption

The hub and the sequencer cooperate: one operator, or two that trust
each other. Neither attacks the other, and that threat is out of scope.
The deployment keeps its two keys (`deployment_id(sequencer, hub)`);
only the trust between them changes.

The threat that remains is the operator against its users. It profits
from the default: whatever isn't withdrawn by `T_close` goes to the hub.
So it has reason to censor returns, stop sealing, withhold data, or
vanish. Users against users is already covered by anchoring and the
chain proof.

## The principle

Alice may exit at any time from any anchored state `S` she can prove
from. Her claim: "these notes of mine were unspent at `S`; pay me
`b`." The operator may answer once with a counter: "one of them was
spent at an anchored state after `S`." This is a claim followed by a
counter-claim, as in ln-gap, one step down:

- Alice's proof speaks for `S`.
- Only the operator can point to something later, and only to
  something that happened. A note's nullifier enters the set in two
  ways only: a spend, which needs the note's keys, or an exit record,
  which must carry the owner's own exit proof (After an exit, below).
  So the operator can't produce a false counter.

The operator can't stop an exit. A censoring operator has no counter to
a true claim. A vanished one times out, and its timeouts pay Alice. The
operator's only defence is a spend that really happened, which is all
the hub needs.

## Alice's claim

A second mode of the withdrawal statement, with one image id.

- **Inputs:**
  - an anchored state `S`: as for a withdrawal, a chain receipt whose
    anchor commits `SR_S` at `h_S`, with headers carrying `W` of work on
    the anchor's block;
  - her notes: each one's opening and her authority over it (`nk` for a
    shielded note, a signature for a transparent one), its path in
    `T_S`, and its nullifier's non-membership in `N_S`.
- **Accepts if:**
  - all of that checks;
  - the notes are distinct;
  - `b ≤ Σ`.
- **Journal:** `b ‖ c ‖ D ‖ E`, with `E = H(c ‖ h_S ‖ SR_S ‖ nullifiers)`.

The nullifiers are part of her input words, and the program checks them
against `E`. They have to be: the operator can only search for a later
spend of nullifiers it knows, and the claim is the only place they
appear. At most, say, 8 notes.

**How much to claim.** A claim spends whole notes, and the contract
pays once, so whatever she still holds afterwards is credit. An exit
therefore claims everything it can:

- `Σ ≤ V_max`: claim `b = Σ`. A dispute pays in multiples of 512 sats,
  so only the rounding is lost.
- `Σ > V_max`: claim `b = V_max`, from the subset of notes that covers
  it with the least excess. The other notes stay out of `E`, so the
  exit record doesn't burn them: they remain hers, as credit, for a
  later contract or a sale to someone with headroom.

The value above `b` in the claimed notes is forfeit, so the wallet
keeps its notes sized to fit the cap closely. It also consolidates
small notes, so that its balance fits in one claim.

No note has to be bound to a contract in advance. The same note claimed
through two contracts is caught by the counter, below.

## The counter

A new statement, proved by the operator, a Groth16 proof of about 256
bytes:

- **Inputs:**
  - Alice's claim (`D`, and `E` with its preimage: `c`, `h_S`, `SR_S`
    and the nullifier list);
  - a later anchored state `S'`, 10 deep, in the same history as `S`;
  - one of the claim's nullifiers, inserted at a height `h_S < h ≤ h_S'`
    by a transaction that isn't contract `c`'s own: neither its exit
    record (below) nor a return with memo `c`;
  - the escalation's confirmation at Bitcoin height `H_esc` (below), and
    the insertion's anchor confirmed at or before `H_esc − m`.
- **Journal:** `D ‖ E ‖ ok`.

"The same history": the counter's chain receipt passes through `S`.
Anchors form a single chain, so this is a hash-forward check from `S`'s
anchor through the anchors it records. Detail for the design pass.

The counter covers three cases:

- **Alice spent the note later** (she paid Bob and then exits an older
  state): the spend.
- **The same note through two contracts:** the first claim's exit
  record (below) inserted the nullifier, and the second claim's counter
  shows it, even if the record was anchored after the cutoff (exit
  records are exempt, below).
- **A claim racing a spend:** the operator, as sequencer, refuses to
  sequence a spend of nullifiers whose claim is pending. A spend
  anchored after the cutoff can't counter (below), so a sequenced one
  is the operator's loss: the exit record then can't retire notes
  already spent, and both the claim and the spend's receiver can be
  paid.

**The cutoff: only what was final before the claim.** A counter may
cite only an insertion whose anchor confirmed at least `m` blocks before
Alice's escalation. Without it, any transaction Alice has signed and the
operator holds is a counter in waiting: the operator includes it during
`W_c`, after she has committed to her claim, and takes her contract.
Excluding her own return fixed one instance of this; the cutoff fixes
all of them. With it, everything a counter can use was already final,
on Bitcoin, when she claimed, so an honest Alice who can read the
anchored data before escalating can't be countered. That leaves data
availability as the only gap (Data availability, below).

- **`H_esc` must be proved, not chosen.** If Alice named her own cutoff,
  she could pick a stale one and hide a spend anchored after it. So the
  counter guest proves the height: the transaction spending contract
  `c`'s funding outpoint, in a block by Merkle path, on headers that
  continue the anchors' chain. The guest must know the outpoint for
  this: if `c` stays a memo number, `E`'s preimage gains the outpoint,
  checked on chain against the contract's terms like `c`. Detail for
  the design pass.
- **The margin `m`.** Alice checks the anchored data up to the tip, then
  broadcasts. Anchors confirmed between her check and `H_esc − m` could
  be cited without her having seen them, so `m` covers her escalation's
  confirmation time: `e` in the Timing table, 6 blocks on mainnet and 20
  on Mutinynet. If her escalation takes longer, she fee-bumps it.
- **The hub loses nothing it can't avoid.** A spend that races the
  claim is one the operator, as sequencer, can refuse (above), and the
  exit record retires the notes afterwards.
- **Exit records are exempt.** Two claims of the same notes through two
  contracts can escalate together. Each one's exit record is posted
  only once its claimant's proof is on chain, at its escalation, so it
  is anchored past both cutoffs, and neither claim could be countered.
  So a counter may cite another contract's exit record anchored at any
  height up to `h_S'`. This doesn't reopen the attack the cutoff closes:
  a record needs an exit proof by the notes' owner for that other
  contract, and an honest Alice never makes one for notes she is
  claiming through `c`. The two claims counter each other, and the
  double claimer loses both contracts. (Found while designing the
  sender acknowledgment below, which relies on it.)

**Why contract `c`'s own return doesn't count.** An honest Alice tries
the cooperative way first: she signs a return of her notes with memo
`c` and exits only when it isn't sealed (Timing, "detect"). The
operator still holds that signed return. If a return could counter,
the operator could sequence it after her escalation and take her whole
contract with her own transaction. Excluding it costs the hub nothing:
if the return is sequenced, the hub has her tokens, and contract `c`
still pays only once.

**Why `c` is inside `E`.** Both exclusions depend on `c`, so the counter
must be about one contract's claim, fixed on chain. If `E` left `c`
out, the operator could post Alice's genuine exit record for `c_A`, then
prove a counter that applies the exclusion for some other `c_B`. To that
counter, `c_A`'s record is an admissible insertion, and with the same
`D` and `E` it would defeat her honest claim through `c_A`. Her censored
return could be used the same way. With `c` in `E`, the counter guest
recomputes `E` from its preimage and excludes for that `c`, so matching
`E` on chain forces the exclusion to be for her contract. A double claim
through `c'` is still countered: its `E` holds `c'`, and `c`'s record
isn't `c'`'s own.

**Considered and rejected: Lightning-style revocation** (2026-10-27).
Claim and counter mirror Lightning's old state and penalty. So could
Alice hand the operator a revocation secret per note when she spends
it, making the counter a hash preimage instead of a proof? No:

- **It can't be atomic with sequencing.** Lightning revokes only once
  the new state is enforceable, and an update there exists as soon as
  both sides sign. Here the spend exists only once the operator
  sequences and anchors it. A secret handed over at spend time lets the
  operator refute her exit of `s` without ever sequencing the spend.
- **So it could only follow the anchor,** say at the kit fetch after a
  spend. Until then Alice holds both `s` and her change, and the proof
  is the only counter. The proof stays, and revocation becomes an
  optimization of the rare case where a dishonest Alice is countered.
- **Anchoring already gives the ordering that revocation stands in for.**
  Lightning needs revocation because Bitcoin can't tell which of two
  commitments is newer. Lichen's anchored history can, so "spent later"
  is provable directly.
- **It would also cost non-interactive receiving.** `H(rev)` must be in
  the note's commitment, and the sender who makes the note must not know
  `rev`, so the recipient would have to supply it, as with an invoice.

## The game (BitVMX; superseded by Under BABE)

ln-gap's game with the operator's counter as a second input, owned by
the verifier. The program definition already lists inputs by owner. The
program changes from "verify Alice's proof" to:

> Accept if and only if either a counter was posted and it doesn't
> verify, or it names another `D` or `E`; or no counter was posted and
> Alice's proof verifies.

**A failed counter pays Alice, whatever her own proof.** That's the rule
throughout ln-gap: a party shown to cheat once, anywhere, loses at once.
It's safe for the hub because a counter is always its choice. Against a
false claim it never needs one, since it challenges her proof instead;
against a stale claim it has a true counter, which wins. A counter that
fails is one the operator chose to post and could have avoided.

Flow:

1. **Escalation.** Alice's claim, with her proof and nullifiers as
   input words. It must confirm by `T_close`, as now. Once it spends the
   contract output, no default can follow.
2. **The counter window `W_c`.** The operator posts its counter's words,
   or doesn't.
3. **The game as today.** Alice commits the trace of the program over
   both inputs. The operator concedes, or bisects it. Each side's
   timeouts pay the other.

| | Alice's proof | counter | result |
|---|---|---|---|
| honest exit | valid | none (none can exist) | Alice is paid |
| she spent it later | valid at `S` | valid | the program rejects; Alice loses the contract |
| a garbage counter | any | invalid | the program accepts; Alice is paid |
| the operator gone | valid | none | timeouts pay Alice |
| a false claim | invalid | — | rejected, as now |

A countered claim loses the whole contract, as any false claim does
today. That penalty is right for a double spend, and a careful wallet
never makes one.

Only Alice proves. The counter is checked inside her trace: if it's
valid she can't produce an accepting trace, and the operator disproves
her. So it's one game, with no second ladder and no roles reversed.

**The alternative, and the conservative route: a separate counter game.**
Alice's escalation output gets a branch: within `W_c`, the hub may
spend into a counter ladder with the roles reversed. The hub proves its
counter, Alice checks it, and one Groth16 trace is bisected, as today.

- **The counter holds:** the hub takes the contract.
- **The counter fails,** or names another `D` or `E`: Alice is paid at
  once, as if she had won her game, which isn't played (the rule above).
- **No counter:** Alice's game, as now.

So exactly one game runs, under any play, not only rational play. A
false counter costs the hub the contract, as losing Alice's game would,
so counters can't be used to double a dispute's cost, and in a mass
exit they can't add load to the chain except at the operator's own
expense. Each game uses today's ELF, depth and rules.

What it needs:

- a role-reversed instance of the ladder. ln-gap fixes the roles by
  position (`pubs[0]` Alice, `play.rs`'s `Prover`), but BitVMX's
  decision functions underneath don't care who plays which side;
- the branch leaf, signed at opening. The pre-signed set roughly doubles
  (about 90 transactions on the mock), but the reserve doesn't, since
  only one game's floors are ever paid, under any play;
- one cross-game check that the counter names Alice's `E`: she
  re-reveals her `E` words beside the hub's, and the hub's output is
  taken if they differ.

The single program above becomes an optimization, if a two-proof ELF
proves cheap.

## Under BABE

The claim, the counter, the cutoff and the exit records stay as above.
What changes is how they ride on the dispute. BABE's graph keeps its
shape (`request`, `respond`, `assert`, `challenge_assert`, each with its
terminal); three things are added. A diagram:
[the exit dispute](https://claude.ai/artifact/PJJkZuAygAEhP9ar62z98F),
a private page.

**A dead operator is already handled.** If the hub never responds,
`request_timeout` pays Alice her `b` after `w_H`, with no proof
(`engine/babe.rs`). The counter design is for an operator that is
present but hostile: one that responds, then censors her return or
stops producing the chain receipts she needs, so that she can't prove
by `T_A` and `respond_timeout` takes her contract.

### `E` and `K` on chain

- **`request`:** Alice signs `b` (as now, a 4-byte one-time key the
  payout reads) and `E` under a second one-time key, 32 bytes. She posts
  the nullifier list in the witness, unsigned since `E` binds it, at 32
  bytes a note (up to 8). That is how the hub learns what to search for.
- **`respond`** (superseded in part: two leaves, and `K` signed itself,
  not `H(K)`; see "The statement's three branches" below): the hub signs
  `b` (as now), `E`, and `H(K)`, all under
  its SHA-256 Winternitz keys. Its script compares the hub's `b` and `E`
  with Alice's, digit by digit, as it compares `b` today. Without that,
  the hub could sign some other `E` and leave her nothing provable. `K`
  itself goes in the witness: "none", or a counter of about 256 bytes.
  Whether `E` and `H(K)` take one 64-byte signature or two 32-byte ones
  is a detail; the witness stays far under the 1,000-element limit
  (roughly 300 elements more).
- **Return mode** (a refused return, today's dispute): `E` is a fixed
  value for return mode, and `K` is "none". So one graph serves both.

### Alice's statement

Fixed at setup, with the journal `c ‖ D ‖ H(pk_H)` as now; `b`, `E` and
`K` reach it through the hub's signature, the trick that already carries
`b`. One guest, two modes:

```
(superseded by "The statement's three branches", below)
the hub signed (b, E, H(K)), and either
   return mode:  a return of b with memo c, anchored, as today
   exit mode:    ( K = none  and  my notes, by E, were in S's tree and
                                  unspent at S, summing to at least b )
                 or
                 ( K ≠ none and ( K doesn't verify, or K's journal
                                  names another D or E ) )
```

A failed counter pays Alice whatever her own claim, the rule from "The
game". There's no second game and no roles reversed: `K` is judged
inside her statement, which BABE already judges. A true counter leaves
her no valid proof (`failure`, or `respond_timeout`); a false one she
proves false.

**What that costs, and when.** Only a counter with her `D` and `E` that
doesn't verify makes her guest run a full Groth16 verification. That
means a hub that has deliberately forged a counter, losing the contract
for it. Malformed points fail early; a counter naming another `D` or `E`
needs only the journal compared. Unmeasured: probably tens of millions
of cycles with RISC Zero's 256-bit accelerator, so dozens of segments,
against days until `T_A`. It's compute only: her proof stays one
Groth16 on chain. (Measured since: 47M cycles, step 0.)

**Anyone can prove it.** The failed-counter branch has no secret
witness: the hub's signatures on `E` and `K`, and `K`, are on chain,
and `D` and `c` are in the journal. So Alice can hand the whole proof to
a proving service or her tower, and nothing needs splitting off. Only
the claim branch needs her secrets (`nk`, or her signature), and it has
no Groth16 in it. Splitting would be possible too, as a receipt of "`K`
fails for `D ‖ E`" that her guest composes (a valid receipt of a true
statement, which is all an assumption needs). It saves nothing here,
since no branch mixes the expensive part with her secrets.

### The counter

The counter statement as above: a RISC Zero guest, wrapped in Groth16.
It uses the same verifying key as Alice's proofs, with its own image id,
which her guest pins. The cutoff is `request`'s confirmation height,
proved by the counter guest from the request transaction in a block on
the anchors' headers; the guest knows the contract's funding outpoint
through `D` or `E`'s preimage (detail).

### Decided while building step 1 (2026-10-30)

Built natively in `crates/withdraw`: the claim (`exit.rs`) and the
counter (`counter.rs`). Building them settled three points the sections
above left open.

**The contract's outpoint is bound by the setup.** The counter's cutoff
is the confirmation of `request`, the transaction spending the funding
outpoint `O`, so `E`'s preimage carries `O`. Something fixed must vouch
for it, or Alice could name an outpoint spent long ago, a stale cutoff,
and hide a later spend. Any other way to recognise `request` (Alice's
signature in its witness, the hub's in `respond`'s, the leaf it reveals)
can be copied into another transaction by whoever gains from it. Today
BABE fixes the journal in `babe_setup`, when the deposit address is
handed out, before any funding transaction exists. So the open flow
changes:

1. `/deposit`: the address only, no setup.
2. Alice pays; her deposit is in the mempool, so its txid is known.
3. `/open`: her keys; the hub builds the funding transaction, so `O` is
   known, and runs the setup with the journal `c ‖ D ‖ H(pk_H ‖ O)`.
4. Her kept instances (a message of their own now, since they depend on
   the setup's commitments), the checks of the opened ones, the
   presignatures; she signs the deposit's spend last.

The funding transaction still waits for the deposit's confirmation, so
the setup runs during that wait. The deposit tree doesn't depend on the
setup, and nothing is broadcast before the presignatures, so Alice is no
more exposed than now. A side benefit: today anyone can make the hub
run a setup by asking for an address; afterwards it takes a payment.

**The nullifier tree records how each note was spent.** The counter's
exceptions depend on what spent a nullifier, which a plain "spent" leaf
can't say. Each leaf now does (`lichen_validity::smt`):

- `spent`: an ordinary transaction;
- `returned(c, r)`: a transaction paying the hub exactly one note, of
  `r` with memo `c ≠ 0` (memo 0 is "no contract", and contract numbers
  start at 1000);
- `exited(c)`: contract `c`'s exit record (`Tx::Exit`, step 2).

The chain guest and the ledger set the leaf on insertion; old ledgers
read as all `spent`. Exits are outside the L2's own rules, so exit
records are how they enter its double-spend protection; the tags decide
which spends may be held against which exit. The counter's rules:

- `spent` counts if final before the cutoff;
- `returned(c', r)` is an ordinary spend unless `c' = c` and `r ≥ b`.
  Then it never counts: the hub has at least `b` of her tokens for
  contract `c`, which pays once. A smaller return, or one to another
  contract, can't shelter a spend, or Alice could tag a payment to Bob
  with a token return and exit the old notes. So `b` joins `E`'s
  preimage, and a wallet exiting after a censored return claims no more
  than the return;
- `exited(c')` counts whenever anchored, unless `c' = c`.

The counter's journal is `D ‖ E`.

**No margin on the cutoff.** The plan above lets a counter cite only an
anchor confirmed `m` blocks before `request`, to protect an honest
Alice from a transaction of hers that the operator held and sequenced
after she checked the tip. But the margin is a window for a dishonest
Alice: she pays Bob, sees the spend anchored, and requests within `m`
blocks, claiming the old notes. No counter can cite the spend, so she
is paid while Bob keeps the payment, at the hub's cost, once per
contract. The counter as built cites any anchor confirmed at or before
`request`'s block. What the margin protected is the held-transaction
case of data availability, which sender acknowledgment closes (a spend
can be cited only with its sender's acknowledgment, which she gives
only after seeing it anchored), so with it no margin is needed. Until
then, a wallet must not exit notes it has signed away in a transaction
that wasn't sequenced; it claims its other notes, or waits.

**What the exit guarantees** (prompted by an outside review asking for
"every redemption consumes exactly one L2 entitlement, even while the
sequencer is unavailable"). Lichen doesn't promise that, by design: a
dead operator posts no exit records and answers no claims, so a note
can be redeemed twice, and nothing forces a restarted sequencer to
include the records it missed. The invariant is instead:

1. No user loses to another user or to the operator: an honest claim
   can't be countered, and every payment received stays good.
2. Every payout not matched by L2 value retired (an exit record, or a
   return of at least `b` to `c`) is the operator's loss.
3. An operator that stays live and follows the protocol (posts records,
   counters, refuses spends whose notes are under a pending claim) can
   always avoid that loss.

**Point 3 fails within anchor latency, until acknowledgment.** A
dishonest Alice pays Bob, and the operator sequences it. She broadcasts
`request` at once, and it confirms before the anchor holding the
payment. With no margin the payment is after the cutoff, so she is paid
`b` and Bob keeps the payment. The operator can't refuse a spend for a
claim that doesn't exist yet. Dropping the margin narrowed this window
to anchor latency but didn't close it.

Sender acknowledgment closes it, by allowing a grace the other way: an
ordinary spend counts if its anchor confirmed no later than `δ` blocks
after `request`'s block, `δ` at least the anchor latency. This is safe
for an honest Alice once a counter must cite her acknowledgment, since
she never claims notes she has acknowledged spending. A dishonest Alice
who never acknowledges leaves Bob's outputs locked, voided by her exit
record, and Bob doesn't deliver until he sees the acknowledgment
anchored. One who acknowledges and then requests at once has the
acknowledgment anchored within `δ`, where a counter can cite it. So the
margin comes back reversed: it protects the operator, and acknowledgment
protects Alice. The counter takes the grace (`counter::GRACE`, with the
anchor block's header and its parents as input), set to 0 until step
10. Until then the race is the operator's loss, bounded at one per
contract.

**The statement's three branches; `K` signed itself.** The design above
has the hub sign `H(K)` and post `K` beside it. But no script can check
that the posted `K` hashes to the signed digits: `OP_SHA256` gives 32
bytes whole, the signature gives nibbles, and without `OP_CAT` neither
becomes the other. So a hub could sign `H(K*)` for a valid counter `K*`
it keeps, post other bytes, and leave Alice no preimage to prove `K*`
false with. She couldn't claim "no counter" either, and
`respond_timeout` would take her contract.

So the hub signs `K` itself: a Groth16 seal compressed to 128 bytes (two
G1 points of 32, a G2 of 64), 256 digits and 3 of checksum. Uncompressed
(256 bytes, 516 digits) would exceed the 1,000-element stack limit at
two elements a digit. To keep that off the honest path, `respond` has
two leaves, both comparing `b` and `E` with `request`'s:

- **plain:** the hub signs `b`, and `E` under `e_plain`. About 77 digits.
- **counter:** the hub signs `b`, `E` under `e_counter`, and `K`. About
  336 digits, 672 elements, roughly 11 kB of witness, paid by a hub
  countering a dishonest claim.

Which `E` key signed shows which leaf ran; each signs once. Alice's
statement (`fixed::check_exit`) wins on any of:

- **return:** the hub signed `b`, and a return of `b` with memo `c` is
  anchored, as today. In either mode: a return pays once, and its `E`
  and `K` don't matter;
- **claim:** the hub signed `b` and `E` in the plain leaf, and her claim
  of `b` with that `E` holds;
- **failed counter:** the hub signed `E` and `K` in the counter leaf,
  and `K` doesn't verify for her `D ‖ E` (decompression failing
  included). A counter for another `D` or `E` fails the same way, so no
  separate check is needed.

The journal is `c ‖ D ‖ H(pk_H ‖ O)` with `pk_H` all four keys (`b`'s,
both `E`s, `K`'s). The Groth16 check is passed in, as the chain
receipt's is; the guest supplies RISC Zero's verifier with the counter
guest's image id (step 4). The old statement (`fixed::check`, return
only, today's journal) stays until the graph changes (step 3).

### Windows and load

- **`w_H` absorbs `W_c`.** The hub must find and prove any counter within
  its response window: about 20 minutes to prove, plus the wrap.
  Mutinynet's 40 blocks (20 minutes) is too short; lengthen it.
- **On chain,** per exit and fixed whatever anyone does:
  - `request` grows by the nullifiers and Alice's second signature (a
    few kB, due only by `T_close`);
  - `respond` grows by the hub's signatures and `K` (a few kB; it counts
    toward the hub's bytes per window, small beside `challenge_assert`'s
    20.7 kvB).

  Nothing grows with misbehaviour.
- **The compute flood.** A wave of stale claims makes the hub prove many
  counters within one `w_H`. It's costly to mount, since each countered
  claimant loses their contract. Counters parallelise, so a proving
  market or more machines scale with the wave, and one proof could
  answer many claims if needed. Size the hub's capacity with `w_H`.

### Exit records under BABE

Alice's whole proof is on chain in `assert` (π1 signed, π2 and π3
beside it), so the operator always has it for the record. The chain
guest then checks a Groth16 per exit record, the same cost as above,
per exit rather than per transaction. If that proves too heavy, the
alternative is the one above: the claim carries the owner's signature
on `c ‖ E`, made inside the exit proof. Measure first.

## After an exit

The operator, as sequencer, posts an exit record on the L2: a
hub-signed transaction `(c, nullifiers)`, which inserts them. This is in
its own interest, since otherwise the exited notes could be spent again
and withdrawn through another contract. They're an L2 transaction type
like mints.

**The record must carry the claimant's exit proof.** The chain guest
accepts an exit record only with an exit receipt whose journal is
`b ‖ c ‖ D ‖ E` for this deployment's `D`, the record's `c`, and an `E`
over exactly the record's nullifiers. A hub signature alone isn't
enough. With only the signature, the operator could forge counters:

1. Bob escalates an honest exit, and his nullifiers become public in his
   input words.
2. The operator posts an exit record with Bob's nullifiers under
   another contract `c'`. The counter excludes only `c`'s own record,
   so this one counts.
3. The record anchors 10 deep within `W_c`, and the operator counters
   Bob with it. Bob loses his contract, and his notes are frozen.

For transparent notes, whose nullifier anyone can compute from the
commitment, the operator wouldn't even need Bob's claim. It could freeze
any notes at any time and counter their exits later.

With the proof required, a record exists only for a claim the notes'
owner made, since only she can prove one (`nk`, or her signature). Then:

- **An honest single claim** can only have a record naming its own `c`,
  which the counter excludes.
- **One note through two contracts:** the first claim's proof makes a
  genuine record, which counters the second, whenever it's anchored
  (exit records are exempt from the cutoff).
- **Nobody's notes can be frozen** by a record, since every record traces
  back to a claim their owner made.

The operator always has the proof: the dispute puts Alice's Groth16
proof on chain as her input words, and a folded exit hands it over off
chain. The chain guest checks it once per exit record. In-guest Groth16
verification (BN254 pairings) is unmeasured. If it's costly, the record
could carry the exit's succinct receipt where the operator has it, or
the claim could carry the owner's signature on `c ‖ E`, made inside the
exit proof, for the record to show instead. Detail for the design pass.

## The operator's death

No mechanism is needed for the users. An absent operator doesn't
counter or move, so exits pay by timeout from any state Alice can prove.
The double claims an absent operator can't answer cost only the
operator: users never gain from each other. A payment Bob received
(anchored, so final) is in a later state than Alice's older one, and
both exit, from the operator's collateral.

So END_PLAN.md's seal leaf and its definition of the end aren't needed
for users' safety here. They would still serve operators that don't
trust each other, or a clean shutdown with one final state. Both are
deferred.

## What Alice must hold: the exit kit

For some anchored state after her last spend:

- the chain receipt (or the withdrawal's kept material);
- each note's path;
- each nullifier's non-membership proof.

The sequencer serves these per note. A kit never goes stale: the tree is
append-only, so a path to `T_S` stays valid, and non-membership in
`N_S` stays true of `S`. A new kit is needed only when her notes change,
so the wallet fetches one after events, not on a schedule:

- **After a spend:** a kit at a state after the spend, 10 deep, covering
  the new notes. She was online to sign, so this is a fetch about 10
  blocks later. Until she has it, the new notes aren't exit-safe, and an
  operator that withholds their data can keep them so (Data
  availability, below).
- **After a receipt:** whenever she next comes online. Until then the
  payment isn't final for her (below).
- **Otherwise:** nothing. A wallet that happens to be online may
  refresh anyway, as a convenience, but no liveness is required.

If the operator stops serving, the last kit still works: Alice hasn't
spent since, so no counter exists.

Hence a rule for receivers: **a payment is final once you hold its kit
at an anchored state 10 deep.** The wallet's "final" already means
anchored 10 deep, and now it also requires the kit in hand.

The tower's package carries the kit, so a tower can exit with no
operator.

## Data availability: the one remaining gap

With the cutoff, the exit is safe exactly when Alice can read the
anchored data she needs. An earlier version of this plan said the
receiver rule narrows data availability to a per-receiver question. It
doesn't: senders are exposed too, through their own new notes.

**The consolidation attack** (found by a reviewer). Alice's whole
balance is covered by her kit. She signs a consolidation of her notes
into one new note, of the same value, as the wallet recommends. The
operator sequences and anchors it, and withholds the new note's data.
Now:

- the old notes are countered: the consolidation really spent them,
  before the cutoff;
- the new note has no kit, so she can't claim it;
- at `T_close` the hub takes the contract.

No payment to anyone else was needed, and the same works on any spend
that leaves her with change. Her protection is lost the moment the
operator anchors one of her transactions and withholds its outputs'
data.

The cutoff has already removed the timing half of the problem (a held
transaction included after her claim). What's left is purely that
anchors are public on Bitcoin but their contents aren't. If nothing has
been anchored since her kit, she's safe. If something has and she can't
read it, she can't tell whether her transactions are in it, or prove
her new notes.

Data availability is a hard problem for a system like this, but the aim
is that it's the only substantial one, and with the cutoff it is.

**Where it can be enforced.** The operator wins a contract only with a
counter. So withholding is harmless whenever a spend whose data Alice
can't read can't be cited. Most options below are rules of that kind:
what a counter must show besides the insertion. Several follow John
Light's survey of data availability for Bitcoin rollups
([bitcoinrollups.org](https://bitcoinrollups.org), Appendices C and D,
2022). The options, still open:

1. **Publish just enough with each anchor** (a rollup's data, trimmed).
   An exit needs only each batch's inserted nullifiers and new note
   commitments, not the transactions: a sender knows her own outputs,
   and a receiver gets his openings off chain. With them on Bitcoin,
   Alice can rebuild both trees, see whether her notes were spent, and
   prove her new notes. At 32 bytes each, a 1-in-2-out transaction is
   96 bytes: about 24 vB in a script-path envelope in the anchor's
   witness, against 269 vB per batch today. Light's full-rollup figures
   are 113.5 WU per transparent transaction and 659 WU per shielded one,
   530 WU of which is encrypted note data, so trimming gets under even
   the transparent figure. Enforced in the counter: a spend counts only
   if its anchor, and every anchor before it, carries its batch's data. The Shielded CSV end of the
   trade-off: no trust, and a cost per transaction on Bitcoin.
2. **Volition: publish some.** Light's per-transaction choice: a flag on
   the transaction puts its nullifiers and commitments in the anchor's
   witness, and the wallet sets it on consolidations and spends with
   change. A path needs every leaf of its batch, though, so published
   outputs would need their own subtree per anchor, all of whose leaves
   are on chain. Option 3 does the same job with nothing on chain.
3. **Sender acknowledgment** (below): a spend can be cited only once its
   sender has said she holds its data. No trust and nothing on chain,
   at the price of two-phase payment finality.
4. **Transaction expiry and a two-branch claim.** Each L2 transaction is
   valid only if anchored by a Bitcoin height it names, so a held
   authorisation dies, and Alice knows exactly which of her
   transactions could be inside anchors she can't read. Her claim then
   lists them: "my notes `N` were unspent at `S`; since then I signed
   only these, and my outputs among them are `O`." A counter showing a
   listed transaction was included switches her claim to `O` instead of
   taking the contract. That's two possible amounts, under two one-time
   keys, with the payout following the counter game's verdict. A
   consolidation is worth the same either way, and a payment pays her
   the full notes if it wasn't included and her change if it was.
   Option 3 reaches the same outcomes with L2 rules in place of a
   second payout branch on chain.
5. **A data committee in the seal.** Light's validium, with the
   attestation enforced by Bitcoin rather than by a contract. Each
   anchor spends the previous anchor's seal output. If that output's key
   is a threshold key of the operator and a committee (FROST, so the
   anchor is still one signature and no larger), an anchor exists only
   if a quorum signed it. Members sign only once they hold the batch's
   data and will serve it, and only if the new seal output pays the
   same key, which the counter's history check can verify too.
   Withholding then needs the operator and a whole quorum to collude:
   one honest signer can serve Alice's kit. A committee that stops
   signing stops anchoring, which harms no one's exit, since stalled
   sealing isn't a counter. The towers, which already hold users'
   packages, are natural members. Nothing on chain; the cost is the
   trust assumption, and the committee's liveness for progress.
6. **Spentness filters** (after Zendoo's certificates, which carry a
   bit vector of the UTXO slots changed each epoch, about 106 KB for 4
   million slots). A compact per-anchor filter of inserted nullifiers
   would tell Alice whether her notes were spent, but not let her prove
   her new notes. Detection only.
7. **Accept the gap and document it.** A user is exit-safe only while
   the operator serves data for her latest transactions; a wallet that
   spends while the operator misbehaves can lose its whole contract.

Not useful here:

- **Collateral that is forfeited for withholding** (Light's "validity
  valutia", zkPorter's guardians). It needs a proof on chain that data
  was withheld, and none exists: anyone can claim it was withheld, and
  anyone can publish late (the fisherman's dilemma). The counter rules
  above get the effect without one: withholding doesn't win the
  contract.
- **Data-availability sampling** (LazyLedger, now Celestia) needs a
  network of light-node samplers; it fits a chain, not one operator.

| option | trust | on Bitcoin | cost to users |
|---|---|---|---|
| 1. publish | none | ~24 vB per L2 tx | none |
| 2. volition | none, for published spends | ~24 vB per published tx | a choice per tx; a subtree per anchor |
| 3. sender acknowledgment | none | nothing | two-phase finality |
| 4. expiry, two-branch claim | none | a second payout branch in the game | transactions expire |
| 5. data committee | one honest signer per quorum | nothing | committee liveness for progress |
| 6. filters | — | a few bytes per tx | detection only |
| 7. accept | the operator serves data | nothing | spending is unsafe while it misbehaves |

Sender acknowledgment looks the strongest: no trust and no bytes on
Bitcoin. A committee could be added to it so that payments keep going
through while the operator misbehaves, but safety doesn't need one.

### Sender acknowledgment

After Light's "adamantium", in which each power user signs every state
root, attesting that she holds its data, and is withdrawn to the parent
chain if she doesn't. Here only a sender signs, only for her own spends,
and silence is the safe default: an unacknowledged spend can't be used
against her, so nobody needs withdrawing.

The rules:

- **Every spend names an acknowledgment key** `ak`, a one-time key its
  sender chooses. It is sequenced and anchored as today: its nullifiers
  enter the spent set and its outputs the tree. But its outputs are
  **locked**: the chain guest refuses any spend of them until the
  acknowledgment is sequenced.
- **The acknowledgment** is a signature under `ak` on the spend, carried
  by any later L2 transaction or on its own. The wallet signs it once
  it holds its kit at the anchored state `S_T` that contains the spend:
  the step "after a spend" in the exit kit becomes a signed statement.
  It unlocks the outputs.
- **A counter may cite a spend only with its acknowledgment,** both
  anchored before the cutoff. Exit records need none, since they carry
  their owner's proof.
- **Only the sender may claim a locked output.** Her exit proof, from
  `S_T`, may include outputs of a spend she hasn't acknowledged, by
  showing that she knows the secret of its `ak`. Her exit record then
  counts as the acknowledgment. If anyone else could claim one, an
  operator playing the receiver could acknowledge Alice's spend for
  her.
- **An exit that retires an unacknowledged spend's inputs voids it:**
  its outputs stay locked for good, a later acknowledgment is invalid,
  and that exit record counters any claim on its outputs. As with a
  spend racing a claim, the operator refuses to sequence the
  acknowledgment of a spend whose inputs are in a pending claim.
- **Transactions the hub signs** (mints, exit records) are acknowledged
  by their own signature. A return is Alice's spend like any other: its
  change is locked until she acknowledges it.

The consolidation attack again:

- **The operator anchors the consolidation and withholds its data.**
  Alice has no kit at `S_T`, so she doesn't acknowledge. A counter on
  her old notes needs an acknowledgment that doesn't exist, so she
  claims them from her old kit.
- **It serves the data, she acknowledges, and it withholds everything
  after.** She already holds her kit at `S_T`, and claims the new note
  from there.
- **It censors her acknowledgment:** the same as the first case.
- **It holds the acknowledgment and seals it during `W_c`:** past the
  cutoff, so not a counter.

Withholding now costs her a stalled spend, not her contract.

Why the hub is still safe:

- **Alice pays Bob, never acknowledges, and claims her old notes.** No
  counter exists, so she is paid. But Bob's output is locked, and her
  exit record voids the spend for good. The notes are paid once.
- **Alice acknowledges, then claims her old notes.** A counter cites
  the spend and its acknowledgment. If the acknowledgment was anchored
  after the cutoff, the operator should have refused it, as for any
  racing spend.
- **Alice claims her locked change and never acknowledges.** Her exit
  record acknowledges the spend, and Bob's output unlocks. The change
  and Bob are paid, which is what the old notes were worth.
- **Both at once, through two contracts:** old notes through `c1`,
  locked change through `c2`. The operator posts one record first. If
  it's `c2`'s, it acknowledges the spend, which counters `c1`. If it's
  `c1`'s, it voids the spend, which counters `c2`. Either way one claim
  is paid. This relies on exit records being exempt from the cutoff
  (The counter, above).

The costs:

- **Two-phase finality.** Bob's payment is final once he holds a kit at
  a state that includes the acknowledgment, 10 deep. That's roughly one
  more anchor interval, plus Alice's round trip.
- **The sender's liveness now matters to the receiver.** Alice must come
  back after her spend's anchor, which she already should, to fetch her
  kit. But until she does, Bob waits. Nothing is lost, only delayed.
- **A per-spend choice.** A sender can acknowledge at once, when she
  signs, if a payee won't wait. That gives up the protection of her own
  outputs, the change, and only for that spend: it's the design without
  this option.
- **Unacknowledged funds are exit-only.** Notes spent by a spend she
  never acknowledges can't be spent again on the L2, only claimed. This
  arises only against a hostile operator.
- **Privacy.** `ak` is fresh per spend, so an acknowledgment shows only
  that the spend's sender has come back, and when: timing the sequencer
  already sees.
- **The guests.**
  - The chain guest gains a lock per output, the acknowledgment, and
    voiding by exit records.
  - The exit guest gains locked outputs with `ak`.
  - The counter guest gains the acknowledgment beside the insertion, and
    voiding as a second ground.

**The receiver, if the acknowledgment waits for him.** The operator can
serve Alice her data and withhold Bob's. If her wallet acknowledges only
once Bob confirms that he holds his kit, by an off-chain message as for
an invoice, the payment fails safely: unacknowledged, it can't counter
her, and her old notes stay claimable. If she acknowledges without
waiting, her payment is gone, Bob can't prove his note, and its value
stays with the hub. So the wallet waits for the payee by default, and
then withholding can only stop payments, not take funds.

## Timing

Alice's escalation must confirm by `T_close`. There's no `N` wait,
since she exits from state that's already anchored:

| term | for | Mutinynet (30 s) | mainnet (10 min) |
|---|---|---|---|
| detect | the return not sealed or folded in time: censorship | 40 (20 min) | 6 (1 h) |
| `P` | her exit proof, wrap, trace | 120 (1 h) | 6 |
| `e` | the escalation confirming | 20 | 6 |
| `Δ_exit` | | 180 (1.5 h) | 18 (3 h) |

Compare END_PLAN's 178 blocks on mainnet: the freeze's `N` is gone. With
a day of user liveness `U` on top, a week's contract on mainnet is
covered for 84% of its life (162 of 1,008 blocks short), a month's for
96%.

The counter window `W_c` runs after the escalation, so `T_close` doesn't
bound it. Any spend it can cite was anchored before the cutoff, so it
must fit only the rest: 10 blocks on that anchor, the counter's proof
(about 20 minutes), and posting it. That's 18 blocks on
mainnet (3 h) and 80 on Mutinynet (40 min). Every dispute gets longer by
`W_c`.

## An example: an honest exit

Mainnet, contract `c` with a week to run and `V_max` = 0.1 BTC. The
operator, hub and sequencer, starts censoring Alice.

Before anything goes wrong:

1. **Opening.** She pays `D`, the hub mints `D` tokens to her, and they
   pre-sign the contract. Her wallet checks the whole pre-signed set.
2. **Using the L2.** She pays and is paid, and holds three notes: 0.02,
   0.02 and 0.015 BTC.
3. **The kit.** After her last spend or receipt, her wallet fetched a
   kit for a state `S` 10 deep after it (above).

The exit:

4. **The normal way first.** On day 5 she signs a return of her notes
   with memo `c` and submits it.
5. **Detect.** About 6 blocks pass, and the return is neither sealed nor
   folded. Her wallet switches to an exit.
6. **The claim.** From her kit's `S`, all three notes: `Σ` = 0.055 ≤
   `V_max`, so `b` = 0.055.
7. **The exit proof.** From her kit, headers with `W` of work on `S`'s
   anchor block, and her notes' openings and `nk`. The guest derives the
   nullifiers, checks paths and non-membership, and outputs
   `b ‖ c ‖ D ‖ E`. Then the wrap, which she can delegate. About 6
   blocks (`P`).
8. **Escalate.** The pre-signed escalation with her one-time-signed
   input words: proof, journal and nullifiers, its fee paid by CPFP. It
   confirms by `T_close`, and the default can no longer happen. About
   18 blocks from detection (`Δ_exit`).
9. **`W_c`, about 18 blocks.** The operator now knows her nullifiers but
   has no counter: none was inserted after `S`, and her own return
   doesn't count. It may fold instead, checking her proof natively and
   paying `b + r_A`.
10. **The game,** if it doesn't fold. She commits the trace over her
    proof and the empty counter, and the program accepts. The operator
    concedes, bisects and loses, or is absent, and its timeouts pay her.
    Her tower can play this.
11. **Payout.** After `δ`, the bit outputs set in `b` (0.055 rounded
    down to 512 sats) and the reserve output with `r_H`, swept in one
    transaction.
12. **After.** The operator posts the exit record with her proof, and
    her three notes are spent on the L2. The contract is over, and
    anything she receives now is credit until a new one.

An absent operator changes only steps 9 to 11, which then pay by
timeout.

## Costs and open questions

- **Data availability,** the main open question: which of the options
  above, or which combination. Sender acknowledgment is the leading
  candidate.
- **ln-gap:**
  - a verifier-owned input link, the counter, with the hub's input-word
    keys signed at opening;
  - the program verifies two Groth16 proofs, so a new verifier ELF built
    from `bitvmx-zk-verifier`'s source (today's is FairgateLabs' as
    shipped);
  - a trace about twice as long, so about one more depth: a larger
    pre-signed set and a larger hub reserve for the deepest dispute;
  - the journal layout gains `E` and the nullifier words.

  All of this must be measured.
- **The exit record's proof check** in the chain guest, once per exit:
  unmeasured.
- **The input words.** About 1 KB of one-time signatures per nullifier
  on chain in a dispute: 8 notes cost about 8 KB.
- **Mass exit** against a hostile operator: every contract escalating
  by its `T_close`. The congestion table again. What the counter design
  changes:
  - **Not the number of games:** one gadget run per contract at most,
    since a failed counter pays Alice. An operator that has gone dark
    posts no counters, and every exit is won by timeouts. One that is
    hostile but present can refuse to fold and force a full run on
    every honest claim, as it can today; so the limit is still the
    worst-case size of one run, which is where BABE's small dispute
    matters most.
  - **A larger escalation:** the nullifiers as input words, about 1 KB
    per note. Low note counts matter, which needs consolidation, which
    is safe only with a data-availability option such as sender
    acknowledgment.
  - **A longer schedule:** `W_c` before Alice's game. Time, not bytes,
    but it tightens every deadline against `T_close` under
    congestion.
- **Exits are disputes:** hours and fees, against a cooperative fold
  today. The operator can fold an exit too, after checking it natively,
  and an honest one would.
- **No contract, no exit.** Value above a contract's cap stays with the
  operator.
- **Claims over the cap** forfeit the rest of the notes claimed; the
  wallet sizes and consolidates notes to keep this small, but only while
  the operator serves data, since a consolidation is itself a spend
  (the consolidation attack).

## Steps (BABE)

0. **Spikes**, to size what is unmeasured. Done (2026-10-30), on a
   real Groth16 receipt of the BABE guest, in RISC Zero 3.0.6's executor
   on lichen-vps (a scratch crate, not kept):

   | Verifier | User cycles | Segments (2^20) |
   |---|---|---|
   | `risc0-groth16` (arkworks, unaccelerated) | 174.4M | 180 |
   | `substrate-bn`, RISC Zero's fork (`bigint2`), points as in the seal | 45.9M | 47 |
   | the same, points compressed | 47.6M | 48 |
   | the same, a counter for another journal (fails) | 47.5M | 48 |

   - Use RISC Zero's `substrate-bn` fork (`risc0/paritytech-bn`, tag
     `v0.6.0-risczero.0`), not `risc0-groth16`: 3.8× fewer cycles.
   - Decompression costs 1.7M cycles (4%), so `K` compressed is cheap.
   - A failing verification costs the same as a passing one. Proving
     ~48 segments at the measured 2^20 rates is roughly 1.5 h on the
     Mac's CPU and 7–9 h on the VPS (the BABE guest's one segment took
     660 s there), against days to `T_A`: fine for Alice's rare case.
     A GPU prover would make it minutes.
   - In the chain guest it's too heavy per exit record (~47M cycles
     each, against 0.4M for a block of one mint today). So the record carries the
     owner's signature on `c ‖ E`, made inside the exit proof (the
     alternative in "After an exit"), not the Groth16.
1. **The statements, native** (`crates/withdraw`). The claim and the
   counter are built, the nullifier tree's leaves tagged, and the three
   branches behind the fixed statement (`fixed::check_exit`); done:
   - exit mode: notes in `T_S`, unspent in `N_S` (non-membership in the
     nullifier set's sparse Merkle tree, `validity/smt.rs`), Alice's
     authority (`nk`, or a signature for transparent notes), distinct
     notes, `b ≤ Σ`, and `E`;
   - the counter: an insertion of one of `E`'s nullifiers after `h_S`,
     final before the cutoff, not contract `c`'s own return or exit
     record, in the same history as `S`, with the cutoff proved from
     `request`'s confirmation;
   - the branches behind the fixed statement: return, claim, failed
     counter (below).

   Unit tests for each, including every case in "The counter".
2. **The L2** (`ledger`, `validity`, `sequencer`):
   - `Tx::Exit`, hub-signed, carrying the claimant's exit proof, checked
     by the chain guest. A new chain guest, so a new deployment.
   - The exit kit served per note: a path and a non-membership proof at
     an anchored state.
   - The sequencer refuses spends of nullifiers in pending claims.
3. **The graph** (`crates/babe`):
   - `request` signs `E` and carries the nullifiers;
   - `respond` gets two leaves, both comparing `b` and `E` with
     `request`'s: plain (`b`, `E` under `e_plain`) and counter (`b`, `E`
     under `e_counter`, and `K` signed itself). Alice presigns both.

   Sizes measured, with the 1,000-element limit checked as for the reveal.
4. **The guests** (`r0/`, built on lichen-vps):
   - the BABE guest with both modes and `K`'s check;
   - the counter guest;
   - the chain guest with `Tx::Exit`.

   Their image ids are pinned in `D`'s scheme as today.
5. **A mock for regtest.** BABE's mock statement takes every claim as
   true, so it can't exercise counters. The mock exit decides natively
   instead: the wallet asserts only if the native check passes, and the
   hub challenges any claim that fails it. That's how BitVMX's mock
   played lies.
6. **The hub** (`dispute/babe.rs`):
   - in exit mode, read the nullifiers, search the spent set, and prove
     and post a counter within `w_H`, or respond "none";
   - post exit records;
   - refuse spends of pending claims' nullifiers;
   - fold an exit it has checked natively, if it chooses.
7. **The wallet** (`engine/babe.rs`, `main.rs`):
   - the exit kit, fetched after each spend or receipt; "final" requires
     it;
   - exit mode: claim, `E`, the nullifiers, and the assertion, proving
     `K` false when it is;
   - the switch from a return to an exit when the return isn't sealed in
     time, so `lichen withdraw` still does the right thing;
   - the tower's package carries the kit.
8. **Windows:** `w_H` long enough for a counter (Mutinynet and mainnet).
9. **Tests:**
   - Regtest, on the mock:
     - an exit while the operator censors;
     - the operator gone (`request_timeout`);
     - an old state after a spend (countered, Alice loses);
     - the same note through two contracts;
     - a bogus counter (Alice wins);
     - a counter for another `E` (Alice wins);
     - her censored return sequenced after her request (not a counter);
     - a spend after the cutoff (not a counter);
     - an exit record without a matching proof (rejected);
     - a spend racing a claim;
     - two claims escalated together;
     - the consolidation attack (Alice loses: the data-availability gap,
       until 10).
   - Regtest on a real proof, opt-in: a countered exit and a bogus
     counter proved false.
   - Mutinynet: a `HOSTILE` operator censoring; Alice exits; Bob's stale
     claim is countered.
10. **Data availability:** sender acknowledgment, as specified above. A
    chain-guest change, after the exit itself works. Until then the
    consolidation test documents the gap.
11. **Docs:** this plan's status, an explainer for the exit, SHIELDED.md's
    Limits, RUN_A_TOWER (the kit), CODE.md, and the papers (the main
    paper's exit section, the BABE companion's counter).
