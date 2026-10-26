# Exits from anchored state, with a counter: plan

2026-10-21, branch `anchor`. Replaces END_PLAN.md for a deployment
whose hub and sequencer are one operator.

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
- **Journal:** `b ‖ c ‖ D ‖ E`, with `E = H(h_S ‖ SR_S ‖ nullifiers)`.

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
  - Alice's claim (`D`, `E`, the nullifier list);
  - a later anchored state `S'`, 10 deep, in the same history as `S`;
  - one of the claim's nullifiers, inserted at a height `h_S < h ≤ h_S'`
    by a transaction that isn't contract `c`'s own: neither its exit
    record (below) nor a return with memo `c`.
- **Journal:** `D ‖ E ‖ ok`.

"The same history": the counter's chain receipt passes through `S`.
Anchors form a single chain, so this is a hash-forward check from `S`'s
anchor through the anchors it records. Detail for the design pass.

The counter covers three cases:

- **Alice spent the note later** (she paid Bob and then exits an older
  state): the spend.
- **The same note through two contracts:** the first claim's exit
  record (below) inserted the nullifier, and the second claim's counter
  shows it.
- **A claim racing a spend:** the operator either refuses to sequence a
  spend of nullifiers whose claim is pending, or sequences it and
  counters.

**Why contract `c`'s own return doesn't count.** An honest Alice tries
the cooperative way first: she signs a return of her notes with memo
`c` and exits only when it isn't sealed (Timing, "detect"). The
operator still holds that signed return. If a return could counter,
the operator could sequence it after her escalation and take her whole
contract with her own transaction. Excluding it costs the hub nothing:
if the return is sequenced, the hub has her tokens, and contract `c`
still pays only once.

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

## The game

ln-gap's game with the operator's counter as a second input, owned by
the verifier. The program definition already lists inputs by owner. The
program changes from "verify Alice's proof" to:

> Accept if and only if Alice's proof verifies, and either there is no
> counter, or the counter doesn't verify, or it names another `D` or
> `E`.

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
| a garbage counter | valid | invalid | the program accepts; Alice is paid |
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
- **The counter fails:** the output returns to Alice's game where it
  left off.
- **No counter:** Alice's game, as now.

With rational play only one game runs. A false counter costs the hub
only that game's floors, and a true claim survives both games. Each
game uses today's ELF, depth and rules.

What it needs:

- a role-reversed instance of the ladder. ln-gap fixes the roles by
  position (`pubs[0]` Alice, `play.rs`'s `Prover`), but BitVMX's
  decision functions underneath don't care who plays which side;
- the branch leaf, signed at opening. The pre-signed set roughly doubles
  (about 90 transactions on the mock), but the reserve doesn't, since
  only one game's floors are ever paid;
- one cross-game check that the counter names Alice's `E`: she
  re-reveals her `E` words beside the hub's, and the hub's output is
  taken if they differ.

The single program above becomes an optimization, if a two-proof ELF
proves cheap.

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
  genuine record, which counters the second.
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
  her change. She was online to sign, so this is a fetch about 10
  blocks later. If she goes offline first, her old kit still exits
  every note she didn't spend: they're unspent at the old `S`, and
  nothing later spends them. Only the change is exposed, and only to
  data withheld in that gap.
- **After a receipt:** whenever she next comes online. Until then the
  payment isn't final for her (below).
- **Otherwise:** nothing. A wallet that happens to be online may
  refresh anyway, as a convenience, but no liveness is required.

If the operator stops serving, the last kit still works: Alice hasn't
spent since, so no counter exists.

So withholding data hurts only payments received after the last kit.
Hence a rule for receivers: **a payment is final once you hold its kit
at an anchored state 10 deep.** The wallet's "final" already means
anchored 10 deep, and now it also requires the kit in hand. This
narrows data availability to a per-receiver question. It doesn't solve
it.

The tower's package carries the kit, so a tower can exit with no
operator.

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
bound it. It must fit: the latest spend's anchor, 10 blocks on it, the
counter's proof (about 20 minutes), and posting it. That's 18 blocks on
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
  by its `T_close`, each dispute with a counter window. The congestion
  table again.
- **Exits are disputes:** hours and fees, against a cooperative fold
  today. The operator can fold an exit too, after checking it natively,
  and an honest one would.
- **No contract, no exit.** Value above a contract's cap stays with the
  operator.
- **Claims over the cap** forfeit the rest of the notes claimed; the
  wallet sizes and consolidates notes to keep this small.

## Steps

1. **The exit claim** in `lichen-withdraw` (native, on the mock
   statement): the journal with `E`.
2. **The counter statement** (native), and the exit record on the L2:
   `Tx::Exit`, hub-signed and carrying the claimant's exit proof, both
   checked by the chain guest. A new chain guest.
3. **ln-gap:** the verifier-owned input, the two-proof program (first
   the mock statement's analogue), the layout with `E`. The real work.
4. **The guests and the verifier ELF;** measure the depths, the
   pre-signed set and the reserve.
5. **The wallet:**
   - the exit kit, refreshed at each anchor;
   - "final" requires the kit;
   - `lichen exit <contract>`.

   The tower's package gains the kit.
6. **The operator:**
   - watches escalations;
   - refuses to sequence spends of nullifiers in pending claims;
   - posts exit records;
   - proves and posts counters within `W_c`;
   - folds an exit it has checked, if it chooses to.
7. **Tests.**
   - Regtest:
     - an exit while the operator censors;
     - an exit with the operator gone (timeouts);
     - an exit of an old state after a spend (countered, Alice loses);
     - the same note through two contracts (the second countered);
     - a garbage counter (Alice wins);
     - an exit record without a matching exit proof (the chain guest
       rejects it);
     - Alice's censored return sequenced after her escalation (not a
       counter; Alice wins);
     - a spend racing a claim.
   - Groth16: a countered exit end to end.
   - Mutinynet: a `HOSTILE` operator censoring; Alice exits, Bob's old
     state is countered.
8. **Docs:** SHIELDED.md's Limits, CODE.md.
