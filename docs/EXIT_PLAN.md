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
  something that happened. Alice spends her notes only by knowing their
  keys, so the operator can't produce a false counter.

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
appear. A claim spends whole notes, so the value above `b` is forfeit.
The wallet keeps its notes sized for this. At most, say, 8 notes.

No note has to be bound to a contract in advance. The same note claimed
through two contracts is caught by the counter, below.

## The counter

A new statement, proved by the operator, a Groth16 proof of about 256
bytes:

- **Inputs:**
  - Alice's claim (`D`, `E`, the nullifier list);
  - a later anchored state `S'`, 10 deep, in the same history as `S`;
  - one of the claim's nullifiers, inserted at a height `h_S < h ≤ h_S'`
    by a transaction that isn't contract `c`'s own exit record (below).
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
and withdrawn through another contract. The chain guest accepts exit
records signed by the hub's key. They're an L2 transaction type like
mints.

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

The sequencer serves these per note, and the wallet refreshes its kit
at each anchor it checks. If the operator stops serving, the last kit
still works: Alice hasn't spent since, so no counter exists.

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
- **Partial claims** forfeit the rest of the notes claimed.

## Steps

1. **The exit claim** in `lichen-withdraw` (native, on the mock
   statement): the journal with `E`.
2. **The counter statement** (native), and the exit record on the L2:
   `Tx::Exit`, hub-signed, checked by the chain guest. A new chain
   guest.
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
     - a spend racing a claim.
   - Groth16: a countered exit end to end.
   - Mutinynet: a `HOSTILE` operator censoring; Alice exits, Bob's old
     state is countered.
8. **Docs:** SHIELDED.md's Limits, CODE.md.
