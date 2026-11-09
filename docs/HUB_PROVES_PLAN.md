# The exit where only the hub proves: plan

2026-11-09. A design in progress, not built. It would replace the
counter design of EXIT_PLAN.md ("Under BABE") and the withdrawal by
return's dispute with one dispute: Alice claims, and only the hub
proves, if it can, that her claim is false.

**Status, 2026-11-09.** Built on branch `hub-proves` on the mock
statement, transparent notes only: the hub's statement natively
(`lichen_withdraw::hp`), the swapped graph (`lichen_babe::hp`), the
setup in which Alice garbles and uploads (`lichen_proto::hp`), both
sides' play, and a regtest test of seven cases (`hp_exit.rs`). Not yet:
the hub's statement as a guest, real proofs, shielded notes. Alongside
`babe` (a return's dispute), as `hub-proves-mock`; the old exit is
removed (build order, step 8). Being thought through with the user:
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
| not live | at `A*`, the leaf at a note's position isn't its commitment (an empty one past the tree's end, too), or its nullifier is spent |
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

## Data availability: the remaining risk

Accepted, scoped as follows (Decided).

**Money at rest is safe.** Only her keys spend her notes. A note that
no transaction of hers spends is live at `A*` whatever the operator
withholds, and she claims it exactly. So she can do nothing until
`T_close − Δ`, and claim then.

**The exposure is an unresolved spend.** From signing a spend until she
has seen, at an anchored state, whether it's included, she can't safely
claim the notes it touches:

- **its inputs:** if an anchor before the cutoff included it, they're
  spent, and the claim is false;
- **its outputs to her:** if no anchor did, they don't exist, and the
  claim is false.

The rest of her notes she claims exactly.

What she needs is not the root: each anchor commits its root on
Bitcoin. It's the data under it: her inputs' nullifiers spent or not at
that root, with paths, and her outputs' positions. An anchor whose data
is withheld tells her nothing about her transactions.

**Bounds:**

- **The value at risk** is the notes the spend touches. A payment of 30
  from a note of 100 puts the 100 at risk, not just the 30.
- **The window** normally closes at the next anchor, minutes later,
  when the sequencer serves its data. A withholding operator can hold
  it open until `T_close`: hold her transaction, keep anchoring
  states, and serve none of them. It decides inclusion before her
  claim, so it can't react to her choice, but each opaque anchor is a
  guess she would have to make.
- **The wallet's rules:**
  - sign while the sequencer serves anchored data promptly;
  - a spend is resolved once she has the data of the latest anchor:
    included, she claims its outputs; not included, its inputs (the
    margin protects that claim while `request` confirms);
  - stop signing when the data stops;
  - leave notes touched by an unresolved spend out of a claim.

  So a censored spend, with data still served, costs her nothing:
  she claims the inputs. Only withheld data leaves a spend unresolved.

**The worst case.** A busy block is sealed and anchored, and its data
is never served. Every sender in it, and every sender whose spend was
pending then (the operator can put those in a later opaque anchor), has
the notes those spends touched stuck for good. Their contracts default
to the hub at `T_close`, so the stuck value is the operator's profit:
the motive. Their other notes are safe. Their receivers lose nothing they had:
without the data, a payment never counted as received. The loss is
the senders' inputs, once. The anchor without data is public, but its
withholding can't be proved.

**The claim:** money at rest is safe; a spend in flight when the
operator turns can lose the notes it spends. The floor, with notes
exactly the payment's size, would be the payment itself, but no
sizing scheme is planned: denominations multiply each transaction's
inputs and outputs, and a shielded transaction's proving time grows
with them (Decided). The operator's prize is the value in flight at
that moment; its cost is its business, since everyone with money at
rest leaves.

**Ways to narrow it later, none needed now:**

- **sender acknowledgment** (EXIT_PLAN step 10): a spend can't be cited
  until she has signed for its data. That closes it, at the price of
  two-phase finality;
- **publishing each anchor's nullifiers and commitments** (EXIT_PLAN
  option 1): about 24 vB per L2 transaction;
- **ambiguous claims** ("those of these notes live at `A*` are worth
  `b`"): with a spend's inputs and outputs both claimed, a merge would
  hold either way. They need the state to answer "never created" by
  nullifier, a chain-guest change, and the user prefers definite
  claims.

**Receivers.** A payment to Bob counts for him once he has seen it
anchored. Until then it's the sender's unresolved spend.

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
- **The claim, per note:** position, value and `r`, 44 bytes. The hub
  knows each leaf's transaction, so `rho`. Once per owner: `H(ask)`,
  `nk`, `X` and a signature, 160 bytes. About 23 notes in today's
  witness space.
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
- The data-availability risk, scoped to notes touched by an unresolved
  spend, is accepted for now: lichen always had one, and this one is
  narrow (the user, 2026-11-09). Whether to add sender acknowledgment
  later is open.
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
   hub refuted; an exit after a return paid; the operator gone, paid by
   timeout.

Next:

5. The hub's statement as a guest (its encoding, the chain receipt
   composed, the Groth16 wrap), and the real statement.
6. Real proofs on regtest, then Mutinynet.
7. Shielded notes ("Shielded notes").
8. Done (2026-11-09): the old exit removed (the hub's counter,
   `respond`'s countering leaf, the failed-counter branch and its
   in-guest Groth16 check, the counter guest, Alice's claim proof and
   its exit set's kits and chain receipts). BABE contracts are
   return-only again, and the BABE guest is rebuilt without the exit.
   The return's dispute stays, under `babe`, until this runs on real
   proofs.
