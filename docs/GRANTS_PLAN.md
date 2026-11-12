# The grants L2: plan

Branch `grants` (from 2026-11-12). The user's decision: a second L2 for
lichen's contracts, transparent, with no global ordering, its payments
made atomic by grants (as in lichen-ecash, m0wer and waxwing, without
the blinding), each user holding at most a couple of notes. Kept from the
anchored L2: the contracts, their opening (VSSS garbling and the upload),
deposit, funding, fold and default, the BABE graph and hub-proves, the
chain crate, the deployment scripts, the app. Dropped: the sequencer, the
chain prover, anchoring, acknowledgments, shielded notes.

## The design

- **A note** is `(id, owner, value)`, settled by the hub's BIP340
  signature (`lichen_notes::Settled`). Any value: a wallet merges its
  notes.
- **A spend** names its input notes and asks for outputs of the same
  total; its outputs' ids derive from its id.
- **A grant**: the payer sends the unsigned spend (`POST /grant`); the hub
  answers `T = tG`, signed, and an adaptor pre-signature under `T` on each
  output. The payer checks it (the payee needn't be online), signs the
  spend with the grant's commitment (`POST /spend`); the hub records it
  (its inputs spent) and publishes `t`, which completes every output.
  Final in one round trip. `t = H(k_iss, sid)`.
- **The mailbox**: the hub keeps each owner's new notes in order
  (`GET /mailbox/<owner>?from=n`); `GET /notes/<owner>` lists an owner's
  unspent notes (a restored wallet).
- **The deposit** is pre-issued with the offer under the funding's
  adaptor point: the note settles when the funding reveals `t`, the same
  swap as the anchored L2's locked mint.
- **A claim** (`lichen_notes::Claim`): settled notes of the contract's
  owner and `b` units, signed by the owner; posted in `request` (up to 8
  notes, in its 1,200 bytes). A cooperative withdrawal hands the same
  claim to the hub, which takes it (its notes spent, the change beyond
  `b` back to the owner) and folds.
- **The wallet's policy**: a payment spends all its notes (the payment
  and one change out); received notes are merged once there are more than
  2 (`KEEP_NOTES`); more than 4 unmerged (`ALARM_NOTES`) means the hub is
  refusing merges: stop taking payments, exit.

## Deployed

On lichen-hub since 2026-11-12, beside the anchored L2's deployment: the
container `lichen-grants-hub` (image `lichen:grants`, from the `grants`
worktree `~/lichen-grants`), on the Mutinynet node's compose network,
its wallet `grants` there, its book in
`~/lichen-grants/deploy/state/mutinynet/hub`, port 18320, behind
`https://thimbly.org/lichen/grants/hub`. On the mock statement until
milestone 3 (the anchored L2's real statement doesn't apply). Its issuer
key: `f7c1929c0b116bb92b57dee1b036c5cb76af04da8f0a412570fbb05af8f6174e`.

## Milestones

1. **Payments** (done 2026-11-12): `lichen-notes` (notes, spends, grants,
   claims, the hub's book), the hub on its book (no sequencer), the
   wallet on notes, the opening's pre-issued deposit, the cooperative
   withdrawal by claim. Exits: the hub takes the posted claim into its
   book and doesn't contest it, so `request_timeout` pays. Tests on
   regtest: payments (final in ~40 ms), the mint's faults, withdrawals
   and defaults, a user on Esplora with an exit.
2. **Exits contested** (design, 2026-11-12): a claim may carry
   fallbacks; the hub answers a claim it can correct with `b_corr`, and
   proves "she is owed at most `b_corr`". BABE fixes the statement's public
   inputs at the opening, so `b_corr` can't be one: the statement reads it
   from the chain, from a new link.

   ```text
   request (Alice: b, E, the claim)
    ├─ request_timeout (after w_H)        → Alice: b
    └─ correct (the hub: b_corr, one-time signed under its key bc)
        │   its fee child (the hub's, SIGHASH_ALL): OP_RETURN with the
        │   unlocks t of the spends it cites
        ├─ correct_timeout (after w_H)    → Alice: b (it never proved)
        └─ assert (the hub: π)
            ├─ success (after Δ2)         → Alice: b_corr's bits (read from the
            │                                hub's signature), her reserve if
            │                                b_corr > 0; the rest the hub's
            └─ challenge_assert (Alice)
                ├─ wrongly_challenged_k   → the hub
                └─ failure (after Δ1)     → Alice: b, and both reserves
   ```

   - **The claim**: settled notes; fallbacks `(sid, change)`, the
     claimant's change of a spend in flight whose inputs are among the
     notes; `b` in units. All her signature covers (`E`).
   - **The statement** ("owed ≤ b_corr", the journal still `c ‖ D ‖
     H(O_D ‖ margin)`): `request` and `correct` from the chain (spends of
     the contract output and of `request`'s, with the contract's work on
     `request`'s block), the fee child's unlocks, the spends the hub cites.
     `owed` is 0 for a malformed claim (its bytes, `E` or `b` not as
     signed; a note not settled under the issuer, or not the contract
     owner's; the owner's signature; `b` above the notes); else the notes
     less those killed, plus the fallbacks revived, in units, at most `b`.
     A note is killed by a spend she signed (her signature on the spend
     and its grant's commitment) whose `t` is in the fee child (`t·G =
     T`), or by another claim of hers on chain naming it; a killing
     spend's change is revived if the claim names it a fallback.
   - **Why the fee child**: data in a witness can be swapped by anyone
     (the request's hole); an output under the hub's `SIGHASH_ALL` can't.
     83 bytes of `OP_RETURN` (Core 29's limit): two unlocks.
   - **`b_corr` binds the payout**: `success`'s bit outputs read the
     hub's one-time signature (from `correct`); two different signatures
     under `bc` (an equivocation) give Alice every bit output.
   - **Mock first**: the hub checks the statement natively and asserts the
     mock's proof; the tests play every branch.
3. **The real guest**: the statement in RISC Zero, its Groth16 wrap.
4. **Hardening**: the claim signed in full in `request` (its posted bytes
   are malleable today: anyone may swap them, and a claim not matching
   its `E` is malformed); compact item encoding (hub-assigned ids and
   MAC tags); the stack-element budget (about 2 per signed digit, 1,000
   in all).

## Open

- Fees: per transaction (burned: the hub's revenue as issuer) and
  liquidity per unit time, as in docs/FORWARD_PLAN.md.
- The hub's book is one JSON file rewritten on each change: fine for a
  testnet, not for volume.
- A spend in flight whose answer is lost is finished at the next sync
  (the hub's grant and record are idempotent); a hub restarted in between
  forgets its pending grants, and the spend is dropped, its inputs still
  the payer's.
