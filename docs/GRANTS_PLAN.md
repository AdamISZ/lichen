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
2. **Exits contested** (done 2026-11-12, on the mock statement): a claim may
   carry fallbacks; the hub answers a claim it can correct with `b_corr`,
   and proves "she is owed at most `b_corr`". BABE fixes the statement's
   public inputs at the opening, so `b_corr` can't be one: the statement
   reads it from the chain, from a new link.

   ```text
   request (Alice: b, E, the claim)
    ├─ request_timeout (after w_H)        → Alice: b
    └─ correct (the hub: b_corr, one-time signed under its key bc)
        │   its fee child (the hub's, SIGHASH_ALL): OP_RETURN with the
        │   unlocks t of the spends it cites
        ├─ correct_timeout (after w_H)    → Alice: b (it never proved)
        └─ assert (the hub: π)
            ├─ success (after Δ2)         → Alice: b_corr's bits (read from the
            │                                hub's signature) and her reserve;
            │                                the rest the hub's
            └─ challenge_assert (Alice)
                ├─ wrongly_challenged_k   → the hub
                └─ failure (after Δ1)     → Alice: b, and both reserves
   ```

   - **The claim** (`lichen_withdraw::grants::Claim`, shared by wallet,
     hub and statement): settled notes (at most 8), fallbacks (at most 4:
     the ids of her spends in flight whose inputs are among the notes),
     `b` in units; her signature on its fingerprint `E`.
   - **Owed** (`grants::owed`): 0 for a malformed claim (not as posted
     under her one-time signatures, a note not settled under the issuer
     or not the owner's, her signature, `b` above the notes). Else the
     candidates not killed, in units, at most `b`. The candidates start as
     the notes; a cited spend she signed (with its grant's commitment)
     whose unlock is in the fee child (`t·G = T`) kills those among its
     inputs, and if the claim names it a fallback its outputs to her join
     the candidates (a later spend may kill them in turn). Her claims on
     other contracts kill the notes they name; one on the same contract
     never does (only the posted claim is paid; a hub taking a cooperative
     claim and refusing the fold can't cite it).
   - **The statement** (`grants::check`, journal still `c ‖ D ‖ H(O_D ‖
     margin)`): `request` (spending the contract output, in a block with
     the contract's work `W` on it), `correct` (spending `request`'s
     output) and the fee child (spending an anchor of `correct`), each in a
     block of the headers given; `owed ≤ b_corr`. The contract keeps a
     checkpoint again for `W`; `D` is the issuer's deployment, no seal.
   - **The hub** (`assess`): the book's evidence against the claim (the
     spend or claim that took each note, through fallbacks to their
     change), at most two spends (two unlocks fill the `OP_RETURN`). Owed
     in full: the claim taken into the book, `request_timeout` pays.
     Otherwise `correct` with `b_corr` = owed, the claim taken at that,
     then, once `W` is on `request`'s block, the statement checked
     natively and proved. After `success` it sweeps its bit outputs
     (`hub_corr_bit_i`, after `Δ`). A cooperative claim is taken only if
     owed in full.
   - **Why the fee child**: data in a witness can be swapped by anyone
     (the request's hole); an output under the hub's `SIGHASH_ALL` can't.
     83 bytes of `OP_RETURN` (Core 29's limit): two unlocks.
   - **`b_corr` binds the payout**: `success`'s bit outputs read the
     hub's one-time signature (from `correct`); two different signatures
     under `bc` (an equivocation) give Alice every bit output
     (`equiv_corr_i`).
   - **No penalty**: `success` returns her reserve whatever `b_corr`. A
     false claim gains her nothing (she's paid what she's owed) and costs
     the hub one dispute per contract; a penalty would also strike honest
     mistakes (a stale backup, the malleable posted bytes until
     milestone 4).
   - **The wallet**: a spend stays a fallback of any claim of its inputs
     until a spend we hold `t` for consumes them, whatever the hub says (a
     hub that recorded it and said otherwise could cite it). A claim goes
     without a sync if the hub won't answer.
   - **Tests** (regtest, `crates/hub/tests/contested.rs`): corrected to
     her change and paid by `success`; a forged correction to 0, refuted;
     a correction never proved, paid by `correct_timeout`.
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
