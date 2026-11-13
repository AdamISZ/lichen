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
  signature (`lichen_notes::Settled`) on its id's first 8 bytes, owner
  and value (what an exit posts names it by). Any value: a wallet merges
  its notes.
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
  owner and `b` units, signed by the owner. A cooperative withdrawal
  hands it to the hub, which takes it (its notes spent, the change beyond
  `b` back to the owner) and folds; an exit posts it compact, one-time
  signed in `request` (milestone 4).
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
   request (Alice: b, the claim, one-time signed)
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
     hub and statement): settled notes, fallbacks (the ids of her spends
     in flight whose inputs are among the notes), `b` in units; her
     signature on its fingerprint `E`. An exit posts it compact
     (milestone 4).
   - **Owed** (`grants::owed`): 0 for a malformed claim (its encoding, a
     note named twice, the hub's signatures on the notes, `b` above the
     notes). Else the
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
     unless a signature in the script covers it; an output under the
     hub's `SIGHASH_ALL` can't be. 83 bytes of `OP_RETURN` (Core 29's
     limit): two unlocks.
   - **`b_corr` binds the payout**: `success`'s bit outputs read the
     hub's one-time signature (from `correct`); two different signatures
     under `bc` (an equivocation) give Alice every bit output
     (`equiv_corr_i`).
   - **No penalty**: `success` returns her reserve whatever `b_corr`. A
     false claim gains her nothing (she's paid what she's owed) and costs
     the hub one dispute per contract; a penalty would also strike honest
     mistakes (a stale backup).
   - **The wallet**: a spend stays a fallback of any claim of its inputs
     until a spend we hold `t` for consumes them, whatever the hub says (a
     hub that recorded it and said otherwise could cite it). A claim goes
     without a sync if the hub won't answer.
   - **Tests** (regtest, `crates/hub/tests/contested.rs`): corrected to
     her change and paid by `success`; a forged correction to 0, refuted;
     a correction never proved, paid by `correct_timeout`.
3. **The real guest** (2026-11-12): `r0/hp-guest` proves `grants::check`
   on this branch (image id `fc24dc37…`, rebuilt for milestone 4,
   r0/guests/README.md); `lichen-r0
   hp|exec-hp|hp-proof <input> [<out>]`, `r0/hp-prover.sh`, `r0/hp-remote.sh`
   without a chain receipt. The hub on the real statement proves in the
   background as the anchored L2's did (`LICHEN_HP_PROVER`, files in
   `hp/<cid>/`); on the mock, `LICHEN_DUMP_HP` writes the statement's
   input. The contested test's corrected exit (one spend cited, 12
   headers): 1,281k user cycles, 2 segments; proved on lichen-vps (4
   cores, CPU) in 973 s and wrapped in Groth16 in 265 s, about 21 minutes,
   inside Mutinynet's `w_H` (2 h) after `correct`. The seal verifies under
   BABE's `Kind::Risc0` for the contract's journal and no other.
4. **Hardening** (2026-11-13): the posted claim can't be swapped, the
   statement binds the owner, a note is claimed through one contract.

   - **The hole**: `request` posted the claim's bytes in witness items no
     signature covered, with her one-time signature on `E` beside them.
     Whoever got a `request` into a block (a miner, or the hub through
     one) could swap the bytes, keeping the txid; a claim not matching
     its `E` was malformed, owed 0, and the hub won with a valid proof.
   - **Signed in full**: her one-time key (fixed at the opening, as `b`'s
     is) signs the posted claim's every byte, so Bitcoin's script checks
     them; `E` and the unsigned items are gone. Script can't hash a
     witness item into something it compares with signed digits (no
     `OP_CAT`), so the bytes themselves are signed: 2 digits a byte, 2
     witness items a digit, and Bitcoin's 1,000 stack elements bound it.
   - **The posted claim** (`grants::Posted`, `POSTED_LEN` = 233 bytes):
     the counts, then per note its id's first 8 bytes, its value (6
     bytes) and its signature's `R`; the hub's signatures' `s`
     half-aggregated into one (Chalkias et al.; Nick and Ruffing's draft
     BIP: `s·G = Σ z_i (R_i + e_i P)`, the weights `z_i` hashing the key,
     messages and `R`s so far); per fallback its id's first 8 bytes;
     zeros. The contract (`c`, deposit, owner) and `b` (signed apart)
     aren't in it. Four notes and two fallbacks fit, or three and four
     (`grants::fits`); the wallet merges above 4 notes, and if its spends
     in flight still don't fit, claims the largest notes that do. `b`'s
     and the claim's signatures and the 2-of-2's are 962 witness items;
     `request` is 11,717 vB (about 2.5 kvB before).
   - **Short ids**: the hub signs a note's id's first 8 bytes (the full
     id stays the book's key). Two notes of one owner with the same short
     id and value share a signature: only their owner can grind for that
     (2^32 spends), and it only hurts her (one claimed, a spend of the
     other kills it). A spend kills a candidate of the same short id and
     value.
   - **Why not MAC tags** (the first plan): she can't check a tag under
     the hub's key, so a hub could issue bad ones and later call the
     notes unissued. A VRF's output would be checkable and short, but the
     payee's tags would come from the hub after `t`, outside the grant's
     atomicity. The hub's BIP340 signatures are hers to check and are
     unlocked by `t` with the outputs.
   - **The owner bound**: `D` was the issuer's deployment alone, and the
     statement took the owner from the hub's input: a hub could prove
     against another owner and count any claim malformed. `D` now hashes
     the issuer and the owner (`GTerms::d`, `contract_word`), fixed at
     the setup (`HpSetupRequest.owner`).
   - **One contract per owner**: a note was kept from being claimed
     through two contracts by her signature on each claim; an exit's
     posted claim no longer carries one. The hub opens one contract at a
     time per owner key, and none for an owner who exited (checked at the
     deposit request, before she pays, and again at the opening). A
     cooperative withdrawal's claim is signed with her key, so a later
     contract's statement still cites it. Lifting the exit rule: she
     signs her earlier exits' claims with her key at the next opening,
     or the wallet takes a fresh key per contract.
   - **Tests** (regtest): the contested exits as in milestone 2, the
     request at full size; a second contract while one is open refused
     (payments.rs), and one after an exit (contested.rs).
   - **The guest** rebuilt: image id `efe219a1…` (r0/guests/README.md);
     on the contested test's corrected exit 1,456k user cycles (1,281k
     before: the aggregate signature), 2 segments, so about milestone
     3's 21 minutes to prove.

## Open

- Fees: per transaction (burned: the hub's revenue as issuer) and
  liquidity per unit time, as in docs/FORWARD_PLAN.md.
- The hub's book is one JSON file rewritten on each change: fine for a
  testnet, not for volume.
- A spend in flight whose answer is lost is finished at the next sync
  (the hub's grant and record are idempotent); a hub restarted in between
  forgets its pending grants, and the spend is dropped, its inputs still
  the payer's.
