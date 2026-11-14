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
        │   unlocks t of the spends it cites (milestone 5: slots in
        │   correct instead)
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
   - **One contract per owner** (replaced in milestone 5 by a fresh key
     per contract): a note was kept from being claimed
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
5. **Reveals** (2026-11-13): a spend counts against her claim only if
   the hub reveals its unlock to her, by completing in `correct` a
   pre-signature she checked before signing the spend; a fresh L2 key per
   contract; one output per owner per spend. The design is written up in
   `papers/lichen-grants-v0.1.0.tex` (a draft).

   - **Why**: the fee child's `OP_RETURN` carried two unlocks (Core 29's
     relay limit), so a claim whose notes three spends took was overpaid.
     And `t` must reach her whenever the hub uses her spend (else the
     hub holds her inputs and the payee gets nothing).
   - **The reveal** (`lichen_notes::Reveal`): each grant carries, for each
     input owner with a contract open, the hub's adaptor pre-signature
     under the spend's `T` on that contract's `correct` sighash (fixed at
     the opening), by the hub's key in it; its commitment, which she
     signs, includes them. The wallet checks its own before signing
     (`Grant::verify_reveal`, against `Held.correct_msg`).
   - **The slots**: `correct`'s leaf ends with 8 of `OP_SIZE 64
     OP_EQUALVERIFY <P_H> OP_CHECKSIGVERIFY` (`grants::SLOTS`). To cite a
     spend the hub puts its completed reveal in a slot (`R = R' + T`), the
     others its plain signature. Bitcoin checked the signature, she
     checked `s'` on the same message, so `s − s' = t`: she reads it from
     the chain (`Wallet::revealed`). The statement checks a slot's `R` is
     her reveal's final nonce: no sighash, no `t`. 64 bytes: no other
     sighash type (whose message differs); the annex is excluded by her
     signature on `correct` from the opening. `correct` is 654 vB. The
     fee child is a plain fee bump again; `others`, `InBlock` and the
     unlocks are gone from the statement.
   - **A fresh key per contract**: the wallet derives each contract's L2
     key from its nonce (`ContractSecrets::l2`); its address is its open
     contract's key, and it moves its other keys' notes there by a merge.
     The hub refuses a contract for a key it knows (a contract's, or any
     note: `Book::knows`), so a contract's key has no spend from before
     its opening (whose grant would have no reveal on its `correct`), and
     no claim on another contract names its notes (`others` gone).
   - **One output per owner** (`Spend::check`): a fallback revives at
     most one candidate, so a claim (4 notes, 4 fallbacks) needs at most
     8 cited spends: the slots.
   - **Tests** (regtest): the contested exits; Alice reads Bob's note
     from `correct` (her in-flight spend's unlock), Dave Erin's; a key
     the hub knows refused at the deposit request (payments.rs).
   - **The guest** rebuilt: image id `1b2e907a…` (r0/guests/README.md);
     on the contested exit 1,306k user cycles (no `t·G` any more), 2
     segments.
   - **Not yet**: the hub checks what it records with its own BIP340
     code, the guest with `k256`; checking at intake with the guest's
     functions would make "the hub accepted it" imply "the statement
     accepts it".

## Open

- Fees: per transaction (burned: the hub's revenue as issuer) and
  liquidity per unit time, as in docs/FORWARD_PLAN.md.
- The hub's book is one JSON file rewritten on each change: fine for a
  testnet, not for volume.
- A spend in flight whose answer is lost is finished at the next sync
  (the hub's grant and record are idempotent); a hub restarted in between
  forgets its pending grants, and the spend is dropped, its inputs still
  the payer's.

### Undecided: short-id collisions (found 2026-11-13, reading v0.1.1)

A note is named by its id's first 8 bytes (in its digest, so in the
hub's signature, and in the posted claim). A *payer* controls `sid`
(e.g. her change key, unchecked), so two of her payments to Bob of the
same `v` can be ground to share `(ι, v)` in about 2^32 hashes. Bob,
offline, then holds two notes with one digest; his wallet's claim names
both (`claim_for` doesn't dedupe), `Posted::holds` calls it malformed,
and he is owed **0**, every note in the claim lost. v0.1.1 wrongly says
only the owner can grind and it only harms her. A targeted collision
with a note Bob already holds is 2^64: out of reach.

The options (the posted claim is bound by Bitcoin's 1,000 stack items:
4 items a byte, 962 used, about 9 bytes spare; a claim is 1 + n·(id +
6 + 32) + 32 + 8f ≤ 233):

| short id | a note | 4 notes | 3 notes | birthday |
|---|---|---|---|---|
| 8 B (now) | 46 | 2 fallbacks | 4 | 2^32, minutes |
| 12 B | 50 | 0 fallbacks | 4 | 2^48, GPU-hours: a colluding hub's reach |
| 16 B | 54 | doesn't fit (249) | 4 | 2^64 |

(a 5-byte value or `b` folded into the claim saves a few bytes: not
enough for 16-byte ids and 4 notes.)

1. **Count once (recommended)**: the statement counts a repeated
   `(ι, v)` once instead of owed 0; the wallet never posts two notes
   with one short id, flags a received note whose short id it holds as
   unprotected (credit) until merged (both spent together). Bob's
   existing notes are safe (2^64); grinding buys only a second payment
   his wallet shows as unprotected on arrival. Keeps 4 notes. Bob
   can't gain by colliding his own: counted once.
2. **16-byte ids**: collisions out of reach; a claim takes 3 notes (and
   4 fallbacks), so 3 protected notes between merges, not 4.

Either: a guest rebuild (lichen-vps), a regtest test of the grind, and
the paper fixed. The user is reading v0.1.1 first; decide then.

### Pending for papers/lichen-grants-v0.1.2

- The posted claim renamed `Q` (not `P`: `P` is every public key).
- §5.1 "b is signed apart": say where and why: `request` signs it
  separately, `W_{K_b}(<b>_4)`, because each bit output paying it reads
  its bits from that signature (a 4-byte word: ~20 items, not the
  claim's ~940).
- Figure 3: show the equivocation leaves (an inset of one bit output):
  on `b`'s bit outputs and the reserve output, `equiv_b_i` (the hub's,
  two signatures under `K_b`; her reserve waits Δ); on `success`'s,
  `equiv_corr_i` (hers, two under `K_corr`; the hub's bit leaf waits Δ).
  None for `K_P`: its signature is only read, never presented again.

- `C`'s reveals indexed `o^(1), μ^(1), …, o^(r), μ^(r)` (not `o_1`,
  which is input 1's owner); the slot's reveal in Algorithm 1 and §5.2
  not written `μ^(q)` as if the grant's q-th; sorting a grant's reveals
  by owner would make a re-asked grant deterministic.
- Figure 1 step 1: `V = Σ v_i` defined, `(o_A, V − v)`; the change output
  left out when `v = V`.
- Figure 1 step 3: for each output, `σ'_j = Complete(ρ_j, t_S)`; `N'_j`
  into the book, live; `(N'_j, σ'_j)` into `o'_j`'s mailbox (settled
  notes, not adaptors: self-contained, nothing of the grant leaked to
  the payee, the mailbox's one format).
- §3.1: the grinding claim corrected (above), and whichever option is
  chosen.
- Offline receiving: protected only up to 4 notes per contract between
  merges (a merge needs the hub); Bob is paid when he holds `σ'_0`, and
  the payer can always produce it (`ρ_0`, `t_S`).
- Open questions already in v0.1.1 to check in code: reveals from the
  moment `N_0` is spendable; taking the claim and its evidence as one
  step of the book.
- §4.2: the work renamed (Ω, not W: W is Winternitz); `u` (sats per
  unit of `b`) in the notation section and recalled at the journal; a
  paragraph on why the statement takes `request` and `correct` from
  blocks with Ω work on top: it reads one-time-signed digits it doesn't
  verify (her keys aren't in the journal) and slots only Bitcoin
  checked, so it needs them mined; binding her keys in `J` would free
  `request`, not `correct`.
- §5.4: place the reveal among adaptor forms. Usually either the
  publisher isn't the key holder (can't swap the nonce) or the nonce is
  joint (MuSig2, an adaptor on a partial). Here the hub holds the key
  and publishes: the DLC-oracle form, nonce committed in advance (the
  grant, in `α`), the consumer (the statement) accepting only that
  nonce, read from the *mined* `correct` (acceptance tied to
  publication). It works because the hub wants the spend counted;
  declining is allowed and is exactly the case where she's owed her
  inputs.

### Undecided: the slots under her key (2026-11-13)

The user asked why the slots can't be Alice's signatures. They can,
and it is the standard adaptor form (publisher ≠ key holder):
`correct`'s slots under her key (`P_A^c` will do); at step 3 of a
payment she makes `μ_A = PreSign_a(m_c, T_S)` and sends it with her
spend signatures; the hub checks `PreVerify` before recording (else it
records a spend it can never cite), completes it into a slot to cite
the spend, and she extracts `t_S = s − s'`.

- Gone: the hub can't put a non-revealing signature in a slot; the
  other-nonce, other-message, sighash-type and annex cases. Reveals
  leave the grant (back to `T_S`, `τ`, the output pre-signatures).
- Padding: her 2-of-2 signature on `correct` from the opening (a valid
  signature on `m_c`), or slots that accept an empty signature (`<K>
  OP_CHECKSIG OP_DROP`, size 0 or 64; `correct` smaller).
- Stays: her signature commits to `μ_A` (`α_o = H(sid, C, o, enc(μ_o))`
  per owner), and the statement matches the slot's `R` to that spend's
  `μ_A` (linearity: else `R'_A := R''_Y + T_Y − T_X` passes off `Y`'s
  completion as `X`'s); the chain evidence for `correct` (publication,
  `b_corr` binding).
- Cost: grant, wallet, hub intake, statement, maybe the leaf, guest
  rebuild: do it with the collision fix. My pick: adopt.

### Why the statement needs the chain (2026-11-13)

The user asked whether her-key slots would let the work proof go. No:
the journal is fixed at the opening (BABE garbles against it), and the
facts judged arise at exit. Two ways in: proved from the chain
(inclusion and Ω of work: ours, as BitVM2 bridges' header-chain proofs)
or committed as signed digits that are extra verifier inputs (BitVM2's
assert). `P`, `b` (her one-time words) and `b_corr` (the hub's) could
go the second way; the slots can't: script verifies a 64-byte
signature whole, and nothing (no `OP_CAT`, no splitting) ties digits
committing its `R` to the signature published. So the mined `correct`
is irreducible, whoever's key signs the slots. With `OP_CAT`/`CSFS` it
could go.

**Open, for the paper**: Ω makes safety a mining-cost bound (a hub
mining Ω on a private fork proves a fake `correct`): ten blocks' work
is about ten blocks' revenue on mainnet, nothing on a testnet. Ω should
scale with `V_max`; state it.

Corrected (the user, same day): `request` needs no chain. Its `P` and
`b` are amount-authenticated as in lichen v0.5 §(BABE with
authenticated amounts): her one-time keys bound in `J`, her signatures
checked by the statement; the anchored L2 reads `request` from the
chain only because it judges claims as of their time, and the grants
L2 has no time. What does need the chain is `correct`: `b_corr` and the
slots are the *prover's own* exit-time values, and a prover's signature
can't bind its value to its own private witness (an equivocation under
`K_corr` is seen only if Alice sees both; a revealing slot in the
witness reveals nothing). So: headers on `correct`'s block, not
`request`'s; dropping the chain entirely needs the hub not to choose
exit-time values (or `b_corr` as a BABE verifier input, changing BABE).

### Undecided: no chain at all, by countersignature (the user, 2026-11-13)

BABE_DISPUTE_PLAN §2's countersignature, reversed (the prover's value
bound by its opponent's one-time signature, script forcing equality):

- **`b_corr`**: a link `ack` after `correct`, Alice's WOTS on `b_corr`
  and the hub's re-posted, digit-equal (both in one transaction, as
  `respond` there); her silence past a window pays `b_corr` unproven
  (accepting). The statement checks her `ack` signature (key in `J`):
  one proof, `owed ≤ b_corr`, binary as now.
- **The reveals**: a BIP340 slot can't be countersigned (its `R` can't
  be compared with digits), so publish the unlocks themselves, `t_S`, as
  the hub's WOTS words in `correct`, countersigned in `ack`; the
  statement checks `t_S·G = T_X`. Reveals leave the grant entirely (no
  `μ`, no `m_c`, no slots).
- Then, with `request` amount-authenticated (v0.5): no headers, no Ω,
  no mining-cost bound; a smaller guest.
- Costs: `ack` carries 2 signatures a byte (8 items): about 120 bytes
  under 1,000 stack items, `b_corr` and 3 unlocks; Proposition 2 needs
  up to 7: several `correct`/`ack` pairs, or smaller claims (2 notes, 1
  fallback: 3 spends), which meets the id-length question. One more
  move by Alice in a window, before `assert`; her tower holds the `ack`
  key (harmless: script forces equality; silence accepts `b_corr`), a
  dent in "keyless tower".
- **Only the hub proves.** Alice signs (`request`; `ack`, mechanical,
  script-forced equal), never proves: the original countersignature
  design with the roles swapped (there the hub countersigned and Alice
  proved). One BABE instance, its cryptography unchanged. The one-sided
  `owed ≤ b_corr` suffices: too low, the hub can't prove (`ack`'s
  timeout or `failure` pays `b`); too high hurts only the hub; no `ack`
  accepts `b_corr`, no proof; a published `t` with `t·G ≠ T` doesn't
  count, hurting only the hub.
- To analyse: the byte budget against the claim's limits; knowledge
  soundness as in babe-amount-authenticated (C4); with the collision
  fix.

### Bug in the built `owed` (found writing v0.2.0, 2026-11-13)

`grants::owed` keeps candidates as a list: a claim posting a spend's
inputs, its change note *and* the spend as a fallback gets the change
revived as a second copy, counted twice (unspent, so no spend can kill
it): a cheating claimant gains her change. Fix: candidates a set (with
16-byte short ids, equal entries are one note), revivals keyed by
fallback prefix (`revived` holds full sids today, so one prefix could
revive two spends). Needs a guest rebuild. v0.2.0's Algorithm 1 has it.
v0.2.0 (papers/lichen-grants-v0.2.0) is the countersigned design, a
proposal; v0.1.1 stays as the built design until one is chosen.

### Capacity levers for v0.2 (2026-11-13)

The user asked whether notes could share the contract's key to shrink
them: they already do (`Q` carries no owner; the statement takes `O_c`
from `J`). A posted note is 16 (id) + 6 (value) + 32 (`r` of the hub's
signature, the issuance evidence). In v0.2 the binding limit is `ack`'s
3 unlocks (32 B, 8 items a byte), not the notes. Levers:
- **16-byte unlock seeds**: `z_S = [H(k_iss, sid)]_16`, `t_S =
  H_unlock(z_S)`; publish `z_S`, the statement checks `H(z_S)·G = T_X`;
  `ack` then holds 6 unlocks (2^128 to invert).
- Then the posted claim binds again (`request` ≤ ~242 B of `Q`): with
  54-byte notes, 3 notes and 3 fallbacks. **BLS** issuance signatures
  (one 48-byte aggregate, a note 22 B) would allow 6 notes, at a
  BLS12-381 pairing in the guest and BLS in wallets.
- **BLS, in detail** (the user's lever: it takes out the bulk): one
  signer, so the aggregate verifies in 2 pairings for any `n`
  (`e(σ, g2) = e(Σ H(m_i), I2)`); no rogue keys; repeats already
  rejected. Atomicity: **not an adaptor** (adaptors with extraction are
  impossible for unique signatures such as BLS: the signer computes `σ`
  itself, so extraction would solve any instance; Erwig et al., PKC
  2021, I believe) but a verifiably encrypted signature (BGLS 2003): a
  signature under `I2 + T2`, `σ' = (k_iss + t)·H(m)`, `σ = σ' − t·H(m)`;
  the pair gives `t·H(m)`, never `t`. v0.2 never extracts from a note's
  signature (`t` travels in the clear: step 4, `U`, the mailbox's
  completed signatures); the opening's extraction is from the funding's
  secp Schnorr signature, unchanged. Grants BLS throughout
  (`τ` on `(sid, T2)`, the statement checks `t·g2 = T2`). The mint ties
  `t_0` to Bitcoin's secp adaptor on the funding: a cross-group DLEQ
  (as in Monero–Bitcoin swaps) before she signs, off chain, once per
  contract. Unmeasured: hash-to-curve and 2 pairings in RISC Zero.

### HASH160 or SHA-256 chains for her one-time keys (2026-11-13)

No capacity at stake: Bitcoin's limit is 1,000 stack *items*, and a
digit is two items either way. Only her four keys (`K_Q`, `K_b`,
`A_corr`, `A_U`) matter: the guest verifies only hers; the hub's
`K_corr`, `K_U` stay HASH160. SHA-256 costs bytes (32-byte preimages
and script elements, witness-discounted): `request` about +2.5 kvB
(+25%), `ack` about +1.4 kvB (+12%), in contested exits only. It saves
the guest's RIPEMD-160 (no accelerator): about 4,900 calls, 15–25M
cycles est., to ~1M. BLS (est. 30–50M) likely dominates; SHA-256 would
still cut about a third. Decide after one short lichen-vps run timing
6 aggregated BLS signatures and a few hundred RIPEMD-160 calls. v0.3.0
says "about 60% more" on chain: wrong (raw preimage size, no witness
discount); fix in the next version.

### A contract-born mint: no cross-group proof (2026-11-13)

With BLS notes, v0.3.0's mint needs `t_0` on both curves and a
cross-group DLEQ (else the hub hands an unrelated `T_{0,2}`: the funding
reveals `t_0`, her note never decrypts). Instead: the journal's `D`
also binds `v_0` (her deposit less the fee, known when the statement
is fixed); `N_0 = (H_issue("mint" || c), O_c, v_0)`; one flag bit in
`Q`'s count byte says the claim includes it, and the statement adds it
as a candidate with no signature; a spend of `N_0` she signed kills it
as any note; the hub books `N_0` once the funding confirms. Atomic by
the contract's existence: funding confirmed ⇒ the contract and its
`v_0` ⇒ `N_0` claimable; never funded ⇒ nothing. No adaptor, no
encryption, no second curve at the opening; M1 trivial. Cost: a flag
bit and `v_0` in `J`. The hub must not record spends of `N_0` before
the funding confirms (its own risk). Proposed for the next version.

### Taken in papers/lichen-grants-v0.4.0 (the user, 2026-11-13)

Capacity 4 (`μ + n + f ≤ 4`: `Q` 137 bytes, `U` 4 seeds, 64 bytes);
SHA-256 chains for her four one-time keys (the hub's stay HASH160);
the contract-born mint (no adaptor at the opening, no cross-group
proof). Main open question: BLS verification in RISC Zero, a hub cost
only. Still a proposal; v0.1.1 is the built design.

### Building v0.4.1 (the user, 2026-11-13)

The user approved building papers/lichen-grants-v0.4.1 (now v0.4.3, which
adds only a note on countersigning a commitment, §5.6), replacing the
v0.1 code. Proofs run on the mock statement at first. Order, by risk:

1. **The script graph** (done 2026-11-13): `lichen_babe::countersigned`
   (`hp.rs` stays until the hub and wallet move over). `ack` is
   `digits_equal`: the hub's signature, its digits parked on the
   altstack, then hers, each digit `ROLL`ed up and `EQUALVERIFY`d. ln-gap's
   payout code (`bit_tree`, `payout`, `pay_alice`, `wots_shape`) is now
   generic over the Winternitz chain, so `K_b` is SHA-256 (ln-gap
   e97ddde). Test `crates/babe/tests/countersigned.rs`, regtest under
   standard policy: every link relayed at its floor; `accept`, `success`,
   `request_timeout` and `ack_timeout` mined, and their bit outputs spent
   by each leaf (set, clear after δ, `equiv_corr`, `equiv_b` on SHA-256);
   an `ack` countersigning another `b_corr`, or a `U` one bit off, refused
   (`OP_EQUALVERIFY`). Measured, against the paper's estimates:

   | link | vsize | items | est. |
   |---|---|---|---|
   | `request` | 8,891 | 578 | 8.8 kvB, 578 |
   | `correct` | 3,611 | 284 | 3.5 kvB, 284 |
   | `ack` | 8,025 | 566 | 7.7 kvB, 566 |
   | `assert` | 7,725 | 258 | (v0.1's) |

   **The hub's reserve must cover the floors**: the five links at 1
   sat/vB, about 21.5k sats with their anchors. A 20k reserve fails
   `payout_less`; check what deployments set.
2. **BLS notes** in the hub, wallet and book.
3. **The guest**: Algorithm 1 with set semantics; BLS with fixed-base
   tables and prepared constants; no `from_bytes_wide`.

### BLS in RISC Zero, measured (2026-11-13)

RISC Zero 3.0.6, the executor on the Mac (cycles are exact; nothing
proved), `bls12_381` fork `v0.8.0-risczero.1` (hash-to-curve needs
`sha2` 0.9), an aggregate of upstream-made signatures (a wrong message
fails it):

| step | cycles |
|---|---|
| decompress `I` (G2) / `σ` (G1) | 1.41M / 1.05M |
| hash-to-curve, one note (G1; G2 would be 2.77M) | 0.89M |
| `G2Prepared`, each of `I` and `−g2` | 1.21M |
| multi Miller loop, 2 pairs | 6.63M |
| final exponentiation | 10.94M |
| `t·g2`, double-and-add / 4-bit fixed-base table | 7.25M / 0.86M |
| 3,200 SHA-256 / 100 HASH160 | 1.56M / 0.31M |

As first written (n = 4): 62.6M, 63 segments, the seeds 35M of it.
With the obvious fixes (fixed-base table for `g2` as constants; compare
`t·g2` compressed with `T` instead of decompressing `T`; `I` and `−g2`
prepared as constants of a per-deployment guest): about 29M for the
whole statement (BLS ≈ 24M, her SHA-256 one-time signatures ≈ 1.6M,
four BIP340 `α` checks est. ≈ 2M). Proving at the old rates: ~4 h on
lichen-vps (4 cores, ~490 s a segment), ~30 min on the M4 Pro; a CUDA
GPU minutes. Further: the final exponentiation (11M) can be replaced
by a hinted check (Novakovic–Eagen, "On proving pairings", 2024).

**A bug in the fork**: `Scalar::from_bytes_wide` in the zkVM build
returns the right value times `R` (`d0 * R + d1 * R2` under `//TODO:
untested`, in a non-Montgomery representation): it disagrees with
upstream. Derive scalars with canonical `from_bytes` (a 254-bit value)
or report it to RISC Zero first. The scratch project:
the session's scratchpad `blsbench/` (host + guest), not kept.

### A candidate v0.5: one note per contract, live receipt (2026-11-14)

Written up in papers/lichen-grants-v0.5.0 for comparison with v0.4, then
revised as v0.5.1 (sequence numbers, below). It's
a proposal, not approved to build. Step 2 below (BLS notes in the hub,
wallet and book) waits on the choice, because v0.5 has no BLS.

Where it came from: v0.4 protects at most 4 notes per exit. A hub that
halts keeps every note beyond that, and it can count, without linking,
how much that is. In the private (denominated) variant the count is
worst: a balance takes popcount(V) notes, and the uncovered part can be
up to V/8 at a cap of 4. The user: a free 12.5% for the adversary is not
acceptable.

The design: each contract key holds exactly one note. A payment is a
joint spend of the payer's note and the payee's, giving each a new note.
Both sign the same α, and one grant opens both outputs. The payee must
be online (Lightning terms).
- **Halves.** sid = H(o1, h(η1), o2, h(η2)), with η = (o, ι_in, v_in,
  v_out, blinding). The counterparty sees only the amount, and the
  statement sees only her half.
- **Rule 1 (statement):** a spend counts only with both owners' ψ.
  Otherwise the hub could cite on the payer's ψ alone, toward a payee
  who doesn't hold the grant.
- **Rule 2 (wallet):** one pending signature per key. Otherwise a payee
  who signed two incoming payments could be followed in only one.
- **Rule 3 (wallet):** sign only spends of your current note.
- **Cancel = reissue.** The hub gives a fresh id for the same value. If
  it later completes the cancelled spend, the hub pays from nothing,
  which is self-punishing.

What drops out:
- Algorithm 1 becomes three cases (unspent; the fallback cited, so
  change counts unless also spent; otherwise 0).
- U is 2 seeds, 32 bytes. Q is 95 bytes (one note, a BIP340 σ, a
  fallback).
- No merges.
- No BLS: notes are BIP340, encrypted by adaptor pre-signatures. The
  statement is about 2.6M cycles (est.: 5 BIP340 at 260k, about 2,100
  compressions, two t·G), against 29M.
- request, correct and ack are about 6.3, 2.0 and 4.4 kvB, scaled from
  the measured 8.9, 3.6 and 8.0.

Deferred receipt (a mailbox) is kept as an option in §7. Its costs:
- The hub forms the payee's half.
- One payment per payee in the mailbox; later payers wait unsigned.
- The payer is locked while the payee is away; cancels race late
  signatures, which strand both sides.

**A gap found while writing, which v0.4 also has:** settling into a
closed contract. The hub records S and withholds z_S. The payee exits
first, and the hub doesn't cite S against him, since citing would raise
what he's owed. Later the hub cites S against the payer: she's debited,
and his new note settles as credit under a closed key. The hub keeps a.
The mitigation in v0.5 §4.3 is that payers exit first: a payee with an
incoming payment in flight waits for the payer's exit. It's bounded by
one pending payment per user. Whether the statement can bind a spend's
use to the payee's contract being open is an open question.

**v0.5.1: sequence numbers (2026-11-14; now v0.5.5, which reworded the storage point and added §9, payment volume against Lightning: the hub keeps O(1) per account, O(N) for N users, against v0.4 keeping every spend).** A note is (o, k, v): owner,
number, value. Every account starts at 0 (a contract key with its mint,
any other key with the empty note), and a spend steps both accounts to
k + 1. Halves name their input by (o, k_in, v_in).

What goes:
- note ids, short ids and output ids, and with them the grinding
  argument. δ(S) survives only as the hashed message;
- fallbacks;
- U's second seed.

Algorithm 1 becomes one comparison: a cited spend supersedes the claim
iff it has both ψ, its seed is in U, and her half's k_in ≥ k. Then
owed = min(b, v_out/u); otherwise min(b, v/u).

Why ≥: the hub may cite any later step against a stale claim, but an
honest claim of the live note leaves it only the spend in flight (Rule
3). A stale claim is paid at most the current balance (eltoo-like, no
penalty), and with "=" a stale claim could get a past, larger balance.

Results:
- One citation always suffices.
- The hub keeps only each account's latest step and any spend in
  flight; the user keeps only the live note and any spend in flight.
- Q is 74 bytes, U 16.
- request, correct and ack are about 5.0, 1.2 and 2.6 kvB (scaled).
- The statement is about 1.7M cycles (3 BIP340 checks and one t·G,
  est.).
- Cancel reissues at k + 1, so the cancelled spend (k_in = k) never
  supersedes the reissue.

### Taken in papers/lichen-grants-v0.5.5 (2026-11-14)

The user asked for this list to be written up as v0.5.5. The paper now
stands alone, at 22 pages (it was 15). Items 1 to 3 are in. Item 4 is
one bullet under Open questions. The principle from item 2 is in §1, and
fig. 1 and Rule 3 point to it. The worked exit is redone for one note.

1. **Say why o appears twice; keep it in h(η) (the user, 2026-11-14).**
   One sentence at §3.2. o goes in the clear in δ(S) because the
   statement checks the counterparty's ψ under the key Alice approved
   (Rule 1), and the payer checks that the payee is her invoice's o_B.
   It stays inside h(η) so that each half names its own owner whatever
   it's embedded in. That guards against order mix-ups, a δ(S) with more
   than two parties, and the hub forming the payee's half in §7.
   Dropping it was considered: it would save one SHA-256 compression in
   the statement (68 bytes of input → 36), out of about 1,500.
2. **The hub checks amounts only for itself (the user).** This is a
   general Lichen principle, and v0.4 has it too. In fig. 1, "values
   balance" is the hub's own check. Nobody else needs it, and the
   statement never checks conservation across the two halves.
   - If the hub gives one party too much, it prints money at its own
     expense: it has signed that note.
   - If it gives a party too little, that party doesn't co-sign (Rule 3:
     each owner checks its own v_out).
   - Whatever the hub signs alone, such as a mint or a reissue, can only
     add to a claim. Supersession needs the owner's ψ. A reissue that
     comes short just isn't claimed: she claims note k, where the worst
     case is the cancelled S, which she signed.

   Where: a short statement in §2 or at Rules (§4.2), pointed to from
   the fig. 1 box. It's the same idea as the "leaves only hurt the hub"
   condition in v0.4's countersigning note (§5.6).
3. **Stand alone, not a delta to v0.4 (the user, 2026-11-14).** §3.3
   says "version 0.4's τ and its commitment C", and neither is defined
   in v0.5. More generally, v0.5 must read on its own.
   - Define in place what's now "as in version 0.4": the setting (§1),
     the notation and one-time signatures (§2), opening and the mint,
     the dispute graph and its figure (§5), request/correct (§6.2) and
     the keyless contest.
   - Drop the asides on what was removed: BLS (§2, the adaptor
     paragraph), ids and short ids (§3.1), τ/C (§3.3), "no fallbacks"
     (§6.4, §6.5), the one-way atomicity (§4.3), the storage contrast
     (§6.7, abstract) and the TeX comment at line 27.
   - Give the costs as measured on regtest for this graph's shape, not
     as "scaled from version 0.4".
   - Keep the comparison in one place: §10, plus a line in the abstract
     and the title page.
4. **Maybe, Open questions: rules at exit.** The statement could enforce
   predicates committed at contract setup. A cited spend counts only if
   it meets them, so they limit only what the hub can debit. They're
   bilateral, have no clock but the chain's, and carry no global facts.
   Example: a vault floor F. Going below F needs a MuSig2 or FROST key
   (one BIP340 check, so no extra proving). This only helps when the
   user's key is stolen: the hub may ignore the rule, but then it pays
   the thief itself. The user found it "interesting" and wasn't sure
   it's useful, so at most one paragraph.

### Pending for papers/lichen-grants-v0.5.6 (2026-11-14)

1. **One width for values: ⟨v⟩₆ everywhere (the user).** v0.5.5 hashes
   v in 8 bytes (δ(N), h(η)'s v_in and v_out, the journal's v₀) but
   posts it in 6 (Q), and bounds it by 2^48 because of Q. Use 6 bytes
   throughout, and say why the bound is enough: v counts sats; u applies
   only to b on chain, so u·b ≤ v < 2^48 = 2^32·2^16, which covers every
   payout for u ≤ 65,536 sats.
2. **Why t_S is hashed from z_S, not z_S itself (the user asked).** Add
   to §8 "Why a seed": a 16-byte scalar would put T's discrete log below
   2^128, so kangaroo would recover it in about 2^64. Anyone holding a
   grant could then complete the notes without the hub publishing, which
   breaks atomicity. Hashing spreads 16 bytes over a full scalar, so
   recovering t means guessing z, at 2^128 work.
3. **The chain as court and bulletin board (the user).** §6.7 says who
   must be online, but not, in plain terms, when anyone has to read the
   chain. Add a short paragraph there, and maybe a sentence in §1:
   - Users read the chain only when something is stuck. Nothing can be
     published against them, since every exit starts with the user's
     own `request` and the hub's only unilateral path is `default`
     after T_close.
   - A user reads the chain in three cases. (a) Her own exit, which she
     started. (b) A stuck incoming payment: ask the payer for z_S first,
     and if that fails, find it in the U of the payer's `correct`. This
     needs no knowledge of the payer's contract: test each `correct`'s
     seed against T_S, one t·G each. This is the payers-exit-first wait.
     (c) The deadline T_close, which needs a clock, not watching.
   - Only the hub watches continuously.
   - Contrast with Lightning, where the chain is a standing threat. Here
     it is consulted on demand, and a wallet can ignore it by default.
4. **"The new note counts" means b_corr (the user asked).** In §4.1, say
   instead: "she is owed the new note's value: the hub's b_corr is
   ⌊v_out/u⌋, which it can prove". For her own exit she never needs the
   new note's signature. Publishing z_S is what completes the payment
   for the counterparty, as in an atomic swap.
   And make the sentence plural, as the user suggested: "...it must
   publish z_S, and both new notes count". Hers is paid as b_corr, and
   the counterparty's settles from the published seed.
5. **Define U properly (the user).** Definition 4 is a description.
   Write: "An exit's unlock is U ∈ {0,1}^128: U = z_S if the hub cites
   spend S against the claim, and U = 0^16 if it cites none." State its
   role in one line: the hub posts it in `correct`, and the statement
   derives t from U by the same rule as t_S from z_S. Consider moving it
   to §6.2, where U first matters, and leaving §3.3 at z_S.
6. **Rule 1 is about atomicity (the user).** Rewrite §4.2's Rule 1 so
   that it says:
   - Publishing z_S settles a new note only for a party that holds its
     ρ. Each ψ is the statement's evidence that its signer does, because
     α commits to T_S, ρ₁ and ρ₂, and a wallet signs only after checking
     its own ρ.
   - With ψ_A alone, the hub could cite S against Alice and publish z_S
     while Bob never received ρ_B. Alice would be debited and Bob not
     credited: the step becomes one-sided.
   - So S counts against either owner only with both ψ together, never
     with each checked separately or with only the exiting party's.
   - Open §4.2 with a sentence on the labels: "Each rule is named by who
     enforces it: the statement, against the hub; the wallet, for its
     owner. Nothing relies on the hub." This ties back to §1's "the hub
     checks amounts for itself".
7. **Settling into a closed contract: by timeouts, not exit order (the
   user).** Replace §4.3's paragraph. "Payers exit first" was a bit off.
   - **Evidence.** The payee is not paid without z_S, and delivers
     nothing. A debited payer always holds z_S: either from step 6, or
     from her own `correct`, since citing S means publishing it. It is
     her proof of payment: she can complete Bob's note by handing z_S
     (and ρ_B, which she holds too) to him. She doesn't need ψ_B (the
     user): Rule 1 holds it for her, and Bob settles from Γ alone. ψ_B
     would only be evidence for a third party, which is out of scope.
   - **The gap is timing.** z_S may reach Bob after his contract has
     closed.
   - **Two wallet timeouts close it.** Let c be the time for a
     `request` to confirm.
     - Payer: in flight longer than p, it exits. The hub must then
       decide within w_H: publish z_S, or lose S against her for good.
     - Payee: it signs no incoming payment after T_close − L, with
       L > p + w_H + 2c, and doesn't exit with an incoming payment
       pending unless T_close − c forces it.
   - **p and L are practical choices.** An invoice may carry the
     payee's last day for receiving. Collusion between payee and hub
     harms only them, since the payer is debited only when z_S exists,
     and z_S completes the payee's note.
   - Drop "payers exit first" here and in §7 (deferred receipt) and
     Open questions. The open question becomes whether a timeout-free
     binding inside the statement is possible.
   - The user's draft-level verdict: the remaining questions are
     practical, and their technical side is the dispute-path timeouts.
