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
