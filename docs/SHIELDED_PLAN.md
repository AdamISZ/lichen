# Shielded transfers, then validity proofs: plan

2026-10-18, branch `shielded` (from `tower`). Background: ln-gap's
`docs/planning/VALIDITY_PROOFS.md` (2026-10-13) and
`docs/planning/research/shielded-pool-costs.md` (the measurements behind
this plan; local notes).

## Status

**Phase 1 done** (2026-10-18): shielded notes and transactions
(`3479996`), the spend guest, its prover and receipts the sequencer
verifies (`bef672a`). Demonstrated on Mutinynet with real receipts,
the sequencer and hub on this branch's images (deployment `837ceb56…`):

| step | proved (Mac, Docker) | user cycles |
|---|---|---|
| Dave shields 11,000 | 6.0 s | 10,163 (2^16) |
| Dave pays Carol 4,000, shielded (1 in, 2 out) | 13.1 s | 46,356 (2^17) |
| Carol shields 10,000, then her contract 1007's deposit of 30,000 | 6.1 s, 6.8 s | 10,163 |
| Carol withdraws 44,000 from three shielded notes: the return | 31.4 s | 109,210 (2^18) |

The hub folded contract 1007 (200 vB, Mutinynet block 3,515,985):
64,000 sats to Carol's payout address, her 44,000 and her reserve. A
return of several notes crosses into a larger segment: each spend is
two depth-16 paths of SHA-256 over 64 bytes, ~30k cycles.

**Phase 2, steps 1–3 done** (2026-10-18): the nullifier tree
(`70fecb5`), the block statement (`acbd9ee`), and the chain guest, its
prover, and the sequencer recording each block. The real-receipt test
(`crates/wallet/tests/shielded_r0.rs`) proves every height it seals,
each from the last, and checks the last receipt ends at the last sealed
root (Mac, Docker, 8 cores; succinct receipts):

| height | block | user cycles | proved |
|---|---|---|---|
| 1 | a mint (genesis before it) | 384,061 (1 segment) | 65 s |
| 2 | Alice shields (a signature, a receipt) | 740,441 | 148 s |
| 3 | Alice pays Bob, shielded (a receipt) | 421,446 | 92 s |
| 4 | Bob returns to the hub (a receipt) | 419,568 | 92 s |

396 s for the four. The first build took 874 s (1.1–1.5M cycles a
height, two segments each): a profile (`lichen-r0 exec-chain`,
RISC0_PPROF_OUT) showed the nullifier tree's 257 empty roots recomputed
in every block (62% of a one-mint block), and each node ~1,300 cycles
for one ~93-cycle compression (byte copies of unaligned blocks). The
empty roots are now a table computed at compile time (`smt::EMPTIES`,
a `const fn` SHA-256 compression), and a node compresses a word-aligned
block: a nullifier insert 751k → 306k cycles. What's left is mostly the
BIP340 signatures (~260k each) and the receipts' resolution.

**Step 4 in progress** (2026-10-18): the withdrawal statement with
validity (`crates/withdraw`): ln-gap's `check`, unchanged, then a chain
receipt ending at the signed root, at its height, under the same hub
(`env::verify(CHAIN_ID, journal)`, `CHAIN_ID` built in from
`r0/guests/chain.id`). Its journal stays ln-gap's `b ‖ c ‖ D`. Checked
natively against ln-gap's statement on the four blocks of
`every_block_is_the_block_statements`: the same journal. The guest
(`r0/withdraw-guest`), `lichen-r0 withdraw|exec-withdraw|wrap|claim`
(the claim's input encoded for BitVMX's verifier, ln-gap's encoder), the
sequencer serving chain receipts (`GET /chain/<h>`), the wallet's
`chain-receipt` and the tower proving with `lichen-r0` are written.

2026-10-19: the guest built on x86 Linux (`r0/guests/withdraw.bin`,
image id `6607a2bc…5861`) and pinned by the contracts
(`lichen_proto::IMAGE_ID`, read from `withdraw.id`). The real-receipt
test (`shielded_r0`) proves Bob's withdrawal under the chain receipt of
height 4: 332k user cycles, 75 s on the Mac. Wrapped on the GCE
`n2-highmem-4` (360 s, then 260 s; the wrap's prover image reached
through the host's Docker): the toy deployment's return of 60, memo 42,
is the new canned claim (`crates/proto/tests/data/claim-60-42.hex`) of
the Groth16 tests: G1 (the hub concedes, 444 s), G2 (the whole search on
a true claim, Alice proves the last step, 779 s) and G3 (b changed to
61, disproved, 554 s) pass on it. Left: a Mutinynet trial with the
tower.

A withdrawal disputed on Bitcoin now needs the sequencer's chain receipt
at its return's height, not only the signed root: a sequencer that stops
proving (or serving receipts) stops dispute withdrawals, as one that
stopped signing roots would. Data availability stays out of scope.

## The aim

Show that lichen is possible with private payments and with dispute
proofs that are validity proofs. Not to re-engineer what rollups and
Zcash have already solved:

- **a.** a user sends a shielded payment in reasonable time on a laptop
  (measured: ~14 s to prove, Mac, Docker);
- **b.** a sequencer sustains some throughput (one machine: ~120
  transactions an hour, estimated);
- **c.** the withdrawal proof judged in the Bitcoin dispute attests that
  the root it uses ends a proven valid history. The dispute game itself
  is unchanged: it judges a Groth16 receipt against an image id the
  contract pins.

c is the goal; a and b only have to be good enough to show it.

Phase 1 is shielded transfers; phase 2, once phase 1 works, validity.

## What stays fixed

The withdrawal statement (`lngap-r0-core`, the committed guest and its
image id) is unchanged in phase 1:

- returns to the hub stay transparent notes (owner the hub, value `b`,
  memo `c`), in the same commitment tree (depth 16, nodes
  `SHA256(left ‖ right)`), under the same state root
  `SHA256("lngap/root" ‖ height ‖ T ‖ N)`;
- the nullifier set's root `N` is opaque to the statement, so phase 2
  can change how it's built;
- mints stay transparent: the deposit `D` is public on Bitcoin anyway.

So the contracts, the hub's checks and the dispute don't change in
phase 1, and every test of them should still pass.

## Phase 1: shielded transfers

### The notes

A shielded note `(value, owner, rho)`:
- `owner = SHA256("lichen/owner" ‖ nk)`, `nk` the owner's nullifier key;
- its commitment `cm = SHA256("lichen/snote" ‖ owner ‖ value ‖ rho)`, a
  leaf of the same tree as transparent notes (domain-separated);
- its nullifier `nf = SHA256("lichen/snf" ‖ nk ‖ rho)`, in the same set
  as transparent ones (`SHA256("lngap/nf" ‖ cm)`): unlinkable to `cm`
  without `nk`;
- `rho` of a transaction's i-th new note is
  `SHA256("lichen/rho" ‖ nf_0 ‖ i)`, `nf_0` the transaction's first
  nullifier: unique, so a sender can't give two notes one nullifier (the
  "faerie gold" attack). The recipient recomputes it when scanning.

Spend authority is knowing `nk`, checked inside the proof: no signature
(two BIP340 checks would put a transaction back at 2^20 cycles).

A shielded address is `owner ‖ E`, `E` an x-only secp256k1 key for note
encryption. A new note's opening goes to its recipient encrypted (ECDH
with `E`, ChaCha20-Poly1305), outside the proof, as in Sapling.

### The transaction

`Tx::Shielded`, any of:
- **shielded spends:** proved, revealing only nullifiers;
- **transparent spends:** notes (mints, returns made earlier) spent as
  today, each owner's BIP340 signature checked by the sequencer, over
  the whole transaction;
- **shielded outputs:** commitments and ciphertexts;
- **transparent outputs:** openings (a return to the hub).

The proof (the spend guest, RISC Zero) shows: each shielded spend's note
is in the tree under the anchor (a sealed tree root) and its owner's
`nk` is known; the nullifiers are theirs; the new notes' `rho`s are
derived; and
`Σ shielded in + Σ transparent in = Σ shielded out + Σ transparent out`.
Its journal, which the sequencer recomputes from the transaction:
the anchor, the transparent spends' nullifiers and total, the shielded
nullifiers, the new shielded commitments, the transparent outputs'
commitments.

The sequencer checks: the anchor is a sealed root's tree; no nullifier
is spent; the transparent signatures; the receipt against the spend
guest's image id and that journal. Then it appends the new notes and
records the transparent openings, as now.

A shielded payment is shielded spends to shielded outputs; shielding
spends a transparent note (the deposit's mint) to shielded outputs; a
return spends shielded notes to a transparent note of the hub's. Up to 4
spends and 4 outputs, so every block is cheap to prove.

### The proof

- The spend guest in `guests/spend/`, its logic in `crates/shielded`
  (`no_std`, shared with the sequencer and the wallet). Built in RISC
  Zero's guest builder (Docker), the ELF committed, its image id derived
  from it, as ln-gap does for the withdrawal guest.
- The input read raw (`env::read_slice` of words), each tree node one
  SHA-256 over 64 bytes: the shape the benchmark measured (34.6k user
  cycles, 2^17, at depth 32).
- The wallet proves with a prover command (`--prover`), as the tower
  does: in Docker on a Mac (RISC Zero's in-process prover needs Xcode's
  Metal compiler), natively on Linux. It uploads the composite receipt;
  the sequencer verifies it as it is.
- Zero-knowledge: RISC Zero targets perfect zero-knowledge but hasn't
  proved it (its security model, checked 2026-10-18); composite receipts
  leak the execution length, which, with every transaction the same
  shape, says nothing. Fine for a demo; say so.
- For tests, a native proof: the private input itself, checked with the
  same code by the sequencer. Accepted only where the sequencer is told
  to (regtest), like the mock statement.

### The wallet

- `nk` and the encryption key derived from the wallet's key; a shielded
  address alongside the transparent one.
- Scanning: the sequencer's state carries each shielded output's
  commitment and ciphertext; the wallet trial-decrypts them, keeps its
  notes and their tree positions, and builds paths itself (asking for a
  path would tell the sequencer which note is yours).
- Commands: `shield`, `send` to a shielded address, `return` from
  shielded notes; `balance` shows both kinds.

### Tests

1. `crates/shielded`: the statement natively (balance, membership,
   a spent note, a forged `nk`, the derived `rho`s).
2. The ledger: `Tx::Shielded` with native proofs, alongside mints and
   transfers.
3. End to end on regtest, native proofs: Alice shields her deposit,
   pays Bob, Bob pays Alice, Alice returns to the hub and withdraws
   cooperatively; then the same return refused and disputed (the
   withdrawal statement unchanged).
4. One payment with a real receipt (opt-in: the prover image).
5. Mutinynet: the demo with real receipts.

### Known gaps in phase 1

- **Validity.** With shielding, nobody but the sequencer can check the
  ledger: a sequencer could insert a note no spend paid for, invisibly,
  return it to the hub and withdraw against its collateral. Today's
  transparent ledger lets anyone audit. So phase 1 leaves the hub more
  exposed to the sequencer than today; phase 2 closes it. A demo, not a
  deployment, until then.
- Amounts that touch Bitcoin are public: deposits and returns.
- The sequencer sees timing and which receipts arrive when.
- Hardware signers (a signature checked outside the proof, as Sapling's
  spend authorisation) are not covered.

## Phase 2: validity proofs

After phase 1 is demonstrated, in this order:

1. **The nullifier set as a sparse Merkle tree**, so a block guest can
   prove non-membership (`N` changes; the withdrawal statement doesn't
   read it).
2. **The block guest**, one per sealed height: verifies each spend
   receipt by composition, checks mints and transparent spends directly,
   updates both trees, commits `(i, SR_i, SR_{i+1})`. The sequencer runs
   it in the executor before sealing and refuses to seal on a mismatch.
3. **The chain guest**: "valid up to i" and block i's proof to "valid up
   to i+1", journal `(i+1, SR_{i+1}, CHAIN_ID)`; genesis pinned by the
   deployment. (Done as one guest with step 2: below.)
4. **The withdrawal guest** with `env::verify(CHAIN_ID, (n, SR_n))`
   before its inclusion path. Its journal stays `b ‖ c ‖ D`; on chain
   only the image id changes. Then the Groth16 dispute test (G2) and a
   Mutinynet trial with the tower.

Step 1 is done (`70fecb5`): 256 levels keyed by the nullifier's bits,
a node one SHA-256 compression of its 64-byte block (no padding: N is
ours to define); an insert proof is a bitmap of the non-empty siblings
and those siblings, `smt::insert` checks it against the root before and
gives the root after. An insert hashes 512 nodes. It lives in
`crates/validity` (`smt`), not `crates/shielded`: the spend guest is
built from `crates/shielded`, and keeping phase 2 out of it keeps the
committed spend guest reproducible from the tree (its ELF rebuilt from
HEAD is the committed one, `ca07debb…`) and its image id unchanged.

Steps 2 and 3 are one guest, the **chain guest** (below): each height's
proof checks its block and verifies the previous height's proof, so one
recursion step per block, not two.

### The block statement (step 2): decisions

A block is the transactions applied between two seals, in order. The
statement, for height `i` to `i+1`:

- **Input:** the state at `i` as its parts (the tree's root and size
  and its frontier, `N`, the recent roots below), the block's
  transactions with their receipts as assumptions, and the witnesses:
  an insert proof per nullifier in order, a path per transparent note
  spent from before the block.
- **It checks** what the sequencer checks, in the same code (the
  rollups' lesson, VALIDITY_PROOFS.md): mints signed by the hub; each
  transparent spend's note in the tree (under `T_i`, or made earlier in
  the block) and its owner's BIP340 signature; each shielded
  transaction's receipt by `env::verify(SPEND_ID, journal)`, its journal
  recomputed from the transaction, its anchor among the recent roots;
  every nullifier unspent, inserted in order; the new leaves appended
  to the frontier.
- **Journal:** `(i, SR_i, RECENT_i) → (i+1, SR_{i+1}, RECENT_{i+1})`,
  `SR = state_root(height, T, N)` as the withdrawal statement has it.
- **Anchors: the last K sealed tree roots** (K = 64), carried beside the
  state root as `RECENT` (a hash of the list). A spend proved against an
  older root is refused; at a seal every 5 s that leaves minutes to get
  a proof in. The state root itself can't carry them: its form is the
  withdrawal statement's. The ledger applies the same rule, so the
  sequencer never accepts what the block statement would refuse.
- **Where blocks are kept:** the sequencer records each height's
  block at its seal, in files per height beside the ledger (receipts
  are ~0.3 MB each; the ledger file is rewritten on every change), for
  its prover (below).
- **Code:** `crates/validity` (`no_std`, for the chain guest), the
  statement checked natively in tests with receipts checked by a
  closure, as `Proof::Native` does for spends.
- **Genesis:** height 0, the empty ledger, pinned by the deployment.
  The Mutinynet deployment's earlier heights have the old flat `N`, so
  phase 2's demo starts a fresh deployment.

### The chain statement (steps 2–3): decisions

- **One guest per height**, `r0/chain-guest`: the block statement
  (`lichen_validity::check`), then the state it starts from is either
  genesis (height 0: the empty tree, the empty nullifier tree, no recent
  roots) or the end of a previous chain receipt, checked by
  `env::verify(CHAIN_ID, journal)`. Journal:
  `hub ‖ height ‖ SR ‖ RECENT ‖ CHAIN_ID` (`ChainJournal`).
- **Its own image id is an input.** A guest can't contain its own image
  id; it takes one, verifies the previous receipt against it, and
  commits it. Whoever checks a chain receipt against `CHAIN_ID` (the
  withdrawal guest) also checks the journal's `chain_id` is `CHAIN_ID`;
  by induction every earlier receipt was against it too.
- **The spend guest's image id is built in** (`include_str!` of
  `r0/guests/spend.id`): the chain guest is rebuilt after the spend
  guest.
- **The prover** (`lichen-r0 chain`): the block's spend receipts
  (composite, as the senders upload them) and the previous chain receipt
  as assumptions, proved to a succinct receipt, which compresses and
  resolves them: the per-receipt cost the plan counts on.
- **Where blocks are kept:** at each seal, the sequencer writes
  `<ledger>.blocks/<h>.input` (the block statement's input, bytes) and
  `<h>.<k>.receipt` (each shielded transaction's receipt). The chain
  prover (`r0/chain-prover.sh`) proves them in order to `<h>.chain`.
  Heights sealed with native proofs are recorded but can't be proved.

Costs (estimates): ~23 s of sequencer proving per transaction on one
8-core machine (compressing a receipt 9 s, resolving it 14 s), plus the
tree updates (~8 s) and ~15–30 s per block; a withdrawal waits for its
block to be proven, and resolving the chain assumption adds one
recursion step (~14 s) before the wrap.

Out of scope: the tail proof, data availability, folding, GPUs, seals
(the sequencer's signature stays in the withdrawal guest, for
canonicity), Poseidon2 (its user ecall executes but doesn't prove in
RISC Zero 3.0.x).
