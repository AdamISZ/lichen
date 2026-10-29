# Scaling the chain prover: research notes and options

2026-10-30. Working notes, not a design: what limits lichen's L2 today,
how existing systems deal with the same limit, and the options for
lichen, with what each would change. Prompted by the question of running
a hub on testnet without a lot of compute.

## The problem

The sequencer's chain prover proves each sealed height valid, from
genesis on (one RISC Zero proof per height, recursively; SHIELDED.md).
A withdrawal on the real statement needs that proof:
- the return anchored on Bitcoin, with the contract's work W on top;
- a chain receipt at the first height that carries that anchor.

Today even a cooperative withdrawal waits for both, since the hub folds
only what a dispute would pay. So the prover's throughput sets how soon
anyone can exit, and it is linear in the L2's transactions.

### Measured (Mutinynet deployment `0dde353e`, 2026-10-28/29; Apple M4 Pro, Docker)

Nineteen heights, each one segment:

| what the height held | heights | user cycles | proving time |
|---|---|---|---|
| no new notes (empty, or an anchor record) | 10 | 96k–159k | 36–47 s |
| a mint (one note) | 3 | 406k–416k | 73–91 s |
| a shielded spend (one or two notes) | 6 | 746k–763k | 128–130 s |

(Which height held what is inferred from the sequencer's note counts:
each contract's mint, Alice's claim of it, and her return with change.)

- **A fixed cost** of about 150k cycles and 46 s a height. Ten of the
  nineteen heights were only that: over a third of the prover's time.
- **A spend adds about 600k cycles,** 80 s on this Mac. Probably the
  note tree's and nullifier set's SHA-256 hashing: not profiled. The
  spend's own proof is an assumption in the guest, almost free there.
- **Steps, not a line.** RISC Zero pads a segment to a power of two
  (2^18, 2^19, 2^20 here). Past ~1M cycles a block splits into segments
  and joins.
- **On a laptop,** that is about 40–45 spends an hour. SHIELDED.md's
  "half a minute more per transaction" understates it.

### Related findings

- **Prover-killer spam.** If proving a transaction costs t₁ and nothing
  bounds the transactions per block, spam ahead of Alice's return can
  push the proof she needs past `T_A`. Only blocks before the height she
  needs count. An outside spammer can only race her; a sequencer
  colluding with the hub can order spam first, but such a sequencer can
  already censor her. The cost asymmetry: shielded spam costs the
  attacker a client proof (~18 s here) against ~80 s to the prover.
  Transparent spam costs a signature, so it is nearly free. **A per-block
  proving budget** (a gas limit, in transactions or cycles), sized so
  that the worst-case backlog is provable well within `T_A` on hardware a
  disputing user can get, is a requirement for any variant. It caps the
  L2's capacity at assumed proving power.
- **Confidential transactions (Liquid-style) would not help.** The chain
  guest would have to verify a range proof per output: a Bulletproof's
  multi-scalar multiplication over ~130 points (est.), likely millions of
  cycles in the zkVM, against a shielded spend's ~600k. Liquid is cheap
  because its federation verifies natively and nothing proves the
  history. CT's real win is on the device: no zkVM there, and hardware
  signers work.
- **Transparent notes** (the plan of 2026-10-20: validity and anchoring,
  no shielding) remove on-device proving, but not the prover's linear
  cost. The per-transaction constant then becomes a signature check plus
  the state update.

## Existing systems

**Zcash, Penumbra: no proof of the history.** Each transaction carries
its own proof. Every node verifies it in milliseconds, and consensus
orders the transactions. Proving is the users' job, so it scales with
them. lichen's sequencer already checks spend proofs this way. What
lichen adds is the chain proof, so that Bitcoin can settle a withdrawal
without trusting the sequencer. A Zcash proposal, Tachyon, aggregates
transaction proofs by recursion (from memory; check its current state).

**Aztec: client proofs and a rollup tree.** Private transactions are
proved on users' devices. The rollup proof is a tree: a base proof per
transaction (or small group), proved in parallel, merged pairwise, and
a root. The work is linear, but latency grows with log n and throughput
with provers. Its nullifier set is an indexed Merkle tree (each leaf
points to the next-higher value, so non-membership is a "low nullifier"
proof). By Aztec's figures that is about 327 hashes an insertion at depth
32, against about 508 for a sparse tree's check and insertion. That's
useful, not transformative.

**Mina: pipelined recursion** (from memory). The SNARK work for a block
is spread over the following blocks in a parallel scan of binary trees,
so proving keeps pace without any block waiting on its own proof.

**Alpen (Strata): batch proofs, checkpoints on Bitcoin.** An EVM chain
settling to Bitcoin.
- The sequencer chooses a range of blocks; the prover proves it.
- The batch proof checks:
  - that every deposit begun on Bitcoin is included (forced inclusion);
  - the range's state transitions;
  - the previous batch's proof, so the latest covers genesis on.
- A checkpoint transaction on Bitcoin carries the batch's data, its
  state commitment and the proof. Full nodes treat a batch as final at
  six confirmations.
- Its testnet accepts an empty proof when the prover hits a bug or falls
  behind: the same throughput problem.
- Blocks travel off chain, so it is a validium, by Alpen's own account.

**Kailua (RISC Zero), OP Succinct Lite (Succinct): optimistic by
default, ZK fault proofs on demand.** For OP Stack rollups.
- The proposer posts state commitments with no proof.
- A challenger disputes one with a single ZK proof that the transition
  was wrong: one round, no bisection.
- Proofs are made only in disputes. Kailua buys them from RISC Zero's
  proving market (Boundless), so the chain runs no prover.
- Kailua describes a path from optimistic to hybrid to validity proofs.
  Its hybrid mode finalises in about 3 hours, against the usual 7 days.
- Deployed or announced: BOB, Eclipse (Kailua's dispute mechanism),
  Celo (OP Succinct Lite).
- Like every optimistic design, it needs the data available to whoever
  might challenge.

**Shielded CSV (Nick, Eagen, Linus): client-side validation.** No
sequencer proves anything. Each coin carries a recursive proof of its
own history (proof-carrying data), and nullifiers go on Bitcoin, one per
transaction. Proving scales with each user's own activity. It is the
furthest from lichen's shape.

## Lessons

- **Prove ranges, not heights.** One proof over many blocks pays the
  fixed cost once (Alpen's checkpoints).
- **Take proving off the paths users wait on.** Cooperative operation
  should need no proof. A proof is needed for a dispute (or for a
  checkpoint), and a dispute here has days.
- **Bound the proving work per block** (above), in every variant.
- **Force inclusion through the L1** against censorship (Alpen's
  deposits; OP Stack's forced transactions).
- **Prove in parallel and buy proving** when it's needed: a tree of
  per-transaction proofs; GPUs; a market (Boundless).
- **Cut the per-transaction constant:**
  - profile first;
  - proof-friendly hashes for the trees (Poseidon2; RISC Zero 3.0's
    accelerator for it didn't prove, see the memory note on it);
  - an indexed tree for nullifiers.
  - A purpose-built circuit beats a general zkVM by a large constant,
    at the cost of flexibility.

## Options for lichen

### A. Validity, cheaper: batches, native cooperation, proofs on demand

Keeps the trust model and the code's shape.
- **Batches.** The chain guest proves a range of heights in one run.
  It runs periodically, and on demand when a dispute needs a height past
  the last checkpoint.
- **Native cooperation.** The hub validates the L2's blocks natively (a
  full node: milliseconds a block) and folds cooperative withdrawals
  without a chain receipt.
- **Disputes** wait for the receipt at their height, as now; `T_A`
  leaves days.
- **The budget.** A per-block proving budget in the ledger's validity
  rules.
- **Alongside:** the transparent-notes refactor; a profile of the chain
  guest; the indexed nullifier tree.

At testnet volume this makes proving a periodic batch job, on the laptop
or a GPU rented for minutes. The total work stays linear in
transactions. That is the floor of any validity design.

### B. Hybrid, the Kailua model: optimistic, with ZK fault proofs

Removes proving from normal operation. The mapping:
- **The commitments exist:** the sequencer's anchors.
- **The withdrawal statement loses the chain receipt:** "my return is in
  an anchored root", the anchoring and the work W as now.
- **The hub's defence becomes a fault proof:** that some transition
  between a root it accepts (genesis, or a checkpoint) and Alice's is
  invalid, proved as one block's re-execution in RISC Zero. That is
  bounded by the per-block budget, and buyable on demand.
- **No global challenge window.** Unlike a rollup, lichen settles each
  withdrawal bilaterally, so the fault proof is a move in Alice's own
  dispute, within the hub's window there.
- **The incentives line up.** The party an invalid history robs is the
  hub, which pays withdrawals, and it already validates every block
  natively.

What it needs rewired, and the open questions:
1. **The dispute on Bitcoin.**
   - **The hub must be able to win with "your root is invalid".** Under
     BABE the hub is the verifier, and its fault proof would need a
     gadget in which Alice is the verifier. The BABE companion's
     "separate game, roles reversed" (§10) is a sketch: a second BABE
     instance garbled by Alice, doubling the setup.
   - **Alternatively, under BitVMX,** a second search with the roles
     reversed.
   - Either way, a new branch of the graph, between `assert` and the
     terminals, or before `assert`.
2. **Data availability becomes the hub's safety, not only users'
   liveness.**
   - With validity proofs, a withheld block can't help a false claim:
     the receipt proves validity regardless. Optimistically, a sequencer
     colluding with Alice could anchor a root over data the hub never
     saw, and the hub could prove no fault in it. This is Plasma's old
     problem.
   - **Options:** the hub co-signs the roots it has validated (and a root
     counts only with its signature, which gives the hub a censorship
     lever that forced inclusion must answer); the sequencer posts the
     data where the hub can fetch it, with a deadline the hub enforces
     by refusing to co-sign; data on Bitcoin (expensive). This is the
     main question for B.
3. **Users against a thieving sequencer.** An invalid transaction that
   takes Alice's notes is answered by a fault proof from Alice:
   - she exits from a root before the theft, and the hub's counter (her
     note spent later) is refuted by proving that spend invalid;
   - the exit design (`exit.md`, EXIT_PLAN.md) is the same machinery,
     with the roles reversed.
4. **The progression.** Kailua's optimistic → hybrid → validity path maps
   to B now, with A's batch proofs as a later validity mode, or as
   checkpoints that shorten what a fault proof must cover.

### C. Client-side validation (Shielded CSV)

The sequencer proves nothing, so proving scales with each user's own
coins. It needs nullifiers on Bitcoin, and a different withdrawal
statement (Alice proves her coin's history). It is a different system,
noted for completeness.

## Recommendation

1. **A, now.** Batch proofs and native cooperative withdrawals; the
   per-block budget; the transparent refactor; a profile of the chain
   guest. It keeps the model, and should make a testnet hub cheap to
   run.
2. **B, as research.** Write it up before building anything: the dispute
   branch for a fault proof (which gadget, which party garbles), and
   above all data availability (2), which decides whether B is safe at
   all for an off-chain-data L2 like lichen's.

## Sources

- Kailua: [introduction](https://risczero.com/blog/introducing-kailua),
  [how it works (Boundless docs)](https://docs.boundless.network/developers/kailua/how),
  [Conduit and Boundless](https://www.conduit.xyz/blog/conduit-boundless-zk-fraud-proofs/)
- OP Succinct (Lite): [OP Succinct](https://blog.succinct.xyz/op-succinct/),
  [RISE](https://docs.risechain.com/docs/rise-evm/zk-fraud-proofs),
  [Celo Eclair](https://forum.celo.org/t/introducing-the-celo-eclair-testnet-the-first-public-network-to-use-op-succinct-lite-and-eigenda-v2/11600)
- Alpen: [system architecture](https://docs.alpenlabs.io/how-alpen-works/system-architecture),
  [transaction lifecycle](https://docs.alpenlabs.io/how-alpen-works/transaction-lifecycle)
- Aztec: [indexed Merkle tree](https://docs.aztec.network/aztec/concepts/storage/trees/indexed_merkle_tree)
- Shielded CSV: ePrint 2025/068 (the main paper cites it).
- Mina's scan state and Zcash's Tachyon are from memory, not checked.
