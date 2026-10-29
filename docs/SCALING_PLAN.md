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
own history (proof-carrying data), and nullifiers go on Bitcoin, about
64 bytes per transaction. But every receiver checks coin proofs against
a nullifier accumulator built from all the nullifiers on Bitcoin. The
details, and what lichen would make of it, are in option C.

**Shielded Bitcoin ([alloc] init, September 2026): every transfer on
Bitcoin.** Zcash-style notes. Each transfer is an envelope published on
Bitcoin: the nullifiers, the encrypted outputs and a 192-byte Groth16
proof. There's no consensus or sequencer of its own. Bitcoin orders the
envelopes, and any indexer rebuilds the same shielded state by replaying
them. Details in option C.

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

### C. A privacy layer on Bitcoin under lichen: Shielded CSV, Shielded Bitcoin

Recorded for completeness: neither looks like a pairing that makes
sense for lichen. Both papers leave the bridge out:
- Shielded Bitcoin calls peg-in and peg-out "outside the scope of this
  paper", for a separate treatment based on PIPEs v2.
- Shielded CSV assumes "an adequate bridging mechanism", and points to
  BitVM for one.

Lichen is a bridge that doesn't care which L2 sits on it, so the
question is what each L2 would cost lichen to prove, and what it would
give its users.

| | lichen's L2 | Shielded Bitcoin | Shielded CSV |
|---|---|---|---|
| where transfers live | off chain, with the sequencer | on Bitcoin, in full | with their owners; nullifiers on Bitcoin |
| ordering | the sequencer, anchored on Bitcoin | Bitcoin | Bitcoin, through the nullifiers |
| validity | the chain proof | indexers replay the envelopes, each Groth16 checked | each coin's recursive proof, checked against the nullifier accumulator |
| Bitcoin space per transfer | none (an anchor per batch, 269 vB) | 625 vB (`OP_RETURN`) or 438 vB (witness), for 2-in-2-out | about 64 bytes, aggregated by publishers |
| finality of a payment | the sequencer's seal, then the anchor's depth | a Bitcoin block | a Bitcoin block, and confirmations against reorgs |
| an offline receiver | yes (the sequencer stores notes) | yes (ciphertexts on chain, scanned) | not specified: the paper's "static donation address" case is future work |
| recovery from a seed | yes | yes (replay) | no: lost wallet state loses the balance |
| shared-state programs | possible, at proving cost | transfers only | no: rules on accounts and coins only |
| the bridge | lichen | out of scope (PIPEs v2) | assumed (BitVM suggested) |

**Shielded CSV in detail (ePrint 2025/068):**
- **Accounts.** A transaction nullifies its sender's account state, not
  each coin. The nullifier is a public key and a Schnorr signature that
  commits to the transaction (sign-to-contract).
- **Publishers.** An open role. They half-aggregate nullifiers and post
  them, which is how a transfer costs about 64 bytes.
- **The accumulator.** Every user scans every nullifier on Bitcoin into
  a nullifier accumulator, one signature check each. A coin proof is
  valid only against it.
- **Two-step payments.** The coin proof can be made only once the
  nullifier is on chain, as part of the fee design (§2). So a payment is
  final after a block, and reorgs need care (the "conditional NAV").
- **Delivery and wallet state.** The sender hands the coin and its proof
  to the receiver over an encrypted channel (§6.1). An offline receiver
  is future work. There's no recovery from a seed (§6.2). Coins created
  in one transaction can be linked by their recipients (§6.3).
- **Spending policies.** t-of-n accounts (MuSig2, FROST), time locks
  (an extension), atomic swaps with Bitcoin through PTLCs, multiple
  assets (§5, A.1). Each is a rule on one account; there's no shared
  state.

**What lichen would have to prove: a global proof in every case.**
- **Shielded Bitcoin:** "the return's envelope is in block X, and
  replaying everything up to X accepts it". That's linear, with a
  Groth16 check per envelope inside the zkVM. The paper's §22.2 lists
  this very proof as an open problem: a succinct proof that the replayed
  root at height h is correct, for light clients.
- **Shielded CSV:** the coin proof, plus a proof that the accumulator it
  is checked against is the right one. Both are built from all the
  nullifiers on Bitcoin, so this too is linear, at one Schnorr check per
  transaction, and needs no sequencer: anyone can maintain it from
  public data. (An earlier draft of this note said a CSV withdrawal
  proof would be constant. It isn't, because of the accumulator.)
- **The pattern.** Every design that lets Bitcoin judge validity without
  trusting a party pays a global proof somewhere. They differ in the
  cost per transaction (a spend, a Groth16 check, a signature check) and
  in who can produce it (the sequencer, or anyone).

**Against Lightning through the hub,** for payments:
- **Lichen as Shielded CSV's bridge keeps the hub at the centre:**
  receiving is limited to each contract's cap (beyond it, credit), as
  with inbound liquidity.
- **CSV then adds costs:** a share of a nullifier on Bitcoin per payment,
  at least a block's wait, a delivery problem for receivers, and lost
  funds with lost wallet state.
- **What it gives back:**
  - privacy against the hub, which on Lightning sees the amount and
    timing of every payment between its own users;
  - atomic swaps with Bitcoin.

  Lightning wins on cost and latency.
- **CSV's natural setting is bearer coins with no hub,** which needs a
  pooled bridge. Lichen's per-user contracts are the opposite kind.
  Since lichen already centres a hub, a sequencer adds little trust, and
  lichen's own L2 is the better fit. It's the only option here with no
  chain cost per payment, offline receivers and shared-state programs
  together.

**Privacy at the boundary, in every case.** Shielded Bitcoin's privacy
analysis lists what stays public: timing, arity, anchor age, envelope
grouping, fee-wallet linkage, and entry and exit. Under lichen the exits
are public by construction:
- a contract's funding shows its deposit and cap;
- a fold pays `b` openly;
- a disputed withdrawal puts `b` on Bitcoin in bit outputs.

Payments inside the L2 are private; the bridge is where privacy systems
on Bitcoin still leak.

### D. A consensus L2: an existing chain, or a committee of our own

**Where the linear cost comes from.** It isn't lichen's. Lichen removes
trust in the hub (the bridge), and takes on the L2's own assumptions:
"the only assumptions are those of the layer 2 itself, kept apart from
the hub" (the main paper's abstract). Validity proofs are one way to make
the L2's assumptions nearly vanish. The cost is linear because the L2's
only source of validity is a proof of its whole history. Give the L2 a
consensus whose finality can be proved succinctly, and the withdrawal
statement shrinks to "a finalized state includes my return". That's a
constant amount of work per withdrawal, made only in a dispute, whatever
the L2's traffic. The trust moves to the consensus, as the L2's stated
assumption.

| the L2's validity rests on | users trust | proving cost |
|---|---|---|
| validity proofs (today, A) | no one | linear in transactions |
| optimistic, fault proofs (B) | one honest watcher, with the data | proofs only in disputes; data availability |
| a consensus (D) | the consensus, as the L2's assumption | a light-client proof per disputed withdrawal |

#### D1. An existing chain: Ethereum

The tokens are an ERC-20 the hub mints, a return is a transfer to the
hub's address with memo `c`, and Ethereum's validators provide validity,
ordering and finality. There's no sequencer, no prover, and no anchoring
on Bitcoin: Ethereum's own finality makes it unnecessary. The withdrawal
statement becomes "a finalized checkpoint, reached from one the contract
fixed at opening, includes a receipt of this transfer". It's still a
RISC Zero proof wrapped in Groth16, so the Bitcoin side, BABE and its
setup, is unchanged. Only the guest and the journal's `D` change: `D`
would hold the token contract, the hub's address, the starting
checkpoint, the chain's identity and the fork schedule.

We set Ethereum aside earlier for want of a usable light-client proof,
and over hard forks. Both now look answerable:

| tool | what it proves | zkVM | status |
|---|---|---|---|
| The Signal (Boundless) | full Casper FFG finality: a valid transition between finalized checkpoints, from the attestations | RISC Zero | proofs published as a public good, "to be consumed anywhere that can verify a RISC Zero proof"; launched with Boundless mainnet, July 2025 |
| Helios, RISC Zero port | the sync committee: its updates, a finality update, and storage slots against the finalized execution state root | RISC Zero | audited by zkSecurity, April 2025 |
| SP1 Helios (Succinct) | the same light client, in SP1 | SP1 | audited (Zellic; OpenZeppelin, May 2025) |
| Steel (RISC Zero) | EVM state and history queries in a guest, linked to beacon block roots (EIP-4788) | RISC Zero | audited (Veridise, 2025); the audit flagged a gap in its history traversal |

**The two routes:**
- **Full finality (The Signal):**
  - **Assumption:** the strongest available, two-thirds of all stake.
  - **Cost:** about 40 billion cycles an epoch, about $30 (its authors'
    figures), so not something we would prove ourselves.
  - **How lichen would use it:** Alice's guest would take a Signal proof
    as an assumption, as it takes the chain receipt today. Lichen then
    depends on Boundless publishing them, or on buying them on its market.
  - **To check:** whether a published proof covers one epoch or recurses
    from a fixed start. A week is about 1,575 epochs.
  - **Its stated limits:** slashings are not modelled within its
    lookahead (a safety violation would need about 20% of stake
    slashed), and liveness halts on long non-finality.
- **The sync committee (Helios):**
  - **Assumption:** weaker: two-thirds of a rotating committee of 512,
    with no slashing for signing a false update (EIP-7657 proposes it).
  - **Cost:** far cheaper. One update a sync-committee period (about 27
    hours) and a BLS aggregate per update, so about seven over a week's
    contract. That's linear in time, not in traffic, and small.
  - **One audit finding to keep:** the chain's identity (the genesis root,
    the forks) wasn't in the journal. Lichen's `D` would commit it.

**Hard forks.** The real constraint, and manageable for short contracts:
- **Signatures:** the fork version enters each signature's domain,
  computed from a fork schedule given as input. Committed in `D`, it's
  fixed for the contract.
- **Code:** a fork can change what the client's code must do. Electra
  moved the generalized indices of the beacon state's fields, which a
  light client's Merkle branches depend on (Snowbridge's Electra
  upgrade, for one, had to make them fork-dependent).
- **The consequence:** a guest built before a fork can't prove past it
  unless it already contains that fork's rules. The contract pins the
  guest's image id at opening, so a contract must not span a fork its
  guest doesn't know. Forks are scheduled months ahead, and a week's
  contract opened with a current guest is safe. A long contract must end
  before the next fork, or be opened after a guest with that fork's rules
  ships.
- **Who bears the residual risk:** an emergency fork at short notice
  could leave Alice unable to prove before `T_A`. The cooperative path
  still works, since the hub just reads the chain.

**What else changes:**
- **The opening's swap.** The hub now mints to a key locked by an adaptor
  point `T`, released when the funding reveals `t`. On Ethereum, `t` would
  have to be shown in a contract: a hashlock (the funding reveals a
  preimage), or a check of `t·G = T` (`ecrecover` can be made to do it).
- **Users need ETH for gas.**
- **Privacy is Ethereum's: none,** unless a privacy pool sits on top.
- **Finality takes about 13 minutes,** where lichen's anchors take ten
  Bitcoin blocks.

**Unmeasured:** a RISC Zero guest that checks a Helios update chain and a
receipt's inclusion (receipts trie, Keccak) for an ERC-20 transfer: its
cycles, and whether RISC Zero's precompiles cover BLS12-381 and Keccak as
The Signal's note suggests for BLS.

#### D1′. A shielded validity rollup as the L2

D1 with privacy. Instead of building our own L2, lichen becomes the
trust-minimised bridge for an existing rollup whose payments are already
shielded and whose history is already proved. The rollup's own provers
prove the history, and Ethereum verifies them, so nobody in lichen runs
a prover. The exit guest, run only for a disputed withdrawal, proves:
1. that Ethereum finalised a checkpoint (The Signal, or Helios: D1);
2. that the rollup's contract on Ethereum holds a state root at that
   checkpoint (a storage proof, with Steel);
3. that Alice's return is a note in that state, opening to `b`, `c` and
   the hub as owner. That's the rollup's own note tree and hash, proved
   once.

Then the same wrap and BABE. The hub's tokens are a private token on
the rollup.

**What we inherit:**
- the rollup's maturity and upgrade governance;
- Ethereum's consensus and the rollup's verifier, so its proof system's
  setup too;
- D1's hard-fork constraint;
- its fees and wallets for users.

**A note on why Ethereum stays in the loop.** A validity proof alone
shows that a history is valid, not that it is *the* history: a sequencer
could prove two valid forks. The rollup's contract on Ethereum is what
makes one canonical, as lichen's anchors on Bitcoin do now.

The candidates, as of 2026-10-30 (secondary sources, unless noted):
- **Aztec.**
  - **Design:** an Ethereum L2 whose private state is encrypted notes
    (UTXO-style). Private functions run and are proved on the user's
    device, and a rollup tree proves the history (base, merge and root
    circuits; Noir, Barretenberg).
  - **Status:** mainnet beta (Ignition) from November 2025; L2BEAT lists
    an Alpha (v4) launch in March 2026.
  - **Setup:** its proofs need Aztec's own ceremony.
  - **For the exit guest:** the note tree is Poseidon2 over BN254,
    modest once per withdrawal.
- **Starknet with STRK20; strkBTC.**
  - **STRK20** (Starknet v0.14.2, "the privacy engine") adds a shielded
    mode to tokens on Starknet's validity rollup (STARKs, settling on
    Ethereum).
  - **strkBTC** (live 2026-05-12) is a BTC-backed token with that mode.
    Its bridge is a federation, reported as five members including
    Xverse, with "a roadmap toward a fully trustless architecture".
  - **So it's shielded BTC on a validity-proved L2, held back by a
    federated bridge:** the gap lichen's bridge is designed for.
  - Developed under "Starknet in detail", below.
- **Miden.** Private notes and accounts, proved on the client, a STARK
  rollup on Ethereum. On testnets as far as could be confirmed; mainnet
  status unclear.
- **Zcash, natively.**
  - **Tachyon** brings recursive proofs (proof-carrying data) to Zcash.
    Its Udon crate was released 2026-09-28 and is merging into Zcash's
    node software (Zakura Common). It's aimed at validators; unconfirmed
    whether it will give an outside verifier a succinct proof of the
    shielded state.
  - **StarkWare's Ztarknet** (a Zcash L2 on Starknet's stack, testnet
    from November 2025) and **Zoro** (a STARK-proved Zcash light client)
    point the same way.
- **Not candidates:**
  - Intmax2 (validity, but not private);
  - Railgun (contracts on Ethereum's L1, not an L2);
  - Penumbra, Namada, Aleo (L1s of their own).

**Starknet in detail** (primary sources: SNIP-38, Starknet's posts and
docs, L2BEAT's privacy page; 2026-10-30):
- **strkBTC's bridge** (SNIP-38, a draft dated 2026-04-21):
  - **Flows:** a deposit to the federation's multisig, then a mint that
    members co-sign. A peg-out is a burn on Starknet that members check
    themselves (no light client or state proof), then co-sign the BTC's
    release.
  - **Members:** at least five, proposed as Xverse, Twinstake, NEAR,
    UTXO, Luganodes and OneKey. KYC/KYB required. The Starknet Security
    Council can remove members. The threshold and the script are left
    to a charter.
  - **Roadmap:** Phase 2 is "BitVM-based verification" for standard
    flows; Phase 3 is OP_CAT or similar, with the federation as fallback.
    No trust models or dates are given. A partnership with Alpen for a
    trust-minimised bridge by the end of 2026 is reported (unverified).
  - **Related:** StarkWare has verified a STARK on Bitcoin's signet with
    OP_CAT, at about 790 kvB a verification.
- **STRK20's privacy pool:**
  - **Design:** notes and nullifiers. Client-side Stwo proofs (STARKs,
    no setup), verified by the protocol since v0.14.2 (SNIP-36).
  - **Compliance:** an escrowed viewing key and screened deposits.
  - **L2BEAT:**
    - weak link privacy;
    - "one auditor key can decrypt every user's history";
    - a 7-of-12 multisig can replace the pool at once;
    - only StarkWare's sequencer checks the proofs, and exit needs it
      (it fails the walkaway test);
    - deposits and withdrawals are public in address, token and amount.
- **Lichen there:** the hub issues lichen-BTC on Starknet, shieldable by
  STRK20 like any token, and backed per holder up to the cap by contracts
  on Bitcoin.
  - **The token contract is ours,** so it's designed for cheap proofs:
    `return(b, c)` burns and records the return in one slot; the opening's
    swap is a mint into escrow released by `t` (Cairo can check
    `t·G = T`: Starknet has secp256k1 syscalls); immutable.
  - **The exit guest:** Ethereum's finality (Signal/Helios), the core
    contract's state root (Steel), then the slot under that root in
    Starknet's tries. Those hash with Pedersen, so curve arithmetic in the
    zkVM: perhaps 10^8 cycles, once (unmeasured).
- **Against strkBTC:**
  - **Custody:** the federation's pooled multisig, against each user's
    2-of-2 with the hub.
  - **A refused peg-out:** trust a federation threshold, against forcing
    it on Bitcoin with BABE, today.
  - **Amounts and liquidity:** any amount and pooled, against a per-user
    cap with the hub's locked liquidity, plus an expiry.

  The two tokens can coexist on Starknet's exchanges.
- **Thin points:**
  - **Starknet's own governance** (L2BEAT, Stage 1, fails the walkaway
    test):
    - **The Security Council (9 of 12)** can upgrade anything at once,
      with no exit window, the verifier included.
    - **Regular upgrades** go through a 2-of-6 StarkWare multisig, behind
      8 days; the verifier is under a 2-of-4 multisig, behind 8 days.
    - **Liveness and censorship.** A whitelisted proposer posts state
      roots. Users can queue L1 transactions but not force them; a
      3-of-12 Council minority can post a root including a stuck one,
      with no defined process or deadline.
    - **For lichen:** an emergency upgrade could post a root recording a
      `return` that never happened, and the exit guest, trusting the core
      contract, would accept it. So the hub's money rests on the Council
      not colluding with a withdrawer. Requiring old roots doesn't help,
      since emergency upgrades have no delay. Lichen there removes the
      federation over the bitcoin, but keeps the Council over the state
      the bridge relies on.
  - **Sequencer censorship.** StarkWare's sequencer censoring a `return`
    is lichen's sequencer hole, in other hands. Whether L1-to-L2 messages
    can force one through is open.
  - **Compliance.** STRK20's escrowed key and screening; lichen-BTC could
    stay transparent, with shielding left to the user.
  - **Instant upgrades.** The 7-of-12 multisig over the pool.
  - **Ethereum's hard forks** (D1).
- **Spikes:**
  1. a Cairo token contract (escrowed mint, `return(b, c)`);
  2. the exit guest's Starknet state proof, its Pedersen cost counted;
  3. L1-to-L2 messages as forced inclusion for a `return`.

**Our own Orchard L2,** for comparison: Zcash's primitives for spends
(Halo2), checked natively by the hub. The history comes either from a
recursive proof in the Halo2 world (new engineering) or from a
federation (D2), and RISC Zero runs only at the exit, verifying the
foreign proof once. The first spike: verify an Orchard action's Halo2
proof and a Sinsemilla path in a RISC Zero guest, and count the cycles.
D1′ makes most of this unnecessary, if a mature shielded rollup is
acceptable as the L2.

#### D2. A committee of our own

The same shape for lichen's own L2:
- **The statement:** a committee signs each root (a threshold signature),
  and the withdrawal statement is the committee's signature and a Merkle
  path.
- **The hub as a required signer** never pays against a root it didn't
  validate, which protects it fully with no proofs.
- **Users trust the committee for their own notes.** Independent signers,
  all required, let any one honest member block a theft, at the price of
  any one halting the chain (so: forced inclusion through Bitcoin, and
  timeouts). Fault proofs for users are the other remedy (the exit
  design).
- **Anchoring still earns its place** here against a committee that
  equivocates, or rewrites history long afterwards with old keys. It
  protects against forks and key compromise over time, not against
  invalid state. (Babylon timestamps proof-of-stake chains on Bitcoin for
  this; from memory.)
- **Precedents:** Liquid's functionaries, Fedimint's federations.

## Parked: lichen as a launchpad (2026-10-30)

An idea to come back to. A small, highly secure lichen L2 ("lichen-core")
whose rules verify proofs, as a settlement layer that other systems
plug into by proof.

- **Recursion makes BABE's fixed statement general.** Each contract's
  statement stays "my return is in lichen-core's valid history", but that
  history can include verified proofs of other systems.
- **A permissionless rule.** Anyone registers a RISC Zero program, and a
  settlement for it is accepted given a receipt, checked as an
  assumption (nearly free in the guest). That's `OP_STARK_VERIFY` from a
  user's view. Foreign proof systems (Stwo, say) come in through a
  registered program that verifies them.
- **Throughput moves to the edges.** Lichen-core's proving is linear in
  settlements and bridge moves, not payments; payments live on L3s, each
  settling a batch with one receipt. That's Ethereum's rollup-centric
  argument, and lichen-core can run under a tight proving budget.
- **The trust under the bitcoin is lichen-core only:** Bitcoin, BABE,
  RISC Zero, the sequencer's liveness. L3s carry their own validity and
  data. Foreign L2s connect through escrows on lichen-core, so a
  compromised one (a council posting a fake root) loses at most its
  escrow. Against D1′ on Starknet, where Starknet's Council sits under
  every bitcoin.
- **Bridges both ways by proofs alone.** Lichen-core verifies a foreign
  chain's finality and state (D1's machinery as registered programs). The
  foreign chain verifies lichen-core's chain proof, a RISC Zero Groth16,
  which Ethereum already verifies routinely. Counterparties are needed
  only to swap into a chain's native assets, which is market liquidity,
  not trust.
- **The hard problems:**
  1. **Data availability.** Lichen-core's data is the sequencer's, and
     L3s posting to it inherit that.
  2. **Upgrades against pinned statements.** Contracts pin the chain
     guest's image id for life, so new base rules would break open
     contracts. The registration rule avoids most upgrades; the base
     still needs versioning, such as accepting a chain of predecessor
     guests.
  3. **Censorship.** Forced inclusion through Bitcoin and the exit
     design become essential.
  4. **The Bitcoin edge.** Trustless BTC still needs a contract with
     enough cap; L3 balances beyond it are credit.
  5. **A single issuer.** One hub's token; several hubs mean several
     assets.
  6. **Funding** the prover and the hub's liquidity, from settlement
     fees.
- **Against per-L2 BitVM bridges** (Alpen, Citrea, Starknet's Phase 2):
  one Bitcoin-facing bridge, which every L2 can use by settling on
  lichen-core, at the price of lichen's caps and expiry.

## Recommendation

1. **A, now.** Batch proofs and native cooperative withdrawals; the
   per-block budget; the transparent refactor; a profile of the chain
   guest. It keeps the model, and should make a testnet hub cheap to
   run.
2. **D1, a spike.** It removes the linear cost outright, and the tooling
   exists. The steps:
   - a RISC Zero guest that checks a Helios update chain from a fixed
     checkpoint and an ERC-20 transfer's receipt under it;
   - its cycles, and whether The Signal's published proofs can stand in
     as an assumption;
   - a check of how a contract would pin the fork schedule.

   The Bitcoin side stays as built.
3. **B, as research.** Write it up before building anything: the dispute
   branch for a fault proof (which gadget, which party garbles), and
   above all data availability (2), which decides whether B is safe at
   all for an off-chain-data L2 like lichen's.
4. **D2** if a testnet hub of our own wants the cheapest workable L2: a
   committee with the hub as a required signer, stated as the L2's trust
   model.

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
- Shielded CSV: [ePrint 2025/068](https://eprint.iacr.org/2025/068)
  (Nick, Eagen, Linus; read in full: §2, §5, §6, A.1)
- Shielded Bitcoin: [[alloc] init, September 2026](https://www.allocinit.xyz/uploads/shielded-bitcoin.pdf)
  (Shikhelman, Komarov, Moskvin; read: §1–4, §11, §17, §22, A.3–A.6)
- The Signal: [ethresear.ch post](https://ethresear.ch/t/the-signal-ethereum-casper-ffg-finality-proofs/22841),
  [site](https://signal.boundless.network/)
- Helios in RISC Zero: [zkSecurity's audit](https://reports.zksecurity.xyz/reports/risc0-helios/);
  SP1 Helios: [Zellic](https://reports.zellic.io/publications/sp1-helios),
  [OpenZeppelin](https://www.openzeppelin.com/news/sp1-helios-audit)
- Steel: [introduction](https://risczero.com/blog/introducing-steel),
  [Veridise audit](https://veridise.com/wp-content/uploads/2025/11/VAR-risczero-250414-steel-V2.pdf)
- Electra's light-client changes: [Snowbridge's upgrade](https://gitlab.parity.io/parity/mirrors/polkadot-sdk/-/commit/dd7562ab5618d9c2a657ead42a0f92b3496ff80f);
  sync committee slashing: [EIP-7657](https://eips.ethereum.org/EIPS/eip-7657)
- Shielded rollups: [L2BEAT: Aztec](https://l2beat.com/scaling/projects/aztecnetwork),
  [Aztec docs](https://docs.aztec.network/vision),
  [strkBTC is live (Starknet)](https://www.starknet.io/strkbtc-is-live-private-bitcoin-arrives-on-starknet/),
  [The Block on strkBTC](https://www.theblock.co/post/400903/starknet-launches-strkbtc-to-bring-zk-powered-shielded-bitcoin-to-its-layer-2-network),
  [Xverse on strkBTC](https://www.xverse.app/blog/strkbtc-privacy-bitcoin-starknet),
  [Starknet v0.14.2](https://www.starknet.io/blog/starknet-v0-14-2-the-privacy-engine-arrives/),
  [Miden docs](https://docs.polygon.technology/miden/miden-base/),
  [Tachyon and Udon](https://cryptobriefing.com/zcash-tachyon-udon-zakura-common-integration/),
  [SNIP-38 (strkBTC)](https://community.starknet.io/t/snip-38-strkbtc-bitcoin-on-starknet/116174),
  [STRK20 notes and nullifiers](https://docs.starknet.io/build/starknet-privacy/notes-and-nullifiers),
  [L2BEAT privacy: STRK20](https://l2beat.com/privacy/projects/strk20),
  [L2BEAT: Starknet](https://l2beat.com/scaling/projects/starknet),
  [STARK verified on Bitcoin signet](https://blockeden.xyz/blog/2026/03/15/starkware-zk-stark-proof-bitcoin-signet-zero-knowledge-native/)
- Mina's scan state and Babylon are from memory, not checked.
