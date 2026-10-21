# Code review: findings and fixes

2026-10-21, branch `review` (off `anchor`). Five read-only reviews:
statements and guests (S), ledger, sequencer, l2 and chain (L), hub
and proto (H), wallet, tower and demo (W), tests and CI (T). Each finding
is checked by reading the code before it's fixed. Status: **fixed**
(commit), **open** (deferred, with why), **design** (a decision for the
user).

Fixes that change a guest change its image id, so they make a new
deployment. Those wait for the next guest build (x86) and are collected
under S.

## S: statements and guests (all need a new guest)

| id | where | finding | status |
|---|---|---|---|
| S1 | validity `check_anchor`, `btc::merkle_root` | The anchor's Merkle path length isn't bound to the block's tree depth: a fake anchor beneath a real 64-byte transaction (CVE-2017-12842 class). It forges an anchor of another history in a real block with real work on top. The cost is a large grind but below `W`'s work. Fix: also prove the coinbase at index 0 with a path of the same length (Bitcoin's own depth), and refuse a 64-byte coinbase. | open (guest) |
| S2 | ledger `apply_tx` vs chain guest | No limit on a shielded transaction's ciphertext size or on a block's size: one user can make a block the chain guest can't prove. Native fix: the sequencer refuses large ciphertexts and bounds a block (no guest change). | fixed natively, see L8 |
| S3 | validity `Mint::digest` | A mint's signature doesn't bind the deployment, so mints replay across deployments that share a hub key. Fix: the deployment id in the digest. | open (guest) |
| S4 | validity `state_root` | The tree's size isn't in the state root, so the chain prover may choose a padded frontier (liveness only). Fix: the size in the root. | open (guest) |
| S5 | shielded journal encoding | List lengths are written as `u8` (not exploitable today: real receipts carry at most 4). Fix: refuse more than `MAX_*`. | open (guest) |

## L: ledger, sequencer, l2, chain

| id | where | finding | status |
|---|---|---|---|
| L1 | sequencer `/tx` | Any client may post `Tx::Anchor`. A fake record (any header whose Merkle root is the fake txid) takes the seal chain over and stops anchoring for good. Fix: only the anchorer applies anchor records. | |
| L2 | ledger `verify_receipt` | A Groth16 spend receipt is accepted, which the chain prover can't take as an assumption, so the prover stops at that height for good. Fix: succinct or composite only. | |
| L3 | ledger `append_leaves` | Capacity is checked mid-append: a transaction that fills the tree leaves some of its leaves behind and isn't pending. The next root is then unprovable. Fix: check capacity up front. (The tree's 65,536 notes are a design limit: see D2.) | |
| L4 | anchorer `step`, chain `get_tx` | An RPC error reads as "gone": the flight is cleared and a second anchor spends the same seal. Also a crash between broadcast and saving the flight. Fix: tell errors from absence; find the seal's spender on chain before sending again. | |
| L5 | anchorer `step` | Recording isn't idempotent: a record already applied fails `Seal` forever. Fix: an anchor already recorded clears the flight. | |
| L6 | sequencer save | The ledger is written in place, after every 200 response (GETs too), and errors are ignored, so a crash can truncate it. Fix: atomic write (tmp, fsync, rename), only after changes, and a failed save refuses the request. | |
| L7 | sequencer `record` | Block files are written before the ledger is saved: after a crash, a stale `<h>.chain` or `<h>.k.receipt` can stay. Fix: clear a height's stale files when recording it again. | |
| L8 | sequencer HTTP | One thread, an unbounded body. Fix: cap the body; cap ciphertexts and outputs (S2). | |
| L9 | anchorer, `anchored_input` | A reorg after recording (1 confirmation by default) strands returns under that anchor. | open: depth by default on testnet4; note |
| L10 | anchorer `send` | Coins stay locked when `new_spk` fails; a flat 270 vB fee whatever the inputs; no fee bump. | |
| L11 | chain `confirmations`, `coins_of` | `u32` subtraction can wrap when servers lag. | |
| L12 | sequencer events | Not persisted: numbering restarts. | open (demo only) |
| L13 | ledger `Tree::levels` | The tree is rebuilt per path, under the lock. | open (performance) |

## H: hub and proto

| id | where | finding | status |
|---|---|---|---|
| H1 | hub fold, default, timeouts | A contract is closed as soon as the hub broadcasts, not when its transaction confirms. A conflicting escalation mined instead goes unwatched, and Alice's timeouts pay her claim. Fix: closed on confirmation; keep watching until then. | |
| H2 | hub watcher | One thread for every contract, and it blocks: a disprove sleeps `δ` (40 blocks on Mutinynet) while another contract's choice window (20) runs out. | design (D3) |
| H3 | hub `disputes_tick` | One contract's error aborts the tick (later contracts starve) and drops its dispute state. Fix: per-contract errors, state kept. | |
| H4 | hub `/accept` | The funding is broadcast before the contract is saved. Fix: save first. | |
| H5 | hub defaults | Each failing attempt makes a fee coin (a wallet transaction) every tick, and its error stops other contracts' defaults. Fix: check the contract output is unspent first; per-contract errors. | |
| H6 | hub `/open` | Input that panics the one HTTP thread: a reserve near `u64::MAX` (Amount overflow); an input-word key with other parameters (`assert_eq!` in presign). Fix: validate, and catch a handler's panic. | |
| H7 | hub `/open` | Repeated for one cid: it locks more hub coins each time, mints again, and overwrites another user's pending offer. Fix: one pending offer per cid, the old one's coins unlocked. | |
| H8 | hub funding | Never fee-bumped: a funding pinned until the refund matures. | open (the known TODO in PLAN.md) |
| H9 | proto `terms` | Alice's reserve has no minimum, so a false claim costs her nothing. | design (D1) |
| H10 | hub floors | Measured once with the first user's keys (follows from H6's unchecked key parameters). | with H6 |
| H11 | hub dispute | "Already settled by timeout" doesn't close the contract. | |
| H12 | hub files | Written in place; one unreadable file stops the hub from starting. Fix: atomic writes. | |
| H13 | proto `Checkpoint::tip` | On testnet4 the tip can be a minimum-difficulty block, so `W` is trivial. | open: note |

## W: wallet, tower, demo

| id | where | finding | status |
|---|---|---|---|
| W1 | wallet `withdraw` | The hub's fold txid is taken on trust, and the contract closed on it: a hub answering any txid stops the dispute. Fix: the txid must be the fold's, seen on chain. | |
| W2 | wallet `open_with` | `T_close` is checked only to be in the future; the deposit's refund timeout is taken from the hub unchecked. Fix: both against the network's. | |
| W3 | wallet `refund`, accept | The deposit record (with `offered`) is dropped when the refund is broadcast, or when the accept returns, before anything confirms. | |
| W4 | wallet `resume_open` | Overwrites an earlier offered record whose presignature is still valid. | |
| W5 | wallet save | Written in place, with default permissions; the only copy of the key. Fix: atomic, 0600. Tower packages too. | |
| W6 | wallet | No lock between `lichen` processes: lost updates. | |
| W7 | wallet `withdraw` | The return is recorded only after the sequencer answers: a lost answer, then a rerun, returns twice. | |
| W8 | wallet `sweep_dispute` | A stored payout isn't checked to be this contract's terminal (and can panic). | |
| W9 | tower `export_dispute` | Ignores the claim the wallet already escalated (Groth16 proofs are randomized). | |
| W10 | wallet shielded prover | The spend's private input (`nk`) is left in a temp directory on failure, readable by others. | |
| W11 | demo `withdraw` | Any withdraw error starts a dispute, which pays a claim with no return under the demo's true-for-all statement. `busy` sticks after a panic. | |
| W12 | wallet `wait_link` | Waits forever on a hub link left unconfirmed in the mempool; a mempool-only conflict is recorded as lost. | |
| W13 | wallet `dispute` CLI | A kept claim overrides the amount silently; b isn't checked against the return on the mock statement. | |
| W14 | wallet finality | Cached anchors' heights aren't rechecked after a reorg; matched by position. | open: low |
| W15 | demo | Orphaned provers (SIGINT; a prover's PID 1 ignores it), the port bound late, `--dir` wiped unchecked. | |

## T: tests and CI

- CI: the electrs tests (four) need electrs. The workflow builds it once
  and caches it.
- Tests to add, ranked: the block statement's refusals (each `Reject`
  never triggered: Encoding, NotInTree, Unbalanced, Empty, TreeFull,
  Shape) and `check_anchor`'s; `merkle_path` against Bitcoin's for 1–9
  transactions; the anchorer's crash windows (L4, L5); the wallet
  refusing bad offers; the hub refusing bad requests; the hub halting on
  two histories.
- Flaky on slow runners: wall-clock block cadence against block-count
  windows (150 ms blocks, hub windows of 10 blocks).

## D: design questions

- **D1 (H9).** A minimum for Alice's reserve, such as the floors of the
  deepest dispute as the hub's, so a false claim costs her what it costs
  the hub.
- **D2 (L3).** The commitment tree holds 65,536 notes (depth 16, the
  statements' constant), with no fees: a spammer can fill it, and then
  the L2 stops. A deeper tree is a new deployment; fees or limits are
  policy.
- **D3 (H2).** The hub's watcher: one thread, blocking. A hub with many
  contracts needs per-contract scheduling (no sleeps), or a thread per
  dispute.
