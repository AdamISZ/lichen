# A BABE dispute for lichen: the transactions and the mass-exit figures

Working notes, 2026-10-24. Nothing here is built. These are estimates for
the paper. Each figure is marked:
- **(paper)**: BABE's own measurements;
- **(lichen)**: lichen's measurements (the paper's Costs section);
- **(est)**: worked out here.

Background:
- ln-gap `docs/planning/BABE_FIXED_STATEMENT.md`: the fixed-statement
  problem, strategies A–C;
- ln-gap `docs/planning/research/babe-amount-authenticated.md`: the hub's
  countersignature, which this note assumes;
- ln-gap `docs/planning/MASS_EXIT.md`: the congestion rule;
- `papers/lichen-v0.1.1.tex`: Tables `exits` and `flood`, and Costs.

Source for BABE: ePrint 2026/065, the revised version (copy of 19 Oct),
§6, App. A.1 and §9.

**Note: BABE's figures have grown since the ln-gap notes.** Those notes
quote Assert 4,533 vB and ChallengeAssert 13,079 vB, about 17.8 kvB in
all, from the January version. The revised paper's Table 1 gives:
- Assert: 9,240 vB;
- ChallengeAssert: 17,400 vB;
- WronglyChallenged: 149 vB.

That is 26.8 kvB in all. These are honest-setup figures, with one set of
input labels on chain. Everything below uses the revised ones.

## 1. Roles

In BABE the Verifier garbles and the Prover evaluates. In lichen:
- **The Prover is Alice**, the claimant.
- **The Verifier is the hub.** At opening it picks the secret r and the
  message msg. It garbles the circuit that computes r·π1 and publishes
  the WE ciphertext (480 B). `H(msg)` goes into a hashlock.
- **A malicious hub could garble wrongly, so that Alice can never
  decrypt.** Cut-and-choose protects her: she checks the opened instances
  and keeps the finalized ones.
- **Alice stores the garbled material, the hub stores almost nothing:**
  about 22 MiB per finalized instance (paper). That is about 89 MiB at
  M = 4. Duty-Free Bits (ePrint 2026/476) reports a 45× smaller BABE
  "encoding", which would be about 2 MiB (est). The 45× is not verified
  against what lichen would store.

## 2. The fixed statement, and the countersignature

The Groth16 public input is fixed at setup. With RISC Zero that input is
the claim digest over `ReceiptClaim::ok(image_id, journal)`. So the journal
must be the same for every withdrawal: it holds the memo `c`, the
deployment `D` and a digest of the hub's one-time key `pk_H`, and not `b`.

`b` moves into the witness. The binding comes from the hub
(babe-amount-authenticated.md, C1–C3):
1. Alice WOTS-signs `b` on chain.
2. The hub WOTS-signs the same `b` with `pk_H`. The script checks digit by
   digit that the two signatures carry the same value. If the hub stays
   silent, Alice's timeout pays her.
3. Alice's guest checks the hub's signature on `b`, along with the
   withdrawal as now. That is a few thousand cycles more (est).

BABE's cryptography is unchanged.

## 3. The transaction graph

The contract's output has three leaves, as now: fold (the key path),
`default` (after T_c) and `request`.

| # | transaction | spends | poster | window | what it carries | size |
|---|---|---|---|---|---|---|
| 1 | `request` | contract | Alice | before T_c | her WOTS signature on `b` (one word) | ~0.4 kvB (est: ~250 vB a word, lichen's `inputs`) |
| 2a | `respond` | 1 | hub | w_H | its WOTS signature on `b`, and Alice's signature again for the equality check | ~0.6 kvB (est) |
| 2b | `request_timeout` | 1 | Alice | after w_H | pays `b` unverified, through the bit outputs (the hub is gone) | ~0.4 kvB (lichen: the dispute's timeout, 430 vB) |
| 3 | `assert` | 2a | Alice | **before T_c − Δ2 − Δ1 − margin** (see §5) | π1, Lamport-signed (508 bits) | 9.24 kvB (paper) |
| 3' | `respond_timeout` | 2a | hub | after Alice's deadline | Alice never asserted: the hub takes the contract | ~0.3 kvB (est) |
| 4a | `challenge_assert` | 3 | hub | Δ2 | the garbled circuit's input labels for π1, and Alice's Lamport signature again (matching) | 17.4 kvB (paper, soldered); ~42 kvB with M = 4 unsoldered (est) |
| 4b | `success` | 3 | Alice | after Δ2 | the hub didn't challenge: Alice is paid | ~0.4 kvB (est) |
| 5a | `wrongly_challenged` | 4a | Alice | Δ1 | msg (the hashlock preimage), decrypted with her proof | 0.15 kvB (paper), ~0.21 with a fee input |
| 5b | `failure` | 3 and 4a | hub | after Δ1 | Alice couldn't decrypt: the hub takes everything | ~0.3 kvB (est) |
| 6 | the payout's bit outputs | 2b, 4b or 5a | each side | at leisure | as today: K = 14 outputs, ~300 vB a spend | ~3 kvB with the payout itself (lichen: 23 kvB less escalate, `inputs` and the timeout) |

How the unsoldered figure is estimated: 4a re-reveals Alice's signature,
about the same as 3, so each label set costs about
17.4 − 9.2 ≈ 8.2 kvB. Four sets give 9.2 + 4 × 8.2 ≈ 42 kvB.

**Pre-signed transactions:** about 8, plus the payout, against the
ladder's ~141.

**Times Alice must act:** request, assert, wrongly_challenged, and the
sweep. Today she acts about 13 times: escalate, `inputs`, 10 rounds, the
record and the proof. Only `wrongly_challenged` (5a) is under real time
pressure, and it is 149 vB and mechanical, so it suits a tower.

**There is no read-lie branch.** The whole verification is inside the
garbled circuit and the WE. So the worst case (187 kvB, the hub's
`combine_8`) has no counterpart.

## 4. Exits by bytes (Table `exits`, recomputed)

Per block = 1,000 kvB ÷ per-user size. "Per day; per month" is at a
quarter of each block (×36 and ×1,080 per block), as in the paper's
table. The payout (~3 kvB) is included in every row.

| exit | today | per block | BABE (est) | per block | per day; per month |
|---|---|---|---|---|---|
| hub present: fold | 0.3 kvB | 3,300 | 0.3 kvB | 3,300 | unchanged |
| hub gone: request (or escalate), timeout, payout | 23 kvB | 43 | ~3.8 kvB (1 + 2b + 6) | ~260 | ~9,500; ~280,000 |
| hub disputes a true claim to the end | 123 kvB | 8 | ~31 kvB soldered (1+2a+3+4a+5a+6); ~56 unsoldered | 32; 18 | ~1,150; ~35,000 (soldered) |
| hub disproves a false claim | 103 kvB | 10 | ~28 kvB soldered (1+2a+3+4a+5b); ~53 unsoldered | 36; 19 | |
| the same with a read lie | 187 kvB | 5 | (no such case) | | |

The ratios:
- **Hostile hub:** about 4× (soldered) or 2.2× (unsoldered).
- **Worst case overall:** about 6× (187 → 31).
- **Hub gone:** about 6×. Most of that comes from no longer publishing
  the input words. The ladder's own "inputs on demand" amelioration
  (MASS_EXIT.md) would get close to it, so don't credit it to BABE alone.

## 5. Congestion (Table `flood`, recomputed)

The rule is unchanged: N ≤ w · 1 MvB / s, where s is the defender's
heaviest move due in one window.

**The hostile-hub column depends on a design choice that BABE makes
possible.** Today Alice's heaviest move is the last step's proof
(25.1 kvB). It must race the hub's timeout, so it is window-bound.
Under BABE her heavy move is `assert`, 9.24 kvB. Its deadline can be tied
to T_c instead of a window, as the escalation's is today:
- **No harm to the hub:** a late `assert` only delays a payout the hub
  owes anyway.
- **No race with proving:** the proof (STARK about 74 s, wrap about 4 min
  on the box) waits on nothing but the hub's response, and then has until
  T_c.

What is then left in a window is `wrongly_challenged`, about 0.21 kvB.
Staggered expiries spread the `assert`s, as they spread escalations today.

| | today | BABE, hostile hub (s = assert, windowed) | BABE, hostile hub (assert before T_c; s = wrongly_challenged) | BABE, hostile users (s = challenge_assert, soldered) | the same, unsoldered |
|---|---|---|---|---|---|
| s | Alice 25.1 / hub 93 kvB | 9.3 kvB | 0.21 kvB | 17.4 kvB | ~42 kvB |
| safe at w = 12 (2 h) | 480 / 130 | 1,300 | ~57,000 | 690 | 290 |
| at w = 144 (a day) | 5,700 / 1,550 | 15,500 | ~690,000 | 8,300 | 3,400 |
| at w = 1,008 (a week) | 40,000 / 10,800 | 108,000 | — | 58,000 | 24,000 |
| window for 3,000 contracts | 75 / 280 blocks | 28 | 1 | 52 (9 h) | 126 (21 h) |
| for 60,000 | 1,510 / 5,580 blocks (10 / 39 days) | 560 | 13 | 1,040 (7 days) | 2,520 (17 days) |

The hostile-users side still binds:
- **The gain is about 5.3×** soldered (93 → 17.4 kvB), and about 2.2×
  unsoldered.
- **Soldering is what decides the figure:** it costs the hub about
  12 min of SNARK proving per contract (paper: 745 s at M = 4).
- **The ladder could also narrow its own figure.** Posting the path's
  chunks in their own windows (MASS_EXIT.md, amelioration 2) would bring
  the ladder's s to 23.6 kvB. Against that, BABE soldered is only 1.4×
  better on this metric. So BABE's case on congestion rests mostly on:
  - the hostile-hub column;
  - the total bytes;
  - the missing read-lie tail.

**The hub's response** (0.6 kvB) also falls in a window, w_H, and grows
with N under hostile users: 60,000 contracts need w_H ≥ 36 blocks. That
is a small move, so the cost is mild.

## 6. Reserves

A reserve must cover the other side's fees in a lost dispute (the paper,
"The contract reserve").

| side's dispute bytes | today | BABE (est) |
|---|---|---|
| Alice's (what the hub's reserve covers) | ~120 kvB (her rounds 92, the proof 25, the input words) | ~12.5 kvB (request, assert, wrongly_challenged, her payout) |
| the hub's (what Alice's reserve covers) | ~70–100 kvB in the read tail | ~18 kvB soldered, ~43 unsoldered |
| the floor the paper uses for both (the deepest dispute, 1 sat/vB) | 195,411 sats | ~31,000 sats (one dispute's total), or per side ~12,500 / ~18,000 |

**The hub's reserve per user falls about 10×.** At 10 sat/vB that is
about 125k sats, against 2M today. The paper's line "suits balances from
about half a million sats" becomes about 50k sats (est).

## 7. Time

A hostile hub stretches a dispute to about:
- **Today:** 10 w_H + w_P ≈ 430 blocks with the paper's windows (3 days).
- **Under BABE:** w_H + Δ2 + Δ1, plus Alice's own time before her
  deadline (her money is waiting, nothing is at risk). With w_H = 12,
  Δ2 = 144 and Δ1 = 12 that is about 170 blocks (~1.2 days).

Δ2 is the hub's heavy window, so it sizes against hostile users (§5).
Δ1 can be short, since its move is tiny.

A vanished hub's users wait w_H, as now.

## 8. Setup per contract: the new cost

All per contract, the paper's figures at (N_CC, M_CC) = (2,268, 4) on a
16-thread laptop:

| | |
|---|---|
| cut-and-choose, both roles | 1 min 37 s, 1.8 GB peak |
| soldering (so that one label set goes on chain) | +745 s |
| Alice stores | ~89 MiB (4 × 22 MiB); ~2 MiB if Duty-Free Bits' 45× applies (est) |
| transfer, hub to Alice | at least the finalized instances, ~89 MiB (est); the opened ones are seeds |
| a hub opening 10,000 contracts | ~270 laptop-hours (16 threads) without soldering, ~2,300 with: parallel, one-off per contract, and repeated at renewal |

**Fewer instances mean more label sets.** (78, 10) sets up in 6 s, but
needs 10 label sets on chain without soldering (~92 kvB, est). Soldering
makes the setup cost and the on-chain cost independent.

## 9. What changes with EXIT_PLAN's counter-proof

The figures above are for today's statement, a withdrawal by return. With
EXIT_PLAN the hub may answer a claim with a counter (a later spend of a
claimed nullifier). Two shapes:
- **The counter inside Alice's statement.** The hub's `respond` carries
  the counter, or a "none", under its signature. Alice proves "valid
  exit, and the hub's counter, if any, is invalid". There is one BABE
  instance, and `respond` grows by the counter's bytes when used:
  - a Groth16 proof and its claim, posted as data;
  - a signed digest;
  - about 3 kvB in all (est).

  Alice's guest must then verify a Groth16 proof inside RISC Zero. Its
  cycles are unmeasured.
- **A separate, role-reversed game.** The hub proves its counter in a
  second BABE instance, and Alice garbles for it:
  - **setup doubles;**
  - **Alice's heaviest windowed move becomes her own challenge_assert**
    (17.4 kvB), so the hostile-hub column falls to the hostile-users
    one: about 8,300 per day-window.

The claim also publishes E (the nullifiers' digest), which the hub must
countersign: 8 more words, about +2 kvB on `request` and +2.5 on
`respond` (est).

## 10. What these figures rest on (for the paper's caveats)

- **BABE's figures are its prototype's:**
  - honest setup on chain, one label set;
  - M = 4 needs soldering (an SP1 proof) or four label sets on chain;
  - VSSS (§9.4) could replace soldering, but has no on-chain design yet.
- **The countersignature construction is a sketch.** Its security needs
  knowledge soundness through Groth16, RISC Zero's STARK and the WE
  (babe-amount-authenticated.md, C4).
- **BABE verifies Groth16 on BN254,** which RISC Zero's wrap already
  produces. So the proving side is unchanged.
- **The lichen-side sizes (request, respond, the timeouts) are scaled**
  from ln-gap's WOTS words and links, not built.
- **Duty-Free Bits' 45× is quoted from its abstract** ("encoding size").
  What it means for Alice's storage is unchecked.
