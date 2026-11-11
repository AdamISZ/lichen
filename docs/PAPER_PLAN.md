# The papers: changes to make

Working notes (2026-11-11), not yet applied. The main paper is
papers/lichen-v0.5.0.tex (the user's text: suggestions, not edits); the
companion papers/lichen-l2-v0.1.0.tex.

## Main paper

- **§5, "Paying b: the bit outputs", last paragraph:** "the fold pays
  $b$ exactly, in sats" is wrong. A withdrawal's claim is in the
  contract's units, cooperative or not (`lichen withdraw` rounds the
  amount down to the unit; Olga's fold on Mutinynet paid 49,984 = 64 ×
  781). The fold could pay exact sats (it isn't pre-signed), but the
  claim's `b` is in units, so the wording is what changes.
- **§8, after Table 2:** "only the hub can be robbed by a false claim, so
  only the hub challenges": in Appendix A's terms the hub asserts and
  Alice challenges. Perhaps "so only the hub contests a claim".
- **Optional, the abstract or §3's L2 examples:** an L2 may ask its users
  for liveness of its own; in ours a sender stays online to acknowledge
  her payments (or the payment waits, never her funds).

## Companion (lichen-l2)

- **§14.2, block space:** about 7,000 contracts a day-long window,
  counting only Alice's challenge; the main paper's Table 1 says about
  35,000 for disputes lasting a week, counting all three windowed moves
  (28.7 kvB). Use one basis, or cross-reference.
- **Facts to check:** the full contents of `E` (written with "…" for the
  shielded part); 64 notes a claim, 13 shielded, about 1,200 bytes; the
  Intmax2 bibliography entry (authors and title from memory).

## Elsewhere

- **lichen-built-v0.1.1:** its title page still says "draft"; mark it not
  maintained, as the BitVMX companion is.
- **docs/explainers/exit.md:** Erin "waited 2 hours and 20 minutes", but
  its own timestamps give 2 h 26 min (02:22 to her sweep at 04:48).
