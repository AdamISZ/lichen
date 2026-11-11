#!/usr/bin/env python3
"""The diagrams of ../pipeline.md, from lichen's guests (spend 9fd630b2…,
chain f06d2420…, hp f424a509…, 2026-11-10), the real-circuit runs of
2026-11-10 and the Mutinynet runs of 2026-11-11. Standard
library only:
    python3 docs/explainers/img/pipeline.py
writes docs/explainers/img/pipeline-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import svg  # noqa: E402
from svg import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L  # noqa: E402


class Svg(svg.Svg):
    PREFIX = "pipeline"


def box(s, x, y, w, h, title, lines, fill, stroke, size=13.5):
    s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=1.6)
    s.text(x + w / 2, y + 22, title, size, INK, 700, "middle")
    for k, l in enumerate(lines):
        s.text(x + w / 2, y + 41 + 16 * k, l, 11.5, INK2, 400, "middle")


# ---------------------------------------------------------------- the whole pipeline
def overview():
    s = Svg(1060, 660)
    s.text(24, 32, "Three statements proved, one checked on Bitcoin: the hub's, that an exit claim is false", 16, INK, 700)
    # the three provers
    y0 = 52
    box(s, 24, y0, 320, 78, "a shielded spend", ["the sender's device, every shielded", "payment; the sequencer checks it"], ALICE_L, ALICE)
    box(s, 370, y0, 320, 78, "the chain, a height at a time", ["the sequencer's prover, every sealed", "height, each receipt verifying the last"], OK_L, OK)
    box(s, 716, y0, 320, 78, "the hub's statement", ["the hub, only when an exit claim", "is false"], HUB_L, HUB)
    s.line(346, y0 + 39, 366, y0 + 39)
    s.line(692, y0 + 39, 712, y0 + 39)
    s.text(356, y0 + 98, "the chain guest checks every spend receipt; the hub's proof stands on the chain receipt at the claim's state", 11, INK2, 400, "middle")
    s.text(24, 182, "only if Alice's exit claim is false: on the hub's machine", 12, HUB, 700)
    y, w, h = 194, 220, 78
    xs = [24, 288, 552, 816]
    rows = [
        ("1. the guest", ["the claim, the state at A*, request", "from Bitcoin: ~1M cycles"]),
        ("2. the STARK", ["about 220 kB, the chain", "receipt resolved"]),
        ("3. the Groth16 proof", ["three points A, B, C", "128 bytes"]),
        ("4. assert, on chain", ["A, Lamport-signed in", "254 digits; B and C beside"]),
    ]
    for x, (t, ls) in zip(xs, rows):
        box(s, x, y, w, h, t, ls, HUB_L, HUB)
    for a, b, lab in [(0, 1, "prove"), (1, 2, "wrap"), (2, 3, "sign A")]:
        s.line(xs[a] + w + 2, y + h / 2, xs[b] - 4, y + h / 2)
        s.text((xs[a] + w + xs[b]) / 2, y + h / 2 - 8, lab, 11, INK2, 600, "middle")
    cx = xs[3] + w / 2
    s.line(cx, y + h + 2, cx, 322)
    box(s, 816, 326, 220, 78, "Alice's wallet checks it", ["the same Groth16 check,", "natively, in about 1.5 ms"], ALICE_L, ALICE)
    s.line(cx, 406, cx, 432)
    s.text(cx, 450, "valid: her claim was false;", 11.5, OK, 700, "middle")
    s.text(cx, 466, "she concedes, success after \u0394\u2082", 11.5, OK, 700, "middle")
    s.path("M 816 365 L 300 365 L 300 504")
    s.text(560, 357, "false (a lying hub): she challenges", 11, INK2, 400, "middle")
    s.text(24, 494, "the challenge", 12, INK2, 700)
    y2 = 508
    box(s, 24, y2, 300, 78, "5. challenge_assert", ["Alice reveals the secrets of A's", "digits, completing the hub's pre-signatures"], ALICE_L, ALICE)
    box(s, 384, y2, 300, 78, "6. her garbled circuits", ["the hub's kept instances, on A's labels,", "give r\u00b7A; with B, C: the key, if valid"], CON_L, CON)
    box(s, 744, y2, 292, 78, "7. the answer", ["msg unlocked: wrongly_challenged takes", "the contract; none: failure pays Alice"], OK_L, OK)
    s.line(326, y2 + 39, 380, y2 + 39)
    s.line(686, y2 + 39, 740, y2 + 39)
    s.text(24, 620, "The garbled circuits were made by Alice when the contract opened, and checked by the hub by cut-and-choose: it kept 10 of 78.", 11.5, INK2)
    s.text(24, 638, "A true claim needs none of this: the hub doesn't assert, and request_timeout pays her.", 11.5, INK2)
    s.save("overview")


# ---------------------------------------------------------------- BABE's check
def babe():
    s = Svg(1060, 470)
    s.text(24, 32, "What a challenge hands the hub, and how a valid proof turns it into msg", 16, INK, 700)
    s.text(24, 64, "at opening, per contract", 12, INK2, 700)
    box(s, 24, 76, 300, 96, "Alice's 78 instances", ["each: a garbled circuit computing r\u00b7A", "from A's bits (r its own secret), and the", "ciphertext: r\u00b7\u03b4, and msg masked by r\u00b7T"], CON_L, CON, 13)
    box(s, 24, 196, 300, 78, "the hub's cut-and-choose", ["it opens 68 and checks them;", "it keeps 10 (239 MiB, uploaded)"], HUB_L, HUB)
    s.line(174, 174, 174, 192)
    s.text(384, 64, "in the dispute, on chain", 12, INK2, 700)
    box(s, 384, 76, 300, 78, "assert (the hub)", ["A's 508 bits in 254 2-bit digits,", "one Lamport preimage each"], HUB_L, HUB)
    box(s, 384, 196, 300, 78, "challenge_assert (Alice)", ["one secret per digit, for the value", "the hub signed: its adaptor pre-signatures"], ALICE_L, ALICE)
    s.line(534, 156, 534, 192)
    s.text(744, 64, "then, on the hub's machine", 12, INK2, 700)
    box(s, 744, 76, 292, 78, "the labels of A", ["each kept instance's, interpolated", "from the secrets and the opened shares"], HUB_L, HUB)
    box(s, 744, 196, 292, 78, "evaluate", ["each kept circuit on A's labels:", "r\u00b7A, under its own r"], CON_L, CON)
    s.path("M 686 235 L 712 235 L 712 115 L 740 115")
    s.line(890, 156, 890, 192)
    s.rect(24, 306, 1012, 104, fill=OK_L, stroke=OK, sw=1.5)
    s.text(530, 332, "Groth16 checks  e(A, B) + e(C, \u03b4) = T.  Multiply through by r:", 13, INK, 700, "middle")
    s.text(530, 356, "e(r\u00b7A, B) + e(C, r\u00b7\u03b4) = r\u00b7T", 14, INK, 700, "middle")
    s.text(530, 380, "The hub has r\u00b7A from the circuit, B and C from its proof, and r\u00b7\u03b4 from the ciphertext: r\u00b7T unmasks msg,", 11.5, INK2, 400, "middle")
    s.text(530, 397, "but only if the proof is valid for the contract's statement. A false proof opens no instance.", 11.5, INK2, 400, "middle")
    s.line(890, 276, 890, 302)
    s.text(24, 440, "The secrets reveal only the labels of the A that the hub signed, so it can evaluate the circuit on that A and no other;", 11.5, INK2)
    s.text(24, 458, "r stays inside the circuit. A kept instance a dishonest Alice garbled wrong would be caught, with overwhelming odds, among the opened ones.", 11.5, INK2)
    s.save("babe")


# ---------------------------------------------------------------- recursion and the wrap
def wrap():
    s = Svg(1060, 400)
    s.text(24, 32, "From an execution to 128 bytes: segments, recursion, and the shrink-wrap", 16, INK, 700)
    # segments
    s.text(24, 64, "a long guest: segments of about a million cycles", 12, INK2, 700)
    segx = [24, 104, 184, 264]
    for k, x in enumerate(segx):
        dash = None if k == 0 else "4 3"
        s.rect(x, 76, 70, 30, fill=ALICE_L if k == 0 else "#ffffff", stroke=ALICE, sw=1.3, dash=dash)
        s.text(x + 35, 96, f"segment {k + 1}", 11, INK, 600, "middle")
        s.rect(x, 130, 70, 26, fill="#ffffff", stroke=ALICE, sw=1.1, dash=dash)
        s.text(x + 35, 147, "lift", 11, INK2, 600, "middle")
        s.line(x + 35, 107, x + 35, 128)
    for a, b, cy in [(0, 1, 182), (2, 3, 182)]:
        mx = (segx[a] + segx[b]) / 2 + 35
        s.rect(mx - 35, cy, 70, 26, fill="#ffffff", stroke=ALICE, sw=1.1, dash="4 3")
        s.text(mx, cy + 17, "join", 11, INK2, 600, "middle")
        s.line(segx[a] + 35, 157, mx - 10, cy - 2)
        s.line(segx[b] + 35, 157, mx + 10, cy - 2)
    s.rect(149, 232, 70, 26, fill="#ffffff", stroke=ALICE, sw=1.1, dash="4 3")
    s.text(184, 249, "join", 11, INK2, 600, "middle")
    s.line(99, 209, 174, 230)
    s.line(269, 209, 194, 230)
    s.text(288, 236, "resolve", 10, INK2, 600, "middle")
    s.text(24, 290, "The hub's guest: about 1M cycles, two", 11.5, ALICE, 600)
    s.text(24, 307, "segments, so two lifts and a join;", 11.5, ALICE, 600)
    s.text(24, 324, "then a resolve takes in the chain receipt.", 11.5, ALICE, 600)
    s.text(24, 341, "Dashed: what a longer guest would add.", 11.5, INK2)
    # the chain of receipts
    y, w, h = 214, 180, 92
    xs = [380, 610, 840]
    box(s, xs[0], y, w, h, "succinct receipt", ["a STARK: Poseidon2", "over BabyBear (31 bits)", "about 220 kB"], ALICE_L, ALICE)
    box(s, xs[1], y, w, h, "identity_p254", ["the same claim, re-proved", "with Poseidon over", "BN254's field"], ALICE_L, ALICE)
    box(s, xs[2], y, w, h - 0, "Groth16 receipt", ["3 BN254 points:", "256 bytes, 128 compressed", "gnark, x86 only"], ALICE_L, ALICE)
    s.path("M 219 245 C 290 245, 300 260, 376 260")
    s.line(xs[0] + w + 2, y + h / 2, xs[1] - 4, y + h / 2)
    s.line(xs[1] + w + 2, y + h / 2, xs[2] - 4, y + h / 2)
    s.text((xs[0] + w + xs[1]) / 2, y + h / 2 - 8, "re-prove", 10, INK2, 600, "middle")
    s.text((xs[1] + w + xs[2]) / 2, y + h / 2 - 8, "wrap", 11, INK2, 600, "middle")
    s.text(380, 92, "Every receipt says the same thing:", 12.5, INK, 700)
    s.text(380, 112, "“the program with image id X ran and output journal J”.", 12.5, INK)
    s.text(380, 136, "Each step changes only how it is proved, so that the next step can take it:", 11.5, INK2)
    s.text(380, 153, "any length → one STARK → a STARK a BN254 circuit can check → Groth16.", 11.5, INK2)
    s.text(380, 340, "The hub's statement: proved in 827 s on a 4-vCPU x86 server, 3.5 s on an RTX 4090;", 11.5, INK2)
    s.text(380, 357, "the wrap in 268 s on that server, with about 8 GB of memory.", 11.5, INK2)
    s.save("wrap")


if __name__ == "__main__":
    for f in (overview, babe, wrap):
        f()
