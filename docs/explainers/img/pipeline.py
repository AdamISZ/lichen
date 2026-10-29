#!/usr/bin/env python3
"""The diagrams of ../pipeline.md, from lichen's guests with anchoring
(the withdrawal guest 11a9f930…, 2026-10-21; BABE's 74b95bb4…,
2026-10-27), BABE's disputes on Mutinynet (2026-10-29) and, for
BitVMX's, Mutinynet contract 1002 (2026-10-13). Standard
library only:
    python3 docs/explainers/img/pipeline.py
writes docs/explainers/img/pipeline-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L  # noqa: E402


class Svg(hub_absent.Svg):
    PREFIX = "pipeline"


def box(s, x, y, w, h, title, lines, fill, stroke, size=13.5):
    s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=1.6)
    s.text(x + w / 2, y + 22, title, size, INK, 700, "middle")
    for k, l in enumerate(lines):
        s.text(x + w / 2, y + 41 + 16 * k, l, 11.5, INK2, 400, "middle")


# ---------------------------------------------------------------- the whole pipeline
def overview():
    s = Svg(1060, 640)
    s.text(24, 32, "A withdrawal claim, from a Rust program to a check on Bitcoin, under BABE", 16, INK, 700)
    s.rect(24, 50, 1012, 40, fill=OK_L, stroke=OK, sw=1.3)
    s.text(40, 75, "The normal case needs no proof from Alice: the hub checks her return natively and signs the fold (cooperative.md).", 12.5, INK, 600)
    # on chain first: request and respond
    s.text(24, 122, "only if the hub refuses the fold: on chain, Alice requests b and the hub signs the same b; then, on Alice's machine:", 12, ALICE, 700)
    y, w, h = 134, 220, 78
    xs = [24, 288, 552, 816]
    rows = [
        ("1. the guest", ["Rust, compiled to RISC-V; checks", "the hub's signature on b: ~480k cycles"]),
        ("2. the STARK", ["about 220 kB, with the", "chain receipt resolved"]),
        ("3. the Groth16 proof", ["three points A, B, C", "128 bytes"]),
        ("4. assert, on chain", ["A, Lamport-signed in", "254 digits; B and C beside"]),
    ]
    for x, (t, ls) in zip(xs, rows):
        box(s, x, y, w, h, t, ls, ALICE_L, ALICE)
    for a, b, lab in [(0, 1, "prove"), (1, 2, "wrap"), (2, 3, "sign A")]:
        s.line(xs[a] + w + 2, y + h / 2, xs[b] - 4, y + h / 2)
        s.text((xs[a] + w + xs[b]) / 2, y + h / 2 - 8, lab, 11, INK2, 600, "middle")
    # the hub's check
    cx = xs[3] + w / 2
    s.line(cx, y + h + 2, cx, 262)
    box(s, 816, 266, 220, 78, "the hub checks it natively", ["the same Groth16 check", "in about 1.5 ms"], HUB_L, HUB)
    s.line(cx, 346, cx, 372)
    s.text(cx, 390, "valid: it lets it stand;", 11.5, OK, 700, "middle")
    s.text(cx, 406, "success pays Alice after \u0394\u2082", 11.5, OK, 700, "middle")
    # the challenge
    s.path("M 816 305 L 300 305 L 300 444")
    s.text(560, 297, "false (or a hub that disputes true claims): it challenges", 11, INK2, 400, "middle")
    s.text(24, 434, "the challenge", 12, INK2, 700)
    y2 = 448
    box(s, 24, y2, 300, 78, "5. challenge_assert", ["the hub reveals the secrets of A's", "digits, as it signed at opening"], HUB_L, HUB)
    box(s, 384, y2, 300, 78, "6. the garbled circuits", ["Alice's kept instances, on A's labels,", "give r\u00b7A; with B, C: the key, if valid"], CON_L, CON)
    box(s, 744, y2, 292, 78, "7. the answer", ["msg unlocked: wrongly_challenged pays", "Alice; none: failure pays the hub"], OK_L, OK)
    s.line(326, y2 + 39, 380, y2 + 39)
    s.line(686, y2 + 39, 740, y2 + 39)
    s.text(24, 560, "The garbled circuits were made by the hub when the contract opened, and checked by Alice by cut-and-choose: she kept 10 of 78.", 11.5, INK2)
    s.text(24, 580, "Under BitVMX, lichen's first gadget, the same Groth16 proof is instead the input of a RISC-V verifier,", 11.5, INK2)
    s.text(24, 598, "whose 478 million steps are searched on chain down to one instruction (section 5).", 11.5, INK2)
    s.save("overview")


# ---------------------------------------------------------------- BABE's check
def babe():
    s = Svg(1060, 470)
    s.text(24, 32, "What a challenge hands Alice, and how a valid proof turns it into msg", 16, INK, 700)
    # left: at opening
    s.text(24, 64, "at opening, per contract", 12, INK2, 700)
    box(s, 24, 76, 300, 96, "the hub's 78 instances", ["each: a garbled circuit computing r\u00b7A", "from A's bits (r its own secret), and the", "ciphertext: r\u00b7\u03b4, and msg masked by r\u00b7T"], CON_L, CON, 13)
    box(s, 24, 196, 300, 78, "Alice's cut-and-choose", ["she opens 68 and checks them;", "she keeps 10 (about 240 MiB)"], ALICE_L, ALICE)
    s.line(174, 174, 174, 192)
    # middle: on chain
    s.text(384, 64, "in the dispute, on chain", 12, INK2, 700)
    box(s, 384, 76, 300, 78, "assert (Alice)", ["A's 508 bits in 254 2-bit digits,", "one Lamport preimage each"], ALICE_L, ALICE)
    box(s, 384, 196, 300, 78, "challenge_assert (the hub)", ["one secret per digit, for the value", "Alice signed: her adaptor pre-signatures"], HUB_L, HUB)
    s.line(534, 156, 534, 192)
    # right: Alice, off chain
    s.text(744, 64, "then, on Alice's machine", 12, INK2, 700)
    box(s, 744, 76, 292, 78, "the labels of A", ["each kept instance's, interpolated", "from the secrets and the opened shares"], ALICE_L, ALICE)
    box(s, 744, 196, 292, 78, "evaluate", ["each kept circuit on A's labels:", "r\u00b7A, under its own r"], CON_L, CON)
    s.path("M 686 235 L 712 235 L 712 115 L 740 115")
    s.line(890, 156, 890, 192)
    # bottom: the pairing
    s.rect(24, 306, 1012, 104, fill=OK_L, stroke=OK, sw=1.5)
    s.text(530, 332, "Groth16 checks  e(A, B) + e(C, \u03b4) = T.  Multiply through by r:", 13, INK, 700, "middle")
    s.text(530, 356, "e(r\u00b7A, B) + e(C, r\u00b7\u03b4) = r\u00b7T", 14, INK, 700, "middle")
    s.text(530, 380, "Alice has r\u00b7A from the circuit, B and C from her proof, and r\u00b7\u03b4 from the ciphertext: r\u00b7T unmasks msg,", 11.5, INK2, 400, "middle")
    s.text(530, 397, "but only if the proof is valid for the contract's statement. A false proof opens no instance.", 11.5, INK2, 400, "middle")
    s.line(890, 276, 890, 302)
    s.text(24, 440, "The secrets reveal only the labels of the A that Alice signed, so she can evaluate the circuit on that A and no other;", 11.5, INK2)
    s.text(24, 458, "r stays inside the circuit. A kept instance a dishonest hub garbled wrong would be caught, with overwhelming odds, among the opened ones.", 11.5, INK2)
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
    s.text(24, 290, "Ours is one segment: 482k cycles for BABE's", 11.5, ALICE, 600)
    s.text(24, 307, "guest, 393k for BitVMX's; one lift, no joins;", 11.5, ALICE, 600)
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
    s.text(380, 340, "Measured on a 4-vCPU x86 server: BABE's guest proved in about 660 s, BitVMX's in 361 s", 11.5, INK2)
    s.text(380, 357, "(75 s on a Mac, in Docker); the wrap in about 255 s, with about 8 GB of memory.", 11.5, INK2)
    s.save("wrap")


# ---------------------------------------------------------------- the verifier's input
def input_words():
    s = Svg(1060, 330)
    s.text(24, 32, "The verifier's input: 204 bytes, 51 words of 4 bytes", 16, INK, 700)
    x0, ww, y, h = 40, 19, 88, 44
    X = lambda i: x0 + i * ww
    fields = [
        (0, 1, "", CON_L, CON),
        (1, 9, "image id", CON_L, CON),
        (9, 17, "A", ALICE_L, ALICE),
        (17, 33, "B", ALICE_L, ALICE),
        (33, 41, "C", ALICE_L, ALICE),
        (41, 42, "", OK_L, OK),
        (42, 43, "", CON_L, CON),
        (43, 51, "D", CON_L, CON),
    ]
    for a, b, lab, fill, st in fields:
        s.add(f'<rect x="{X(a):.1f}" y="{y}" width="{(b - a) * ww:.1f}" height="{h}" fill="{fill}" stroke="{st}" stroke-width="1.3"/>')
        for i in range(a + 1, b):
            s.line(X(i), y + h - 6, X(i), y + h, stroke=st, sw=0.8, arrow=False)
        if lab:
            s.text((X(a) + X(b)) / 2, y + 27, lab, 13, INK, 700, "middle")
    # word numbers
    for i in (0, 1, 9, 17, 33, 41, 42, 43, 50):
        s.text(X(i) + ww / 2, y - 8, str(i), 10, INK2, 400, "middle")
    s.text(x0, 66, "word", 10.5, INK2, 600)
    # labels above, for the one-word fields
    s.text(X(0) + ww / 2, y + 27, "n", 11, INK, 700, "middle")
    s.text(X(41) + ww / 2, y + 27, "b", 12, INK, 700, "middle")
    s.text(X(42) + ww / 2, y + 27, "c", 12, INK, 700, "middle")
    # brackets below
    def brace(a, b, yy, lab, col, sub=None):
        s.path(f"M {X(a) + 2} {yy} L {X(a) + 2} {yy + 6} L {X(b) - 2} {yy + 6} L {X(b) - 2} {yy}", stroke=col, sw=1.3, arrow=False)
        s.text((X(a) + X(b)) / 2, yy + 22, lab, 11.5, col, 700, "middle")
        if sub:
            s.text((X(a) + X(b)) / 2, yy + 37, sub, 11, INK2, 400, "middle")
    brace(9, 41, y + h + 6, "the Groth16 proof: 128 bytes", ALICE, "A and C in G1, B in G2, compressed")
    brace(41, 51, y + h + 6, "the journal: b ‖ c ‖ D", OK, "40 bytes")
    # escalate / inputs
    yy = 222
    s.text(24, yy, "where Alice signs them:", 12, INK, 700)
    s.text(24, yy + 20, "escalate", 12, ALICE, 700)
    s.text(110, yy + 20, "11 words: n, the image id, b and c, with move 1 of the search", 11.5, INK2)
    s.text(24, yy + 38, "inputs", 12, ALICE, 700)
    s.text(110, yy + 38, "the other 40: the proof and D (too many for escalate's witness, within Script's 1,000-item stack)", 11.5, INK2)
    s.text(24, yy + 64, "purple: the 18 checked words", 12, CON, 700)
    s.text(232, yy + 64, "n, the image id, c and D must equal the contract's values, or the hub takes the contract at once.", 11.5, INK2)
    s.text(24, yy + 82, "green: b", 12, OK, 700)
    s.text(232, yy + 82, "the amount: the payout's scripts read its bits from Alice's signature on word 41.", 11.5, INK2)
    s.save("input")


# ---------------------------------------------------------------- the 8-ary search
def search():
    s = Svg(1060, 470)
    s.text(24, 32, "The search: Alice posts 7 hashes, the hub picks one of 8 intervals, ten times", 16, INK, 700)
    x0, W = 190, 820

    def row(y, lo, hi, pick, title, sub, scale_lo, scale_hi):
        s.text(24, y + 14, title, 13, INK, 700)
        s.text(24, y + 31, sub, 11, INK2)
        s.line(x0, y + 16, x0 + W, y + 16, stroke=LINE, sw=6, arrow=False)
        for k in range(8):
            a = x0 + k * W / 8
            if k == pick:
                s.add(f'<rect x="{a:.1f}" y="{y + 4}" width="{W / 8:.1f}" height="24" rx="3" fill="{HUB_L}" stroke="{HUB}" stroke-width="1.4"/>')
            if k:
                s.circle(a, y + 16, 5.5, fill=ALICE, stroke=ALICE)
        s.text(x0, y + 46, scale_lo, 10.5, INK2, 400, "middle")
        s.text(x0 + W, y + 46, scale_hi, 10.5, INK2, 400, "middle")
        return x0 + pick * W / 8, x0 + (pick + 1) * W / 8

    a, b = row(70, 0, 1, 5, "round 1", "moves 1 and 2", "step 0", "2^29")
    s.path(f"M {a} {104} L {x0} {140}", stroke=HUB, sw=1, arrow=False, dash="3 3")
    s.path(f"M {b} {104} L {x0 + W} {140}", stroke=HUB, sw=1, arrow=False, dash="3 3")
    a, b = row(146, 0, 1, 2, "round 2", "moves 3 and 4", "", "")
    s.path(f"M {a} {180} L {x0} {216}", stroke=HUB, sw=1, arrow=False, dash="3 3")
    s.path(f"M {b} {180} L {x0 + W} {216}", stroke=HUB, sw=1, arrow=False, dash="3 3")
    s.text(24, 236, "…", 16, INK, 700)
    s.text(x0 + W / 2, 236, "… each round narrows the interval 8 times …", 11.5, INK2, 400, "middle")
    a, b = row(256, 0, 1, 6, "round 10", "moves 19 and 20", "", "")
    # the final step
    fx = x0 + 6.5 * W / 8
    s.line(fx, 290, fx, 318)
    s.rect(610, 322, 420, 50, fill=OK_L, stroke=OK, sw=1.5)
    s.text(820, 342, "move 21: Alice's record of step t + 1", 12.5, INK, 700, "middle")
    s.text(820, 360, "its instruction, its reads, its write, the hashes either side", 11, INK2, 400, "middle")
    # legend
    s.circle(30, 402, 5.5, fill=ALICE, stroke=ALICE)
    s.text(44, 406, "a hash Alice posts: the state after that step", 11.5, INK2)
    s.add(f'<rect x="24" y="420" width="14" height="14" rx="3" fill="{HUB_L}" stroke="{HUB}"/>')
    s.text(44, 432, "the interval the hub disputes: it agrees with her hash at the left end, not at the right", 11.5, INK2)
    s.text(24, 458, "8^10 = 2^30 covers the verifier's 2^29 steps. They end agreeing on the hash after step t and disagreeing after step t + 1.", 11.5, INK2)
    s.save("search")


# ---------------------------------------------------------------- the jump list
def jumps():
    s = Svg(1060, 314)
    s.text(24, 32, "A disputed read: the hub's path through the jump list, from the agreed step back to the write", 16, INK, 700)
    x0, W, y = 60, 940, 150
    s.line(x0, y, x0 + W, y, stroke=LINE, sw=4, arrow=False)
    lo, hi = 0, 48
    X = lambda i: x0 + (i - lo) * W / (hi - lo)
    # the path: t=92 back to w=21 by hops, long jumps as arcs above, single steps as small arcs below
    hops = [(46, 45, False), (45, 40, True), (40, 32, True), (32, 31, False), (31, 16, True), (16, 12, True), (12, 11, False), (11, 8, True)]
    for a, b, long_ in hops:
        xa, xb = X(a), X(b)
        if long_:
            hgt = 22 + (a - b) * 4.5
            s.path(f"M {xa} {y - 4} C {xa} {y - hgt}, {xb} {y - hgt}, {xb + 3} {y - 7}", stroke=HUB, sw=1.6)
        else:
            s.path(f"M {xa} {y + 4} C {xa} {y + 22}, {xb} {y + 22}, {xb + 2} {y + 7}", stroke=HUB, sw=1.4)
    for i in sorted({h[0] for h in hops} | {hops[-1][1]}):
        s.circle(X(i), y, 5, fill="#ffffff", stroke=HUB)
    s.circle(X(46), y, 7, fill=OK_L, stroke=OK, sw=2)
    s.text(X(46) - 20, y + 44, "step t: both agree on its hash", 11.5, OK, 700, "end")
    s.circle(X(8), y, 7, fill=ALICE_L, stroke=ALICE, sw=2)
    s.text(X(8) - 10, y + 44, "the write Alice names for her read", 11.5, ALICE, 700, "start")
    s.text(X(26), y + 64, "← hops back to the previous step, or to the step's long jump", 11.5, HUB, 600, "middle")
    s.text(24, 250, "Each step's hash covers the previous step's hash and its long jump's: h(i) = BLAKE3(h(i−1) ‖ h(jump(i)) ‖ write_i ‖ i).", 11.5, INK2)
    s.text(24, 268, "So from h(t) a short path reaches any earlier step: at most 86 hops over 2^29 steps, about 52 on average.", 11.5, INK2)
    s.text(24, 286, "The hub posts the path; Alice may challenge any hop she finds false; the verdict compares the write found with her read.", 11.5, INK2)
    s.save("jumps")


if __name__ == "__main__":
    for f in (overview, babe, wrap, input_words, search, jumps):
        f()
