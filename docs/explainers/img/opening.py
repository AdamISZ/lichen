#!/usr/bin/env python3
"""The diagrams of ../opening.md, from the opening of Mutinynet contract
1001 (Test B, 2026-10-12). Standard library only:
    python3 docs/explainers/img/opening.py
writes docs/explainers/img/opening-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(hub_absent.Svg):
    PREFIX = "opening"


# ---------------------------------------------------------------- the messages
def sequence():
    s = Svg(1060, 700)
    s.text(24, 32, "Opening contract 1001: four requests, two transactions, then the mint", 16, INK, 700)
    lanes = [(180, "Alice's wallet", ALICE, ALICE_L), (470, "the hub", HUB, HUB_L), (760, "Bitcoin", CON, CON_L), (950, "the L2", OK, OK_L)]
    top, bottom = 56, 676
    for x, name, col, fill in lanes:
        s.rect(x - 70, top, 140, 32, fill=fill, stroke=col, rx=6)
        s.text(x, top + 21, name, 13, INK, 700, "middle")
        s.line(x, top + 32, x, bottom, stroke=LINE, sw=1.2, arrow=False, dash="4 4")
    X = {k: v[0] for k, v in zip(("A", "H", "B", "L"), lanes)}

    def msg(y, a, b, label, sub=None, col=INK2, dash=None):
        x1, x2 = X[a], X[b]
        d = 1 if x2 > x1 else -1
        s.line(x1 + 4 * d, y, x2 - 6 * d, y, stroke=col, sw=1.5, dash=dash)
        mid = (x1 + x2) / 2
        s.text(mid, y - 8, label, 12, INK, 600, "middle")
        if sub:
            s.text(mid, y + 16, sub, 11, INK2, 400, "middle")

    def note(y, a, lines, col, fill, w=250):
        x = X[a] - w / 2
        h = 10 + 16 * len(lines)
        s.rect(x, y, w, h, fill=fill, stroke=col, rx=6)
        for k, l in enumerate(lines):
            s.text(X[a], y + 19 + 16 * k, l, 11.5, INK, 400, "middle")
        return y + h

    y = 122
    msg(y, "A", "H", "1. /info", "network, deployment, statement, 21 depths: checked")
    y += 52
    msg(y, "A", "H", "2. /deposit: Alice's deposit key")
    y += 30
    msg(y, "H", "A", "contract 1001, the hub's key, a refund timeout", dash="5 3")
    y += 46
    msg(y, "A", "B", "3. 71,000 to the deposit address (from any wallet)", "deposit dc089a53…, block 3,500,811")
    y += 58
    msg(y, "A", "H", "4. /open: the terms she asks, her addresses,", "her one-time keys (51 input words, her moves, 8 hops), the deposit coin")
    y += 58
    msg(y, "H", "A", "the offer: T_close, r_H, the hub's keys, the funding,", dash="5 3")
    s.text((X["A"] + X["H"]) / 2, y + 16, "and its 169 signatures on the 141 pre-signed transactions", 11, INK2, 400, "middle")
    y += 34
    y = note(y, "A", ["checks the terms, the funding's outputs", "and every one of the hub's signatures;", "then signs the 141, and the deposit input"], ALICE, ALICE_L, 270) + 26
    msg(y, "A", "H", "5. /accept: her 169 signatures, her deposit signature")
    y += 26
    y = note(y, "H", ["checks them; signs its own input"], HUB, HUB_L, 230) + 26
    msg(y, "H", "B", "the funding", "418b42cc…, block 3,500,812")
    y += 52
    y = note(y, "H", ["sees the funding confirm"], HUB, HUB_L, 200) + 24
    msg(y, "H", "L", "mint 30,000 tokens to Alice's L2 address")
    s.save("sequence")


# ---------------------------------------------------------------- the funding
def funding():
    s = Svg(1060, 470)
    s.text(24, 32, "The funding of contract 1001 (418b42cc…, 305 vB, fee 2,000: 1,000 from each side)", 16, INK, 700)
    # inputs
    s.text(24, 70, "in", 13, INK, 700)
    s.rect(24, 84, 250, 64, fill=ALICE_L, stroke=ALICE, sw=1.5)
    s.text(40, 108, "Alice's deposit: 71,000", 13, INK, 700)
    s.text(40, 128, "spent by deposit_open: the hub's", 11.5, INK2)
    s.text(40, 143, "and Alice's signatures", 11.5, INK2)
    s.rect(24, 164, 250, 64, fill=HUB_L, stroke=HUB, sw=1.5)
    s.text(40, 188, "a coin of the hub's: 465,964", 13, INK, 700)
    s.text(40, 208, "its wallet, by key", 11.5, INK2)
    s.rect(320, 104, 120, 104, fill=CON_L, stroke=CON, sw=1.6)
    s.text(380, 150, "funding", 14, INK, 700, "middle")
    s.text(380, 168, "305 vB", 11.5, INK2, 400, "middle")
    s.line(274, 116, 318, 140)
    s.line(274, 196, 318, 172)
    # outputs
    s.text(490, 70, "out", 13, INK, 700)
    outs = [(84, "the contract: 282,891", "V_max + r_A + r_H: what every ending divides", CON, CON_L), (164, "Alice's fee budget: 20,000", "her key: fee coins for a dispute's terminals", ALICE, ALICE_L), (244, "the hub's change: 232,073", "back to its wallet", HUB, HUB_L)]
    for y, t, u, col, fill in outs:
        s.rect(490, y, 300, 60, fill=fill, stroke=col, sw=1.5)
        s.text(506, y + 25, t, 13, INK, 700)
        s.text(506, y + 44, u, 11.5, INK2)
        s.path(f"M 440 156 C 465 156, 465 {y + 30}, 488 {y + 30}", sw=1.2)
    # who put what into the contract
    y = 340
    s.text(24, y, "Who put what into the contract's 282,891", 13, INK, 700)
    total = 282891
    x0, w = 24, 1012
    segs = [(30000, "D: Alice's deposit", ALICE, ALICE_L), (20000, "r_A", ALICE, ALICE_L), (35535, "V_max − D", HUB, HUB_L), (197356, "r_H: the hub's reserve, the floors of the deepest dispute", HUB, HUB_L)]
    x = x0
    for v, lab, col, fill in segs:
        ww = w * v / total
        s.rect(x, y + 14, ww, 40, fill=fill, stroke=col, rx=0, sw=1.2)
        s.text(x + ww / 2, y + 32, lab, 11.5, INK, 600, "middle")
        s.text(x + ww / 2, y + 47, n(v), 11, INK2, 400, "middle")
        x += ww
    s.text(24, y + 80, "Alice: 30,000 + 20,000, plus 1,000 of fee and the 20,000 budget = her 71,000.", 12, INK)
    s.text(24, y + 98, "The hub: 35,535 + 197,356, plus 1,000 of fee = 233,891 out of its coin; its change is the rest.", 12, INK)
    s.save("funding")


if __name__ == "__main__":
    for f in (sequence, funding):
        f()
