#!/usr/bin/env python3
"""The diagrams of ../opening.md, from the opening of Mutinynet contract
1000 on the hub-proves deployment (2026-11-11), with the setup's timings
from contract 1006's, opened alone. Standard library only:
    python3 docs/explainers/img/opening.py
writes docs/explainers/img/opening-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import svg  # noqa: E402
from svg import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(svg.Svg):
    PREFIX = "opening"


# ---------------------------------------------------------------- the messages
def sequence():
    s = Svg(1060, 900)
    s.text(24, 32, "Opening a contract, with contract 1000's figures: seven requests, two transactions, one swap", 16, INK, 700)
    lanes = [(180, "Alice's wallet", ALICE, ALICE_L), (470, "the hub", HUB, HUB_L), (760, "Bitcoin", CON, CON_L), (950, "the L2", OK, OK_L)]
    top, bottom = 56, 876
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
    msg(y, "A", "H", "1. /info", "network, deployment, statement and guests: checked")
    y += 52
    msg(y, "A", "H", "2. /deposit: Alice's deposit key")
    y += 30
    msg(y, "H", "A", "contract 1000, the hub's key, a refund timeout", dash="5 3")
    y += 46
    msg(y, "A", "B", "3. 151,000 to the deposit address (from any wallet)", "deposit 9749619e…, block 3,580,029")
    y += 52
    msg(y, "A", "H", "4. /hp/setup")
    y += 30
    msg(y, "H", "A", "the statement's checkpoint, unit and margin; its Lamport and adaptor keys", dash="5 3")
    y += 22
    y = note(y, "A", ["deals a secret per digit of the proof's", "point; garbles 78 instances: 9.3 s"], ALICE, ALICE_L, 270) + 26
    msg(y, "A", "H", "/hp/commit: her keys for b and E, 78 hashes, the dealing")
    y += 30
    msg(y, "H", "A", "the 10 it keeps", dash="5 3")
    y += 40
    msg(y, "A", "H", "/hp/instance: the 10 kept, 23.9 MiB each", "65 s on a 30 Mbit/s uplink")
    y += 52
    msg(y, "A", "H", "5. /open: the terms, her addresses, the deposit coin,", "her keys, and the other 68 instances opened")
    y += 26
    y = note(y, "H", ["rebuilds and checks the 68: 20 to 36 s"], HUB, HUB_L, 250) + 26
    msg(y, "H", "L", "mint 99,000 to P = H(A ‖ T)·A + T", "locked: spending it takes t")
    y += 50
    msg(y, "H", "A", "the offer: T_close, r_H, the windows, the funding, its 7 signatures,", dash="5 3")
    s.text((X["A"] + X["H"]) / 2, y + 16, "its 1,016 pre-signatures on challenge_assert, T and the mint", 11, INK2, 400, "middle")
    y += 34
    y = note(y, "A", ["checks the terms, the funding, the hub's", "signatures and pre-signatures; signs the", "17; sees the mint sealed; pre-signs the", "deposit input, locked to T"], ALICE, ALICE_L, 270) + 26
    msg(y, "A", "H", "6. /accept: her 17 signatures, her pre-signature")
    y += 26
    y = note(y, "H", ["checks them; completes her", "pre-signature with t; signs its input"], HUB, HUB_L, 250) + 26
    msg(y, "H", "B", "the funding: its witness reveals t", "59f181a9…, block 3,580,038")
    y += 46
    msg(y, "H", "A", "the funding's txid, and t", dash="5 3")
    y += 36
    msg(y, "A", "L", "Alice moves the 99,000 to her own key, with t, and acknowledges it")
    s.save("sequence")


# ---------------------------------------------------------------- the funding
def funding():
    s = Svg(1060, 470)
    s.text(24, 32, "The funding of contract 1000 (59f181a9…, 305 vB, fee 2,000: 1,000 from each side)", 16, INK, 700)
    # inputs
    s.text(24, 70, "in", 13, INK, 700)
    s.rect(24, 84, 250, 64, fill=ALICE_L, stroke=ALICE, sw=1.5)
    s.text(40, 108, "Alice's deposit: 151,000", 13, INK, 700)
    s.text(40, 128, "spent by deposit_open: the hub's", 11.5, INK2)
    s.text(40, 143, "and Alice's signatures", 11.5, INK2)
    s.rect(24, 164, 250, 64, fill=HUB_L, stroke=HUB, sw=1.5)
    s.text(40, 188, "a coin of the hub's: 1,519,842", 13, INK, 700)
    s.text(40, 208, "its wallet, by key", 11.5, INK2)
    s.rect(320, 104, 120, 104, fill=CON_L, stroke=CON, sw=1.6)
    s.text(380, 150, "funding", 14, INK, 700, "middle")
    s.text(380, 168, "305 vB", 11.5, INK2, 400, "middle")
    s.line(274, 116, 318, 140)
    s.line(274, 196, 318, 172)
    # outputs
    s.text(490, 70, "out", 13, INK, 700)
    outs = [(84, "the contract: 250,971", "V_max + r_A + r_H: what every ending divides", CON, CON_L), (164, "Alice's fee budget: 30,000", "her key: fee coins for an exit's terminals", ALICE, ALICE_L), (244, "the hub's change: 1,387,871", "back to its wallet", HUB, HUB_L)]
    for y, t, u, col, fill in outs:
        s.rect(490, y, 300, 60, fill=fill, stroke=col, sw=1.5)
        s.text(506, y + 25, t, 13, INK, 700)
        s.text(506, y + 44, u, 11.5, INK2)
        s.path(f"M 440 156 C 465 156, 465 {y + 30}, 488 {y + 30}", sw=1.2)
    # who put what into the contract
    y = 340
    s.text(24, y, "Who put what into the contract's 250,971", 13, INK, 700)
    total = 250971
    x0, w = 24, 1012
    segs = [(100000, "D: Alice's deposit", ALICE, ALICE_L), (20000, "r_A", ALICE, ALICE_L), (99155, "V_max − D: the liquidity", HUB, HUB_L), (31816, "r_H", HUB, HUB_L)]
    x = x0
    for v, lab, col, fill in segs:
        ww = w * v / total
        s.rect(x, y + 14, ww, 40, fill=fill, stroke=col, rx=0, sw=1.2)
        s.text(x + ww / 2, y + 32, lab, 11.5, INK, 600, "middle")
        s.text(x + ww / 2, y + 47, n(v), 11, INK2, 400, "middle")
        x += ww
    s.text(24, y + 80, "Alice: 100,000 + 20,000, plus 1,000 of fee and the 30,000 budget = her 151,000.", 12, INK)
    s.text(24, y + 98, "The hub: 99,155 + 31,816, plus 1,000 of fee = 131,971 out of its coin; its change is the rest.", 12, INK)
    s.save("funding")


if __name__ == "__main__":
    for f in (sequence, funding):
        f()
