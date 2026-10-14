#!/usr/bin/env python3
"""The diagrams of ../lie-caught.md, from Mutinynet contracts 1003 and 1004
(2026-10-14). Standard library only:
    python3 docs/explainers/img/lie.py
writes docs/explainers/img/lie-*.svg."""

import math
import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(hub_absent.Svg):
    PREFIX = "lie"


# each dispute's transactions as mined: (name, vB, whose)
A, H = "A", "H"
SEARCH = [("escalate", 11595, A), ("inputs", 9932, A)]
_1003 = [337, 7516, 329, 7524, 336, 7522, 337, 7524, 337, 7534, 345, 7529, 345, 7533, 345, 7540, 353, 3370, 353, 6766]
_1004 = [337, 7505, 329, 7521, 336, 7521, 337, 7532, 345, 7527, 337, 7522, 345, 7533, 345, 7530, 345, 3369, 345, 6765]
D1003 = SEARCH + [(f"move {k + 2}", v, H if k % 2 == 0 else A) for k, v in enumerate(_1003)] + [("disprove_halt_exit", 5143, H)]
D1004 = [("escalate", 11593, A), ("inputs", 9932, A)] + [(f"move {k + 2}", v, H if k % 2 == 0 else A) for k, v in enumerate(_1004)] + [("path_split", 587, H), ("combine_7", 81056, H), ("disprove_read_2", 23599, H)]


# ---------------------------------------------------------------- the sizes
def sizes():
    s = Svg(1060, 470)
    s.text(24, 32, "Two lies, every transaction: sizes as mined (vB)", 16, INK, 700)
    s.rect(24, 46, 14, 14, fill=ALICE_L, stroke=ALICE, rx=3)
    s.text(44, 58, "Alice's", 12, INK2)
    s.rect(110, 46, 14, 14, fill=HUB_L, stroke=HUB, rx=3)
    s.text(130, 58, "the hub's", 12, INK2)
    scale = 190 / 81056

    def panel(y0, title, sub, txs, height):
        s.text(24, y0, title, 13.5, INK, 700)
        s.text(24, y0 + 18, sub, 11.5, INK2)
        base = y0 + height
        s.line(24, base, 1036, base, stroke=LINE, arrow=False)
        x, w = 40, 32
        for name, v, who in txs:
            h = max(2, v * scale)
            s.rect(x, base - h, w - 6, h, fill=ALICE_L if who == A else HUB_L, stroke=ALICE if who == A else HUB, rx=2, sw=1)
            if (v > 3000 or name.startswith(("path", "disprove"))) and name != "combine_7":
                s.text(x + (w - 6) / 2, base - h - 5, f"{v / 1000:.1f}k", 10, INK2, 400, "middle")
            x += w
        return x, base

    x, base = panel(84, "1003: the exit code", "23 transactions, 100,445 vB, 100,576 sats of fees; escalate to verdict 68 blocks (34 min)", D1003, 72)
    s.text(x - 16, base + 16, "disprove_halt_exit", 11, HUB, 600, "end")
    x, base = panel(206, "1004: a read", "25 transactions, 200,493 vB, 200,832 sats of fees; escalate to verdict 111 blocks (55 min)", D1004, 232)
    s.text(x - 72, base - 170, "combine_7, the 66-hop path: 81.1k", 11.5, HUB, 600, "end")
    s.text(x - 16, base + 16, "path_split, combine_7, disprove_read_2", 11, HUB, 600, "end")
    s.text(40, base + 16, "escalate, inputs, then 20 moves: the hub's choices (~340 vB) and Alice's seven hashes (~7.5k)", 11, INK2)
    s.save("sizes")


# ---------------------------------------------------------------- the path
def jump(i, bits=29, counter=5):
    c = i & ((1 << counter) - 1)
    if c < counter or c >= bits or (i >> c) & 1 == 0:
        return i - 1
    above = (i >> (c + 1)) << (c + 1)
    data_below = ((1 << c) - 1) & ~((1 << counter) - 1)
    return (above | data_below | c) - 1


def path(fr, to):
    v, s = [], fr
    while s > to:
        j = jump(s)
        if j != s - 1 and j >= to:
            v.append(("L", j))
            s = j
        else:
            v.append(("S", s - 1))
            s -= 1
    return v


def path_diagram():
    s = Svg(1060, 440)
    t, y = 478324073, 7
    p = path(t, y)
    assert len(p) == 66
    s.text(24, 32, "1004: the hub's path, from the agreed step back to the write Alice's read names (66 hops)", 16, INK, 700)
    x0, x1, ay = 60, 1000, 250

    def X(step):
        return x0 + (x1 - x0) * math.log10(step) / math.log10(t)

    s.line(x0, ay, x1, ay, stroke=INK2, arrow=False)
    for e in range(0, 9):
        xx = X(10 ** e)
        s.line(xx, ay, xx, ay + 6, stroke=INK2, arrow=False)
        s.text(xx, ay + 22, "1" if e == 0 else f"10^{e}", 11, INK2, 400, "middle")
    s.text((x0 + x1) / 2, ay + 44, "step number (log scale)", 11.5, INK2, 400, "middle")
    # hops: long ones as arcs above the axis
    prev = t
    for kind, to in p:
        a, b = X(prev), X(to)
        if kind == "L" and a - b > 1.5:
            hgt = min(150, 12 + (a - b) * 0.9)
            s.path(f"M {a:.1f} {ay} Q {(a + b) / 2:.1f} {ay - hgt:.1f} {b:.1f} {ay}", stroke=HUB, sw=1.4, arrow=False)
        prev = to
    s.circle(X(t), ay, 6, fill=ALICE_L, stroke=ALICE)
    s.circle(X(y), ay, 6, fill=HUB_L, stroke=HUB)
    s.text(X(t), ay + 64, "step 478,324,073: the last", 11.5, ALICE, 600, "end")
    s.text(X(t), ay + 80, "agreed step; the lie is at the next", 11.5, ALICE, 600, "end")
    s.text(X(y) - 4, ay + 64, "step 7: the write to 0xe07ffff0", 11.5, HUB, 600, "start")
    s.text(X(y) - 4, ay + 80, "her read names (it wrote 0, not 1)", 11.5, HUB, 600, "start")
    notes = [
        (X(t) - 10, 76, "13 hops among the last 400 steps,", "then one long jump to 268,435,451", "end"),
        ((X(2 ** 28) + X(37)) / 2, 76, "22 long jumps, each about halving the step,", "down to step 37", "middle"),
        (X(30), 126, "30 short hops,", "36 down to 7", "middle"),
    ]
    for x, yy, a, b, anc in notes:
        s.text(x, yy, a, 12, INK, 600, anc)
        s.text(x, yy + 16, b, 12, INK, 600, anc)
    s.text(24, 404, "Each hop goes to the previous step or to the step's long jump; the hub signs every hash along the way. It posts them in 7 chunks of", 12, INK2)
    s.text(24, 422, "about ten (one input each, under Script's 1,000-item stack): path_split makes the carriers, combine_7 spends all seven at once.", 12, INK2)
    s.save("path")


if __name__ == "__main__":
    for f in (sizes, path_diagram):
        f()
