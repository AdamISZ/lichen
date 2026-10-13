#!/usr/bin/env python3
"""The diagrams of ../minting.md. Standard library only:
    python3 docs/explainers/img/minting.py
writes docs/explainers/img/minting-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, FEE, FEE_L, INK, INK2, LINE  # noqa: E402

CAR, CAR_L = "#0f766e", "#ccfbf1"


class Svg(hub_absent.Svg):
    PREFIX = "minting"


# ---------------------------------------------------------------- the sports car
def car():
    s = Svg(1060, 470)
    s.text(24, 32, "Alice's contract: the same $100,100 throughout. Only who gets it at the end changes.", 16, INK, 700)
    x0, W = 250, 780
    sc = W / 100100
    rows = [
        ("1. Alice opens", "Alice $100, the hub $100,000", [(100, ALICE, ALICE_L, ""), (100000, HUB, HUB_L, "the hub's $100,000: back to the hub if Alice leaves now")], "Alice holds 100 tokens"),
        ("2. The hub prints", "100,000 tokens, from nothing", [(100, ALICE, ALICE_L, ""), (100000, HUB, HUB_L, "unchanged: nothing new is locked, nothing is unlocked")], "the hub holds 100,000 tokens"),
        ("3. The hub buys the car", "paying Alice 100,000 tokens", [(100100, ALICE, ALICE_L, "Alice's $100,100: what she can take out now")], "Alice holds 100,100 tokens"),
        ("4. Alice withdraws", "she hands back 100,100 tokens", [(100100, ALICE, ALICE_L, "$100,100 to Alice, in bitcoin")], "the hub's $100,000 is gone: it paid for the car"),
    ]
    y = 70
    for title, sub, segs, note in rows:
        s.text(24, y + 20, title, 13.5, INK, 700)
        s.text(24, y + 38, sub, 11.5, INK2)
        x = x0
        for v, col, light, lab in segs:
            ww = max(v * sc, 3)
            s.add(f'<rect x="{x:.1f}" y="{y}" width="{ww:.1f}" height="46" fill="{light}" stroke="{col}" stroke-width="1.4"/>')
            if lab:
                s.text(x + ww / 2, y + 28, lab, 12, INK, 600, "middle")
            x += ww
        s.text(x0, y + 64, note, 11.5, INK2, 400, "start", italic=True)
        y += 92
    # the $100 sliver
    s.text(x0 + 2, 64, "Alice's $100", 11, ALICE, 600)
    for k, (lab, col, light) in enumerate([("Alice's if the contract closed now", ALICE, ALICE_L), ("the hub's if the contract closed now", HUB, HUB_L)]):
        s.rect(x0 + k * 300, 446, 14, 14, fill=light, stroke=col, rx=2)
        s.text(x0 + 20 + k * 300, 458, lab, 12, INK2)
    s.save("car")


# ---------------------------------------------------------------- what a token is worth
def cover():
    s = Svg(1060, 300)
    s.text(24, 32, "What a token is worth depends on who holds it: the holder's contract, not the token", 16, INK, 700)
    x0, sc = 250, 780 / 160100
    people = [
        ("Alice", "contract: up to $100,100", 100100, 100100),
        ("Alice, past her cap", "paid 60,000 more", 160100, 100100),
        ("Bob", "no contract", 5000, 0),
    ]
    y = 64
    for name, sub, bal, cap in people:
        s.text(24, y + 19, name, 13.5, INK, 700)
        s.text(24, y + 37, sub, 11.5, INK2)
        cov = min(bal, cap)
        if cov:
            s.add(f'<rect x="{x0}" y="{y}" width="{cov * sc:.1f}" height="40" fill="{ALICE_L}" stroke="{ALICE}" stroke-width="1.4"/>')
            s.text(x0 + cov * sc / 2, y + 25, f"covered: ${cov:,}", 12, INK, 600, "middle")
        if bal > cov:
            xx = x0 + cov * sc
            ww = max((bal - cov) * sc, 26)
            s.add(f'<rect x="{xx:.1f}" y="{y}" width="{ww:.1f}" height="40" fill="#ffffff" stroke="{FEE}" stroke-width="1.4" stroke-dasharray="4 3"/>')
            if ww > 200:
                s.text(xx + ww / 2, y + 25, f"${bal - cov:,}: only the hub's word", 12, INK2, 600, "middle")
            else:
                s.text(xx + ww + 8, y + 25, f"${bal - cov:,}: only the hub's word", 12, INK2, 600)
        if cap:
            cx = x0 + cap * sc
            s.line(cx, y - 6, cx, y + 46, stroke=CON, sw=2, arrow=False)
        y += 66
    s.text(x0 + 100100 * sc, 58, "her cap", 11, CON, 700, "middle")
    s.text(24, 280, "Printing more tokens never shrinks anyone's covered part; it can only add tokens that nobody's contract covers.", 12, INK2)
    s.save("cover")


if __name__ == "__main__":
    for f in (car, cover):
        f()
