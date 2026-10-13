#!/usr/bin/env python3
"""The diagrams of ../hub-returns.md, from the transactions of Mutinynet
contract 1002 (2026-10-13). Standard library only:
    python3 docs/explainers/img/hub_returns.py
writes docs/explainers/img/hub-returns-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(hub_absent.Svg):
    PREFIX = "hub-returns"


# ---------------------------------------------------------------- the timeline, with the hub's
def timeline():
    s = Svg(1060, 380)
    s.text(24, 32, "Contract 1002 in blocks (30 s apart on Mutinynet): Alice's transactions, and the hub's return", 16, INK, 700)
    lo, hi = 3502325, 3502540
    x0, W = 50, 960
    X = lambda h: x0 + (h - lo) * W / (hi - lo)
    y = 200
    s.line(x0, y, x0 + W, y, stroke=INK2, arrow=False)
    for h in range(3502330, hi, 10):
        s.line(X(h), y - 4, X(h), y + 4, stroke=INK2, arrow=False)
    for h in (3502340, 3502380, 3502420, 3502460, 3502500, 3502540):
        s.text(X(h), y + 20, f"{h:,}", 10.5, INK2, 400, "middle")
    ev = [(3502331, "funding", "12:00", CON, -18), (3502411, "escalate", "12:43", ALICE, -18), (3502412, "inputs", "12:44", ALICE, -48),
          (3502493, "timeout", "13:28", ALICE, -18), (3502534, "sweep", "13:50", ALICE, -18)]
    for h, lab, t, col, dy in ev:
        s.circle(X(h), y, 6, fill=col, stroke=col)
        s.text(X(h), y + dy, lab, 12.5, col, 700, "middle")
        s.text(X(h), y + dy + 14 if dy < -20 else y + 38, t + " UTC", 10.5, INK2, 400, "middle")

    def window(a, b, yy, lab, col):
        s.add(f'<rect x="{X(a):.1f}" y="{yy}" width="{X(b) - X(a):.1f}" height="16" rx="3" fill="{col}" opacity="0.18"/>')
        s.text((X(a) + X(b)) / 2, yy + 12, lab, 11, INK, 600, "middle")

    window(3502412, 3502492, 96, "the hub's window: δ + δ′ = 80 blocks", HUB)
    window(3502493, 3502533, 96, "δ = 40", HUB)
    # the hub's lane
    hy = 264
    s.text(24, hy - 8, "the hub", 12.5, HUB, 700)
    s.add(f'<rect x="{X(3502334):.1f}" y="{hy}" width="{X(3502416) - X(3502334):.1f}" height="22" rx="4" fill="#ffffff" stroke="{FEE}" stroke-dasharray="4 3"/>')
    s.text((X(3502334) + X(3502416)) / 2, hy + 15, "stopped, before Alice's return", 11.5, INK2, 600, "middle")
    s.add(f'<rect x="{X(3502416):.1f}" y="{hy}" width="{X(hi) - X(3502416):.1f}" height="22" rx="4" fill="{HUB_L}" stroke="{HUB}"/>')
    s.text((X(3502416) + X(hi)) / 2, hy + 15, "running: posts nothing", 11.5, INK, 600, "middle")
    s.add(f'<rect x="{X(lo):.1f}" y="{hy}" width="{X(3502334) - X(lo):.1f}" height="22" rx="4" fill="{HUB_L}" stroke="{HUB}"/>')
    for h, lab, t in [(3502416, "started 12:46:40; conceded 12:46:43", 0), (3502492, "settled 13:27:57", 1)]:
        s.line(X(h), hy + 24, X(h), hy + 40, stroke=HUB, arrow=False)
        s.text(X(h) + (6 if t == 0 else -6), hy + 52, lab, 11.5, HUB, 700, "start" if t == 0 else "end")
    s.text(x0, 344, "The hub was back 4 blocks into its 80-block window. Had the claim been false, it had 76 blocks left to post move 2.", 12, INK2)
    s.text(x0, 362, "The claim was true, so the hub posted nothing, and the dispute ran exactly as if it were still away: escalation to sweep, 67 minutes.", 12, INK2)
    s.save("timeline")


# ---------------------------------------------------------------- what the hub reads, and decides
def reads():
    s = Svg(1060, 590)
    s.text(24, 32, "What the hub has after a restart, what it reads from the chain, and what it decides", 16, INK, 700)

    def box(x, y, w, h, title, lines, fill, stroke):
        s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=1.6)
        s.text(x + 14, y + 22, title, 13.5, INK, 700)
        for k, l in enumerate(lines):
            s.text(x + 14, y + 42 + 17 * k, l, 11.5, INK2)

    box(24, 60, 300, 118, "on its disk: the contract", ["the terms, both sides' keys", "every pre-signed transaction, both signatures", "the 18 checked words' agreed values", "(nothing about the dispute)"], HUB_L, HUB)
    box(24, 200, 300, 100, "on chain: escalate's witness", ["Alice's one-time signatures on", "11 input words (b, the memo, the image id…)", "and move 1 (the trace's claim)"], ALICE_L, ALICE)
    box(24, 316, 300, 84, "on chain: inputs' witness", ["the other 40 input words:", "the Groth16 proof, the deployment id"], ALICE_L, ALICE)
    # the input
    box(390, 220, 250, 84, "the claim's input", ["51 words, 204 bytes: what the", "verifier program would run on"], "#ffffff", INK2)
    s.path("M 324 250 L 388 258")
    s.path("M 324 356 L 388 284")
    # the steps
    sx = 700
    steps = [
        (70, "1. the 18 checked words", "all equal to the agreed values?", "no: take the contract at once (a check leaf)", None),
        (190, "2. the proof, checked natively", "lngap-zk's Groth16 verifier, milliseconds", "rejected: play the search, move by move", None),
        (310, "3. accepted: concede", "post nothing; Alice's timeout will pay her", "", True),
        (420, "4. watch the ladder output", "spent by her timeout: the contract is settled", "", True),
    ]
    for y, t, sub, alt, ok in steps:
        fill, stroke = (OK_L, OK) if ok else ("#ffffff", CON)
        s.rect(sx, y, 336, 62 if not alt else 84, fill=fill, stroke=stroke, sw=1.6)
        s.text(sx + 14, y + 22, t, 13, INK, 700)
        s.text(sx + 14, y + 41, sub, 11.5, INK2)
        if alt:
            s.text(sx + 14, y + 66, "→ " + alt, 11.5, FEE, 600, italic=True)
    s.path("M 640 262 C 670 262, 670 110, 698 110")
    s.line(sx + 168, 154, sx + 168, 188)
    s.line(sx + 168, 274, sx + 168, 308)
    s.line(sx + 168, 372, sx + 168, 418)
    s.text(sx + 178, 175, "yes", 11, INK2)
    s.text(sx + 178, 295, "accepted", 11, INK2)
    s.text(24, 530, "Nothing of the dispute needs to be kept: the claim is on chain, signed by Alice, and the moves (had there been any) are too.", 12, INK2)
    s.text(24, 548, "The native check stands in for the 477,810,565 steps of the verifier program, which the hub would emulate only to dispute.", 12, INK2)
    s.text(24, 566, "Here: started 12:46:40, conceded 12:46:43.", 12, INK, 600)
    s.save("reads")


# ---------------------------------------------------------------- Test B's ending and Test C's
def ending():
    s = Svg(1060, 330)
    s.text(24, 32, "After the timeout: what reached Alice's payout address, and what was left behind", 16, INK, 700)
    x0, W = 190, 640
    sc = W / 250000

    def bar(y, label, sub, segs):
        s.text(24, y + 20, label, 13.5, INK, 700)
        s.text(24, y + 37, sub, 11.5, INK2)
        x = x0
        for v, lab, col, light, dash in segs:
            ww = max(v * sc, 3)
            d = ' stroke-dasharray="4 3"' if dash else ""
            s.add(f'<rect x="{x:.1f}" y="{y}" width="{ww:.1f}" height="44" fill="{light}" stroke="{col}" stroke-width="1.3"{d}/>')
            if ww > 70:
                s.text(x + ww / 2, y + 19, lab, 11.5, INK, 600, "middle")
                s.text(x + ww / 2, y + 35, n(v), 11.5, INK2, 400, "middle")
            x += ww
        return x

    xb = bar(64, "Test B (1001)", "before the fixes", [(34816, "b's bits", ALICE, ALICE_L, False), (195153, "the reserve output", ALICE, ALICE_L, False), (17840, "", FEE, "#ffffff", True), (660, "", FEE, "#ffffff", True)])
    s.text(xb + 10, 84, "17,840 budget + 660 anchors:", 11.5, INK2, 600)
    s.text(xb + 10, 100, "Alice's, left behind", 11.5, INK2, 600)
    s.text(x0, 128, "swept 228,769 (fee 1,200); the timeout's fee coin 2,000; the rest needed sweep-fees", 11.5, INK2)
    xc = bar(160, "Test C (1002)", "after the fixes", [(29696, "b's bits", ALICE, ALICE_L, False), (195153, "the reserve output", ALICE, ALICE_L, False), (19240, "", ALICE, ALICE_L, False), (660, "", ALICE, ALICE_L, False)])
    s.text(xc + 10, 180, "19,240 budget + 660 anchors:", 11.5, ALICE, 600)
    s.text(xc + 10, 196, "in the same sweep", 11.5, ALICE, 600)
    s.text(x0, 224, "swept 243,067 in one transaction (8 inputs, 1,680 vB, fee 1,682); the timeout's fee coin 600", 11.5, INK2)
    s.text(24, 270, "b differs (35,000 in B, 30,000 in C), so the bits differ; the reserve output is the same 195,153 in both:", 12, INK2)
    s.text(24, 288, "r_A + r_H less the floors and anchors of the same two links. Dashed: Alice's, but not in the sweep.", 12, INK2)
    s.save("ending")


if __name__ == "__main__":
    for f in (timeline, reads, ending):
        f()
