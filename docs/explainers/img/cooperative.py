#!/usr/bin/env python3
"""The diagrams of ../cooperative.md, from the transactions of Mutinynet
contract 1000 (2026-10-12). Standard library only:
    python3 docs/explainers/img/cooperative.py
writes docs/explainers/img/cooperative-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n, tx_box  # noqa: E402

BOB, BOB_L = "#0f766e", "#ccfbf1"


class Svg(hub_absent.Svg):
    PREFIX = "cooperative"


# ---------------------------------------------------------------- overview
def overview():
    s = Svg(1180, 520)
    s.text(24, 32, "Contract 1000: every transaction, and what happened off chain", 16, INK, 700)
    # the L2 lane
    s.rect(16, 50, 1148, 112, fill="#fafafa", stroke=LINE, dash="5 4")
    s.text(28, 70, "off chain", 12, INK2, 700)
    offs = [
        (230, "mint 30,000 tokens", "the hub, at funding"),
        (450, "pay Bob 5,000", "an L2 transfer"),
        (670, "return 20,000", "to the hub, memo 1000"),
        (890, "ask for the fold", "the return's index, her signature"),
    ]
    for x, t, u in offs:
        s.rect(x, 82, 190, 60, fill="#ffffff", stroke="#9ca3af", dash="4 3")
        s.text(x + 95, 106, t, 13, INK, 600, "middle")
        s.text(x + 95, 124, u, 11, INK2, 400, "middle")
    for a, b in [(420, 450), (640, 670), (860, 890)]:
        s.line(a, 112, b - 2, 112)

    # the chain lane
    y, h, w = 230, 62, 140
    xs = {"deposit": 60, "funding": 300, "fold": 820}
    tx_box(s, xs["deposit"], y, w, h, "deposit", "3,500,707", FEE_L, FEE, "165 vB")
    tx_box(s, xs["funding"], y, w, h, "funding", "3,500,731", CON_L, CON, "315 vB")
    tx_box(s, xs["fold"], y, w, h, "fold", "3,500,756", OK_L, OK, "193 vB")
    my = y + h / 2
    s.line(xs["deposit"] + w, my, xs["funding"] - 2, my)
    s.text((xs["deposit"] + w + xs["funding"]) / 2, my - 8, "71,000", 11.5, INK, 600, "middle")
    s.line(xs["funding"] + w, my, xs["fold"] - 2, my)
    s.text((xs["funding"] + w + xs["fold"]) / 2, my - 8, "282,891: the contract output", 11.5, INK, 600, "middle")
    # the mint, from the funding; the fold, from the request
    s.line(xs["funding"] + w / 2, y - 2, 325, 144, dash="4 3", arrow=False)
    s.path(f"M 985 143 C 985 190, {xs['fold'] + 70} 180, {xs['fold'] + 70} {y - 3}", dash="4 3")
    s.text(888, 192, "the hub checks the return, signs, broadcasts", 11.5, INK2, 400, "end")
    # payer and payout
    s.circle(24, my, 7)
    s.text(24, my + 24, "payer", 10.5, INK2, 400, "middle")
    s.line(31, my, xs["deposit"] - 2, my)
    px = 1130
    s.line(xs["fold"] + w, my, px - 8, my)
    s.text((xs["fold"] + w + px) / 2, my - 8, "40,000: b + r_A", 11.5, ALICE, 600, "middle")
    s.circle(px, my, 7, stroke=ALICE)
    s.text(px, my - 16, "payout", 10.5, ALICE, 600, "middle")

    # stubs below: what each leaves behind
    def stub(x, label, sub, color):
        s.line(x, y + h, x, 352, stroke=color, arrow=False)
        s.circle(x, 358, 6, stroke=color)
        s.text(x, 382, label, 11.5, color, 600, "middle")
        if sub:
            s.text(x, 397, sub, 10.5, INK2, 400, "middle")

    stub(xs["deposit"] + 70, "228,831", "payer's change", FEE)
    stub(xs["funding"] + 105, "465,964", "hub's change (funds 1001)", HUB)
    stub(xs["fold"] + 105, "241,891", "the hub's: the rest", HUB)
    # the fee budget lane
    fy = 430
    bx = 600
    s.path(f"M {xs['funding'] + 35} {y + h} L {xs['funding'] + 35} {fy + 25} L {bx - 2} {fy + 25}")
    s.text(xs["funding"] + 45, fy + 18, "20,000: Alice's fee budget, unused", 11.5, ALICE, 600)
    tx_box(s, bx, fy, 150, 50, "sweep-fees", "3,500,785 · 99 vB", ALICE_L, ALICE)
    s.path(f"M {bx + 150} {fy + 25} L {px} {fy + 25} L {px} {my + 9}")
    s.text(bx + 162, fy + 18, "19,500", 11.5, ALICE, 600)
    s.text(px - 10, fy - 6, "59,500 in all", 11.5, ALICE, 700, "end")
    s.text(24, 505, "The dispute machinery (141 pre-signed transactions, 169 signatures each way) was exchanged at opening and never used.", 11.5, INK2)
    s.save("overview")


# ---------------------------------------------------------------- the L2
def l2():
    s = Svg(1060, 380)
    s.text(24, 32, "On the L2: three transactions, each sealed by the sequencer within 5 seconds", 16, INK, 700)
    s.text(24, 52, "A note is (owner, value, memo). A transfer spends notes, signed by their owners, into new notes of the same total.", 12, INK2)
    nw, nh = 150, 46

    def note(x, y, who, v, memo, spent=False):
        col, light = {"Alice": (ALICE, ALICE_L), "Bob": (BOB, BOB_L), "the hub": (HUB, HUB_L)}[who]
        s.rect(x, y, nw, nh, fill="#ffffff" if spent else light, stroke=col, sw=1.6, dash="4 3" if spent else None)
        s.text(x + 12, y + 20, who, 12.5, col, 700)
        s.text(x + nw - 12, y + 20, n(v), 13, INK, 700, "end")
        s.text(x + 12, y + 37, f"memo {memo}" + ("  (spent)" if spent else ""), 11, INK2)

    def txn(x, y, title, sub):
        s.rect(x, y, 120, 54, fill="#fafafa", stroke=INK2, sw=1.2, rx=6)
        s.text(x + 60, y + 22, title, 13, INK, 700, "middle")
        s.text(x + 60, y + 40, sub, 10.5, INK2, 400, "middle")

    y1, y2 = 110, 190
    txn(24, 150, "mint", "the hub signs")
    note(176, 154, "Alice", 30000, 0, spent=True)
    s.line(144, 177, 174, 177)
    txn(358, 150, "pay Bob", "Alice signs")
    s.line(326, 177, 356, 177)
    note(510, y1, "Bob", 5000, 0)
    note(510, y2 + 46, "Alice", 25000, 0, spent=True)
    s.path(f"M 478 170 C 495 170, 490 {y1 + 23}, 508 {y1 + 23}")
    s.path(f"M 478 190 C 495 190, 490 {y2 + 69}, 508 {y2 + 69}")
    txn(700, y2 + 42, "return", "Alice signs")
    s.line(660, y2 + 69, 698, y2 + 69)
    note(880, y2 - 10, "the hub", 20000, 1000)
    note(880, y2 + 92, "Alice", 5000, 0)
    s.path(f"M 820 {y2 + 60} C 850 {y2 + 60}, 850 {y2 + 13}, 878 {y2 + 13}")
    s.path(f"M 820 {y2 + 80} C 850 {y2 + 80}, 850 {y2 + 115}, 878 {y2 + 115}")
    s.text(955, y2 - 20, "the return: the fold checks it", 11, HUB, 600, "middle")
    s.text(955, y2 + 154, "no contract behind it", 11, ALICE, 600, "middle")
    s.text(585, y1 - 10, "no contract behind it", 11, BOB, 600, "middle")
    s.text(24, 352, "Nothing here touches Bitcoin. Dashed: spent. After the fold, the unspent notes are Bob's 5,000, Alice's 5,000 and the hub's 20,000.", 12, INK2)
    s.save("l2")


# ---------------------------------------------------------------- the contract output's leaves, and the fold's bytes
def leaves():
    s = Svg(1060, 560)
    s.text(24, 32, "The contract output, and how the fold spends it", 16, INK, 700)
    s.text(24, 52, "✓ the leaf the fold used. Grey: the other two, revealed only as one 32-byte hash in the fold's control block.", 12, INK2)
    # the tree
    rx, ry = 200, 90
    s.rect(rx - 120, ry, 240, 50, fill=CON_L, stroke=CON, sw=1.6)
    s.text(rx, ry + 21, "contract output", 14, INK, 700, "middle")
    s.text(rx, ry + 39, "282,891 sats · funding:0 · taproot", 11.5, INK2, 400, "middle")
    s.line(rx - 40, ry + 50, 150, 200)
    s.line(rx + 40, ry + 50, 330, 200)
    s.circle(330, 208, 8, fill=FEE_L, stroke=FEE)
    s.text(346, 212, "a branch: 32 bytes in the control block", 11, INK2)
    s.line(324, 215, 305, 300)
    s.line(338, 213, 560, 300)

    def leaf(x, y, w, name, cond, what, used):
        fill, stroke, ink = (OK_L, OK, INK) if used else (FEE_L, LINE, INK2)
        s.rect(x, y, w, 70, fill=fill, stroke=stroke, rx=6, sw=1.4)
        s.text(x + 12, y + 22, ("✓ " if used else "") + name, 13, ink, 700, mono=True)
        s.text(x + 12, y + 41, cond, 11.5, ink)
        s.text(x + 12, y + 58, what, 11.5, ink)

    leaf(30, 202, 262, "fold", "2-of-2, signed when it happens", "b + r_A to Alice, the rest to the hub", True)
    leaf(195, 302, 240, "default", "2-of-2 pre-signed, after T_close", "r_A to Alice, the rest to the hub", False)
    leaf(450, 302, 240, "escalate", "2-of-2 pre-signed, after 10 blocks", "Alice's claim: the dispute path", False)
    s.text(30, 405, "default: had Alice not withdrawn by T_close (3,520,890, a week after opening), the hub's.", 11.5, INK2)
    s.text(30, 423, "escalate: had the hub refused the fold, Alice's (see hub-absent.md).", 11.5, INK2)

    # the fold's bytes
    x0, sc = 700, 1.5
    s.text(x0, 96, "the fold: 193 vB", 14, INK, 700)
    s.text(x0, 114, "one input, two outputs; vB = weight / 4", 11.5, INK2)
    parts = [
        (125, "the transaction", "version, input, 2 outputs, locktime", FEE, FEE_L),
        (32.5, "2 signatures", "64 B each (Schnorr)", ALICE, ALICE_L),
        (18, "leaf script", "71 B: 2 keys, CHECKSIG, CHECKSIGADD, 2", CON, CON_L),
        (16.5, "control block", "65 B: the internal key, 1 hash", CON, CON_L),
        (0.75, "", "", FEE, FEE_L),
    ]
    y, ly = 130, 0
    for vb, lab, sub, col, light in parts:
        hh = vb * sc
        s.add(f'<rect x="{x0}" y="{y:.1f}" width="70" height="{hh:.1f}" fill="{light}" stroke="{col}" stroke-width="1.2"/>')
        if lab:
            ly = max(y + hh / 2, ly + 36)
            s.line(x0 + 72, y + hh / 2, x0 + 96, ly - 4, stroke=LINE, arrow=False)
            s.text(x0 + 100, ly, f"{lab}: {vb:g} vB", 12, INK, 600)
            s.text(x0 + 100, ly + 15, sub, 11, INK2)
        y += hh
    s.text(x0, max(y, ly) + 34, "and 0.75 vB of witness framing", 11, INK2)
    y = max(y, ly) + 64
    s.text(x0, y, "With MuSig2 (a TODO), the fold would be", 12, INK)
    s.text(x0, y + 18, "a key-path spend: one 64-byte signature,", 12, INK)
    s.text(x0, y + 36, "142 vB, and look like any taproot payment.", 12, INK)
    s.save("leaves")


# ---------------------------------------------------------------- the money
def money():
    s = Svg(1060, 470)
    s.text(24, 32, "The contract's 282,891 sats, and Alice's 71,000", 16, INK, 700)
    x0, W = 120, 900

    def bar(y, total, segs, label):
        sc = W / total
        s.text(24, y + 25, label, 13, INK, 700)
        x = x0
        for v, lab, col, light in segs:
            ww = v * sc
            s.add(f'<rect x="{x:.1f}" y="{y}" width="{ww:.1f}" height="40" fill="{light}" stroke="{col}" stroke-width="1.2"/>')
            if ww > 54:
                s.text(x + ww / 2, y + 18, lab, 11.5, INK, 600, "middle")
                s.text(x + ww / 2, y + 33, n(v), 11.5, INK2, 400, "middle")
            x += ww

    s.text(x0, 66, "the contract output", 12.5, CON, 700)
    bar(76, 282891, [(30000, "D, Alice's", ALICE, ALICE_L), (35535, "V_max − D, hub", HUB, HUB_L), (20000, "r_A, hers", ALICE, ALICE_L), (197356, "r_H: the hub's reserve", HUB, HUB_L)], "in")
    bar(130, 282891, [(20000, "b", ALICE, ALICE_L), (20000, "r_A back", ALICE, ALICE_L), (44535, "V_max − b − fee", HUB, HUB_L), (197356, "r_H back", HUB, HUB_L), (1000, "", FEE, FEE_L)], "fold")
    s.text(x0 + W - 4, 190, "the fold's fee, 1,000, from the hub's side", 11, INK2, 400, "end")
    for k, (lab, col, light) in enumerate([("Alice's", ALICE, ALICE_L), ("the hub's", HUB, HUB_L), ("Bob's", BOB, BOB_L), ("fees", FEE, FEE_L)]):
        s.rect(x0 + 470 + k * 110, 22, 14, 14, fill=light, stroke=col, rx=2)
        s.text(x0 + 490 + k * 110, 34, lab, 12, INK2)

    s.text(x0, 236, "Alice's deposit", 12.5, ALICE, 700)
    bar(246, 71000, [(30000, "D: minted on the L2", ALICE, ALICE_L), (20000, "r_A", ALICE, ALICE_L), (1000, "", FEE, FEE_L), (20000, "the fee budget", ALICE, ALICE_L)], "paid")
    bar(300, 71000, [(5000, "Bob's", BOB, BOB_L), (5000, "on the L2", ALICE, "#ffffff"), (20000, "b", ALICE, ALICE_L), (20000, "r_A", ALICE, ALICE_L), (1000, "", FEE, FEE_L), (19500, "the budget's rest", ALICE, ALICE_L), (500, "", FEE, FEE_L)], "now")
    sc = W / 71000
    s.text(x0 + 50500 * sc, 360, "funding fee share 1,000", 11, INK2, 400, "middle")
    s.text(x0 + W, 360, "sweep fee 500", 11, INK2, 400, "end")
    s.text(x0, 392, "D became tokens. 10,000 of them are still on the L2 (Bob's 5,000 and Alice's 5,000), with no contract behind them;", 12, INK2)
    s.text(x0, 410, "the 20,000 she returned came back as b. Her Bitcoin: 71,000 out, 40,000 + 19,500 = 59,500 back.", 12, INK2)
    s.text(x0, 440, "The hub: in 233,891 (V_max − D, r_H, its 1,000 fee share), back 241,891: +8,000, the 10,000 tokens outstanding less its 2,000 of fees.", 12, INK2)
    s.save("money")


if __name__ == "__main__":
    for f in (overview, l2, leaves, money):
        f()
