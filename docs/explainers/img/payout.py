#!/usr/bin/env python3
"""The diagrams of ../payout.md: a toy payout (base 2^10), and how
Mutinynet contract 1001's payout (Test B, 2026-10-12) reads b from Alice's
signature. Standard library only:
    python3 docs/explainers/img/payout.py
writes docs/explainers/img/payout-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(hub_absent.Svg):
    PREFIX = "payout"


# ---------------------------------------------------------------- the toy
def toy():
    s = Svg(1060, 560)
    s.text(24, 32, "A toy payout: cap 16,383, base 2^10, Alice's b = 5,120", 16, INK, 700)
    b, top, base = 5120, 13, 10
    # b in binary, bits 13 to 0
    s.text(24, 92, "b, binary", 13, INK, 700)
    x0, cw = 140, 52
    for k in range(top + 1):
        i = top - k
        bit = (b >> i) & 1
        paid = i >= base
        fill = (ALICE_L if bit else HUB_L) if paid else FEE_L
        stroke = (ALICE if bit else HUB) if paid else LINE
        x = x0 + k * cw
        s.rect(x, 70, cw - 6, 36, fill=fill, stroke=stroke, rx=5)
        s.text(x + (cw - 6) / 2, 95, str(bit), 17, INK if paid else INK2, 700, "middle", mono=True)
        s.text(x + (cw - 6) / 2, 124, f"2^{i}", 11, INK2, 400, "middle")
    s.line(x0, 136, x0 + 4 * cw - 8, 136, arrow=False)
    s.text(x0 + 2 * cw - 3, 154, "bits 10 to 13: an output each", 12, INK, 600, "middle")
    s.line(x0 + 4 * cw, 136, x0 + 14 * cw - 8, 136, stroke=LINE, arrow=False)
    s.text(x0 + 9 * cw - 3, 154, "bits 0 to 9: no outputs; one output of 1,023 to the hub", 12, INK2, 400, "middle")

    # the transaction
    ty = 196
    s.rect(24, ty + 40, 150, 70, fill=CON_L, stroke=CON, sw=1.6)
    s.text(99, ty + 66, "the contract", 14, INK, 700, "middle")
    s.text(99, ty + 84, "16,383 + 30,000", 11.5, INK2, 400, "middle")
    s.text(99, ty + 100, "= 46,383", 11.5, INK2, 400, "middle")
    s.line(174, ty + 75, 218, ty + 75)
    s.rect(220, ty + 20, 150, 110, fill=ALICE_L, stroke=ALICE, sw=1.6)
    s.text(295, ty + 50, "the payout", 14, INK, 700, "middle")
    s.text(295, ty + 70, "pre-signed at opening,", 11.5, INK2, 400, "middle")
    s.text(295, ty + 86, "before b is known;", 11.5, INK2, 400, "middle")
    s.text(295, ty + 102, "used when Alice", 11.5, INK2, 400, "middle")
    s.text(295, ty + 118, "wins the dispute", 11.5, INK2, 400, "middle")
    outs = [
        (1024, "bit 10 of b is 1", "Alice's, after δ", ALICE),
        (2048, "bit 11 of b is 0", "the hub's", HUB),
        (4096, "bit 12 of b is 1", "Alice's, after δ", ALICE),
        (8192, "bit 13 of b is 0", "the hub's", HUB),
        (30000, "both reserves", "Alice's, after δ", ALICE),
        (1023, "bits 0 to 9 of the cap", "the hub's address", HUB),
    ]
    oy = ty
    for k, (v, why, who, col) in enumerate(outs):
        y = oy + k * 40
        s.rect(420, y, 360, 32, fill=ALICE_L if col == ALICE else HUB_L, stroke=col, rx=5)
        s.text(434, y + 21, n(v), 13, INK, 700)
        s.text(504, y + 21, why, 12, INK)
        s.text(766, y + 21, who, 12, col, 600, "end")
        s.path(f"M 370 {ty + 75} C 395 {ty + 75}, 395 {y + 16}, 418 {y + 16}", sw=1.2)
    s.text(420, oy + 6 * 40 + 14, "Each bit output can go either way; Alice's signed b decides which.", 11.5, INK2, italic=True)

    # totals
    tx = 812
    s.rect(tx, ty, 224, 232, fill="#fafafa", stroke=LINE)
    s.text(tx + 16, ty + 26, "Alice", 14, ALICE, 700)
    s.text(tx + 16, ty + 48, "4,096 + 1,024 = 5,120", 12.5, INK)
    s.text(tx + 16, ty + 66, "+ reserves 30,000", 12.5, INK)
    s.text(tx + 16, ty + 86, "= 35,120", 12.5, INK, 700)
    s.text(tx + 16, ty + 122, "The hub", 14, HUB, 700)
    s.text(tx + 16, ty + 144, "8,192 + 2,048 + 1,023", 12.5, INK)
    s.text(tx + 16, ty + 164, "= 11,263 = 16,383 − 5,120", 12.5, INK, 700)
    s.text(tx + 16, ty + 196, "together: 46,383,", 11.5, INK2, italic=True)
    s.text(tx + 16, ty + 213, "the whole contract", 11.5, INK2, italic=True)

    # the leaves of one bit output
    ly = 476
    s.text(24, ly, "Every bit output (here bit 12's) has the same three leaves:", 13, INK, 700)
    leaves = [
        ("alice_bit_12", "Alice, after δ, if bit 12 of her signed b is 1", ALICE, ALICE_L),
        ("hub_bit_12", "the hub, at once, if it is 0", HUB, HUB_L),
        ("equiv_b_12", "the hub, at once, if she signed two values of b", HUB, HUB_L),
    ]
    for k, (name, what, col, fill) in enumerate(leaves):
        x = 24 + k * 340
        s.rect(x, ly + 14, 328, 50, fill=fill, stroke=col, rx=6)
        s.text(x + 12, ly + 34, name, 12.5, INK, 700, mono=True)
        s.text(x + 12, ly + 53, what, 11.5, INK2)
    s.save("toy")


# ---------------------------------------------------------------- reading b
def read():
    s = Svg(1060, 600)
    s.text(24, 32, "Test B: reading b = 35,000 off the chain, and deciding two outputs", 16, INK, 700)
    s.text(24, 56, "The sweep's input for bit 11 (21ee8b9f…, input 0) carries Alice's one-time signature on b: ten digits, each with its hash.", 12, INK2)
    digits = [0, 0, 0, 0, 8, 8, 11, 8, 5, 5]
    x0, cw, y = 24, 64, 76
    for k, d in enumerate(digits):
        chk = k >= 8
        x = x0 + k * cw + (16 if chk else 0)
        s.rect(x, y, cw - 8, 40, fill=FEE_L if chk else CON_L, stroke=FEE if chk else CON, rx=5)
        s.text(x + (cw - 8) / 2, y + 26, format(d, "X"), 17, INK, 700, "middle", mono=True)
        s.text(x + (cw - 8) / 2, y + 56, f"nibble {k}" if not chk else f"check {k - 8}", 10.5, INK2, 400, "middle")
    s.text(x0 + 4 * cw - 4, y + 82, "8 message digits, big-endian: 0x000088B8 = 35,000", 12.5, INK, 600, "middle")
    s.text(x0 + 9 * cw + 12, y + 82, "0x55 = 85 = Σ (15 − d)", 12.5, INK, 600, "middle")

    # the low 16 bits, by nibble
    by = 214
    s.text(24, by - 10, "The low four nibbles in binary: an output for each bit from 9 up (bits below 9 get none)", 13, INK, 700)
    bx, bw = 24, 58
    b = 35000
    for k in range(16):
        i = 15 - k
        bit = (b >> i) & 1
        paid = i >= 9
        x = bx + k * bw + (k // 4) * 14
        fill = (ALICE_L if bit else HUB_L) if paid else FEE_L
        stroke = (ALICE if bit else HUB) if paid else LINE
        s.rect(x, by + 4, bw - 8, 36, fill=fill, stroke=stroke, rx=5)
        s.text(x + (bw - 8) / 2, by + 29, str(bit), 16, INK if paid else INK2, 700, "middle", mono=True)
        s.text(x + (bw - 8) / 2, by + 56, f"bit {i}", 10.5, INK2, 400, "middle")
    for k, (lab, v) in enumerate([("nibble 4", 8), ("nibble 5", 8), ("nibble 6", 11), ("nibble 7", 8)]):
        x = bx + k * (4 * bw + 14)
        s.text(x + 2 * bw - 4, by + 80, f"{lab} = {format(v, 'X')} = {v:04b}", 12, INK, 600, "middle")

    # two leaves deciding
    cy = 340
    s.text(24, cy, "Each bit leaf checks the whole signature, picks its nibble, and tests one bit of it:", 13, INK, 700)
    cards = [
        ("alice_bit_11", ALICE, ALICE_L, [
            "bit 11 = bit 3 of nibble 5 (bits 8–11)",
            "nibble 5 = 8",
            "8 ≥ 8?  yes: the bit is 1",
            "→ the 2,048 output is Alice's (after δ = 40 blocks)",
            "spent by the sweep: 1,122 B of witness, 787 B of it script",
        ]),
        ("hub_bit_9", HUB, HUB_L, [
            "bit 9 = bit 1 of nibble 5",
            "nibble 5 = 8; reduce mod 4: 8 − 8 = 0",
            "0 ≥ 2?  no: the bit is 0, and OP_NOT makes that a pass",
            "→ the 512 output is the hub's (no wait)",
            "collected by the hub's sweep of its bits, block 3,513,196",
        ]),
    ]
    for k, (name, col, fill, lines) in enumerate(cards):
        x = 24 + k * 512
        s.rect(x, cy + 16, 500, 150, fill=fill, stroke=col, sw=1.4)
        s.text(x + 16, cy + 42, name, 14, INK, 700, mono=True)
        for j, l in enumerate(lines):
            s.text(x + 16, cy + 66 + 20 * j, l, 12, INK if j < 3 else col, 400 if j < 3 else 600)
    s.text(24, cy + 196, "Nobody else can change the reading: a Winternitz digit's hash can only be hashed further (to a larger digit), and the", 12, INK2)
    s.text(24, cy + 214, "checksum digits would then have to get smaller, which needs a preimage. Two different values of b signed by Alice herself are", 12, INK2)
    s.text(24, cy + 232, "an equivocation: the hub's equiv_b leaf on every output takes them, which is why her leaves wait δ.", 12, INK2)
    s.save("read")


if __name__ == "__main__":
    for f in (toy, read):
        f()
