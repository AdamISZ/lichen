#!/usr/bin/env python3
"""The diagrams of ../payout.md: a toy payout (a unit of 1,000, 4 bits),
and how Mutinynet contract 1002's payout (Erin's exit, 2026-11-11) reads
b from Alice's signature. Standard library only:
    python3 docs/explainers/img/payout.py
writes docs/explainers/img/payout-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import svg  # noqa: E402
from svg import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L, n  # noqa: E402


class Svg(svg.Svg):
    PREFIX = "payout"


# ---------------------------------------------------------------- the toy
def toy():
    s = Svg(1060, 560)
    s.text(24, 32, "A toy payout: a unit of 1,000 sats, 4 bits, a cap of 15 units; Alice's b = 9 units", 16, INK, 700)
    b, k_bits, u = 9, 4, 1000
    # b in binary, bits 3 to 0
    s.text(24, 92, "b, binary", 13, INK, 700)
    x0, cw = 140, 90
    for k in range(k_bits):
        i = k_bits - 1 - k
        bit = (b >> i) & 1
        x = x0 + k * cw
        s.rect(x, 70, cw - 10, 36, fill=ALICE_L if bit else HUB_L, stroke=ALICE if bit else HUB, rx=5)
        s.text(x + (cw - 10) / 2, 95, str(bit), 17, INK, 700, "middle", mono=True)
        s.text(x + (cw - 10) / 2, 124, f"{n(u << i)} sats", 11, INK2, 400, "middle")
    s.text(x0 + k_bits * cw + 10, 95, "= 9 units: every bit has an output of u·2^i", 12, INK, 600)
    s.text(x0 + k_bits * cw + 10, 113, "(none is under 512 sats, so none is dust)", 11.5, INK2)

    # the transaction
    ty = 196
    s.rect(24, ty + 40, 150, 70, fill=CON_L, stroke=CON, sw=1.6)
    s.text(99, ty + 66, "the contract", 14, INK, 700, "middle")
    s.text(99, ty + 84, "15,000 + 30,000", 11.5, INK2, 400, "middle")
    s.text(99, ty + 100, "= 45,000", 11.5, INK2, 400, "middle")
    s.line(174, ty + 75, 218, ty + 75)
    s.rect(220, ty + 20, 150, 110, fill=ALICE_L, stroke=ALICE, sw=1.6)
    s.text(295, ty + 50, "the payout", 14, INK, 700, "middle")
    s.text(295, ty + 70, "pre-signed at opening,", 11.5, INK2, 400, "middle")
    s.text(295, ty + 86, "before b is known;", 11.5, INK2, 400, "middle")
    s.text(295, ty + 102, "used when Alice", 11.5, INK2, 400, "middle")
    s.text(295, ty + 118, "wins the exit", 11.5, INK2, 400, "middle")
    outs = [
        (1000, "bit 0 of b is 1", "Alice's, after δ", ALICE),
        (2000, "bit 1 of b is 0", "the hub's", HUB),
        (4000, "bit 2 of b is 0", "the hub's", HUB),
        (8000, "bit 3 of b is 1", "Alice's, after δ", ALICE),
        (30000, "both reserves", "Alice's, after δ", ALICE),
    ]
    oy = ty
    for k, (v, why, who, col) in enumerate(outs):
        y = oy + k * 40
        s.rect(420, y, 360, 32, fill=ALICE_L if col == ALICE else HUB_L, stroke=col, rx=5)
        s.text(434, y + 21, n(v), 13, INK, 700)
        s.text(504, y + 21, why, 12, INK)
        s.text(766, y + 21, who, 12, col, 600, "end")
        s.path(f"M 370 {ty + 75} C 395 {ty + 75}, 395 {y + 16}, 418 {y + 16}", sw=1.2)
    s.text(420, oy + 5 * 40 + 14, "Each bit output can go either way; Alice's signed b decides which.", 11.5, INK2, italic=True)

    # totals
    tx = 812
    s.rect(tx, ty, 224, 232, fill="#fafafa", stroke=LINE)
    s.text(tx + 16, ty + 26, "Alice", 14, ALICE, 700)
    s.text(tx + 16, ty + 48, "8,000 + 1,000 = 9,000", 12.5, INK)
    s.text(tx + 16, ty + 66, "+ reserves 30,000", 12.5, INK)
    s.text(tx + 16, ty + 86, "= 39,000", 12.5, INK, 700)
    s.text(tx + 16, ty + 122, "The hub", 14, HUB, 700)
    s.text(tx + 16, ty + 144, "4,000 + 2,000", 12.5, INK)
    s.text(tx + 16, ty + 164, "= 6,000 = 15,000 − 9,000", 12.5, INK, 700)
    s.text(tx + 16, ty + 196, "together: 45,000,", 11.5, INK2, italic=True)
    s.text(tx + 16, ty + 213, "the whole contract", 11.5, INK2, italic=True)

    # the leaves of one bit output
    ly = 476
    s.text(24, ly, "Every bit output (here bit 3's) has the same three leaves:", 13, INK, 700)
    leaves = [
        ("alice_bit_3", "Alice, after δ, if bit 3 of her signed b is 1", ALICE, ALICE_L),
        ("hub_bit_3", "the hub, at once, if it is 0", HUB, HUB_L),
        ("equiv_b_3", "the hub, at once, if she signed two values of b", HUB, HUB_L),
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
    s.text(24, 32, "Erin's exit: reading b = 126 units off the chain, and deciding two outputs", 16, INK, 700)
    s.text(24, 56, "Her request (834b657f…) carries her one-time signature on b: ten digits, each with its hash; each bit leaf checks it again.", 12, INK2)
    digits = [0, 0, 0, 0, 0, 0, 7, 14, 6, 3]
    x0, cw, y = 24, 64, 76
    for k, d in enumerate(digits):
        chk = k >= 8
        x = x0 + k * cw + (16 if chk else 0)
        s.rect(x, y, cw - 8, 40, fill=FEE_L if chk else CON_L, stroke=FEE if chk else CON, rx=5)
        s.text(x + (cw - 8) / 2, y + 26, format(d, "X"), 17, INK, 700, "middle", mono=True)
        s.text(x + (cw - 8) / 2, y + 56, f"nibble {k}" if not chk else f"check {k - 8}", 10.5, INK2, 400, "middle")
    s.text(x0 + 4 * cw - 4, y + 82, "8 message digits, big-endian: 0x0000007E = 126 units", 12.5, INK, 600, "middle")
    s.text(x0 + 9 * cw + 12, y + 82, "0x63 = 99 = Σ (15 − d)", 12.5, INK, 600, "middle")

    # the 8 bits, by nibble
    by = 214
    s.text(24, by - 10, "The contract's 8 bits, in its last two nibbles: an output of 781 · 2^i for each", 13, INK, 700)
    bx, bw = 24, 116
    b = 126
    for k in range(8):
        i = 7 - k
        bit = (b >> i) & 1
        x = bx + k * bw + (k // 4) * 28
        s.rect(x, by + 4, bw - 10, 36, fill=ALICE_L if bit else HUB_L, stroke=ALICE if bit else HUB, rx=5)
        s.text(x + (bw - 10) / 2, by + 29, str(bit), 16, INK, 700, "middle", mono=True)
        s.text(x + (bw - 10) / 2, by + 56, f"bit {i}: {n(781 << i)}", 10.5, INK2, 400, "middle")
    for k, (lab, v) in enumerate([("nibble 6", 7), ("nibble 7", 14)]):
        x = bx + k * (4 * bw + 28)
        s.text(x + 2 * bw - 4, by + 80, f"{lab} = {format(v, 'X')} = {v:04b}", 12, INK, 600, "middle")

    # two leaves deciding
    cy = 340
    s.text(24, cy, "Each bit leaf checks the whole signature, picks its nibble, and tests one bit of it:", 13, INK, 700)
    cards = [
        ("alice_bit_6", ALICE, ALICE_L, [
            "bit 6 = bit 2 of nibble 6 (bits 4–7)",
            "nibble 6 = 7; reduce mod 8: 7",
            "7 ≥ 4?  yes: the bit is 1",
            "→ the 49,984 output is Erin's (after δ = 40 blocks)",
            "swept by her sweep: 1,127 B of witness, 794 B of it script",
        ]),
        ("hub_bit_7", HUB, HUB_L, [
            "bit 7 = bit 3 of nibble 6",
            "nibble 6 = 7; reduce mod 16: 7",
            "7 ≥ 8?  no: the bit is 0, and OP_NOT makes that a pass",
            "→ the 99,968 output is the hub's (no wait)",
            "collected by the hub the next block (69fa312f…)",
        ]),
    ]
    for k, (name, col, fill, lines) in enumerate(cards):
        x = 24 + k * 512
        s.rect(x, cy + 16, 500, 150, fill=fill, stroke=col, sw=1.4)
        s.text(x + 16, cy + 42, name, 14, INK, 700, mono=True)
        for j, l in enumerate(lines):
            s.text(x + 16, cy + 66 + 20 * j, l, 12, INK if j < 3 else col, 400 if j < 3 else 600)
    s.text(24, cy + 196, "Nobody else can change the reading: a Winternitz digit's hash can only be hashed further (to a larger digit), and the", 12, INK2)
    s.text(24, cy + 214, "checksum digits would then have to get smaller, which needs a preimage. Two different values of b signed by Erin herself are", 12, INK2)
    s.text(24, cy + 232, "an equivocation: the hub's equiv_b leaf on every output takes them, which is why her leaves wait δ.", 12, INK2)
    s.save("read")


if __name__ == "__main__":
    for f in sys.argv[1:] or ("toy", "read"):
        globals()[f]()
