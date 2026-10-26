#!/usr/bin/env python3
"""The diagrams of ../hub-absent.md, from the transactions of Mutinynet
contract 1001 (2026-10-12). Standard library only:
    python3 docs/explainers/img/hub_absent.py
writes docs/explainers/img/hub-absent-*.svg."""

import os

HERE = os.path.dirname(os.path.abspath(__file__))

# palette: Alice blue, the hub orange, the contract purple, fees grey
ALICE, ALICE_L = "#2563eb", "#dbeafe"
HUB, HUB_L = "#c2410c", "#ffedd5"
CON, CON_L = "#7c3aed", "#ede9fe"
FEE, FEE_L = "#6b7280", "#f3f4f6"
INK, INK2, LINE = "#111827", "#4b5563", "#d1d5db"
OK, OK_L = "#15803d", "#dcfce7"
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Svg:
    PREFIX = "hub-absent"

    def __init__(self, w, h):
        self.w, self.h, self.parts = w, h, []

    def add(self, s):
        self.parts.append(s)

    def rect(self, x, y, w, h, fill="none", stroke=LINE, rx=8, sw=1.2, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def text(self, x, y, s, size=13, fill=INK, weight=400, anchor="start", mono=False, italic=False):
        f = MONO if mono else SANS
        st = ' font-style="italic"' if italic else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{f}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, stroke=INK2, sw=1.5, arrow=True, dash=None):
        m = ' marker-end="url(#ah)"' if arrow else ""
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"{m}{d}/>')

    def path(self, d, stroke=INK2, sw=1.5, arrow=True, dash=None):
        m = ' marker-end="url(#ah)"' if arrow else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}"{m}{da}/>')

    def circle(self, x, y, r, fill="#fff", stroke=INK2, sw=1.5):
        self.add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')

    def save(self, name):
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}">'
                f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                f'<path d="M0,0 L10,5 L0,10 z" fill="{INK2}"/></marker></defs>'
                f'<rect x="0.5" y="0.5" width="{self.w - 1}" height="{self.h - 1}" rx="12" fill="#ffffff" stroke="#e5e7eb"/>')
        with open(os.path.join(HERE, f"{self.PREFIX}-{name}.svg"), "w") as f:
            f.write(head + "".join(self.parts) + "</svg>\n")


def n(v):
    return f"{v:,}"


def tx_box(s, x, y, w, h, title, sub, fill, stroke, sub2=None):
    s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=1.6)
    s.text(x + w / 2, y + 21, title, 14, INK, 700, "middle")
    s.text(x + w / 2, y + 38, sub, 11.5, INK2, 400, "middle")
    if sub2:
        s.text(x + w / 2, y + 53, sub2, 11.5, INK2, 400, "middle")


# ---------------------------------------------------------------- overview
def overview():
    s = Svg(1180, 530)
    s.text(24, 32, "Contract 1001: every transaction, and what happened off chain", 16, INK, 700)
    # the L2 lane
    s.rect(16, 50, 1148, 112, fill="#fafafa", stroke=LINE, dash="5 4")
    s.text(28, 70, "off chain", 12, INK2, 700)
    offs = [
        (180, "mint 30,000 tokens", "the hub, at funding"),
        (380, "return 35,000 tokens", "memo 1001 (an L2 transfer)"),
        (580, "prove", "RISC Zero → Groth16: 204 B"),
        (780, "trace", "477,810,565 steps, halts 0"),
    ]
    for x, t, u in offs:
        s.rect(x, 82, 170, 60, fill="#ffffff", stroke="#9ca3af", dash="4 3")
        s.text(x + 85, 106, t, 13, INK, 600, "middle")
        s.text(x + 85, 124, u, 11, INK2, 400, "middle")
    for a, b in [(350, 380), (550, 580), (750, 780)]:
        s.line(a, 112, b - 2, 112)

    # the chain lane
    y, h, w = 220, 62, 124
    xs = {"deposit": 50, "funding": 238, "escalate": 426, "inputs": 614, "timeout": 802, "sweep": 990}
    tx_box(s, xs["deposit"], y, w, h, "deposit", "3,500,811", FEE_L, FEE, "154 vB")
    tx_box(s, xs["funding"], y, w, h, "funding", "3,500,812", CON_L, CON, "305 vB")
    tx_box(s, xs["escalate"], y, w, h, "escalate", "3,500,867", ALICE_L, ALICE, "11,586 vB")
    tx_box(s, xs["inputs"], y, w, h, "inputs", "3,500,868", ALICE_L, ALICE, "9,932 vB")
    tx_box(s, xs["timeout"], y, w, h, "timeout", "3,500,949", ALICE_L, ALICE, "589 vB")
    tx_box(s, xs["sweep"], y, w, h, "sweep", "3,500,990", ALICE_L, ALICE, "790 vB")
    my = y + h / 2
    for a, b, lab in [("deposit", "funding", "71,000"), ("funding", "escalate", "282,891"), ("escalate", "inputs", "270,954"), ("inputs", "timeout", "260,688"), ("timeout", "sweep", "229,969")]:
        s.line(xs[a] + w, my, xs[b] - 2, my)
        s.text((xs[a] + w + xs[b]) / 2, my - 8, lab, 11.5, INK, 600, "middle")
    # the claim and the trace's hashes go into escalate (and inputs)
    s.path(f"M 865 143 C 865 190, {xs['escalate'] + 62} 180, {xs['escalate'] + 62} {y - 3}", dash="4 3")
    s.path(f"M 665 143 C 665 180, {xs['inputs'] + 62} 190, {xs['inputs'] + 62} {y - 3}", dash="4 3")
    s.text(880, 172, "move 1, from the trace: to escalate", 11.5, INK2)
    s.text(655, 196, "the input's 51 words: 11 to escalate, 40 to inputs", 11.5, INK2, 400, "end")
    # the mint, from the funding
    s.line(xs["funding"] + w / 2, y - 2, 240, 144, dash="4 3", arrow=False)
    # payer and payout
    s.circle(24, my, 7)
    s.text(24, my + 24, "payer", 10.5, INK2, 400, "middle")
    s.line(31, my, xs["deposit"] - 2, my)
    s.line(xs["sweep"] + w, my, 1150, my)
    s.circle(1156, my, 6, stroke=ALICE)
    s.text(1160, my + 26, "payout", 10.5, ALICE, 600, "end")
    s.text(1160, my + 40, "228,769", 10.5, ALICE, 600, "end")

    # stubs below: what each leaves behind
    def stub(x, label, sub, color):
        s.line(x, y + h, x, 352, stroke=color, arrow=False)
        s.circle(x, 358, 6, stroke=color)
        s.text(x, 382, label, 11.5, color, 600, "middle")
        if sub:
            s.text(x, 397, sub, 10.5, INK2, 400, "middle")

    stub(xs["deposit"] + 62, "157,489", "payer's change", FEE)
    stub(xs["funding"] + 90, "232,073", "hub's change", HUB)
    stub(xs["escalate"] + 62, "330", "anchor", ALICE)
    stub(xs["inputs"] + 90, "330", "anchor", ALICE)
    stub(xs["timeout"] + 90, "30,719", "the hub's share", HUB)
    # the fee budget lane
    fy = 430
    bx = xs["inputs"] - 40
    s.path(f"M {xs['funding'] + 30} {y + h} L {xs['funding'] + 30} {fy + 25} L {bx - 2} {fy + 25}")
    s.text(xs["funding"] + 40, fy + 18, "20,000: Alice's fee budget", 11.5, ALICE, 600)
    tx_box(s, bx, fy, 130, 50, "split", "3,500,949 · 154 vB", ALICE_L, ALICE)
    s.path(f"M {bx + 130} {fy + 25} L {xs['timeout'] + 30} {fy + 25} L {xs['timeout'] + 30} {y + h + 2}")
    s.text(bx + 140, fy + 18, "2,000: the fee coin", 11.5, INK, 600)
    s.path(f"M {bx + 65} {fy + 50} L {bx + 65} {fy + 70} L {xs['sweep'] - 6} {fy + 70}", arrow=False)
    s.circle(xs["sweep"], fy + 70, 6, stroke=ALICE)
    s.text(xs["sweep"] + 12, fy + 74, "17,840: sweep-fees, to come", 11, ALICE, 600)
    s.save("overview")


# ---------------------------------------------------------------- the outputs and their leaves
def leaves():
    s = Svg(1060, 796)
    s.text(24, 32, "The outputs on the dispute path: who could spend each one, and how", 16, INK, 700)
    s.text(24, 52, "✓ the leaf this dispute used. Grey: what the hub could have done, had it been there.", 12, INK2)
    cards = [
        ("contract output", "282,891", "funding:0", [
            ("fold", "2-of-2, signed when it happens", "the cooperative withdrawal (Test A)", None),
            ("default", "2-of-2 pre-signed, after T_close 3,520,971", "the hub's, Alice's reserve back to her", None),
            ("escalate", "2-of-2 pre-signed, after 10 blocks", "Alice's claim and move 1", True),
        ]),
        ("claimed output", "270,954", "escalate:0", [
            ("inputs", "2-of-2 pre-signed", "the rest of Alice's input", True),
            ("split_HubWins", "2-of-2 pre-signed, after 80 blocks", "everything to the hub, if Alice stalls", None),
        ]),
        ("ladder output after move 1", "260,688", "inputs:0", [
            ("post", "2-of-2 pre-signed, after 1 block", "the hub's move 2, its first choice", None),
            ("split_UserWins", "2-of-2 pre-signed, after 80 blocks", "the payout, if the hub doesn't move", True),
            ("18 input-word checks", "the hub, at once", "journal_len, memo, image_1…8, deployment_1…8 wrong", None),
            ("equiv_d_1_0 … 7", "the hub, at once", "a field of move 1 signed two ways", None),
        ]),
    ]
    x0, cw = 24, 1012
    y = 72
    spent_by = {"contract output": "escalate cb5b1dd1…", "claimed output": "inputs 47b2ad8a…", "ladder output after move 1": "timeout d6bf7b34…"}
    for title, value, where, ls in cards:
        hh = 46 + 34 * len(ls)
        s.rect(x0, y, cw, hh, fill="#ffffff", stroke=CON, sw=1.6)
        s.text(x0 + 16, y + 25, title, 14, INK, 700)
        s.text(x0 + 250, y + 25, value + " sats", 13, CON, 700)
        s.text(x0 + cw - 16, y + 25, where, 11.5, INK2, 400, "end", mono=True)
        for i, (name, cond, what, used) in enumerate(ls):
            ly = y + 38 + 34 * i
            fill, stroke, ink = (OK_L, OK, INK) if used else (FEE_L, LINE, INK2)
            s.rect(x0 + 12, ly, cw - 24, 28, fill=fill, stroke=stroke, rx=6)
            s.text(x0 + 26, ly + 19, ("✓ " if used else "") + name, 12.5, ink, 700, mono=True)
            s.text(x0 + 250, ly + 19, cond, 12, ink)
            s.text(x0 + 600, ly + 19, what, 12, ink)
        y += hh + 34
        s.line(x0 + cw / 2, y - 34, x0 + cw / 2, y - 2)
        s.text(x0 + cw / 2 + 12, y - 13, spent_by[title], 11.5, INK2, 400, mono=True)
    half = (cw - 20) / 2
    for k, (title, value, ls) in enumerate([
        ("each bit output 2^i, i = 9 … 15", "512 … 32,768", [
            ("alice_bit_i", "Alice, after 40 blocks", "if bit i of her signed b is 1", True),
            ("hub_bit_i", "the hub, at once", "if bit i is 0", None),
            ("equiv_b_i", "the hub, at once", "b signed two ways", None),
        ]),
        ("the reserve output", "195,153", [
            ("alice_reserve", "Alice, after 40 blocks", "both reserves, less the floors", True),
            ("equiv_b_16", "the hub, at once", "b signed two ways", None),
        ]),
    ]):
        x = x0 + k * (half + 20)
        hh = 46 + 34 * 3
        s.rect(x, y, half, hh, fill="#ffffff", stroke=CON, sw=1.6)
        s.text(x + 14, y + 25, title, 13.5, INK, 700)
        s.text(x + half - 14, y + 25, value, 12.5, CON, 700, "end")
        for i, (name, cond, what, used) in enumerate(ls):
            ly = y + 38 + 34 * i
            fill, stroke, ink = (OK_L, OK, INK) if used else (FEE_L, LINE, INK2)
            s.rect(x + 10, ly, half - 20, 28, fill=fill, stroke=stroke, rx=6)
            s.text(x + 20, ly + 19, ("✓ " if used else "") + name, 12, ink, 700, mono=True)
            s.text(x + 150, ly + 19, cond, 11.5, ink)
            s.text(x + 312, ly + 19, what, 11.5, ink)
    s.save("leaves")


# ---------------------------------------------------------------- sizes
def sizes():
    s = Svg(1060, 420)
    s.text(24, 32, "What the bytes are: the two big transactions, by virtual size", 16, INK, 700)
    s.text(24, 52, "The scripts verify Winternitz one-time signatures, one 4-bit digit at a time: about 74 bytes of script and 23 of witness per digit.", 12, INK2)
    # weight units / 4 = vB
    rows = [
        ("escalate", 11586, [("transaction", 550, FEE), ("leaf script: 470 digits' checks", 34834, CON), ("one-time signatures: 470 digits", 10756, ALICE), ("2 signatures, control block", 201, INK2)]),
        ("inputs", 9932, [("transaction", 550, FEE), ("leaf script: 400 digits' checks", 29794, CON), ("one-time signatures: 400 digits", 9180, ALICE), ("2 signatures, control block", 201, INK2)]),
    ]
    scale = 820 / 11586
    x0 = 120
    y = 82
    for name, vs, parts in rows:
        s.text(24, y + 26, name, 14, INK, 700)
        x = x0
        for lab, wu, col in parts:
            vb = wu / 4
            ww = vb * scale
            s.add(f'<rect x="{x:.1f}" y="{y}" width="{ww:.1f}" height="40" fill="{col}" opacity="0.85"/>')
            if ww > 140:
                s.text(x + ww / 2, y + 18, lab, 11.5, "#ffffff", 600, "middle")
                s.text(x + ww / 2, y + 33, f"{vb:,.0f} vB", 11.5, "#ffffff", 400, "middle")
            x += ww
        s.text(x + 8, y + 26, f"{n(vs)} vB", 13, INK, 700)
        y += 70
    s.text(x0, y + 6, "Grey: the transaction itself (one input, two outputs), 137 vB. Dark: two Schnorr signatures and the control block, 50 vB.", 11.5, INK2)
    # the small ones, to the same scale
    y += 40
    s.text(24, y, "To the same scale", 13, INK, 700)
    y += 14
    for name, vs, col in [("split", 154, ALICE), ("timeout", 589, ALICE), ("sweep", 790, ALICE), ("fold (Test A)", 193, OK)]:
        s.text(24, y + 15, name, 12.5, INK, 600)
        s.add(f'<rect x="{x0}" y="{y + 2}" width="{max(vs * scale, 2):.1f}" height="18" fill="{col}" opacity="0.85"/>')
        s.text(x0 + vs * scale + 8, y + 16, f"{n(vs)} vB", 12, INK)
        y += 28
    s.text(x0 + 300, y - 74, "the five dispute transactions: 23,051 vB", 13, INK, 700)
    s.text(x0 + 300, y - 56, "the cooperative fold: 193 vB, about 120× less", 13, OK, 700)
    s.save("sizes")


# ---------------------------------------------------------------- the payout: b in bits
def payout():
    s = Svg(1060, 520)
    s.text(24, 32, "The timeout's payout: b = 35,000 in bits", 16, INK, 700)
    b = 35000
    bits = [(b >> i) & 1 for i in range(15, -1, -1)]
    x0, cw = 140, 50
    s.text(24, 92, "b, binary", 13, INK, 700)
    for k, bit in enumerate(bits):
        i = 15 - k
        x = x0 + k * cw
        paid = i >= 9
        fill = (ALICE_L if bit else HUB_L) if paid else FEE_L
        stroke = (ALICE if bit else HUB) if paid else LINE
        s.rect(x, 70, cw - 6, 36, fill=fill, stroke=stroke, rx=5)
        s.text(x + (cw - 6) / 2, 95, str(bit), 17, INK if paid else INK2, 700, "middle", mono=True)
        s.text(x + (cw - 6) / 2, 124, f"2^{i}", 11, INK2, 400, "middle")
    s.text(x0 + 3.5 * cw - 3, 154, "bits 9 to 15: an output each", 12, INK, 600, "middle")
    s.line(x0, 136, x0 + 7 * cw - 8, 136, stroke=INK2, arrow=False)
    s.text(x0 + 11.5 * cw - 3, 154, "bits 0 to 8: no output (dust); paid to the hub", 12, INK2, 400, "middle")
    s.line(x0 + 7 * cw, 136, x0 + 16 * cw - 8, 136, stroke=LINE, arrow=False)
    # the outputs
    outs = [(512, 9), (1024, 10), (2048, 11), (4096, 12), (8192, 13), (16384, 14), (32768, 15)]
    y = 186
    s.text(24, y + 4, "outputs", 13, INK, 700)
    s.text(140, y + 4, "timeout d6bf7b34…, 589 vB: in, the ladder output (260,688) and Alice's fee coin (2,000), all of it the fee", 12, INK2)
    y += 22
    for k, (v, i) in enumerate(outs):
        a = (b >> i) & 1
        s.rect(140, y, 520, 26, fill=ALICE_L if a else HUB_L, stroke=ALICE if a else HUB, rx=5)
        s.text(152, y + 18, f"{k}", 11.5, INK2, 400, mono=True)
        s.text(176, y + 18, f"{n(v)}", 12.5, INK, 700)
        s.text(260, y + 18, f"bit {i} = {a}", 12, INK)
        s.text(360, y + 18, "Alice's: spent by the sweep" if a else "the hub's: collected at 3,513,196", 12, ALICE if a else HUB, 600)
        y += 30
    for k, (v, lab, who) in enumerate([(195153, "both reserves less the floors: Alice's, spent by the sweep", ALICE), (511, "bits 0 to 8 of V_max: the hub's payout address", HUB)]):
        s.rect(140, y, 520, 26, fill=ALICE_L if who == ALICE else HUB_L, stroke=who, rx=5)
        s.text(152, y + 18, f"{7 + k}", 11.5, INK2, 400, mono=True)
        s.text(176, y + 18, n(v), 12.5, INK, 700)
        s.text(260, y + 18, lab, 12, who, 600)
        y += 30
    # totals
    tx = 700
    s.rect(tx, 208, 336, 236, fill="#fafafa", stroke=LINE)
    s.text(tx + 16, 234, "Alice", 14, ALICE, 700)
    s.text(tx + 16, 256, "2,048 + 32,768 = 34,816 of b", 12.5, INK)
    s.text(tx + 16, 274, "r_A 20,000 + r_H 197,356", 12.5, INK)
    s.text(tx + 16, 292, "  − floors 21,543 − anchors 660 = 195,153", 12.5, INK)
    s.text(tx + 16, 312, "229,969, then the sweep's 1,200 fee", 12.5, INK, 700)
    s.text(tx + 16, 346, "The hub", 14, HUB, 700)
    s.text(tx + 16, 368, "65,535 − 34,816 = 30,719 of V_max:", 12.5, INK)
    s.text(tx + 16, 386, "five bit outputs (30,208) and 511", 12.5, INK)
    s.text(tx + 16, 404, "its reserve: forfeited", 12.5, INK, 700)
    s.text(tx + 16, 428, "b's low 184 sats stay with the hub, in the 511", 11.5, INK2, italic=True)
    s.save("payout")


# ---------------------------------------------------------------- the money
def money():
    s = Svg(1060, 330)
    s.text(24, 32, "The contract's 282,891 sats: where they came from, where they went", 16, INK, 700)
    total = 282891
    x0, W = 120, 900
    sc = W / total

    def bar(y, segs, label):
        s.text(24, y + 25, label, 13, INK, 700)
        x = x0
        for v, lab, col, light in segs:
            ww = v * sc
            s.add(f'<rect x="{x:.1f}" y="{y}" width="{ww:.1f}" height="40" fill="{light}" stroke="{col}" stroke-width="1.2"/>')
            if ww > 50:
                s.text(x + ww / 2, y + 18, lab, 11.5, INK, 600, "middle")
                s.text(x + ww / 2, y + 33, n(v), 11.5, INK2, 400, "middle")
            x += ww
        return x

    bar(64, [(30000, "D, Alice's", ALICE, ALICE_L), (35535, "V_max − D, hub", HUB, HUB_L), (20000, "r_A, hers", ALICE, ALICE_L), (197356, "r_H: the hub's reserve", HUB, HUB_L)], "in")
    bar(150, [(34816, "b's bits", ALICE, ALICE_L), (20000, "r_A back", ALICE, ALICE_L), (175153, "r_H less the floors, to Alice", ALICE, ALICE_L), (21543, "floors", FEE, FEE_L), (660, "", ALICE, ALICE_L), (30719, "hub: V_max − b", HUB, HUB_L)], "out")
    s.text(x0 + (229969 + 21543 + 330) * sc, 210, "anchors 660 (Alice's)", 11, INK2, 400, "middle")
    for k, (lab, col, light) in enumerate([("Alice's", ALICE, ALICE_L), ("the hub's", HUB, HUB_L), ("fees", FEE, FEE_L)]):
        s.rect(x0 + 520 + k * 120, 22, 14, 14, fill=light, stroke=col, rx=2)
        s.text(x0 + 540 + k * 120, 34, lab, 12, INK2)
    s.text(x0, 250, "The contract funds no fees of its own except the links' floors (1 sat/vB each), and they come out of the loser's reserve.", 12, INK2)
    s.text(x0, 268, "Alice's other costs came from her fee budget, a separate 20,000 output: 160 (split) + 2,000 (the timeout's fee coin),", 12, INK2)
    s.text(x0, 286, "and the sweep's 1,200 came out of what it swept.", 12, INK2)
    s.save("money")


# ---------------------------------------------------------------- the timeline
def timeline():
    s = Svg(1060, 318)
    s.text(24, 32, "The dispute in blocks (30 s apart on Mutinynet), and the windows that set the pace", 16, INK, 700)
    lo, hi = 3500805, 3500998
    x0, W = 50, 960
    X = lambda h: x0 + (h - lo) * W / (hi - lo)
    y = 170
    s.line(x0, y, x0 + W, y, stroke=INK2, arrow=False)
    for h in range(3500810, hi, 10):
        s.line(X(h), y - 4, X(h), y + 4, stroke=INK2, arrow=False)
    for h in (3500820, 3500860, 3500900, 3500940, 3500980):
        s.text(X(h), y + 20, f"{h:,}", 10.5, INK2, 400, "middle")
    ev = [(3500812, "funding", "22:09", CON), (3500867, "escalate", "22:39", ALICE), (3500868, "inputs", "22:39", ALICE), (3500949, "timeout", "23:24", ALICE), (3500990, "sweep", "23:46", ALICE)]
    for k, (h, lab, t, col) in enumerate(ev):
        s.circle(X(h), y, 6, fill=col, stroke=col)
        dy = -18 if k != 2 else -48
        s.text(X(h), y + dy, lab, 12.5, col, 700, "middle")
        s.text(X(h), y + dy + 14 if dy < -20 else y + 38, t + " UTC", 10.5, INK2, 400, "middle")
    # windows
    def window(a, b, row, lab, col):
        yy = 80 + row * 22
        s.add(f'<rect x="{X(a):.1f}" y="{yy}" width="{X(b) - X(a):.1f}" height="16" rx="3" fill="{col}" opacity="0.18"/>')
        s.text((X(a) + X(b)) / 2, yy + 12, lab, 11, INK, 600, "middle")
    window(3500812, 3500822, 0, "10", ALICE)
    window(3500868, 3500948, 0, "the hub's window: δ + δ′ = 80 blocks, 40 min", HUB)
    window(3500949, 3500989, 0, "δ = 40: equiv_b's window", HUB)
    s.text(X(3500812), 74, "to_self_delay", 10.5, INK2, 400, "start")
    s.text(x0, 236, "Funding to escalation (30 min) was Alice's: the return on the L2, the proof, the trace (~2 min) and her decision to go.", 12, INK2)
    s.text(x0, 254, "Escalation to sweep (67 min) is the protocol's: one block between the links, then two windows the hub had to let pass.", 12, INK2)
    s.text(x0, 272, "A window counts from the block of the output it guards: the timeout could first be mined in 3,500,948 (it was in 949), the sweep in 989 (990).", 12, INK2)
    s.text(x0, 290, "Since 2026-10-17 the hub's window for a choice like move 2 is 20 blocks on Mutinynet, not 80: the same dispute would take about 30 min.", 12, INK2)
    s.save("timeline")


if __name__ == "__main__":
    for f in (overview, leaves, sizes, payout, money, timeline):
        f()
