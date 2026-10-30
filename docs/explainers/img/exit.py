#!/usr/bin/env python3
"""The diagrams of ../exit.md. Standard library only:
    python3 docs/explainers/img/exit.py
writes docs/explainers/img/exit-*.svg."""

import sys

sys.dont_write_bytecode = True  # no __pycache__ beside the diagrams
import hub_absent  # noqa: E402
from hub_absent import ALICE, ALICE_L, HUB, HUB_L, CON, CON_L, FEE, FEE_L, INK, INK2, LINE, OK, OK_L  # noqa: E402

GAD, GAD_L = "#0f766e", "#ccfbf1"  # the gadget: teal


class Svg(hub_absent.Svg):
    PREFIX = "exit"


def lines(s, x, y, rows, size=12, step=19):
    """Rows of (text, fill, weight, mono); a row starting with '•' is indented."""
    for t, fill, weight, mono in rows:
        dx = 12 if t.startswith("•") else 24 if t.startswith(" ") else 0
        s.text(x + dx, y, t.strip(), size, fill, weight, mono=mono)
        y += step


def box(s, x, y, w, h, title, sub, fill, stroke, dash=None):
    s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=1.6, dash=dash)
    s.text(x + w / 2, y + 22, title, 13.5, INK, 700, "middle")
    for k, t in enumerate(sub):
        s.text(x + w / 2, y + 41 + 16 * k, t, 11.5, INK2, 400, "middle")


def gadget(s, x, y, w, h, title, who):
    """The verification gadget, drawn as a black box: its moves are its own."""
    s.rect(x, y, w, h, fill=GAD_L, stroke=GAD, sw=1.8)
    s.text(x + 14, y + 22, title, 13.5, INK, 700)
    s.text(x + 14, y + 40, who, 11.5, INK2)
    s.rect(x + 14, y + 52, w - 28, h - 66, fill="#ffffff", stroke=GAD, rx=6, dash="4 3")
    cy = y + 52 + (h - 66) / 2 - 8
    for k in range(5):
        cx = x + 40 + k * (w - 80) / 4
        s.circle(cx, cy, 5, fill="#ffffff", stroke=GAD)
        if k < 4:
            s.line(cx + 6, cy, cx + (w - 80) / 4 - 7, cy, stroke=GAD, sw=1.2)
    s.text(x + w / 2, cy + 19, "challenge–response moves, not shown", 11, GAD, 600, "middle", italic=True)


# ---------------------------------------------------------------- the two proofs
def proofs():
    s = Svg(1060, 640)
    s.text(24, 32, "Two proofs, by two parties, from different data; both RISC Zero guests, wrapped in Groth16", 16, INK, 700)
    cols = [
        (24, ALICE, ALICE_L, "Alice's claim", "proved after the hub responds plainly, from what she holds", [
            ("from her exit kit, for an anchored state S:", INK, 600, False),
            ("• the chain receipt, the root SR_S at height h_S", INK2, 400, False),
            ("• each note's path in T_S, its nullifier absent from N_S", INK2, 400, False),
            ("from Bitcoin: S's anchor, and request in its block,", INK, 600, False),
            ("   each with W of work on it", INK, 600, False),
            ("from her wallet: the notes' openings and her keys", INK, 600, False),
        ], "the BABE guest, its claim branch", ["the notes in S and unspent there, b ≤ Σ,", "request carries this claim, signed"],
            "c ‖ D ‖ H(pk_H ‖ O_D)", "the contract's journal, fixed at its opening"),
        (556, HUB, HUB_L, "The hub's counter", "proved before it responds, only if one exists", [
            ("from Alice's request, on chain:", INK, 600, False),
            ("• her E, and the claim it hashes: notes, h_S, SR_S", INK2, 400, False),
            ("from its own ledger (it is the sequencer), either:", INK, 600, False),
            ("• one of the notes spent at a later anchored S′,", INK2, 400, False),
            ("   anchored by request's block (not her own return)", INK2, 400, False),
            ("• or her signed claim of it through another contract", INK2, 400, False),
        ], "the counter guest", ["S′ in S's history and the spend in it,", "or the other claim's signature"],
            "D ‖ E", "the same E as Alice's claim, so the same contract"),
    ]
    for x, col, light, title, sub, rows, guest, gsub, jour, jsub in cols:
        w = 480
        s.text(x, 68, title, 14, col, 700)
        s.text(x, 86, sub, 11.5, INK2, 400, italic=True)
        s.rect(x, 98, w, 150, fill=light, stroke=col, sw=1.4)
        lines(s, x + 14, 122, rows)
        s.line(x + w / 2, 248, x + w / 2, 270)
        box(s, x, 272, w, 68, guest, gsub, "#ffffff", col)
        s.line(x + w / 2, 340, x + w / 2, 362)
        s.rect(x, 364, w, 56, fill="#ffffff", stroke=col, sw=1.4)
        s.text(x + w / 2, 388, jour, 14, INK, 700, "middle", mono=True)
        s.text(x + w / 2, 408, jsub, 11.5, INK2, 400, "middle")
        s.line(x + w / 2, 420, x + w / 2, 442)
    box(s, 24, 444, 480, 58, "π: Alice's proof, asserted", ["checked on Bitcoin by BABE: the hub challenges a false one"], FEE_L, FEE)
    box(s, 556, 444, 480, 58, "K: 128 bytes, signed in respond", ["checked inside Alice's statement: a false K pays her"], FEE_L, FEE)
    s.path("M 796 502 C 796 560, 520 540, 470 580", stroke=HUB)
    s.path("M 264 502 L 264 578", stroke=ALICE)
    s.rect(120, 580, 520, 46, fill=GAD_L, stroke=GAD, sw=1.8)
    s.text(380, 600, "Alice's statement: return, or claim, or K is no counter", 13, INK, 700, "middle")
    s.text(380, 617, "one guest, one journal; BABE checks the proof of it", 11.5, INK2, 400, "middle")
    s.save("proofs")


# ---------------------------------------------------------------- why a counter exists only for a real spend
def heights():
    s = Svg(1060, 470)
    s.text(24, 32, "The L2's anchored history: a counter can only point to an insertion of her nullifier after S", 16, INK, 700)
    x0, x1 = 230, 1030
    rows = [
        (110, "honest Alice", "nothing spent since S"),
        (230, "Alice spent later", "she paid Bob, then claims S"),
        (350, "a forged insertion", "the operator tries"),
    ]
    anchors = [x0 + 30 + 80 * k for k in range(10)]
    xs, xspend, xsp = anchors[2], anchors[4] + 30, anchors[7]
    for y, name, sub in rows:
        s.text(24, y + 5, name, 13.5, INK, 700)
        s.text(24, y + 23, sub, 11.5, INK2)
        s.line(x0, y, x1, y, stroke=INK2, sw=1.6)
        for a in anchors:
            s.line(a, y - 7, a, y + 7, stroke=CON, sw=2, arrow=False)
        # S: her kit
        s.circle(xs, y, 8, fill=ALICE_L, stroke=ALICE, sw=2)
        s.text(xs, y - 16, "S: her kit", 11.5, ALICE, 700, "middle")
        s.text(xs, y + 26, "h_S", 11.5, ALICE, 600, "middle", mono=True)
        # S': the counter's state
        s.add(f'<rect x="{xs + 10}" y="{y + 34}" width="{xsp - xs - 10}" height="10" fill="{HUB_L}" stroke="{HUB}" stroke-width="1"/>')
        s.text((xs + xsp) / 2, y + 60, "the counter's window: h_S < h ≤ h_S′", 11, HUB, 600, "middle")
        s.circle(xsp, y, 6, fill="#ffffff", stroke=HUB, sw=1.8)
        s.text(xsp, y - 16, "S′, 10 deep", 11.5, HUB, 700, "middle")
    # row 1: nothing to point to
    s.text(1030, 136, "no insertion of her nullifiers: no counter can exist", 12, OK, 700, "end")
    # row 2: the spend
    y = 230
    s.circle(xspend, y, 8, fill=HUB_L, stroke=HUB, sw=2)
    s.text(xspend, y - 16, "her spend to Bob inserts n₁", 11.5, HUB, 700, "middle")
    s.text(1030, y + 26, "the counter: valid, if anchored by request's block", 12, HUB, 700, "end")
    # row 3: forgeries
    y = 350
    for x, lab, lab2 in [(anchors[3] + 40, "an exit record, not signed by her", "the chain guest rejects it"),
                         (anchors[5] + 40, "her own return, memo c", "excluded from counters")]:
        s.circle(x, y, 8, fill=FEE_L, stroke=FEE, sw=2)
        s.line(x - 6, y - 6, x + 6, y + 6, stroke=FEE, sw=2, arrow=False)
        s.line(x - 6, y + 6, x + 6, y - 6, stroke=FEE, sw=2, arrow=False)
        s.text(x, y - 30, lab, 11, FEE, 700, "middle")
        s.text(x, y - 16, lab2, 11, FEE, 400, "middle")
    s.text(1030, y + 26, "no counter", 12, OK, 700, "end")
    # legend
    s.line(24, 446, 24, 460, stroke=CON, sw=2, arrow=False)
    s.text(34, 458, "an anchor: a Bitcoin transaction spending the last one's seal", 11.5, INK2)
    s.text(500, 458, "a spend needs the note's keys; an exit record, her signature on a claim", 11.5, INK2)
    s.save("heights")


# ---------------------------------------------------------------- on chain: BABE's graph with the exit
def graph():
    s = Svg(1060, 600)
    s.text(24, 32, "On chain: BABE's dispute, with the exit's claim in request and the counter in respond", 16, INK, 700)
    box(s, 24, 70, 170, 74, "contract output", ["V_max + r_A + r_H", "pre-signed at opening"], CON_L, CON)
    box(s, 228, 62, 210, 92, "request", ["Alice signs b and E, and posts", "the claim: its notes, h_S, SR_S,", "the owners' signatures"], ALICE_L, ALICE)
    s.line(194, 107, 226, 107)
    # respond's two leaves: one transaction
    box(s, 478, 54, 250, 64, "respond, plain", ["the hub signs b, and E under e_plain"], HUB_L, HUB)
    box(s, 478, 128, 250, 76, "respond, countering", ["the hub signs b, E under e_counter,", "and K, its counter's proof itself"], HUB_L, HUB)
    s.text(603, 222, "two leaves, one transaction: either way, assert follows", 11, INK2, 400, "middle", italic=True)
    s.line(438, 100, 476, 86)
    s.line(438, 112, 476, 160)
    box(s, 768, 86, 268, 92, "assert", ["Alice's proof π of her statement,", "before T_A; the hub challenges a", "false one (BABE's challenge)"], ALICE_L, ALICE)
    s.line(728, 86, 766, 120)
    s.line(728, 166, 766, 140)
    # timeouts
    box(s, 228, 262, 210, 74, "request_timeout", ["after w_H, no response:", "Alice is paid b"], OK_L, OK)
    s.line(333, 154, 333, 260, dash="4 3")
    box(s, 478, 262, 250, 74, "respond_timeout", ["from T_A, no assertion:", "the hub takes the contract"], FEE_L, FEE)
    s.line(603, 230, 603, 260, dash="4 3")
    box(s, 768, 262, 268, 74, "success, or the answer", ["Alice is paid b (in bits)", "and the reserves"], OK_L, OK)
    s.line(902, 178, 902, 260)
    # the statement's branches
    s.rect(24, 370, 1012, 200, fill=GAD_L, stroke=GAD, sw=1.6)
    s.text(40, 396, "Alice's statement: one guest, one journal; she wins on any of three branches", 13.5, INK, 700)
    lines(s, 40, 424, [
        ("• return: the hub signed b, and a return of b to the contract is anchored (a refused withdrawal; E doesn't matter)", INK2, 400, False),
        ("• claim: the hub signed b and E in the plain leaf, and her claim holds: her notes unspent at S, request posting it", INK2, 400, False),
        ("• failed counter: the hub signed E and K in the counter leaf, and K isn't a counter for her D ‖ E", INK2, 400, False),
        ("", INK2, 400, False),
        ("A true counter leaves her no branch: she can't assert, and from T_A the contract is the hub's.", INK, 600, False),
        ("A false one pays her through the third, and anyone can prove it: it needs no secret of hers.", INK, 600, False),
        ("The key that signed E says which leaf ran; script compares the hub's b and E with hers, digit by digit.", INK2, 400, False),
    ], size=12, step=21)
    s.save("graph")


if __name__ == "__main__":
    for f in (proofs, heights, graph):
        f()
