#!/usr/bin/env python3
"""The diagrams of ../exit.md (a design: docs/EXIT_PLAN.md). Standard
library only:
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
    s = Svg(1060, 660)
    s.text(24, 32, "Two proofs, by two parties, from different data; the same pipeline and the same gadget", 16, INK, 700)
    cols = [
        (24, ALICE, ALICE_L, "Alice's exit proof", "made before she escalates, from what she holds", [
            ("from her exit kit, for an anchored state S:", INK, 600, False),
            ("• the chain receipt at height h_S, root SR_S", INK2, 400, False),
            ("• each note's path in the tree T_S", INK2, 400, False),
            ("• each nullifier's non-membership in N_S", INK2, 400, False),
            ("from Bitcoin: headers with W of work on S's anchor", INK, 600, False),
            ("from her wallet: the notes' openings, and nk", INK, 600, False),
        ], "the exit guest", ["derives the nullifiers from the notes and nk,", "checks every path and non-membership, b ≤ Σ"],
            "b ‖ c ‖ D ‖ E", "E = H(c ‖ h_S ‖ SR_S ‖ nullifiers)"),
        (556, HUB, HUB_L, "The operator's counter proof", "made only if a later spend exists, within W_c", [
            ("from Alice's escalation, on chain:", INK, 600, False),
            ("• her E, and what it hashes: c, h_S, SR_S, nullifiers", INK2, 400, False),
            ("from its own ledger (it is the sequencer):", INK, 600, False),
            ("• the chain receipt at a later anchored S′, 10 deep", INK2, 400, False),
            ("• one of her nullifiers, inserted at h_S < h ≤ h_S′,", INK2, 400, False),
            ("   not by contract c's own return or exit record", INK2, 400, False),
        ], "the counter guest", ["checks that S′'s history passes through S,", "and the insertion, in it"],
            "D ‖ E ‖ ok", "the same E as Alice's claim, so the same contract c"),
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
        box(s, x, 444, w, 46, "STARK, then Groth16: about 256 bytes", [], FEE_L, FEE)
    # both into the gadget
    s.path("M 264 490 C 264 515, 420 512, 440 540", stroke=ALICE)
    s.path("M 796 490 C 796 515, 640 512, 620 540", stroke=HUB)
    gadget(s, 200, 542, 660, 100, "the verification gadget", "checks a Groth16 proof and its journal on Bitcoin; reads chosen journal words into Script")
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
    s.text(1030, y + 26, "the counter: valid", 12, HUB, 700, "end")
    # row 3: forgeries
    y = 350
    for x, lab, lab2 in [(anchors[3] + 40, "an exit record, no proof of hers", "the chain guest rejects it"),
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
    s.text(500, 458, "a spend needs the note's keys; an exit record needs her exit proof", 11.5, INK2)
    s.save("heights")


# ---------------------------------------------------------------- on chain: the gadget in one of two places
def graph():
    s = Svg(1060, 600)
    s.text(24, 32, "On chain: one escalation, then the gadget in one of two places", 16, INK, 700)
    box(s, 24, 70, 196, 74, "contract output", ["V_max + r_A + r_H", "2-of-2, pre-signed at opening"], CON_L, CON)
    box(s, 260, 70, 220, 90, "escalate", ["Alice: her proof, b ‖ c ‖ D ‖ E,", "and her nullifiers, signed;", "confirms by T_close"], ALICE_L, ALICE)
    box(s, 520, 70, 164, 74, "counter window W_c", ["≈ 18 blocks on mainnet", "the operator may counter"], "#ffffff", INK2, dash="5 4")
    s.line(220, 107, 258, 107)
    s.line(480, 107, 518, 107)
    # the two places
    gadget(s, 744, 56, 292, 122, "the counter game", "the operator proves its counter; Alice challenges")
    gadget(s, 744, 326, 292, 122, "Alice's game", "Alice proves her claim; the operator challenges")
    s.line(684, 107, 742, 107, stroke=HUB)
    s.text(713, 99, "counters", 11, HUB, 600, "middle")
    s.path("M 602 144 C 602 280, 700 380, 742 380", stroke=ALICE)
    s.text(608, 250, "no counter", 11, ALICE, 600)
    # the counter game's outcomes
    box(s, 744, 200, 140, 72, "counter holds", ["she spent since S:", "the operator takes all"], HUB_L, HUB)
    box(s, 896, 200, 140, 72, "counter fails", ["Alice's game", "goes on"], OK_L, OK)
    s.line(814, 178, 814, 198)
    s.line(966, 178, 966, 198)
    s.line(966, 272, 966, 324, stroke=OK)
    # Alice's game's outcomes
    box(s, 744, 470, 140, 88, "proof holds", ["(or a timeout):", "Alice b + r_A + r_H,", "the hub V_max − b"], OK_L, OK)
    box(s, 896, 470, 140, 88, "proof fails", ["a false claim:", "the operator takes all"], HUB_L, HUB)
    s.line(814, 448, 814, 468)
    s.line(966, 448, 966, 468)
    # the other ways out
    box(s, 24, 220, 196, 74, "default", ["after T_close, only if", "no escalation has confirmed"], FEE_L, FEE)
    s.line(122, 144, 122, 218, dash="4 3")
    box(s, 24, 330, 196, 74, "fold", ["both sign, at any time:", "Alice b + r_A"], OK_L, OK)
    s.path("M 30 144 C 8 200, 8 300, 30 328", dash="4 3")
    s.path("M 370 160 C 370 290, 260 367, 222 367", dash="4 3")
    s.text(470, 240, "the operator may still fold", 11, INK2, 400, "middle", italic=True)
    s.text(470, 256, "after checking her proof itself", 11, INK2, 400, "middle", italic=True)
    # note
    s.text(24, 470, "With rational play at most one game is played:", 12, INK, 700)
    lines(s, 24, 490, [
        ("• a true counter wins its game, so the operator plays it, and Alice loses;", INK2, 400, False),
        ("• a true claim with no counter wins Alice's game, so the operator folds;", INK2, 400, False),
        ("• a false counter only costs the operator its game.", INK2, 400, False),
    ], size=11.5, step=18)
    s.text(24, 560, "Each game is one instance of the gadget, pre-signed at opening;", 11.5, INK2)
    s.text(24, 577, "its moves, windows and timeouts are the gadget's own.", 11.5, INK2)
    s.save("graph")


if __name__ == "__main__":
    for f in (proofs, heights, graph):
        f()
