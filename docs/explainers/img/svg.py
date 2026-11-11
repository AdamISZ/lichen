#!/usr/bin/env python3
"""The explainers' diagrams' shared parts: the palette, a minimal SVG
writer, and a transaction's box. Standard library only; each
`<explainer>.py` beside it draws its own."""

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
    PREFIX = ""

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
