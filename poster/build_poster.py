#!/usr/bin/env python3
"""Build the CIS 6950 Assignment 3 project poster (48 in x 36 in, landscape).

All words come from poster/poster-copy.md; all numbers in that file come from
docs/a2-evidence-pack.md. This script only does layout, charts and export.

    python poster/build_poster.py            # .pptx + charts (+ .pdf/preview if LibreOffice is found)
    python poster/build_poster.py --no-pdf   # .pptx + charts only

Outputs (in poster/):
    Colon_Luis_Project_Poster.pptx   editable PowerPoint            (not committed)
    Colon_Luis_Project_Poster.pdf    submission file, fonts embedded (not committed)
    preview.png                      whole poster at 25% scale (12 in x 9 in @ 150 dpi)
    img/*.png                        generated charts and screenshot crop (committed)
    build-report.json                font sizes, line counts, image dpi, overflow checks

Requires python-pptx, matplotlib, Pillow, lxml, and segno (QR code; pip install segno).

Font: Calibri in the .pptx (PowerPoint default on Windows). LibreOffice renders it with
Carlito, which is metric-identical, so line breaks match. Charts use the same family.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from lxml import etree  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from PIL import Image, ImageFont  # noqa: E402
from pptx import Presentation  # noqa: E402
from pptx.dml.color import RGBColor  # noqa: E402
from pptx.enum.dml import MSO_LINE_DASH_STYLE  # noqa: E402
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE  # noqa: E402
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN  # noqa: E402
from pptx.oxml.ns import qn  # noqa: E402
from pptx.util import Inches, Pt  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
IMG = HERE / "img"
COPY = HERE / "poster-copy.md"
OUT_PPTX = HERE / "Colon_Luis_Project_Poster.pptx"
OUT_PDF = HERE / "Colon_Luis_Project_Poster.pdf"
OUT_PREVIEW = HERE / "preview.png"
OUT_REPORT = HERE / "build-report.json"
SCREENSHOT = REPO / "docs" / "screenshots" / "02-operator-dashboard.png"
SCREENSHOT_CROP = (512, 446, 1134, 776)  # TOOL / VERDICT / RULE columns of "Recent decisions", source px

# --------------------------------------------------------------------------- page + type
W, H = 48.0, 36.0
MARGIN = 1.0
GUTTER = 1.0
COL_W = (13.0, 18.0, 13.0)  # left, centre (~39% of the 46 in live width), right
COL_X = (MARGIN, MARGIN + COL_W[0] + GUTTER, MARGIN + COL_W[0] + GUTTER + COL_W[1] + GUTTER)
HEADER_H = 4.85  # full-bleed title band
BODY_TOP = HEADER_H + 0.6
FOOTER_TOP = 32.1  # references band starts here
BODY_BOTTOM = FOOTER_TOP - 0.4

FONT = "Calibri"
SZ = {
    "title": 100,
    "subtitle": 48,
    "byline": 34,
    "header": 56,
    "body": 30,
    "small": 26,  # sub-labels inside diagram boxes and chips
    "callout": 88,
    "callout_label": 26,
    "caption": 22,
    "ref": 20,
}
LINE = 1.2207  # Calibri/Carlito single line height, in em

# --------------------------------------------------------------------------- palette
# Taken from docs/diagrams/*.mmd classDefs. Verdict mapping is the same in the diagram,
# the charts and the console: ALLOW green, GATE amber, DENY red.
C = {
    "navy": "1F3864",
    "blue": "2E5C8A",
    "blue_lt": "DCE6F1",
    "blue_bg": "F4F8FC",
    "ink": "1F2A36",
    "muted": "4D5866",
    "neutral_lt": "E9ECF1",
    "grey_lt": "F1F1F1",
    "grey": "6B6B6B",
    "allow": "4A7C3F",
    "allow_lt": "E8F0E3",
    "allow_dk": "254A1D",
    "gate": "B58105",
    "gate_lt": "FFF3CD",
    "gate_dk": "6B4C00",
    "deny": "A94442",
    "deny_lt": "F8D7DA",
    "deny_dk": "7A2A2F",
    "store": "5E35B1",
    "store_lt": "EDE7F6",
    "store_dk": "311B92",
    "white": "FFFFFF",
    "footer": "F2F4F7",
}
VERDICT = {
    "ALLOW": ("allow", "allow_lt", "allow_dk"),
    "GATE": ("gate", "gate_lt", "gate_dk"),
    "DENY": ("deny", "deny_lt", "deny_dk"),
}


def rgb(key: str) -> RGBColor:
    return RGBColor.from_string(C.get(key, key))


# --------------------------------------------------------------------------- copy parsing
def load_copy(path: Path) -> dict[str, str]:
    text = re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    blocks: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        m = re.match(r"^## (\S+)\s*$", line)
        if m:
            key = m.group(1)
            blocks[key] = ""
        elif key:
            blocks[key] += line + "\n"
    return {k: v.strip() for k, v in blocks.items()}


def items(block: str) -> list[list[str]]:
    out = []
    for line in block.splitlines():
        if line.startswith("- "):
            out.append([f.strip() for f in line[2:].split(" | ")])
    return out


def runs_of(text: str) -> list[tuple[str, bool, bool]]:
    """Split **bold** / *italic* markup into (text, bold, italic) runs."""
    out = []
    for part in re.split(r"(\*\*.+?\*\*|\*[^*]+?\*)", text):
        if not part:
            continue
        if part.startswith("**"):
            out.append((part[2:-2], True, False))
        elif part.startswith("*"):
            out.append((part[1:-1], False, True))
        else:
            out.append((part, False, False))
    return out


# --------------------------------------------------------------------------- text measurement
def _font_file(bold: bool, italic: bool) -> str:
    win = {(0, 0): "calibri.ttf", (1, 0): "calibrib.ttf", (0, 1): "calibrii.ttf", (1, 1): "calibriz.ttf"}
    lin = {(0, 0): "Regular", (1, 0): "Bold", (0, 1): "Italic", (1, 1): "BoldItalic"}
    cands = [Path("C:/Windows/Fonts") / win[(bold, italic)],
             Path(f"/usr/share/fonts/truetype/crosextra/Carlito-{lin[(bold, italic)]}.ttf")]
    for c in cands:
        if c.exists():
            return str(c)
    prop = font_manager.FontProperties(family=["Calibri", "Carlito"], weight="bold" if bold else "normal",
                                       style="italic" if italic else "normal")
    return font_manager.findfont(prop, fallback_to_default=False)


_FONTS: dict = {}


def text_w(s: str, size: float, bold=False, italic=False) -> float:
    """Width in inches of s at size pt."""
    key = (bold, italic)
    if key not in _FONTS:
        _FONTS[key] = ImageFont.truetype(_font_file(bold, italic), 1000)
    return _FONTS[key].getlength(s) / 1000 * size / 72


def wrap_count(runs, size, width_in) -> int:
    """Greedy word wrap, same rule PowerPoint uses closely enough for layout."""
    words = []  # (word, bold, italic, trailing_space)
    for t, b, i in runs:
        for tok in re.findall(r"\S+\s*", t) or ([t] if t else []):
            words.append((tok.rstrip(), b, i, tok != tok.rstrip()))
    lines, cur = 1, 0.0
    for w_, b, i, sp in words:
        ww = text_w(w_, size, b, i)
        if cur > 0 and cur + ww > width_in:
            lines += 1
            cur = 0.0
        if ww > width_in:  # very long token (URL) breaks across lines
            extra = int(ww // width_in)
            lines += extra
            ww -= extra * width_in
        cur += ww + (text_w(" ", size, b, i) if sp else 0)
    return lines


# --------------------------------------------------------------------------- report
@dataclass
class Report:
    fonts: set = field(default_factory=set)
    blocks: list = field(default_factory=list)
    images: list = field(default_factory=list)
    columns: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    qr: dict = field(default_factory=dict)


REPORT = Report()


# --------------------------------------------------------------------------- pptx helpers
@dataclass
class Para:
    text: str
    size: float = SZ["body"]
    color: str = "ink"
    bold: bool = False
    italic: bool = False
    align: str = "l"
    bullet: str | None = None  # bullet character or None
    bullet_color: str = "blue"
    indent: float = 0.42
    after: float = 10.0  # pt
    before: float = 0.0
    name: str = ""  # for the line-count report


ALIGN = {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER, "r": PP_ALIGN.RIGHT}


def para_height(p: Para, width: float) -> tuple[float, int]:
    w = width - (p.indent if p.bullet else 0)
    n = wrap_count(runs_of(p.text), p.size, w)
    return n * LINE * p.size / 72 + (p.before + p.after) / 72, n


def fill_frame(tf, paras: list[Para], anchor=MSO_ANCHOR.TOP, margins=(0, 0, 0, 0)):
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.margin_left, tf.margin_top, tf.margin_right, tf.margin_bottom = (Inches(m) for m in margins)
    tf.vertical_anchor = anchor
    for idx, p in enumerate(paras):
        para = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
        para.alignment = ALIGN[p.align]
        para.line_spacing = 1.0
        para.space_after = Pt(p.after)
        para.space_before = Pt(p.before)
        for t, b, i in runs_of(p.text):
            r = para.add_run()
            r.text = t
            f = r.font
            f.name = FONT
            f.size = Pt(p.size)
            f.bold = p.bold or b
            f.italic = p.italic or i
            f.color.rgb = rgb(p.color)
            REPORT.fonts.add(p.size)
        if p.bullet:
            pPr = para._p.get_or_add_pPr()
            pPr.set("marL", str(Inches(p.indent)))
            pPr.set("indent", str(-Inches(p.indent)))
            buClr = etree.SubElement(pPr, qn("a:buClr"))
            etree.SubElement(buClr, qn("a:srgbClr")).set("val", C[p.bullet_color])
            etree.SubElement(pPr, qn("a:buFont")).set("typeface", FONT)
            etree.SubElement(pPr, qn("a:buChar")).set("char", p.bullet)


def add_text(slide, x, y, w, paras: list[Para], h=None, anchor=MSO_ANCHOR.TOP) -> float:
    total = 0.0
    for p in paras:
        ph, n = para_height(p, w)
        total += ph
        if p.name:
            REPORT.blocks.append({"block": p.name, "lines": n, "size_pt": p.size})
            if n > 4:
                REPORT.warnings.append(f"{p.name}: {n} lines (> 4)")
    if paras:
        total -= paras[-1].after / 72
    box_h = h if h is not None else total
    if h is not None and total > h + 0.02:
        REPORT.warnings.append(f"text overflows its box: {paras[0].text[:40]!r} needs {total:.2f} in, has {h:.2f}")
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(box_h))
    fill_frame(tb.text_frame, paras, anchor)
    return total


def no_shadow(shape):
    """Remove the theme drop shadow. An empty effectLst alone is ignored by LibreOffice, so also
    point the shape style's effectRef at the theme's empty effect slot (idx 0)."""
    shape.shadow.inherit = False
    st = shape._element.find(qn("p:style"))
    if st is not None and st.find(qn("a:effectRef")) is not None:
        st.find(qn("a:effectRef")).set("idx", "0")


def box(slide, x, y, w, h, fill=None, line=None, lw=2.25, shape=MSO_SHAPE.RECTANGLE, radius=None,
        dash=False, paras: list[Para] | None = None, anchor=MSO_ANCHOR.MIDDLE, pad=0.15):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    no_shadow(s)
    if radius is not None and len(s.adjustments):
        s.adjustments[0] = radius
    if fill:
        s.fill.solid()
        s.fill.fore_color.rgb = rgb(fill)
    else:
        s.fill.background()
    if line:
        s.line.color.rgb = rgb(line)
        s.line.width = Pt(lw)
        if dash:
            s.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    else:
        s.line.fill.background()
    if paras:
        need = sum(para_height(p, w - 2 * pad)[0] for p in paras) - paras[-1].after / 72
        if need > h - 0.1:
            REPORT.warnings.append(f"shape text overflow: {paras[0].text[:40]!r} needs {need:.2f} in, has {h:.2f}")
        for p in paras:
            REPORT.fonts.add(p.size)
        fill_frame(s.text_frame, paras, anchor, margins=(pad, 0.05, pad, 0.05))
    return s


def line(slide, x1, y1, x2, y2, color="muted", lw=3.0, arrow=True, dash=False):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    c.line.color.rgb = rgb(color)
    c.line.width = Pt(lw)
    no_shadow(c)
    if dash:
        c.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    if arrow:
        ln = c.line._get_or_add_ln()
        t = etree.SubElement(ln, qn("a:tailEnd"))
        t.set("type", "triangle")
        t.set("w", "med")
        t.set("len", "med")
    return c


def polyline(slide, pts, **kw):
    for i in range(len(pts) - 1):
        line(slide, *pts[i], *pts[i + 1], **{**kw, "arrow": kw.get("arrow", True) and i == len(pts) - 2})


def section_header(slide, x, y, w, text) -> float:
    h = add_text(slide, x, y, w, [Para(text, SZ["header"], "navy", bold=True, after=0)])
    box(slide, x, y + h + 0.08, w, 0.09, fill="blue")
    return h + 0.08 + 0.09 + 0.3


def picture(slide, path: Path, x, y, w, label: str):
    pic = slide.shapes.add_picture(str(path), Inches(x), Inches(y), width=Inches(w))
    with Image.open(path) as im:
        px_w, px_h = im.size
    h = w * px_h / px_w
    REPORT.images.append({"image": str(path.relative_to(REPO)).replace("\\", "/"), "use": label,
                          "pixels": f"{px_w}x{px_h}", "placed_in": f"{w:.2f} x {h:.2f}",
                          "effective_dpi": round(px_w / w)})
    return pic, h


# --------------------------------------------------------------------------- charts
def chart_font():
    fams = {f.name for f in font_manager.fontManager.ttflist}
    fam = "Calibri" if "Calibri" in fams else "Carlito"
    plt.rcParams.update({"font.family": fam, "hatch.linewidth": 2.0, "svg.fonttype": "none"})
    return fam


def chart_attacks(cp: dict, path: Path, w: float, h: float):
    rows = {r[0]: (float(r[1]), r[2]) for r in items(cp["results.chartA"])}
    na, dn, gt, esc = (rows[k][0] for k in ("not_attempted", "deny", "gate", "escaped"))
    fig = plt.figure(figsize=(w, h), dpi=300)
    ax = fig.add_axes([0.005, 0.30, 0.99, 0.32])
    segs = [  # left, width, face, hatch, text colour, number
        (0, na, "#" + C["grey_lt"], "//", C["grey"], na),
        (na, dn, "#" + C["deny"], "", "#FFFFFF", dn),
        (na + dn, gt, "#" + C["gate"], "..", "#FFFFFF", gt),
    ]
    for left, width, face, hatch, tcol, num in segs:
        ax.barh(0, width, left=left, height=1.0, color=face, hatch=hatch,
                edgecolor="#" + (C["grey"] if face.endswith(C["grey_lt"]) else "FFFFFF"), linewidth=2.5)
        ax.text(left + width / 2, 0, f"{num:g}", ha="center", va="center", fontsize=36, weight="bold",
                color=tcol if tcol.startswith("#") else "#" + tcol,
                bbox={"boxstyle": "round,pad=0.12", "fc": "#" + C["grey_lt"] if face.endswith(C["grey_lt"]) else face,
                          "ec": "none"} if hatch else None)
    total = na + dn + gt + esc
    ax.set_xlim(0, total)
    ax.set_ylim(-0.5, 0.5)
    ax.axis("off")
    # labels under each segment
    lab = fig.add_axes([0.005, 0.0, 0.99, 0.28])
    lab.set_xlim(0, total)
    lab.set_ylim(0, 1)
    lab.axis("off")
    lab.text(na / 2, 0.92, rows["not_attempted"][1], ha="center", va="top", fontsize=24, color="#" + C["muted"])
    lab.text(na + dn / 2, 0.92, "stopped\nautomatically (DENY)", ha="center", va="top", fontsize=24,
             color="#" + C["deny_dk"], weight="bold", linespacing=0.95)
    lab.text(na + dn + gt / 2, 0.92, "stopped at the\nhuman gate (GATE)", ha="center", va="top", fontsize=24,
             color="#" + C["gate_dk"], weight="bold", linespacing=0.95)
    # bracket over the attempted part
    top = fig.add_axes([0.005, 0.64, 0.99, 0.36])
    top.set_xlim(0, total)
    top.set_ylim(0, 1)
    top.axis("off")
    top.plot([na + 0.1, na + 0.1, total - 0.1, total - 0.1], [0.05, 0.3, 0.3, 0.05], color="#" + C["navy"], lw=3)
    top.text((na + total) / 2, 0.42, cp["results.chartA.annotation"], ha="center", va="bottom", fontsize=26,
             weight="bold", color="#" + C["navy"])
    fig.savefig(path, dpi=300, facecolor="white")
    plt.close(fig)


def chart_routine(cp: dict, path: Path, w: float, h: float):
    rows = [(r[0], r[1]) for r in items(cp["results.chartB"])]
    fig = plt.figure(figsize=(w, h), dpi=300)
    ax = fig.add_axes([0.385, 0.25, 0.60, 0.73])
    labels = [r[0] for r in rows][::-1]
    vals = [float(r[1]) for r in rows][::-1]
    shown = [r[1] for r in rows][::-1]
    ax.barh(range(len(vals)), vals, height=0.62, color="#" + C["gate"], hatch="..", edgecolor="#FFFFFF",
            linewidth=2.0)
    for i, (v, s) in enumerate(zip(vals, shown)):
        txt = s if v > 0 else f"{s}  (no approvals needed)"
        ax.text(v + 0.08, i, txt, va="center", ha="left", fontsize=26, weight="bold" if v > 0 else "normal",
                color="#" + (C["gate_dk"] if v > 0 else C["muted"]))
    ax.set_yticks(range(len(vals)), labels, fontsize=26, color="#" + C["ink"])
    ax.set_xlim(0, 5.2)
    ax.set_xticks([0, 1, 2, 3, 4], ["0", "1", "2", "3", "4"], fontsize=22, color="#" + C["muted"])
    ax.set_xlabel(cp["results.chartB.xlabel"], fontsize=22, color="#" + C["muted"], labelpad=6)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#" + C["muted"])
        ax.spines[s].set_linewidth(1.5)
    ax.tick_params(axis="y", length=0, pad=10)
    ax.tick_params(axis="x", width=1.5, color="#" + C["muted"])
    ax.grid(axis="x", color="#D5DAE1", lw=1.2)
    ax.set_axisbelow(True)
    fig.savefig(path, dpi=300, facecolor="white")
    plt.close(fig)


def crop_screenshot(path: Path):
    with Image.open(SCREENSHOT) as im:
        im.convert("RGB").crop(SCREENSHOT_CROP).save(path, optimize=True)


# --------------------------------------------------------------------------- sections
def header_band(slide, cp):
    box(slide, 0, 0, W, HEADER_H, fill="navy")
    box(slide, 0, HEADER_H, W, 0.14, fill="blue")
    y = 0.6
    y += add_text(slide, MARGIN, y, W - 2 * MARGIN, [Para(cp["title"], SZ["title"], "white", bold=True, after=0,
                                                         name="title")])
    y += 0.12
    y += add_text(slide, MARGIN, y, W - 2 * MARGIN, [Para(cp["subtitle"], SZ["subtitle"], "gate_lt", after=0,
                                                         name="subtitle")])
    y += 0.25
    y += add_text(slide, MARGIN, y, W - 2 * MARGIN, [Para(cp["byline"], SZ["byline"], "blue_lt", after=0,
                                                         name="byline")])
    if y > HEADER_H - 0.3:
        REPORT.warnings.append(f"header text ends at {y:.2f} in, band is {HEADER_H} in")


def bullets(block: str, name: str, size=None, after=12.0) -> list[Para]:
    return [Para(b[0], size or SZ["body"], bullet="•", after=after, name=f"{name}[{i}]")
            for i, b in enumerate(items(block))]


def left_column(slide, cp) -> float:
    x, w = COL_X[0], COL_W[0]
    y = BODY_TOP
    # 1. Overview
    y += section_header(slide, x, y, w, cp["overview.header"])
    y += add_text(slide, x, y, w, bullets(cp["overview.bullets"], "overview"))
    y += 0.3
    y += add_text(slide, x, y, w, [Para(cp["overview.verdicts.lead"], SZ["body"], "navy", bold=True, after=0,
                                        name="overview.verdicts.lead")])
    y += 0.2
    vs = items(cp["overview.verdicts"])
    gap = 0.3
    pw = (w - gap * (len(vs) - 1)) / len(vs)
    ph = 1.65
    for i, (name, desc) in enumerate(vs):
        dk, lt, ink = VERDICT[name]
        box(slide, x + i * (pw + gap), y, pw, ph, fill=lt, line=dk, lw=3, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
            radius=0.18, paras=[Para(name, 34, ink, bold=True, align="c", after=0),
                                Para(desc, SZ["small"], ink, align="c", after=0)])
    y += ph + 0.35
    crop = IMG / "console-decisions.png"
    crop_screenshot(crop)
    sw_ = 6.6
    pic, sh_ = picture(slide, crop, x, y, sw_, "Console screenshot (crop of docs/screenshots/02-operator-dashboard.png)")
    pic.line.color.rgb = rgb("muted")
    pic.line.width = Pt(1.5)
    add_text(slide, x + sw_ + 0.3, y, w - sw_ - 0.3, [Para(cp["overview.screenshot.caption"], SZ["caption"],
                                                           "muted", after=0, name="figure1.caption")],
             h=sh_, anchor=MSO_ANCHOR.MIDDLE)
    y += sh_ + 0.5

    # 2. Background & significance
    y += section_header(slide, x, y, w, cp["background.header"])
    y += add_text(slide, x, y, w, bullets(cp["background.bullets"], "background"))
    y += 0.15
    nums = [c[0] for c in items(cp["background.callouts"])]
    nw = max(text_w(n, SZ["callout"], True) for n in nums) + 0.3
    for i, (num, label) in enumerate(items(cp["background.callouts"])):
        ch = 1.6
        box(slide, x, y, w, ch, fill="blue_bg", line=None)
        box(slide, x, y, 0.16, ch, fill="blue")
        add_text(slide, x + 0.4, y, nw, [Para(num, SZ["callout"], "navy", bold=True, after=0)], h=ch,
                 anchor=MSO_ANCHOR.MIDDLE)
        add_text(slide, x + 0.4 + nw, y, w - nw - 0.55, [Para(label, SZ["callout_label"], "ink", after=0,
                                                             name=f"background.callout[{i}]")],
                 h=ch, anchor=MSO_ANCHOR.MIDDLE)
        y += ch + 0.2
    y += 0.05
    y += add_text(slide, x, y, w, [Para(cp["background.note"], SZ["small"], "muted", after=0,
                                        name="background.note")])
    y += 0.55

    # 3. Objectives
    y += section_header(slide, x, y, w, cp["objectives.header"])
    y += add_text(slide, x, y, w, [Para(b[0], SZ["body"], bullet="•", bullet_color="allow", after=12,
                                        name=f"objectives[{i}]")
                                   for i, b in enumerate(items(cp["objectives.bullets"]))])
    return y


def architecture(slide, cp, x0, y0) -> float:
    """Figure 1, drawn as native shapes (adapted from docs/diagrams/03-proposed.mmd)."""
    d = {r[0]: r[1:] for r in items(cp["methodology.diagram"])}

    def lab(key, title_sz=30, sub_sz=SZ["small"], color="ink", align="c"):
        t, *rest = d[key]
        ps = [Para(t, title_sz, color, bold=True, align=align, after=2)]
        if rest and rest[0]:
            ps.append(Para(rest[0], sub_sz, color, align=align, after=0))
        return ps

    X = lambda v: x0 + v  # noqa: E731
    Y = lambda v: y0 + v  # noqa: E731
    arrow_c, lw = "muted", 3.5

    # Row A: agent + untrusted input
    box(slide, X(2.4), Y(0), 7.0, 1.9, fill="neutral_lt", line="muted", lw=3,
        shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.12, paras=lab("agent"))
    box(slide, X(11.6), Y(0), 6.4, 1.9, fill="grey_lt", line="grey", lw=3, dash=True,
        shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.12, paras=lab("input", color="ink"))
    line(slide, X(11.6), Y(0.95), X(9.4), Y(0.95), arrow_c, lw)

    # proposed tool call
    line(slide, X(5.9), Y(1.9), X(5.9), Y(2.85), arrow_c, lw)
    add_text(slide, X(6.15), Y(2.02), 5.0, [Para(d["e.proposed"][0], SZ["caption"] + 2, "muted", italic=True,
                                                 after=0)])

    # Row B: monitor container with three steps + policy
    mon_y, mon_h = 2.85, 3.85
    box(slide, X(0.7), Y(mon_y), 17.3, mon_h, fill="blue_bg", line="blue", lw=3,
        shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.05)
    add_text(slide, X(1.05), Y(mon_y + 0.18), 16.0,
             [Para(f"**{d['monitor'][0]}**  ·  {d['monitor'][1]}", 32, "navy", after=0)])
    sw, sg, sy, sh = 3.75, 0.55, mon_y + 1.05, 2.45
    for i, key in enumerate(("step1", "step2", "step3")):
        sx = 1.05 + i * (sw + sg)
        box(slide, X(sx), Y(sy), sw, sh, fill="blue_lt", line="blue", lw=2.5, paras=lab(key, 28, color="navy"))
        if i < 2:
            line(slide, X(sx + sw), Y(sy + sh / 2), X(sx + sw + sg), Y(sy + sh / 2), "blue", 3.5)
    px = 1.05 + 3 * (sw + sg) + 0.15
    box(slide, X(px), Y(sy - 0.1), 17.7 - px, sh + 0.2, fill="store_lt", line="store", lw=2.5, shape=MSO_SHAPE.CAN,
        paras=lab("policy", 28, color="store_dk"), anchor=MSO_ANCHOR.BOTTOM, pad=0.05)
    line(slide, X(px), Y(sy + sh / 2), X(1.05 + 2 * (sw + sg) + sw), Y(sy + sh / 2), "store", 3, dash=True)

    # Verdict diamond
    cx = 9.35
    dy, dh, dw = mon_y + mon_h + 0.75, 1.9, 3.8
    line(slide, X(cx), Y(mon_y + mon_h), X(cx), Y(dy), arrow_c, lw)
    box(slide, X(cx - dw / 2), Y(dy), dw, dh, fill="blue", line="navy", lw=3, shape=MSO_SHAPE.DIAMOND,
        paras=[Para(d["verdict"][0], 32, "white", bold=True, align="c", after=0)], pad=0.0)
    dmid = dy + dh / 2

    # Row C: outcomes
    oy, oh, ow = dy + dh + 0.95, 2.0, 4.6
    ox = {"allow": 0.95, "gate": cx - ow / 2, "deny": 18.0 - ow}
    for key in ("allow", "gate", "deny"):
        dk, lt, ink = VERDICT[key.upper()]
        box(slide, X(ox[key]), Y(oy), ow, oh, fill=lt, line=dk, lw=4, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
            radius=0.1, paras=lab(key, 34, color=ink))
    # diamond -> outcomes (coloured by verdict)
    polyline(slide, [(X(cx - dw / 2), Y(dmid)), (X(ox["allow"] + ow / 2), Y(dmid)),
                     (X(ox["allow"] + ow / 2), Y(oy))], color="allow", lw=4.5)
    line(slide, X(cx), Y(dy + dh), X(cx), Y(oy), "gate", 4.5)
    polyline(slide, [(X(cx + dw / 2), Y(dmid)), (X(ox["deny"] + ow / 2), Y(dmid)),
                     (X(ox["deny"] + ow / 2), Y(oy))], color="deny", lw=4.5)
    # gate -> approve / reject
    gy = oy + oh * 0.5
    line(slide, X(ox["gate"]), Y(gy), X(ox["allow"] + ow), Y(gy), "allow", 4)
    line(slide, X(ox["gate"] + ow), Y(gy), X(ox["deny"]), Y(gy), "deny", 4)
    gap_w = ox["gate"] - (ox["allow"] + ow)
    add_text(slide, X(ox["allow"] + ow), Y(gy + 0.12), gap_w,
             [Para(d["e.approve"][0], SZ["caption"], "allow_dk", italic=True, align="c", after=0)])
    add_text(slide, X(ox["gate"] + ow), Y(gy + 0.12), gap_w,
             [Para(d["e.reject"][0], SZ["caption"], "deny_dk", italic=True, align="c", after=0)])

    # result loop back to the agent
    rx = 0.3
    polyline(slide, [(X(ox["allow"]), Y(oy + oh / 2)), (X(rx), Y(oy + oh / 2)), (X(rx), Y(0.95)),
                     (X(2.4), Y(0.95))], color="muted", lw=3, dash=True)
    add_text(slide, X(rx + 0.15), Y(0.3), 2.0, [Para(d["e.result"][0], SZ["caption"], "muted", italic=True,
                                                    after=0)])

    # audit log bar
    ly, lh = oy + oh + 0.85, 1.25
    box(slide, X(0.95), Y(ly), 17.05, lh, fill="store_lt", line="store", lw=3, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
        radius=0.2, paras=[Para(f"**{d['log'][0]}:** {d['log'][1]}", 30, "store_dk", align="c", after=0)])
    for key in ("allow", "gate", "deny"):
        line(slide, X(ox[key] + ow / 2), Y(oy + oh), X(ox[key] + ow / 2), Y(ly), "store", 4.5)
    add_text(slide, X(ox["deny"] + ow / 2 + 0.2), Y(oy + oh + 0.12), 4.0,
             [Para(d["e.log"][0], SZ["caption"], "store_dk", italic=True, after=0)])
    return y0 + ly + lh


def centre_column(slide, cp) -> float:
    x, w = COL_X[1], COL_W[1]
    y = BODY_TOP
    y += section_header(slide, x, y, w, cp["methodology.header"])
    y = architecture(slide, cp, x, y + 0.15) + 0.3
    y += add_text(slide, x, y, w, [Para(cp["methodology.diagram.caption"], SZ["caption"], "muted", after=0,
                                        name="figure2.caption")])
    y += 0.9

    # method strip
    y += add_text(slide, x, y, w, [Para(cp["methodology.strip.header"], 34, "navy", bold=True, after=0)])
    y += 0.2
    st = items(cp["methodology.strip"])
    g = 0.42
    cw = (w - g * (len(st) - 1)) / len(st)
    chh = 2.55
    for i, (t, s) in enumerate(st):
        cx = x + i * (cw + g)
        box(slide, cx, y, cw, chh, fill="blue_lt", line="blue", lw=2.5, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
            radius=0.1, paras=[Para(t, 28, "navy", bold=True, align="c", after=4),
                               Para(s, 24, "ink", align="c", after=0)], pad=0.12)
        if i < len(st) - 1:
            box(slide, cx + cw + 0.08, y + chh / 2 - 0.22, g - 0.16, 0.44, fill="blue", shape=MSO_SHAPE.ISOSCELES_TRIANGLE)
            slide.shapes[-1].rotation = 90
    y += chh + 0.18
    y += add_text(slide, x, y, w, [Para(cp["methodology.strip.note"], SZ["caption"] + 2, "muted", after=0)])
    y += 0.9

    # kill-chain strip (adapted from Figure 4)
    y += add_text(slide, x, y, w, [Para(cp["methodology.chain.header"], 34, "navy", bold=True, after=0)])
    y += 0.2
    ch_items = items(cp["methodology.chain"])
    g = 0.55
    cw = (w - g * (len(ch_items) - 1)) / len(ch_items)
    chh = 1.75
    for i, (step, verdict) in enumerate(ch_items):
        cx = x + i * (cw + g)
        dk, lt, ink = VERDICT[verdict]
        box(slide, cx, y, cw, chh, fill="white", line=dk, lw=3, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.12)
        add_text(slide, cx, y + 0.15, cw, [Para(step, 26, "ink", bold=True, align="c", after=0)])
        pw_ = 2.1
        box(slide, cx + (cw - pw_) / 2, y + chh - 0.78, pw_, 0.6, fill=lt, line=dk, lw=2.5,
            shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.5,
            paras=[Para(verdict, 24, ink, bold=True, align="c", after=0)], pad=0.02)
        if i < len(ch_items) - 1:
            line(slide, cx + cw, y + chh / 2, cx + cw + g, y + chh / 2, "muted", 3.5)
    y += chh + 0.2
    y += add_text(slide, x, y, w, [Para(cp["methodology.chain.caption"], SZ["caption"], "muted", after=0,
                                        name="figure3.caption")])
    return y


def right_column(slide, cp) -> float:
    x, w = COL_X[2], COL_W[2]
    y = BODY_TOP
    # 5. Results
    y += section_header(slide, x, y, w, cp["results.header"])
    cs = items(cp["results.callouts"])
    g = 0.3
    cw = (w - g * (len(cs) - 1)) / len(cs)
    chh = 2.75
    colors = ["deny_dk", "allow_dk", "gate_dk"]
    for i, (num, label) in enumerate(cs):
        cx = x + i * (cw + g)
        box(slide, cx, y, cw, chh, fill="blue_bg", line="blue", lw=2.25, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
            radius=0.08)
        add_text(slide, cx, y + 0.05, cw, [Para(num, SZ["callout"], colors[i], bold=True, align="c", after=0)])
        add_text(slide, cx + 0.15, y + 1.38, cw - 0.3, [Para(label, 24, "ink", align="c", after=0,
                                                             name=f"results.callout[{i}]")])
    y += chh + 0.5

    y += add_text(slide, x, y, w, [Para(cp["results.chartA.title"], 28, "navy", bold=True, after=0,
                                        name="chartA.title")])
    ca_h = 2.75
    chart_attacks(cp, IMG / "chart-attack-outcomes.png", w, ca_h)
    picture(slide, IMG / "chart-attack-outcomes.png", x, y + 0.05, w, "Chart A")
    y += ca_h + 0.35

    y += add_text(slide, x, y, w, [Para(cp["results.chartB.title"], 28, "navy", bold=True, after=0,
                                        name="chartB.title")])
    cb_h = 3.6
    chart_routine(cp, IMG / "chart-routine-approvals.png", w, cb_h)
    picture(slide, IMG / "chart-routine-approvals.png", x, y + 0.05, w, "Chart B")
    y += cb_h + 0.6

    # 6. Conclusions & recommendations
    y += section_header(slide, x, y, w, cp["conclusions.header"])
    y += add_text(slide, x, y, w, [Para(cp["conclusions.lead"], SZ["body"], "navy", after=0, name="conclusion")])
    y += 0.22
    y += add_text(slide, x, y, w, [Para(b[0], 28, bullet="•", bullet_color="navy", after=10, name=f"recommendation[{i}]")
                                   for i, b in enumerate(items(cp["conclusions.bullets"]))])
    y += 0.85

    # 7. Future directions + not-yet-proven callout
    y += section_header(slide, x, y, w, cp["future.header"])
    fw = 6.6
    fh = add_text(slide, x, y, fw, [Para(b[0], 28, bullet="→", after=10, name=f"future[{i}]")
                                    for i, b in enumerate(items(cp["future.bullets"]))])
    nx, nw = x + fw + 0.35, w - fw - 0.35
    paras = [Para(cp["future.unproven.header"], 28, "gate_dk", bold=True, after=6)] + \
            [Para(b[0], 24, "ink", bullet="!", bullet_color="gate", indent=0.32, after=6,
                  name=f"unproven[{i}]") for i, b in enumerate(items(cp["future.unproven"]))]
    need = sum(para_height(p, nw - 0.5)[0] for p in paras) - paras[-1].after / 72 + 0.4
    nh = max(need, fh)
    box(slide, nx, y - 0.05, nw, nh, fill="gate_lt", line="gate", lw=3, shape=MSO_SHAPE.ROUNDED_RECTANGLE,
        radius=0.06, paras=paras, anchor=MSO_ANCHOR.MIDDLE, pad=0.25)
    return y + nh


def qr_code(slide, url: str, x: float, y: float, size: float) -> dict:
    """Draw a QR code for url as native vector squares (grouped), including the quiet zone."""
    try:
        import segno
    except ImportError as exc:  # pragma: no cover - environment guard
        raise SystemExit("The QR code needs segno:  pip install segno") from exc
    qr = segno.make(url, error="m", boost_error=False)
    rows = [list(r) for r in qr.matrix]
    n, quiet = len(rows), 4
    mod = size / (n + 2 * quiet)
    grp = slide.shapes.add_group_shape()
    grp.name = "QR code"

    def sq(gx, gy, gw, gh, color):
        s = grp.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(gx), Inches(gy), Inches(gw), Inches(gh))
        no_shadow(s)
        s.fill.solid()
        s.fill.fore_color.rgb = RGBColor.from_string(color)
        s.line.fill.background()

    sq(x, y, size, size, "FFFFFF")
    for r, row in enumerate(rows):
        c = 0
        while c < n:
            if row[c]:
                start = c
                while c < n and row[c]:
                    c += 1
                # +0.002 in overlap hides hairline seams between adjacent rows in some renderers
                sq(x + (quiet + start) * mod, y + (quiet + r) * mod, (c - start) * mod, mod + 0.002, "000000")
            else:
                c += 1
    info = {"url": url, "version": qr.version, "error": qr.error, "modules": n,
            "module_in": round(mod, 3), "size_in": size, "vector": True}
    REPORT.images.append({"image": "QR code (vector shapes)", "use": url, "pixels": "n/a",
                          "placed_in": f"{size:.2f} x {size:.2f}", "effective_dpi": "vector"})
    return info


def footer(slide, cp):
    box(slide, 0, FOOTER_TOP, W, H - FOOTER_TOP, fill="footer")
    box(slide, 0, FOOTER_TOP, W, 0.08, fill="blue")
    y = FOOTER_TOP + 0.35
    add_text(slide, MARGIN, y, 6, [Para(cp["references.header"], 34, "navy", bold=True, after=0)])
    refs = items(cp["references"])
    qr_url = cp.get("footer.qr.url", "").strip()
    qr_size = 2.35
    qr_x, qr_y = W - MARGIN - qr_size, H - MARGIN - qr_size
    cols = [refs[:3], refs[3:]]
    cx = [MARGIN, MARGIN + 23.3]
    cw = [22.7, (qr_x - 4.6) - cx[1] if qr_url else 22.7]
    yy = y + 0.65
    for col, x, w in zip(cols, cx, cw):
        paras = [Para(r[0], SZ["ref"], "ink", after=6, name="reference") for r in col]
        hh = add_text(slide, x, yy, w, paras)
        # APA hanging indent
        tb = slide.shapes[-1]
        for p in tb.text_frame.paragraphs:
            pPr = p._p.get_or_add_pPr()
            pPr.set("marL", str(Inches(0.4)))
            pPr.set("indent", str(-Inches(0.4)))
        if yy + hh > H - MARGIN:
            REPORT.warnings.append(f"references overflow the 1 in margin: end at {yy + hh:.2f} in")
    if qr_url:
        REPORT.qr = qr_code(slide, qr_url, qr_x, qr_y, qr_size)
        lines = [ln.strip() for ln in cp.get("footer.qr.label", "").splitlines() if ln.strip()]
        paras = [Para(ln, 24 if i == 0 else SZ["ref"] + 2, "navy" if i == 0 else "ink", align="r",
                      after=4, name="footer.qr.label") for i, ln in enumerate(lines)]
        add_text(slide, qr_x - 4.35, qr_y, 4.1, paras, h=qr_size, anchor=MSO_ANCHOR.MIDDLE)


# --------------------------------------------------------------------------- export
def soffice() -> str | None:
    for c in ("soffice", "libreoffice", r"C:\Program Files\LibreOffice\program\soffice.exe"):
        p = shutil.which(c) or (c if Path(c).exists() else None)
        if p:
            return p
    return None


def export_pdf_and_preview():
    exe = soffice()
    if not exe:
        print("LibreOffice not found: skipped PDF/preview (export the PDF from PowerPoint instead).")
        return False
    opts = ('pdf:impress_pdf_Export:{"UseLosslessCompression":{"type":"boolean","value":"true"},'
            '"ReduceImageResolution":{"type":"boolean","value":"false"},'
            '"EmbedStandardFonts":{"type":"boolean","value":"true"}}')
    subprocess.run([exe, "--headless", "--convert-to", opts, "--outdir", str(HERE), str(OUT_PPTX)],
                   check=True, capture_output=True)
    if shutil.which("pdftoppm"):
        # 25% scale: 12 in x 9 in at 150 dpi = 1800 x 1350 px  (0.25 * 48 in * 150 dpi)
        stem = HERE / "preview"
        subprocess.run(["pdftoppm", "-png", "-r", str(150 * 0.25), "-singlefile", str(OUT_PDF), str(stem)],
                       check=True)
    else:
        print("pdftoppm not found: preview.png not rendered")
    return True


# --------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-pdf", action="store_true")
    args = ap.parse_args(argv)

    IMG.mkdir(exist_ok=True)
    chart_font()
    cp = load_copy(COPY)

    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(W), Inches(H)
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = rgb("white")
    prs.core_properties.title = cp["title"]
    prs.core_properties.author = "Luis Colón Sánchez"
    prs.core_properties.subject = "CIS 6950 IT Capstone: Assignment 3 Project Poster"

    header_band(slide, cp)
    ends = {"left": left_column(slide, cp), "centre": centre_column(slide, cp), "right": right_column(slide, cp)}
    footer(slide, cp)
    for k, v in ends.items():
        REPORT.columns[k] = {"ends_at_in": round(v, 2), "limit_in": BODY_BOTTOM,
                             "slack_in": round(BODY_BOTTOM - v, 2)}
        if v > BODY_BOTTOM:
            REPORT.warnings.append(f"{k} column overflows by {v - BODY_BOTTOM:.2f} in")

    prs.save(OUT_PPTX)
    print(f"wrote {OUT_PPTX.name}")
    if not args.no_pdf:
        export_pdf_and_preview()

    rep = {
        "smallest_font_pt": min(REPORT.fonts),
        "font_sizes_pt": sorted(REPORT.fonts),
        "columns": REPORT.columns,
        "images": REPORT.images,
        "max_lines_per_paragraph": max(b["lines"] for b in REPORT.blocks),
        "blocks_over_4_lines": [b for b in REPORT.blocks if b["lines"] > 4],
        "line_counts": REPORT.blocks,
        "qr_code": REPORT.qr,
        "warnings": REPORT.warnings,
    }
    OUT_REPORT.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: rep[k] for k in ("smallest_font_pt", "columns", "max_lines_per_paragraph", "warnings")},
                     indent=2))
    return 1 if REPORT.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
