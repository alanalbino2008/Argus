"""Render a :class:`ReportData` as a client-ready PDF (ReportLab, pure Python).

Security: ReportLab paragraphs understand a small markup language, and that language
can do more than formatting: ``<img src="/etc/passwd">`` makes the renderer read a local
file and ``<a href="javascript:…">`` creates a live link. Host names, page titles and
attack-path titles come from scanned websites, i.e. from potential attackers, so **every**
untrusted value passes through :func:`esc` before reaching a paragraph. Only markup written
in this file is ever interpreted.
"""

from __future__ import annotations

import io
import os
import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    Image,
    KeepTogether,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from argus.reports.data import SEVERITIES, TLP_MEANING, ReportData

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
RULE = colors.HexColor("#e5e7eb")
SOFT = colors.HexColor("#f5f6f8")
SEVERITY_COLOURS = {
    "critical": colors.HexColor("#c0262d"),
    "high": colors.HexColor("#e8590c"),
    "medium": colors.HexColor("#c99a06"),
    "low": colors.HexColor("#2f6fdf"),
    "minimal": colors.HexColor("#2f9e44"),
}
# FIRST Traffic Light Protocol 2.0: coloured label text on a black background.
TLP_COLOURS = {
    "CLEAR": colors.white,
    "GREEN": colors.HexColor("#33FF00"),
    "AMBER": colors.HexColor("#FFC000"),
    "AMBER+STRICT": colors.HexColor("#FFC000"),
    "RED": colors.HexColor("#FF2B2B"),
}
FONT_DIRS = [
    os.environ.get("ARGUS_REPORT_FONT_DIR", ""),
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu",
    "/usr/local/share/fonts",
    "/Library/Fonts",
]
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


# ---------------------------------------------------------------------------- fonts
class _Fonts:
    regular = "Helvetica"
    bold = "Helvetica-Bold"
    unicode = False


def _register_fonts() -> None:
    """DejaVu Sans covers Latin, Greek, Cyrillic and more; PDF base fonts only cover Latin-1."""
    if _Fonts.unicode:
        return
    for directory in FONT_DIRS:
        if not directory:
            continue
        regular, bold = Path(directory, "DejaVuSans.ttf"), Path(directory, "DejaVuSans-Bold.ttf")
        if regular.is_file() and bold.is_file():
            pdfmetrics.registerFont(TTFont("ArgusSans", str(regular)))
            pdfmetrics.registerFont(TTFont("ArgusSans-Bold", str(bold)))
            pdfmetrics.registerFontFamily(
                "ArgusSans", normal="ArgusSans", bold="ArgusSans-Bold", italic="ArgusSans", boldItalic="ArgusSans-Bold"
            )
            _Fonts.regular, _Fonts.bold, _Fonts.unicode = "ArgusSans", "ArgusSans-Bold", True
            return


def esc(value: Any, limit: int = 2000) -> str:
    """Untrusted text -> safe paragraph text (markup neutralised, unprintable characters removed)."""
    text = "".join(ch for ch in str(value)[:limit] if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    if not _Fonts.unicode:  # base fonts: keep what Latin-1 can show
        text = unicodedata.normalize("NFKD", text).encode("latin-1", "replace").decode("latin-1")
    return escape(text, {'"': "&quot;"})


# ---------------------------------------------------------------------------- styles
def _styles(accent: colors.Color) -> dict[str, ParagraphStyle]:
    r, b = _Fonts.regular, _Fonts.bold
    base = ParagraphStyle("body", fontName=r, fontSize=9.5, leading=13.5, textColor=INK, splitLongWords=1, spaceAfter=4)
    return {
        "body": base,
        "muted": ParagraphStyle("muted", parent=base, textColor=MUTED, fontSize=8.5, leading=12),
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8.3, leading=10.8, spaceAfter=0),
        "cellb": ParagraphStyle("cellb", parent=base, fontName=b, fontSize=8.3, leading=10.8, spaceAfter=0),
        "H1": ParagraphStyle("H1", parent=base, fontName=b, fontSize=16, leading=20, spaceBefore=6, spaceAfter=8,
                             textColor=INK),
        "H2": ParagraphStyle("H2", parent=base, fontName=b, fontSize=11.5, leading=15, spaceBefore=10, spaceAfter=4),
        "kicker": ParagraphStyle("kicker", parent=base, fontName=b, fontSize=8.5, textColor=accent, leading=11),
        "cover_title": ParagraphStyle("ct", parent=base, fontName=b, fontSize=30, leading=35, textColor=INK),
        "cover_target": ParagraphStyle("cg", parent=base, fontName=b, fontSize=17, leading=22, textColor=accent),
        "cover_meta": ParagraphStyle("cm", parent=base, fontSize=10.5, leading=16, textColor=INK),
        "toc0": ParagraphStyle("toc0", parent=base, fontSize=10.5, leading=19),
        "center": ParagraphStyle("center", parent=base, alignment=TA_CENTER),
        "left": ParagraphStyle("left", parent=base, alignment=TA_LEFT),
    }  # fmt: skip


# ---------------------------------------------------------------------------- page furniture
class NumberedCanvas(rl_canvas.Canvas):
    """Two-pass page numbering: 'Page 3 of 12' needs the total before drawing footers."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._pages: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self.setFont(_Fonts.regular, 7.5)
                self.setFillColor(MUTED)
                self.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def _tlp_badge(c: rl_canvas.Canvas, tlp: str, x_right: float, y: float, size: float = 7.5) -> None:
    label = f"TLP:{tlp}"
    width = pdfmetrics.stringWidth(label, _Fonts.bold, size) + 8
    c.setFillColor(colors.black)
    c.rect(x_right - width, y - 2.5, width, size + 5, stroke=0, fill=1)
    c.setFillColor(TLP_COLOURS.get(tlp, colors.white))
    c.setFont(_Fonts.bold, size)
    c.drawString(x_right - width + 4, y, label)


class _Doc(BaseDocTemplate):
    def __init__(self, buffer: io.BytesIO, data: ReportData, accent: colors.Color):
        self.data, self.accent = data, accent
        b = data.branding
        super().__init__(
            buffer,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN + 6 * mm,
            bottomMargin=MARGIN,
            title=f"Attack-surface assessment: {data.target}",
            author=b.organisation,
            subject=f"{data.report_id} · TLP:{data.options.tlp}",
            creator=data.generator,
            keywords=["attack surface", "OSINT", data.report_id, f"TLP:{data.options.tlp}"],
        )
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates(
            [
                PageTemplate(id="cover", frames=[frame], onPage=self._cover_page),
                PageTemplate(id="body", frames=[frame], onPage=self._body_page),
            ]
        )
        self._heading = 0

    def _cover_page(self, c: rl_canvas.Canvas, _doc: Any) -> None:
        c.saveState()
        c.setFillColor(self.accent)
        c.rect(0, PAGE_H - 9 * mm, PAGE_W, 9 * mm, stroke=0, fill=1)
        _tlp_badge(c, self.data.options.tlp, PAGE_W - MARGIN, PAGE_H - 18 * mm, 9)
        _tlp_badge(c, self.data.options.tlp, PAGE_W - MARGIN, 12 * mm, 9)
        c.restoreState()

    def _body_page(self, c: rl_canvas.Canvas, _doc: Any) -> None:
        d = self.data
        c.saveState()
        c.setStrokeColor(self.accent)
        c.setLineWidth(1.4)
        c.line(MARGIN, PAGE_H - MARGIN + 1 * mm, PAGE_W - MARGIN, PAGE_H - MARGIN + 1 * mm)
        c.setFont(_Fonts.bold, 7.5)
        c.setFillColor(INK)
        c.drawString(MARGIN, PAGE_H - MARGIN + 3 * mm, _plain(d.branding.organisation)[:60])
        c.setFont(_Fonts.regular, 7.5)
        c.setFillColor(MUTED)
        c.drawString(
            MARGIN + pdfmetrics.stringWidth(_plain(d.branding.organisation)[:60], _Fonts.bold, 7.5) + 6,
            PAGE_H - MARGIN + 3 * mm,
            f"Attack-surface assessment · {_plain(d.target)[:70]}",
        )
        _tlp_badge(c, d.options.tlp, PAGE_W - MARGIN, PAGE_H - MARGIN + 3 * mm)
        c.setStrokeColor(RULE)
        c.setLineWidth(0.6)
        c.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
        c.setFont(_Fonts.regular, 7.5)
        c.setFillColor(MUTED)
        footer = f"{d.report_id} · {d.generated_at:%d %b %Y}"
        if d.branding.footer_note:
            footer += f" · {_plain(d.branding.footer_note)}"
        badge_left = PAGE_W - MARGIN - 28 * mm - pdfmetrics.stringWidth(f"TLP:{d.options.tlp}", _Fonts.bold, 6.5) - 8
        c.drawString(MARGIN, 10 * mm, _fit(footer, _Fonts.regular, 7.5, badge_left - MARGIN - 6 * mm))
        _tlp_badge(c, d.options.tlp, PAGE_W - MARGIN - 28 * mm, 10 * mm, 6.5)
        c.restoreState()

    def beforeDocument(self) -> None:
        self._heading = 0

    def afterFlowable(self, flowable: Flowable) -> None:
        """Feed the table of contents and the PDF outline (bookmarks) from H1 headings."""
        if isinstance(flowable, Paragraph) and flowable.style.name == "H1":
            self._heading += 1
            key = f"section-{self._heading}"
            text = flowable.getPlainText()
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=0)
            self.notify("TOCEntry", (0, escape(text), self.page, key))  # TOC entries are markup too


def _fit(text: str, font: str, size: float, width: float) -> str:
    """Shorten ``text`` with an ellipsis so it fits ``width`` points."""
    if pdfmetrics.stringWidth(text, font, size) <= width:
        return text
    while text and pdfmetrics.stringWidth(text + "…", font, size) > width:
        text = text[:-1]
    return text.rstrip() + "…"


def _plain(value: Any) -> str:
    text = "".join(ch for ch in str(value) if unicodedata.category(ch)[0] != "C")
    if not _Fonts.unicode:
        text = unicodedata.normalize("NFKD", text).encode("latin-1", "replace").decode("latin-1")
    return text


# ---------------------------------------------------------------------------- small building blocks
def _pill(severity: str, s: dict[str, ParagraphStyle]) -> Table:
    colour = SEVERITY_COLOURS.get(severity, MUTED)
    cell = Paragraph(
        f'<font color="#ffffff"><b>{esc(severity.upper())}</b></font>',
        ParagraphStyle("pill", parent=s["small"], alignment=TA_CENTER, fontSize=7, leading=9, spaceAfter=0),
    )
    t = Table([[cell]], colWidths=[20 * mm], rowHeights=[5 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colour),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return t


def _table(rows: list[list[Any]], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), SOFT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfc")])]
    t.setStyle(TableStyle(style))
    return t


def _bullets(items: Iterable[str], s: dict[str, ParagraphStyle], style: str = "body") -> ListFlowable:
    return ListFlowable(
        [ListItem(Paragraph(esc(i), s[style]), leftIndent=10) for i in items],
        bulletType="bullet",
        start="•",
        leftIndent=10,
        bulletFontName=_Fonts.regular,
    )


def _gauge(score: int, rating: str) -> Drawing:
    d = Drawing(62 * mm, 36 * mm)
    cx, cy, r = 31 * mm, 8 * mm, 25 * mm
    d.add(Wedge(cx, cy, r, 0, 180, radius1=r - 6 * mm, fillColor=RULE, strokeColor=None, annular=True))
    share = max(0, min(100, score)) / 100
    if share:
        d.add(
            Wedge(cx, cy, r, 180 - 180 * share, 180, radius1=r - 6 * mm, annular=True,
                  fillColor=SEVERITY_COLOURS.get(rating, MUTED), strokeColor=None)
        )  # fmt: skip
    d.add(String(cx, cy + 4 * mm, str(score), fontName=_Fonts.bold, fontSize=20, textAnchor="middle", fillColor=INK))
    d.add(String(cx, cy - 1 * mm, "risk score / 100", fontName=_Fonts.regular, fontSize=7, textAnchor="middle",
                 fillColor=MUTED))  # fmt: skip
    return d


def _bars(items: list[tuple[str, int, colors.Color]], width: float, row: float = 6.5 * mm) -> Drawing:
    label_w = 30 * mm
    peak = max([v for _, v, _ in items] + [1])
    d = Drawing(width, row * len(items) + 2)
    for i, (label, value, colour) in enumerate(items):
        y = d.height - (i + 1) * row
        d.add(String(0, y + 2.2 * mm, _plain(label)[:24], fontName=_Fonts.regular, fontSize=8, fillColor=INK))
        bar = (width - label_w - 12 * mm) * value / peak
        d.add(Rect(label_w, y + 1.2 * mm, max(bar, 0.6), row - 2.6 * mm, fillColor=colour, strokeColor=None))
        d.add(String(label_w + bar + 2 * mm, y + 2.2 * mm, str(value), fontName=_Fonts.bold, fontSize=8,
                     fillColor=INK))  # fmt: skip
    return d


def _metric(value: Any, label: str, s: dict[str, ParagraphStyle], colour: colors.Color = INK) -> list[Paragraph]:
    big = ParagraphStyle("metric", parent=s["body"], fontName=_Fonts.bold, fontSize=18, leading=22, textColor=colour)
    return [Paragraph(esc(value), big), Paragraph(esc(label), s["muted"])]


# ---------------------------------------------------------------------------- sections
def _cover(d: ReportData, s: dict[str, ParagraphStyle], accent: colors.Color) -> list[Flowable]:
    out: list[Flowable] = [Spacer(1, 14 * mm)]
    if d.branding.logo_png:
        reader = ImageReader(io.BytesIO(d.branding.logo_png))
        w, h = reader.getSize()
        scale = min(55 * mm / w, 20 * mm / h)
        out += [Image(io.BytesIO(d.branding.logo_png), width=w * scale, height=h * scale, hAlign="LEFT"),
                Spacer(1, 18 * mm)]  # fmt: skip
    else:
        out.append(Spacer(1, 38 * mm))
    rating_colour = SEVERITY_COLOURS.get(d.rating, MUTED)
    out += [
        Paragraph("CONFIDENTIAL · ATTACK-SURFACE INTELLIGENCE", s["kicker"]),
        Spacer(1, 4 * mm),
        Paragraph("Attack-Surface Assessment", s["cover_title"]),
        Spacer(1, 3 * mm),
        Paragraph(esc(d.target), s["cover_target"]),
        Spacer(1, 14 * mm),
    ]
    meta = []
    if d.options.prepared_for:
        meta.append(("Prepared for", esc(d.options.prepared_for)))
    meta += [
        ("Prepared by", esc(d.branding.organisation)),
        ("Assessment date", esc(d.investigation["scanned"])),
        ("Report issued", f"{d.generated_at:%d %B %Y}"),
        ("Report reference", esc(d.report_id)),
    ]
    rows = [[Paragraph(f'<font color="#6b7280">{k}</font>', s["cover_meta"]), Paragraph(v, s["cover_meta"])]
            for k, v in meta]  # fmt: skip
    t = Table(rows, colWidths=[42 * mm, 120 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 1)]))
    out += [t, Spacer(1, 14 * mm)]
    badge = Table(
        [[Paragraph('<font color="#ffffff">OVERALL EXPOSURE</font>', s["small"]),
          Paragraph(f'<font color="#ffffff" size="13"><b>{esc(d.rating.upper())}</b></font>', s["body"])]],
        colWidths=[38 * mm, 40 * mm], hAlign="LEFT",
    )  # fmt: skip
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), rating_colour), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8)]))  # fmt: skip
    out += [badge, Spacer(1, 22 * mm)]
    out.append(
        Paragraph(
            f"<b>TLP:{esc(d.options.tlp)}</b>: {esc(TLP_MEANING[d.options.tlp])} This report describes security "
            "weaknesses; store and share it accordingly.",
            s["muted"],
        )
    )
    return out


def _contents(d: ReportData, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    toc = TableOfContents()
    toc.levelStyles = [s["toc0"]]
    toc.dotsMinLevel = 0
    control = [
        ["Item", "Detail"],
        ["Target", Paragraph(esc(d.target), s["cell"])],
        ["Report reference", d.report_id],
        ["Investigation", Paragraph(esc(d.investigation["id"]), s["cell"])],
        ["Classification", f"TLP:{d.options.tlp}"],
        ["Purpose / engagement", Paragraph(esc(d.investigation.get("purpose") or "—"), s["cell"])],
        ["Scan launched by", Paragraph(esc(d.investigation.get("created_by") or "—"), s["cell"])],
        ["Generated by", Paragraph(esc(d.generator), s["cell"])],
    ]
    return [
        Paragraph("Contents", ParagraphStyle("toch", parent=s["H1"])),
        toc,
        Spacer(1, 10 * mm),
        Paragraph("Document control", s["H2"]),
        _table(control, [45 * mm, 129 * mm], zebra=False),
    ]


def _executive(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    sev = [(x.title(), d.severity_counts[x], SEVERITY_COLOURS[x]) for x in SEVERITIES]
    charts = Table([[_gauge(d.score, d.rating), _bars(sev, width - 70 * mm)]], colWidths=[66 * mm, width - 66 * mm])
    charts.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    trend = d.trend
    trend_text = "—" if not trend else f"{trend['risk_delta']:+d}"
    trend_colour = (
        INK if not trend else SEVERITY_COLOURS["critical"] if trend["risk_delta"] > 0 else SEVERITY_COLOURS["minimal"]
    )
    metrics = Table(
        [[_metric(d.counts["assets"], "assets discovered", s), _metric(d.counts["paths"], "attack paths", s),
          _metric(d.severity_counts["critical"], "critical paths", s, SEVERITY_COLOURS["critical"]),
          _metric(trend_text, "risk change since last scan", s, trend_colour)]],
        colWidths=[width / 4] * 4,
    )  # fmt: skip
    metrics.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, RULE), ("LINEAFTER", (0, 0), (-2, -1), 0.5, RULE),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))  # fmt: skip
    out: list[Flowable] = [Paragraph("1. Executive summary", s["H1"])]
    out += [Paragraph(esc(p), s["body"]) for p in d.summary[:1]]
    out += [Spacer(1, 4 * mm), metrics, Spacer(1, 5 * mm), charts, Spacer(1, 3 * mm)]
    out += [Paragraph(esc(p), s["body"]) for p in d.summary[1:]]
    out.append(Spacer(1, 2 * mm))
    out.append(
        Paragraph(
            "The risk score combines the number and severity of exposures found; attack paths are plausible attacker "
            "routes assembled from public evidence and should be validated before remediation is prioritised.",
            s["muted"],
        )
    )
    return out


def _recommendations(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("2. Priority recommendations", s["H1"])]
    if not d.recommendations:
        return [*out, Paragraph("No remediation is required based on the findings.", s["body"])]
    out.append(Paragraph("Ordered by urgency. Each action is the first step for the attack paths listed.", s["muted"]))
    out.append(Spacer(1, 2 * mm))
    rows: list[list[Any]] = [["#", "Action", "Priority", "Addresses"]]
    for i, rec in enumerate(d.recommendations, 1):
        addressed = rec["paths"][:3] + ([f"+{len(rec['paths']) - 3} more"] if len(rec["paths"]) > 3 else [])
        rows.append([
            Paragraph(str(i), s["cellb"]), Paragraph(esc(rec["action"]), s["cell"]), _pill(rec["severity"], s),
            Paragraph("<br/>".join(esc(a) for a in addressed), s["cell"]),
        ])  # fmt: skip
    out.append(_table(rows, [8 * mm, width * 0.45, 24 * mm, width - 32 * mm - width * 0.45]))
    return out


def _path_block(i: int, p: dict[str, Any], s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    colour = SEVERITY_COLOURS.get(p["severity"], MUTED)
    head = Table(
        [[_pill(p["severity"], s), Paragraph(f"<b>3.{i}  {esc(p['title'])}</b>", s["body"]),
          Paragraph(f"<b>{int(p['score'])}</b>/100", ParagraphStyle("sc", parent=s["body"], alignment=2))]],
        colWidths=[23 * mm, width - 43 * mm, 20 * mm],
    )  # fmt: skip
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 1.2, colour),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))  # fmt: skip
    chain = "  →  ".join(f"{esc(step['label'], 160)} <font color=\"#6b7280\">({esc(step['role'], 60)})</font>"
                         for step in p.get("steps", [])[:8])  # fmt: skip
    rows: list[list[Any]] = [
        [Paragraph("Scenario", s["cellb"]), Paragraph(esc(p.get("narrative", "")), s["cell"])],
        [Paragraph("Attack chain", s["cellb"]), Paragraph(chain or "—", s["cell"])],
        [Paragraph("MITRE ATT&amp;CK", s["cellb"]),
         Paragraph("<br/>".join(f"{esc(t['id'])} {esc(t['name'])} <font color=\"#6b7280\">({esc(t.get('tactic', ''))})</font>"
                                for t in p.get("techniques", [])) or "—", s["cell"])],
    ]  # fmt: skip
    if p.get("evidence"):
        rows.append(
            [Paragraph("Evidence", s["cellb"]), Paragraph("<br/>".join(esc(e) for e in p["evidence"][:6]), s["cell"])]
        )
    if p.get("remediation"):
        fixes = "<br/>".join(f"{n}. {esc(r)}" for n, r in enumerate(p["remediation"][:6], 1))
        rows.append([Paragraph("Remediation", s["cellb"]), Paragraph(fixes, s["cell"])])
    body = _table(rows, [28 * mm, width - 28 * mm], header=False, zebra=False)
    return [CondPageBreak(45 * mm), KeepTogether([head, Spacer(1, 2 * mm), body]),
            Spacer(1, 6 * mm)]  # fmt: skip


def _paths(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("3. Attack paths", s["H1"])]
    if not d.paths:
        return [*out, Paragraph("No attack paths were identified.", s["body"])]
    note = (f"The {len(d.paths)} highest-scoring of {d.paths_total} paths are detailed below; the rest are in Argus."
            if d.paths_total > len(d.paths) else "Every path identified is detailed below, highest risk first.")  # fmt: skip
    out += [Paragraph(esc(note), s["muted"]), Spacer(1, 4 * mm)]
    for i, p in enumerate(d.paths, 1):
        out += _path_block(i, p, s, width)
    return out


def _exposure(d: ReportData, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("4. Exposure indicators", s["H1"])]
    out.append(_bullets(d.flags, s) if d.flags else Paragraph("None identified.", s["body"]))
    p = d.people
    out += [Spacer(1, 4 * mm), Paragraph("People and social-engineering exposure", s["H2"])]
    facts = [
        f"{p['people']} people linked to the organisation through public sources, with {p['linked_accounts']} "
        f"linked online account(s); {p['exposed']} appear in attack paths.",
        f"{p['personal_items']} personal identifiers (emails, usernames, profiles, phone numbers) were found. "
        "They are summarised here, not listed: the full detail is available to authorised analysts in Argus.",
    ]
    if p.get("email_format"):
        facts.append(f"The email address format can be inferred ({p['email_format']}), so attackers can guess "
                     "valid addresses for any employee whose name is public.")  # fmt: skip
    if p.get("role_mailboxes"):
        facts.append("Published role mailboxes: " + ", ".join(p["role_mailboxes"]) + ".")
    out.append(_bullets(facts, s))
    if d.lookalikes:
        out += [Spacer(1, 4 * mm), Paragraph("Brand impersonation (lookalike domains)", s["H2"])]
        out.append(Paragraph(
            "Registered domains that imitate yours. Impostors with mail servers can send phishing that appears to come "
            "from you. Domains marked yours share your name servers or hosting (defensive registrations).", s["muted"]))  # fmt: skip
        label = {"suspicious": "Impostor", "parked": "Parked", "yours": "Yours"}
        rows: list[list[Any]] = [["Domain", "How it imitates you", "Status", "Email", "Risk"]]
        rows += [[Paragraph(esc(x["display"]) + (f'<br/><font color="#6b7280" size="7">{esc(x["domain"])}</font>'
                                                 if x["display"] != x["domain"] else ""), s["cell"]),
                  Paragraph(esc(x["detail"]), s["cell"]), Paragraph(esc(label.get(x["verdict"], x["verdict"])), s["cell"]),
                  Paragraph("Yes" if x["mx"] else "No", s["cell"]), Paragraph(str(x["risk"]), s["cellb"])]
                 for x in d.lookalikes]  # fmt: skip
        out.append(_table(rows, [52 * mm, 52 * mm, 22 * mm, 16 * mm, 16 * mm]))
    if d.related:
        out += [Spacer(1, 4 * mm), Paragraph("Related infrastructure", s["H2"])]
        out.append(Paragraph(
            "Domains that share an analytics ID, certificate organisation, name servers or hosting with the target. "
            "They were not assessed: confirm whether they are yours and in scope, and include them in a future "
            "assessment if so. Forgotten assets are a common way in.", s["muted"]))  # fmt: skip
        rel_rows: list[list[Any]] = [["Domain", "Linked by", "Confidence"]]
        rel_rows += [[Paragraph(f"<b>{esc(x['domain'])}</b><br/><font color=\"#6b7280\" size=\"7\">{esc(x['attribution'])}</font>",
                                s["cell"]),
                      Paragraph("<br/>".join(esc(v) for v in x["evidence"]), s["cell"]),
                      Paragraph(f"{round(x['confidence'] * 100)}%", s["cellb"])] for x in d.related]  # fmt: skip
        out.append(_table(rel_rows, [55 * mm, 95 * mm, 24 * mm]))
    return out


def _inventory(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("5. Attack-surface inventory", s["H1"])]
    accent_bars = [(c["label"], c["count"], colors.HexColor("#64748b")) for c in d.categories[:10]]
    if accent_bars:
        out += [_bars(accent_bars, width), Spacer(1, 4 * mm)]
    if d.inventory:
        rows: list[list[Any]] = [["Category", "Asset", "Source"]]
        rows += [[Paragraph(esc(r["category"]), s["cell"]), Paragraph(esc(r["value"], 400), s["cell"]),
                  Paragraph(esc(r["source"]), s["muted"])] for r in d.inventory]  # fmt: skip
        out.append(_table(rows, [34 * mm, width - 74 * mm, 40 * mm]))
        if d.inventory_truncated:
            out.append(Paragraph(f"{d.inventory_truncated} further assets are available in Argus.", s["muted"]))
    elif not d.options.include_inventory:
        out.append(Paragraph("The detailed asset list was excluded from this report.", s["muted"]))
    return out


def _attack(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("6. MITRE ATT&amp;CK reconnaissance coverage", s["H1"])]
    out.append(Paragraph("What an adversary can learn at the reconnaissance stage (tactic TA0043), and how to reduce it.",
                         s["muted"]))  # fmt: skip
    out.append(Spacer(1, 2 * mm))
    if not d.techniques:
        return [*out, Paragraph("No techniques were applicable.", s["body"])]
    rows: list[list[Any]] = [["Technique", "Findings", "Defensive guidance"]]
    rows += [[Paragraph(f"<b>{esc(t['id'])}</b> {esc(t['name'])}", s["cell"]), Paragraph(str(t["count"]), s["cell"]),
              Paragraph(esc(t["defence"]), s["cell"])] for t in d.techniques]  # fmt: skip
    out.append(_table(rows, [58 * mm, 18 * mm, width - 76 * mm]))
    return out


def _method(d: ReportData, s: dict[str, ParagraphStyle], width: float) -> list[Flowable]:
    inv = d.investigation
    out: list[Flowable] = [Paragraph("7. Scope, methodology and limitations", s["H1"])]
    scope = [
        f"Target: {d.target}. Purpose recorded at launch: {inv.get('purpose') or 'not recorded'}.",
        f"The person who launched the assessment confirmed they were authorised to assess this target; the "
        f"confirmation is held in Argus's tamper-evident audit log ({inv['id']}).",
        f"Discovery depth: {inv['depth']} hop(s) from the target. "
        + (
            "Passive mode: no request was sent to the target's own systems."
            if inv["passive_only"]
            else "Two active checks contacted the target directly with ordinary single requests (a TLS handshake and an "
            "HTTP request)."
        ),
    ]
    out.append(_bullets(scope, s))
    out += [Spacer(1, 3 * mm), Paragraph("Limitations", s["H2"])]
    out.append(_bullets([
        "Findings come from public sources (DNS, certificate transparency, RDAP, public scan and breach databases, "
        "code hosting and public profiles) at the time of the assessment, and may be incomplete or out of date.",
        "No exploitation, credential testing or brute forcing was performed. Attack paths are rule-based assessments "
        "of plausible attacker routes, not confirmed compromise.",
        "Absence of a finding is not proof of absence of a weakness.",
    ], s))  # fmt: skip
    if d.sources:
        out += [Spacer(1, 3 * mm), Paragraph("Sources consulted", s["H2"])]
        rows: list[list[Any]] = [["Collector", "Findings"]]
        rows += [[Paragraph(esc(x["module"]), s["cell"]), Paragraph(str(x["findings"]), s["cell"])] for x in d.sources]
        out.append(_table(rows, [width - 30 * mm, 30 * mm]))
    return out


def _appendix(d: ReportData, s: dict[str, ParagraphStyle], width: float, verify_url: str | None) -> list[Flowable]:
    out: list[Flowable] = [Paragraph("Appendix: definitions and verification", s["H1"])]
    scale = [["Severity", "Meaning"],
             [_pill("critical", s), Paragraph("Likely to be exploited soon with serious impact. Act immediately.", s["cell"])],
             [_pill("high", s), Paragraph("A realistic route to compromise or data exposure. Fix within days.", s["cell"])],
             [_pill("medium", s), Paragraph("Useful to an attacker in combination with other weaknesses. Plan a fix.", s["cell"])],
             [_pill("low", s), Paragraph("Information that slightly eases attacks. Address as hygiene.", s["cell"])]]  # fmt: skip
    out += [_table(scale, [26 * mm, width - 26 * mm], zebra=False), Spacer(1, 5 * mm)]
    tlp = [["Label", "Sharing"]] + [[Paragraph(f"<b>TLP:{k}</b>", s["cell"]), Paragraph(esc(v), s["cell"])]
                                    for k, v in TLP_MEANING.items()]  # fmt: skip
    out += [
        Paragraph("Traffic Light Protocol (FIRST TLP 2.0)", s["H2"]),
        _table(tlp, [38 * mm, width - 38 * mm], zebra=False),
    ]
    out += [Spacer(1, 5 * mm), Paragraph("Verifying this report", s["H2"])]
    how = (
        f"Reference <b>{esc(d.report_id)}</b>. Argus records a SHA-256 fingerprint of every report it issues. To confirm "
        'this file is genuine and unmodified, compute its fingerprint (for example <font name="Courier">sha256sum '
        "report.pdf</font>) and look it up"
    )
    how += f" at <b>{esc(verify_url)}</b>." if verify_url else " with the issuing organisation's Argus administrator."
    out.append(Paragraph(how, s["body"]))
    return out


# ---------------------------------------------------------------------------- entry point
def render_pdf(data: ReportData, *, verify_url: str | None = None) -> bytes:
    _register_fonts()
    accent = colors.HexColor(data.branding.accent if _HEX.match(data.branding.accent or "") else "#4f46e5")
    s = _styles(accent)
    buffer = io.BytesIO()
    doc = _Doc(buffer, data, accent)
    width = doc.width
    story: list[Flowable] = [NextPageTemplate("cover"), *_cover(data, s, accent), NextPageTemplate("body"), PageBreak()]
    story += [*_contents(data, s), PageBreak()]
    story += [*_executive(data, s, width), Spacer(1, 6 * mm)]
    story += [*_recommendations(data, s, width), Spacer(1, 6 * mm), CondPageBreak(110 * mm)]
    story += [*_paths(data, s, width), PageBreak()]
    story += [*_exposure(data, s), Spacer(1, 6 * mm), CondPageBreak(110 * mm)]
    story += [*_inventory(data, s, width), PageBreak()]
    story += [*_attack(data, s, width), PageBreak()]
    story += [*_method(data, s, width), Spacer(1, 6 * mm), CondPageBreak(150 * mm)]
    story += _appendix(data, s, width, verify_url)
    doc.multiBuild(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
