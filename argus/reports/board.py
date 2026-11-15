"""The board report: two pages a director can read in five minutes.

Page 1 answers "how are we doing?": an overall status with its reason, the key messages (worst
first, good news included), and the five areas as red / amber / green with why. Page 2 is the
evidence: ratings and their trend, the risks to act on (with owners and deadlines), remediation
performance, and how to read the report.

It is built from the same house style, TLP marking, page numbering and **escaping** as the
assessment report. Target names and path titles come from scanned websites, so every value
goes through :func:`argus.reports.pdf.esc`. It names the **owners** of work (accountability) but
never the people findings are about: exposure appears only as counts, and addresses in finding
titles are masked.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from argus.reports.data import Branding
from argus.reports.pdf import (
    _HEX,
    GRADE_COLOURS,
    INK,
    MARGIN,
    MUTED,
    PAGE_H,
    PAGE_W,
    RULE,
    SOFT,
    NumberedCanvas,
    _bullets,
    _Fonts,
    _metric,
    _pill,
    _plain,
    _register_fonts,
    _styles,
    _table,
    _tlp_badge,
    esc,
)

RAG = {
    "red": (colors.HexColor("#c0262d"), "RED"),
    "amber": (colors.HexColor("#c99a06"), "AMBER"),
    "green": (colors.HexColor("#2f9e44"), "GREEN"),
    "grey": (MUTED, "NOT MEASURED"),
}
RAG_MEANING = [
    ("RED", "Needs a decision or resources now: an emergency, or well outside tolerance."),
    ("AMBER", "Below target but under control: watch it and agree a plan."),
    ("GREEN", "Within tolerance."),
    ("NOT MEASURED", "Argus has no data for this area yet."),
]


class _BoardDoc(BaseDocTemplate):
    def __init__(self, buffer: io.BytesIO, meta: dict[str, Any], accent: colors.Color, branding: Branding):
        self.meta, self.accent, self.branding = meta, accent, branding
        super().__init__(
            buffer, pagesize=(PAGE_W, PAGE_H), leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN + 10 * mm,
            bottomMargin=MARGIN, title=f"Cyber security board report: {meta['workspace']}", author=branding.organisation,
            subject=f"{meta['report_id']} · TLP:{meta['tlp']}", creator=meta["generator"],
            keywords=["board report", "cyber security", meta["report_id"], f"TLP:{meta['tlp']}"],
        )  # fmt: skip
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=self._page)])

    def _page(self, c: rl_canvas.Canvas, _doc: Any) -> None:
        m = self.meta
        c.saveState()
        c.setFillColor(self.accent)
        c.rect(0, PAGE_H - 7 * mm, PAGE_W, 7 * mm, stroke=0, fill=1)
        x = MARGIN
        if self.branding.logo_png:  # re-encoded and validated when uploaded
            c.drawImage(ImageReader(io.BytesIO(self.branding.logo_png)), x, PAGE_H - 19 * mm, width=22 * mm,
                        height=9 * mm, preserveAspectRatio=True, anchor="w", mask="auto")  # fmt: skip
            x += 25 * mm
        c.setFont(_Fonts.bold, 9)
        c.setFillColor(INK)
        c.drawString(x, PAGE_H - 15 * mm, _plain(self.branding.organisation)[:60])
        c.setFont(_Fonts.regular, 8)
        c.setFillColor(MUTED)
        c.drawString(x, PAGE_H - 19 * mm, _plain(f"Cyber security board report · {m['workspace']}")[:90])
        _tlp_badge(c, m["tlp"], PAGE_W - MARGIN, PAGE_H - 16 * mm, 8)
        c.setStrokeColor(RULE)
        c.setLineWidth(0.6)
        c.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
        c.setFont(_Fonts.regular, 7.5)
        c.setFillColor(MUTED)
        footer = f"{m['report_id']} · {m['generated_at']:%d %b %Y}"
        if self.branding.footer_note:
            footer += f" · {_plain(self.branding.footer_note)[:80]}"
        c.drawString(MARGIN, 10 * mm, footer)
        _tlp_badge(c, m["tlp"], PAGE_W - MARGIN - 28 * mm, 10 * mm, 6.5)
        c.restoreState()


def _rag(status: str, s: dict[str, ParagraphStyle], width: float = 31 * mm) -> Table:
    colour, label = RAG[status]
    cell = Paragraph(f'<font color="#ffffff"><b>{label}</b></font>',
                     ParagraphStyle("rag", parent=s["small"], alignment=TA_CENTER, fontSize=7.5, leading=9, spaceAfter=0))  # fmt: skip
    t = Table([[cell]], colWidths=[width], rowHeights=[5.5 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colour), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))  # fmt: skip
    return t


def _overall(summary: dict[str, Any], s: dict[str, ParagraphStyle], width: float) -> Table:
    colour, label = RAG[summary["overall"]]
    big = ParagraphStyle("overall", parent=s["body"], fontName=_Fonts.bold, fontSize=20, leading=24,
                         textColor=colors.white)  # fmt: skip
    verdict = ParagraphStyle("verdict", parent=s["body"], fontSize=10.5, leading=14, textColor=colors.white)
    t = Table([[Paragraph(f"Overall: {label}", big)], [Paragraph(esc(summary["verdict"]), verdict)]],
              colWidths=[width])  # fmt: skip
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colour), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (0, 0), 8), ("BOTTOMPADDING", (0, -1), (-1, -1), 9)]))  # fmt: skip
    return t


def _due(risk: dict[str, Any]) -> str:
    if risk["status"] == "untracked":
        return "No owner yet"
    due = (risk.get("due_at") or "")[:10]
    return f"OVERDUE (was due {due})" if risk.get("overdue") else f"Due {due}" if due else ""


def render_board_pdf(
    summary: dict[str, Any],
    *,
    branding: Branding,
    report_id: str,
    workspace: str,
    tlp: str,
    prepared_for: str,
    generated_at: datetime,
    generator: str,
    verify_url: str | None,
) -> bytes:
    _register_fonts()
    accent = colors.HexColor(branding.accent if _HEX.match(branding.accent or "") else "#4f46e5")
    s = _styles(accent)
    meta = {"report_id": report_id, "workspace": workspace, "tlp": tlp, "generated_at": generated_at,
            "generator": generator}  # fmt: skip
    buffer = io.BytesIO()
    doc = _BoardDoc(buffer, meta, accent, branding)
    width = doc.width
    days = summary["period_days"]

    story: list[Flowable] = [
        Paragraph("CYBER SECURITY · BOARD REPORT", s["kicker"]),
        Paragraph("How exposed are we, and are we fixing it fast enough?", s["H1"]),
        Paragraph(
            esc(
                f"{workspace} · last {days} days to {generated_at:%d %B %Y}"
                + (f" · prepared for {prepared_for}" if prepared_for else "")
            ),
            s["muted"],
        ),
        Spacer(1, 4 * mm),
        _overall(summary, s, width),
        Spacer(1, 5 * mm),
        Paragraph("Key messages", s["H2"]),
        _bullets(summary["messages"] or ["Nothing notable in this period."], s),
        Spacer(1, 4 * mm),
        Paragraph("Areas", s["H2"]),
    ]
    rows = [
        [Paragraph("<b>Area</b>", s["cell"]), Paragraph("<b>Status</b>", s["cell"]), Paragraph("<b>Why</b>", s["cell"])]
    ]
    rows += [[Paragraph(esc(a["title"]), s["cellb"]), _rag(a["status"], s), Paragraph(esc(a["reason"]), s["cell"])]
             for a in summary["areas"]]  # fmt: skip
    story.append(_table(rows, [46 * mm, 35 * mm, width - 81 * mm]))

    # ---- page 2: the evidence
    story += [Spacer(1, 6 * mm), Paragraph("Security ratings", s["H2"])]
    orgs = summary["organisations"]
    if orgs:
        rating_rows = [[Paragraph(f"<b>{h}</b>", s["cell"]) for h in ("Organisation", "Grade", "Score", "Change")]]
        for o in sorted(orgs, key=lambda o: o["score"]):
            grade = o["grade"]
            change = o.get("change")
            rating_rows.append([
                Paragraph(esc(o["target"]), s["cell"]),
                Paragraph(f'<font color="{GRADE_COLOURS[grade].hexval().replace("0x", "#")}"><b>{grade}</b></font>', s["cell"]),
                Paragraph(str(round(o["score"])), s["cell"]),
                Paragraph("—" if change is None else f"{'+' if change > 0 else ''}{change}", s["cell"]),
            ])  # fmt: skip
        story.append(_table(rating_rows, [width - 75 * mm, 22 * mm, 22 * mm, 31 * mm]))
    else:
        story.append(Paragraph("No organisation of yours has been rated yet.", s["muted"]))

    story += [Spacer(1, 5 * mm), Paragraph("Risks to act on", s["H2"])]
    if summary["top_risks"]:
        risk_rows = [[Paragraph(f"<b>{h}</b>", s["cell"]) for h in ("", "Risk", "Owner", "Deadline")]]
        risk_rows += [[_pill(r["severity"], s), Paragraph(esc(f"{r['title']} ({r['target']})"), s["cell"]),
                       Paragraph(esc(r["owner"] or "Unassigned"), s["cell"]), Paragraph(esc(_due(r)), s["cell"])]
                      for r in summary["top_risks"]]  # fmt: skip
        story.append(_table(risk_rows, [24 * mm, width - 106 * mm, 48 * mm, 34 * mm]))
    else:
        story.append(Paragraph("No open critical or high risks.", s["muted"]))

    figures = {a["key"]: a["figures"] for a in summary["areas"]}
    rem, exp, sup = figures.get("remediation", {}), figures.get("exposure", {}), figures.get("suppliers", {})

    def value(v: Any, suffix: str = "") -> str:
        return "—" if v is None else f"{v}{suffix}"

    cells = [
        _metric(value(rem.get("overdue")), "remediation tasks overdue", s),
        _metric(value(rem.get("sla_compliance"), "%"), "of fixes verified on time", s),
        _metric(value(rem.get("mttr_critical"), " d"), "median days to fix a critical issue", s),
        _metric(value(exp.get("infostealers")), "infostealer infections", s),
        _metric(value(sup.get("below_minimum")), "suppliers below minimum grade", s),
    ]
    metrics_table = Table([cells], colWidths=[width / 5] * 5)
    metrics_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                       ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6)]))  # fmt: skip
    story += [Spacer(1, 5 * mm), KeepTogether([Paragraph("Performance", s["H2"]), metrics_table])]

    legend = [
        [Paragraph(f"<b>{label}</b>", s["cell"]), Paragraph(meaning, s["cell"])] for label, meaning in RAG_MEANING
    ]
    notes = [
        "Ratings are outside-in: what an attacker can see from the internet, graded A to F by Argus's published "
        "methodology.",
        "A fix only counts as done when a later scan, at least as thorough as the first, no longer finds the problem.",
        "Exposure figures are counts only, and addresses in findings are masked: the people affected are never named.",
    ]
    if verify_url:
        notes.append(f"Check this document is genuine and unaltered: {verify_url} (SHA-256 of this file).")
    story += [Spacer(1, 5 * mm), KeepTogether([Paragraph("How to read this report", s["H2"]),
              _table(legend, [30 * mm, width - 30 * mm], header=False, zebra=False), Spacer(1, 2 * mm),
              _bullets(notes, s, "muted")])]  # fmt: skip
    doc.multiBuild(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
