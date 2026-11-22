"""The brand-protection report: lookalikes, live threats, takedowns and how fast they work.

Two to three pages for a security lead or a board: headline numbers, the weekly trend, the open
threats and takedowns waiting longest, and the campaigns. Domain names come from Certificate
Transparency, i.e. from whoever registered them, so every value is escaped (:func:`esc`).
"""

from __future__ import annotations

import io
from collections.abc import Callable
from datetime import datetime
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from argus.reports.data import Branding
from argus.reports.pdf import MARGIN, MUTED, PAGE_H, PAGE_W, RULE, SOFT, _Fonts, _register_fonts, _styles, esc

ACCENT = colors.HexColor("#4f5bd5")
SEVERITY = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563"}
WIDTH = PAGE_W - 2 * MARGIN


def _frame(workspace: str, tlp: str, report_id: str, generated: str) -> Callable[[Any, Any], None]:
    def draw(c: Any, doc: Any) -> None:
        c.saveState()
        c.setFont(_Fonts.bold, 7.5)
        c.setFillColor(colors.HexColor("#b45309"))
        c.drawString(MARGIN, PAGE_H - 11 * mm, f"TLP:{tlp}")
        c.setFillColor(MUTED)
        c.setFont(_Fonts.regular, 7.5)
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 11 * mm, f"Brand protection · {workspace[:60]}")
        c.setStrokeColor(RULE)
        c.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
        c.drawString(MARGIN, 10 * mm, f"Report {report_id} · {generated}")
        c.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}")
        c.restoreState()

    return draw


def _cells(rows: list[list[Any]], widths: list[float], s: dict[str, Any]) -> Table:
    table = Table([[c if not isinstance(c, str) else Paragraph(c, s["cellb" if i == 0 else "cell"]) for c in row]
                   for i, row in enumerate(rows)], colWidths=widths, repeatRows=1)  # fmt: skip
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), SOFT), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))  # fmt: skip
    return table


def _figures(summary: dict[str, Any], s: dict[str, Any]) -> Table:
    take = summary["takedowns"]
    median_days = take["median_days_to_down"]
    items = [
        (
            summary["open_threats"]["count"],
            "open threats",
            "#b91c1c" if summary["open_threats"]["count"] else "#15803d",
        ),
        (summary["found"]["new"], f"new lookalikes ({summary['period_days']} days)", "#111827"),
        (take["down_in_period"], "taken down in the period", "#15803d"),
        (f"{median_days:g} d" if median_days is not None else "n/a", "median time to takedown", "#111827"),
        (summary["campaigns"]["count"], "campaigns", "#111827"),
    ]
    big = s["H1"].clone("fig", fontSize=20, leading=24, spaceBefore=0, spaceAfter=0)
    cells = [[Paragraph(f"<font color='{colour}'>{esc(value)}</font>", big), Paragraph(esc(label), s["muted"])]
             for value, label, colour in items]  # fmt: skip
    table = Table([cells], colWidths=[WIDTH / len(items)] * len(items))
    table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
                               ("BACKGROUND", (0, 0), (-1, -1), SOFT), ("TOPPADDING", (0, 0), (-1, -1), 8),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))  # fmt: skip
    return table


def _trend(summary: dict[str, Any]) -> Drawing:
    trend = summary["trend"]
    drawing = Drawing(WIDTH, 58 * mm)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 12 * mm, 10 * mm, WIDTH - 16 * mm, 40 * mm
    chart.data = [trend["new_lookalikes"] or [0], trend["taken_down"] or [0]]
    chart.categoryAxis.categoryNames = [d[5:] for d in trend["week_starts"]]
    chart.categoryAxis.labels.fontName, chart.categoryAxis.labels.fontSize = _Fonts.regular, 6.5
    chart.categoryAxis.labels.angle = 45 if len(trend["week_starts"]) > 14 else 0
    chart.valueAxis.labels.fontName, chart.valueAxis.labels.fontSize = _Fonts.regular, 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(4, max(*chart.data[0], *chart.data[1]) + 1)
    chart.bars[0].fillColor, chart.bars[1].fillColor = colors.HexColor("#c2410c"), colors.HexColor("#15803d")
    chart.bars.strokeColor = None
    drawing.add(chart)
    for x, colour, label in ((12 * mm, "#c2410c", "New lookalikes"), (52 * mm, "#15803d", "Taken down")):
        drawing.add(Rect(x, 54 * mm, 2.6 * mm, 2.6 * mm, fillColor=colors.HexColor(colour), strokeColor=None))
        drawing.add(String(x + 4 * mm, 54 * mm, label, fontName=_Fonts.regular, fontSize=8, fillColor=MUTED))
    return drawing


def render_brand_pdf(
    summary: dict[str, Any], *, branding: Branding, report_id: str, workspace: str, tlp: str, prepared_for: str,
    generated_at: datetime, generator: str, verify_url: str | None,
) -> bytes:  # fmt: skip
    _register_fonts()
    s = _styles(ACCENT)
    buffer = io.BytesIO()
    generated = generated_at.strftime("%d %b %Y %H:%M UTC")
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN + 4 * mm,
                            bottomMargin=MARGIN, title="Brand protection report", author=branding.organisation or "Argus")  # fmt: skip
    brands = ", ".join(b["domain"] for b in summary["brands"]) or "no brand watched yet"
    story: list[Any] = [
        Paragraph("BRAND PROTECTION", s["kicker"]),
        Paragraph(esc(f"Lookalike domains, phishing and takedowns: {brands}"), s["H1"]),
        Paragraph(
            esc(
                f"The last {summary['period_days']} days, to {generated}. "
                + (f"Prepared for {prepared_for}. " if prepared_for else "")
                + f"Issued by {branding.organisation or 'Argus'}."
            ),
            s["muted"],
        ),
        Spacer(1, 4 * mm),
        _figures(summary, s),
        Spacer(1, 5 * mm),
        Paragraph("Trend", s["H2"]),
        _trend(summary),
    ]

    story.append(Paragraph("Open threats", s["H2"]))
    threats = summary["open_threats"]["top"]
    if threats:
        rows: list[list[Any]] = [["Domain", "Verdict", "Severity", "First seen", "Takedown"]]
        for t in threats:
            colour = SEVERITY.get(t["severity"], "#4b5563")
            rows.append([esc(t["domain"]), esc(t["label"]), f"<font color='{colour}'><b>{esc(t['severity'])}</b></font>",
                         esc(str(t["first_seen"] or "")[:10]), esc(t["takedown"] or "not started")])  # fmt: skip
        story.append(_cells(rows, [62 * mm, 38 * mm, 20 * mm, 22 * mm, WIDTH - 142 * mm], s))
    else:
        story.append(Paragraph("None: no lookalike is currently judged an active phishing page, a copy of your site, "
                               "or a high-severity mail-capable domain.", s["body"]))  # fmt: skip

    take = summary["takedowns"]
    story.append(Paragraph("Takedowns", s["H2"]))
    by_status = take["by_status"]
    story.append(Paragraph(esc(
        f"{by_status.get('reported', 0)} reported and waiting, {by_status.get('drafted', 0)} drafted, "
        f"{by_status.get('down', 0)} taken down, {by_status.get('closed', 0)} closed. In the period: "
        f"{take['reported_in_period']} reported, {take['down_in_period']} taken down"
        + (f"; median {take['median_days_to_down']:g} days from report to takedown." if take["median_days_to_down"]
           is not None else ".")), s["body"]))  # fmt: skip
    if take["open"]:
        rows = [["Waiting longest", "Brand", "Status", "Days open", "Recipients"]]
        rows += [[esc(t["domain"]), esc(t["brand"]), esc(t["status"]),
                  esc(f"{t['waiting_days']:g}" if t["waiting_days"] is not None else "?"), esc(t["recipients"])]
                 for t in take["open"]]  # fmt: skip
        story.append(_cells(rows, [62 * mm, 40 * mm, 22 * mm, 20 * mm, WIDTH - 144 * mm], s))

    story.append(Paragraph("Campaigns", s["H2"]))
    if summary["campaigns"]["largest"]:
        rows = [["Campaign (shared infrastructure)", "Items", "Severity"]]
        rows += [[esc(c["name"]), esc(c["size"]), esc(c["severity"])] for c in summary["campaigns"]["largest"]]
        story.append(_cells(rows, [WIDTH - 44 * mm, 18 * mm, 26 * mm], s))
    else:
        story.append(Paragraph("None: no group of lookalikes shares infrastructure.", s["body"]))

    story.append(Paragraph("Watched brands", s["H2"]))
    rows = [["Brand", "Lookalikes known", "New in period", "Open threats", "Last check"]]
    rows += [[esc(b["domain"]), esc(b["known"]), esc(b["new"]), esc(b["threats"]),
              esc(f"{str(b['last_run_at'] or '')[:10]} {b['last_status'] or ''}")] for b in summary["brands"]]  # fmt: skip
    story.append(_cells(rows, [56 * mm, 30 * mm, 28 * mm, 26 * mm, WIDTH - 140 * mm], s))

    footer = f"Generated by {generator}."
    if verify_url:
        footer += f" Check this PDF is genuine: compute its SHA-256 and open {verify_url}."
    story += [
        Spacer(1, 6 * mm),
        KeepTogether(
            [
                Paragraph("How to read this report", s["H2"]),
                Paragraph(
                    esc(
                        "Lookalike domains come from Certificate Transparency (crt.sh and Cert Spotter). Each is triaged: DNS (does "
                        "it resolve, can it send email, is it parked or yours) and, where website checks are allowed, its page "
                        "(a password field, your favicon, title or look). An open threat is a lookalike judged an active phishing "
                        "page, a copy of your site, or a high-severity mail-capable domain that has not been taken down. Time to "
                        "takedown runs from when the abuse report was marked sent to when Argus saw the domain stop resolving or "
                        "its site disappear."
                    ),
                    s["small"],
                ),
                Paragraph(esc(footer), s["muted"]),
            ]
        ),
    ]
    page = _frame(workspace, tlp, report_id, generated)
    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buffer.getvalue()
