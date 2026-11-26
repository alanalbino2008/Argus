"""A case as one self-contained HTML file: summary, network, timeline, evidence and notes.

For handing a case over: to an editor, a lawyer, a client or a court, or for the file. It opens in
any browser, offline, years from now, with nothing else installed:

* **One file, nothing fetched.** Styles are inline, the network is drawn as inline SVG, and a
  Content-Security-Policy forbids scripts and every outside request. Opening it never tells anyone
  (a subject's server included) that it is being read.
* **Nothing clickable leads to a subject.** Addresses of captured pages are shown as text, never as
  links, so a reader cannot visit a subject's site by accident.
* **Evidence is described, not embedded.** Each capture's files are listed with their SHA-256, the
  chain of custody and the integrity check made at export; the files themselves travel in the
  evidence bundle (ZIP), whose hashes these match.
* Protected people (for example, children) stay unnamed, as everywhere else in Argus.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from html import escape
from typing import Any

from argus import __version__
from argus.reports.case_pdf import CAVEAT, CONFIDENCE_COLOUR, RANGE

MAX_TIMELINE = 3000
MAX_CHART_NODES = 150
CHART_W, CHART_H, PAD_X, PAD_Y = 960, 520, 90, 36
TYPE_COLOUR = {
    "person": "#4f5bd5", "organisation": "#0f766e", "username": "#7c3aed", "account": "#7c3aed",
    "email": "#b45309", "phone": "#be185d", "domain": "#0369a1", "ip": "#475569", "address": "#15803d",
    "location": "#15803d", "vehicle": "#9a3412", "document": "#6b7280", "wallet": "#a16207",
}  # fmt: skip
KIND_LABEL = {
    "fact": "Fact", "event": "Event", "scan": "Scan", "capture": "Capture", "upload": "Evidence added",
    "photo": "Photo", "change": "Change", "account_change": "Account change", "note": "Note", "person": "Person", "import": "Imported data",
}  # fmt: skip

CSS = """
:root{--ink:#111827;--muted:#6b7280;--rule:#e5e7eb;--soft:#f9fafb;--accent:#4f5bd5}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,
"Segoe UI",Roboto,Helvetica,Arial,sans-serif}main{max-width:1040px;margin:0 auto;padding:24px 20px 60px}
.banner{background:#991b1b;color:#fff;text-align:center;font-weight:600;letter-spacing:.04em;padding:6px;font-size:12px}
h1{font-size:26px;margin:18px 0 4px}h2{font-size:18px;margin:36px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
h3{font-size:15px;margin:18px 0 6px}.muted{color:var(--muted)}.small{font-size:12px}.mono{font-family:ui-monospace,
SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:12px 0}dl.meta dt{color:var(--muted)}dl.meta dd{margin:0}
.figures{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.figure{border:1px solid var(--rule);border-radius:8px;padding:10px 12px;background:var(--soft)}
.figure b{display:block;font-size:22px}.figure span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{text-align:left;vertical-align:top;padding:6px 8px;
border-bottom:1px solid var(--rule)}th{font-size:12px;color:var(--muted);font-weight:600;background:var(--soft)}
td.when{white-space:nowrap;width:1%}.against{color:#b45309}.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;
font-weight:600;border:1px solid currentColor;white-space:nowrap}.ok{color:#15803d}.bad{color:#b91c1c}
.card{border:1px solid var(--rule);border-radius:8px;padding:12px 14px;margin:12px 0;break-inside:avoid}
.prose{white-space:pre-wrap}svg{width:100%;height:auto;border:1px solid var(--rule);border-radius:8px;background:var(--soft)}
.legend span{display:inline-block;margin-right:14px;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;
border-radius:50%;margin-right:5px;vertical-align:middle}footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--rule)}
@media (max-width:640px){table{display:block;overflow-x:auto}dl.meta{grid-template-columns:1fr}dl.meta dd{margin-bottom:6px}h1{font-size:22px}}
@media print{.banner{position:fixed;top:0;left:0;right:0}main{padding-top:36px}h2{break-after:avoid}a{color:inherit}}
"""


def e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _when(value: str | None, precision: str = "time") -> str:
    if not value:
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return e(value)
    if precision in ("day", "date") or (moment.hour, moment.minute, moment.second) == (0, 0, 0):
        return moment.strftime("%d %b %Y")
    if precision == "month":
        return moment.strftime("%b %Y")
    if precision == "year":
        return moment.strftime("%Y")
    return moment.strftime("%d %b %Y %H:%M UTC")


def _size(n: int | None) -> str:
    if not n:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n} B"


# ----------------------------------------------------------------------------- the network chart
def force_layout(
    order: list[str], links: list[tuple[str, str]], iterations: int = 150
) -> dict[str, tuple[float, float]]:
    """Fruchterman-Reingold in plain Python: linked nodes pull together, all nodes push apart.

    Deterministic (nodes start on a circle in ``order``, no randomness) and dependency-free; at most
    ``MAX_CHART_NODES`` nodes, so the O(n^2) steps stay well under a second.
    """
    n = len(order)
    if n == 1:
        return {order[0]: (0.0, 0.0)}
    index = {nid: i for i, nid in enumerate(order)}
    xs = [math.cos(2 * math.pi * i / n) for i in range(n)]
    ys = [math.sin(2 * math.pi * i / n) for i in range(n)]
    pairs = [(index[a], index[b]) for a, b in links]
    k = 1.6 / math.sqrt(n)
    temperature = 0.2
    for _ in range(iterations):
        dx, dy = [0.0] * n, [0.0] * n
        for i in range(n):
            for j in range(i + 1, n):
                ox, oy = xs[i] - xs[j], ys[i] - ys[j]
                dist2 = max(ox * ox + oy * oy, 1e-6)
                push = k * k / dist2  # force k²/d along the unit vector (o/d)
                dx[i] += ox * push
                dy[i] += oy * push
                dx[j] -= ox * push
                dy[j] -= oy * push
        for i, j in pairs:
            ox, oy = xs[i] - xs[j], ys[i] - ys[j]
            pull = math.sqrt(ox * ox + oy * oy) / k  # force d²/k along o/d
            dx[i] -= ox * pull
            dy[i] -= oy * pull
            dx[j] += ox * pull
            dy[j] += oy * pull
        for i in range(n):
            length = math.sqrt(dx[i] * dx[i] + dy[i] * dy[i])
            if length > 0:
                step = min(length, temperature) / length
                xs[i] += dx[i] * step
                ys[i] += dy[i] * step
        temperature = max(temperature * 0.97, 0.002)
    return {nid: (xs[i], ys[i]) for i, nid in enumerate(order)}


def network_svg(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    """The case's link chart as inline SVG (laid out here, deterministically: same case, same picture)."""
    if not nodes:
        return ""
    ranked = sorted(nodes, key=lambda n: (-int(n.get("degree") or 0), str(n.get("label"))))[:MAX_CHART_NODES]
    order = [n["id"] for n in ranked]
    shown = set(order)
    drawn = [x for x in edges if x["from"] in shown and x["to"] in shown and x["from"] != x["to"]]
    pos = force_layout(order, [(x["from"], x["to"]) for x in drawn])
    xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
    span_x, span_y = (max(xs) - min(xs)) or 1.0, (max(ys) - min(ys)) or 1.0

    def at(nid: str) -> tuple[float, float]:
        x, y = pos[nid]
        if len(order) == 1:
            return CHART_W / 2, CHART_H / 2
        return (
            PAD_X + (x - min(xs)) / span_x * (CHART_W - 2 * PAD_X),
            PAD_Y + (y - min(ys)) / span_y * (CHART_H - 2 * PAD_Y - 14),
        )

    parts = [f'<svg viewBox="0 0 {CHART_W} {CHART_H}" role="img" aria-label="Network of the case">']
    for link in drawn:
        (x1, y1), (x2, y2) = at(link["from"]), at(link["to"])
        colour = CONFIDENCE_COLOUR.get(str(link.get("confidence")), "#9ca3af")
        dash = ' stroke-dasharray="5 4"' if link.get("confidence") in ("likely", "possible") else ""
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{colour}" '
                     f'stroke-width="1.6" opacity=".75"{dash}><title>{e(link.get("text") or link.get("label"))}</title></line>')  # fmt: skip
    for n in ranked:
        x, y = at(n["id"])
        r = 6 + min(int(n.get("degree") or 0), 10)
        colour = "#9ca3af" if n.get("protected") else TYPE_COLOUR.get(str(n.get("type")), "#6b7280")
        label = str(n.get("label") or "")
        short = label if len(label) <= 26 else label[:25] + "…"
        parts.append(f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{colour}" stroke="#fff" stroke-width="2">'
                     f"<title>{e(label)} ({e(n.get('type'))})</title></circle>"
                     f'<text x="{x:.1f}" y="{y + r + 12:.1f}" text-anchor="middle" font-size="11" fill="#111827" stroke="#f9fafb" stroke-width="3" paint-order="stroke">{e(short)}</text></g>')  # fmt: skip
    parts.append("</svg>")
    return "".join(parts)


# ----------------------------------------------------------------------------- sections
def _header(case: dict[str, Any], by: str, generated_at: datetime) -> str:
    tags = " ".join(f'<span class="pill">{e(t)}</span>' for t in case.get("tags") or [])
    return f"""<h1>{e(case["title"])}</h1>
<p class="muted">Case report · generated {e(generated_at.strftime("%d %b %Y %H:%M UTC"))} by {e(by)}</p>
<dl class="meta">
<dt>Purpose</dt><dd>{e(case.get("purpose"))}</dd>{f"<dt>Authorisation</dt><dd>{e(case['authorization'])}</dd>" if case.get("authorization") else ""}
<dt>Status</dt><dd>{e(str(case.get("status", "")).capitalize())}</dd>
<dt>Opened</dt><dd>{_when(case.get("created_at"))} by {e(case.get("created_by"))}</dd>
<dt>Last change</dt><dd>{_when(case.get("updated_at"))}</dd>
<dt>Handling</dt><dd>{"Anonymous: subjects were never contacted directly" if case.get("opsec_mode") == "anonymous" else "Standard"}{" · restricted to named members" if case.get("restricted") else ""}</dd>
{f"<dt>Tags</dt><dd>{tags}</dd>" if tags else ""}
<dt>Case id</dt><dd class="mono">{e(case["id"])}</dd>
</dl>"""


def _figures(counts: dict[str, int]) -> str:
    cells = "".join(f'<div class="figure"><b>{n:,}</b><span>{e(label)}</span></div>' for label, n in counts.items())
    return f'<div class="figures">{cells}</div>'


def _network(network: dict[str, Any]) -> str:
    nodes, edges, analysis = network.get("nodes") or [], network.get("edges") or [], network.get("analysis") or {}
    if not nodes:
        return "<h2>Network</h2><p class='muted'>No people, organisations or other entities recorded yet.</p>"
    labels = {n["id"]: n.get("label") or n["id"] for n in nodes}
    types = Counter(str(n.get("type")) for n in nodes)
    legend = "".join(f'<span><i style="background:{TYPE_COLOUR.get(t, "#6b7280")}"></i>{e(t)} ({c})</span>'
                     for t, c in types.most_common())  # fmt: skip
    more = f" The chart shows the {MAX_CHART_NODES} most connected." if len(nodes) > MAX_CHART_NODES else ""
    key = analysis.get("key_people") or []
    bridges = analysis.get("bridges") or []
    rows = "".join(
        f"<tr><td>{e(labels.get(x['from']))}</td><td>{e(x.get('text') or x.get('label'))}</td>"
        f"<td>{e(labels.get(x['to']))}</td><td><span class='pill' style='color:{CONFIDENCE_COLOUR.get(str(x.get('confidence')), '#6b7280')}'>"
        f"{e(x.get('confidence') or 'recorded')}</span></td>"
        f"<td class='when'>{e(RANGE.join(p for p in (x.get('since') or '', x.get('until') or '') if p))}</td></tr>"
        for x in edges
    )  # fmt: skip
    return f"""<h2>Network</h2>
<p>{len(nodes):,} entities and {len(edges):,} links.{more} Solid lines are confirmed or recorded; dashed lines are likely or possible.</p>
{network_svg(nodes, edges)}
<p class="legend">{legend}</p>
{"<h3>Most connected</h3><p>" + ", ".join(f"{e(k['label'])} ({k['connections']})" for k in key[:10]) + "</p>" if key else ""}
{"<h3>Bridges between groups</h3><p>" + ", ".join(e(b.get("label")) for b in bridges[:10]) + "</p>" if bridges else ""}
{f"<h3>Links</h3><table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th><th>When</th></tr></thead><tbody>{rows}</tbody></table>" if rows else ""}"""


def _timeline_row(x: dict[str, Any]) -> str:
    kind = str(x.get("kind") or "")
    label = KIND_LABEL.get(kind, kind.replace("_", " ").capitalize())
    detail = f"<div class='small'>{e(x['detail'])}</div>" if x.get("detail") else ""
    return (
        f"<tr><td class='when'>{_when(x.get('at'), str(x.get('precision') or 'time'))}</td>"
        f"<td><span class='pill'>{e(label)}</span></td><td><b>{e(x.get('title'))}</b>{detail}</td>"
        f"<td class='small muted'>{e(x.get('by') or '')}</td></tr>"
    )


def _timeline(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "<h2>Timeline</h2><p class='muted'>Nothing dated yet.</p>"
    shown = entries[-MAX_TIMELINE:]
    cut = (
        f"<p class='muted small'>The {len(shown):,} most recent of {len(entries):,} entries.</p>"
        if len(entries) > len(shown)
        else ""
    )
    rows = "".join(_timeline_row(x) for x in shown)
    return f"""<h2>Timeline</h2>
<p>Everything dated in the case, oldest first: events, evidence, scans and the facts inside them.</p>{cut}
<table><thead><tr><th>When</th><th>What</th><th></th><th>By</th></tr></thead><tbody>{rows}</tbody></table>"""


def _evidence(captures: list[dict[str, Any]]) -> str:
    if not captures:
        return "<h2>Evidence</h2><p class='muted'>No evidence captured or added yet.</p>"
    cards = []
    for c in captures:
        check = c.get("integrity") or {}
        status = ("<span class='pill ok'>Intact at export</span>" if check.get("intact")
                  else f"<span class='pill bad'>Integrity problem</span> {e('; '.join(check.get('problems') or []))}")  # fmt: skip
        files = "".join(f"<tr><td>{e(f['name'])}</td><td>{e(f.get('media_type'))}</td><td>{_size(f.get('size'))}</td>"
                        f"<td class='mono'>{e(f.get('sha256'))}</td></tr>" for f in c.get("files") or [])  # fmt: skip
        custody = "".join(f"<tr><td class='when'>{_when(x.get('at'))}</td><td>{e(x.get('action'))}</td><td>{e(x.get('by'))}</td>"
                          f"<td class='small'>{e(x.get('detail'))}</td></tr>" for x in c.get("custody") or [])  # fmt: skip
        source = c.get("final_url") or c.get("url")
        cards.append(f"""<div class="card"><h3>{e(c.get("title") or source or c["id"])}</h3>
<dl class="meta"><dt>Kind</dt><dd>{"Added by an investigator" if c.get("kind") == "upload" else "Captured by Argus"}</dd>
{f"<dt>Address</dt><dd class='mono'>{e(source)}</dd>" if source else ""}
<dt>When</dt><dd>{_when(c.get("captured_at"))} by {e(c.get("captured_by"))}</dd>
{f"<dt>Note</dt><dd>{e(c.get('note'))}</dd>" if c.get("note") else ""}
<dt>Digest</dt><dd class="mono">SHA-256 {e(c.get("digest"))}</dd>
<dt>Timestamp</dt><dd>{"RFC 3161 token from a timestamp authority" if c.get("timestamped") else "None"}</dd>
<dt>Integrity</dt><dd>{status}</dd>
<dt>Evidence id</dt><dd class="mono">{e(c["id"])}</dd></dl>
{f"<table><thead><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{files}</tbody></table>" if files else ""}
{f"<details><summary class='small'>Chain of custody ({len(c.get('custody') or [])} entries)</summary><table><tbody>{custody}</tbody></table></details>" if custody else ""}
</div>""")
    return ("<h2>Evidence</h2><p>The files themselves are in the case's evidence bundle (ZIP); their hashes match these.</p>"
            + "".join(cards))  # fmt: skip


def _scans(scans: list[dict[str, Any]]) -> str:
    if not scans:
        return ""
    rows = "".join(f"<tr><td>{e(s['target'])}</td><td>{e(s.get('status'))}</td><td class='when'>{_when(s.get('started_at'))}</td>"
                   f"<td>{e(s.get('created_by'))}</td><td class='mono'>{e(s['id'])}</td></tr>" for s in scans)  # fmt: skip
    return f"""<h2>Scans</h2><table><thead><tr><th>Target</th><th>Status</th><th>Started</th><th>By</th><th>Id</th></tr></thead>
<tbody>{rows}</tbody></table>"""


def _notes(items: list[dict[str, Any]]) -> str:
    notes = [i for i in items if i.get("kind") == "note"]
    if not notes:
        return ""
    cards = "".join(f"<div class='card'><h3>{e(n.get('title') or 'Note')}</h3><div class='prose'>{e(n.get('body'))}</div>"
                    f"<p class='muted small'>{e(n.get('created_by'))} · {_when(n.get('updated_at') or n.get('created_at'))}</p></div>"
                    for n in notes)  # fmt: skip
    return f"<h2>Notes</h2>{cards}"


KNOWN_LABELS = (("names", "Names"), ("usernames", "Usernames"), ("emails", "Email addresses"), ("phones", "Phone numbers"),
                ("profiles", "Accounts"), ("websites", "Websites"))  # fmt: skip


def _confirmed_row(c: dict[str, Any]) -> str:
    where = f" · {e(c['url'])}" if c.get("url") else ""
    against = f"<div class='small against'>Against: {e('; '.join(c['conflict']))}</div>" if c.get("conflict") else ""
    note = f"<div>{e(c['note'])}</div>" if c.get("note") else ""
    return (
        f"<tr><td><b>{e(c.get('label'))}</b><div class='small muted'>{e(c.get('platform') or c.get('kind'))}{where}</div></td>"
        f"<td>{e(c.get('score'))}/100</td><td class='small'>{e('; '.join(c.get('agree') or []) or '-')}{against}</td>"
        f"<td class='small'>{e(c.get('decided_by') or '')}<div class='muted'>{_when(c.get('decided_at'))}</div>{note}</td></tr>"
    )


def _person(p: dict[str, Any]) -> str:
    known = p.get("known") or {}
    rows = [(label, ", ".join(known.get(key) or [])) for key, label in KNOWN_LABELS if known.get(key)]
    rows += [(label, str(known[key])) for key, label in (("city", "Town or city"), ("employer", "Employer"),
                                                         ("birth_year", "Year of birth"), ("utc_offset", "Usual time zone (UTC)"))
             if known.get(key)]  # fmt: skip
    if known.get("photo_hash"):
        rows.append(("Photo", "A known photo was compared with profile pictures (only its fingerprint is kept)"))
    meta = "".join(f"<dt>{e(label)}</dt><dd>{e(value)}</dd>" for label, value in rows)
    cands = p.get("candidates") or []
    confirmed = [c for c in cands if c.get("status") == "confirmed"]
    open_count = sum(1 for c in cands if c.get("status") == "open")
    rejected = sum(1 for c in cands if c.get("status") == "rejected")
    found = "".join(_confirmed_row(c) for c in confirmed)
    run = p.get("run") or {}
    last = (f"Last search {_when(run.get('started_at'))} by {e(run.get('by'))}, {e(run.get('status'))}, "
            f"{len(run.get('steps') or [])} searches "
            f"{'made directly' if (run.get('route') or 'direct') == 'direct' else 'through the ' + e(run['route']) + ' route'}"
            f"{' (passive sources only)' if run.get('passive_only') else ''}." if run else "Not searched yet.")  # fmt: skip
    watch = " Watched weekly for new accounts." if p.get("watch") else ""
    table = (f"<h3>Confirmed as theirs ({len(confirmed)})</h3><table><thead><tr><th>Found</th><th>Score</th>"
             f"<th>Why</th><th>Confirmed by</th></tr></thead><tbody>{found}</tbody></table>" if found
             else "<p class='muted small'>Nothing found has been confirmed as theirs yet.</p>")  # fmt: skip
    return f"""<div class="card"><h3>{e(p.get("name"))}</h3>
<dl class="meta">{meta or "<dt>Known</dt><dd>Nothing recorded</dd>"}</dl>
<p class="small">{last}{watch} {open_count} not yet reviewed; {rejected} ruled out (not listed, as they belong to other people).</p>
{table}</div>"""


def _people(people: list[dict[str, Any]] | None) -> str:
    if not people:
        return ""
    return ("<h2>People researched</h2><p>What was known about each person, and what the investigators confirmed "
            "as theirs from the searches made from it, with the reasons. Scores are aids to judgement, not "
            "identifications.</p>" + "".join(_person(p) for p in people))  # fmt: skip


def _signature_note(signing: dict[str, str] | None) -> str:
    if not signing:
        return ""
    return (f"<p><b>Signed.</b> This file carries an Ed25519 signature by the report-signing key "
            f"<span class='mono'>{e(signing['key_id'])}</span>. Any change to it, however small, breaks the signature. "
            "Check it with <span class='mono'>argus --verify-report FILE</span>, the Argus Python client "
            "(<span class='mono'>verify_report</span>) or in Argus (Cases → Verify a report), and compare the key id "
            "with the one the organisation that issued it publishes.</p>")  # fmt: skip


def case_report_html(
    case: dict[str, Any],
    *,
    items: list[dict[str, Any]],
    captures: list[dict[str, Any]],
    network: dict[str, Any],
    timeline: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    by: str,
    generated_at: datetime,
    signing: dict[str, str] | None = None,
    people: list[dict[str, Any]] | None = None,
) -> str:
    """The report page. With ``signing`` (``tags`` and ``key_id`` from a :class:`ReportSigner`), it carries
    the signature tags (empty: the caller signs the result) and says how to check it."""
    counts = {
        "entities": len(network.get("nodes") or []),
        "links": len(network.get("edges") or []),
        "dated entries": len(timeline),
        "evidence items": len(captures),
        "scans": len(scans),
        "notes": sum(1 for i in items if i.get("kind") == "note"),
    }
    if people:
        counts["people researched"] = len(people)
    summary = f"<h2>Summary</h2><div class='prose'>{e(case.get('summary'))}</div>" if case.get("summary") else ""
    body = "".join((
        _header(case, by, generated_at), _figures(counts), summary, _people(people), _network(network), _timeline(timeline),
        _evidence(captures), _scans(scans), _notes(items),
    ))  # fmt: skip
    csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">{signing["tags"] if signing else ""}
<title>{e(case["title"])}: case report</title><style>{CSS}</style></head>
<body><div class="banner">CONFIDENTIAL · may contain personal data · handle under the case's legal basis</div>
<main>{body}
<footer class="muted small"><p>{e(CAVEAT)}</p>
<p>Generated by Argus {e(__version__)}. This file is self-contained: it loads nothing from the internet and runs no
scripts. Its SHA-256 was recorded in the Argus audit log when it was exported.</p>
{_signature_note(signing)}</footer>
</main></body></html>
"""
