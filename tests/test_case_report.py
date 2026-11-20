"""Phase 70: a case as one self-contained HTML report."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from argus.reports.case_html import case_report_html, network_svg
from tests.test_cases import client, keys, new_case  # noqa: F401  (the fixture is used by name)


def _build(c):
    case = new_case(c, summary="Donations after the floods.\n<b>not bold</b>", tags=["fraud"]).json()
    url = f"/api/cases/{case['id']}/items"

    def ent(kind, value, **attributes):
        return c.post(
            url, json={"kind": "entity", "data": {"type": kind, "value": value, "attributes": attributes}}
        ).json()

    jane, org = ent("person", "Jane Roe"), ent("organisation", "Helping <Hands> Ltd")
    child = ent("person", "Kid Roe", protected="true")
    c.post(url, json={"kind": "link", "data": {"from": jane["id"], "to": org["id"], "relation": "director",
                                                "confidence": "confirmed", "since": "2023-02"}})  # fmt: skip
    c.post(url, json={"kind": "link", "data": {"from": jane["id"], "to": child["id"], "relation": "parent"}})
    c.post(url, json={"kind": "event", "title": "Appeal launched", "occurred_at": "2026-02-11T09:00:00Z"})
    inv = c.get("/api/investigations").json()[0]
    c.post(url, json={"kind": "scan", "data": {"investigation_id": inv["id"]}})
    c.post(url, json={"kind": "note", "title": "Lead", "body": "Ask the <regulator>."})
    upload = c.post(f"/api/cases/{case['id']}/uploads", files={"file": ("chat.png", b"\x89PNG\r\n\x1a\nfake", "image/png")},
                    data={"note": "From a source"}).json()  # fmt: skip
    return case, upload


def test_the_report_is_one_safe_self_contained_file(client):  # noqa: F811
    case, upload = _build(client)
    r = client.get(f"/api/cases/{case['id']}/report.html")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert re.match(r'attachment; filename="argus-case-fake-charity-\d{8}\.html"', r.headers["content-disposition"])
    assert r.headers["x-argus-report-sha256"] == hashlib.sha256(r.content).hexdigest()
    assert "sandbox" in r.headers["content-security-policy"]
    page = r.text
    # Nothing runs and nothing is fetched.
    assert "<script" not in page and "default-src 'none'" in page
    assert not re.search(r'\s(src|href)=["\']https?:', page) and "<link" not in page
    # Everything the case holds, escaped.
    assert "Helping &lt;Hands&gt; Ltd" in page and "<Hands>" not in page and "&lt;b&gt;not bold" in page
    assert "Ask the &lt;regulator&gt;." in page and "Appeal launched" in page and "Scan of" in page
    assert "<svg" in page and "Jane Roe" in page and "director" in page.lower()
    assert "Kid Roe" not in page and "Protected person" in page  # protected people stay unnamed
    assert upload["files"][0]["sha256"] in page and upload["digest"] in page and "Intact at export" in page
    assert "CONFIDENTIAL" in page and "Domain registered" in page  # facts from the linked scan
    audit = [e for e in client.get("/api/audit?limit=50").json() if e["action"] == "case.report"]
    assert audit and audit[0]["details"]["sha256"] == r.headers["x-argus-report-sha256"]
    custody = client.get(f"/api/evidence/{upload['id']}").json()["custody"]
    assert any(x["action"] == "reported" for x in custody)


def test_tampered_evidence_shows_in_the_report(client):  # noqa: F811
    case, upload = _build(client)

    async def tamper():
        from sqlalchemy import update

        from argus.storage.db import EvidenceFileRow

        async with client.app.state.db.session() as s, s.begin():
            await s.execute(
                update(EvidenceFileRow).where(EvidenceFileRow.capture_id == upload["id"]).values(data=b"edited")
            )

    client.portal.call(tamper)
    page = client.get(f"/api/cases/{case['id']}/report.html").text
    assert "Integrity problem" in page and "has changed" in page


def test_who_can_export_it(client):  # noqa: F811
    case, _ = _build(client)
    _analyst, as_viewer = keys(client)
    assert client.get(f"/api/cases/{case['id']}/report.html", headers=as_viewer).status_code == 200
    private = new_case(client, title="Source", restricted=True).json()
    assert client.get(f"/api/cases/{private['id']}/report.html", headers=as_viewer).status_code == 404
    client.post("/api/workspaces", json={"name": "Other"})
    assert client.get(f"/api/cases/{case['id']}/report.html", headers={"X-Argus-Workspace": "other"}).status_code == 404


def test_an_empty_case_and_a_big_chart():
    case = {"id": "case_x", "title": "Empty", "purpose": "A legitimate purpose", "status": "open"}
    page = case_report_html(case, items=[], captures=[], network={}, timeline=[], scans=[], by="me",
                            generated_at=datetime(2026, 11, 20, tzinfo=timezone.utc))  # fmt: skip
    assert "Nothing dated yet" in page and "No evidence" in page and "<svg" not in page
    nodes = [{"id": f"n{i}", "label": f"Node {i}", "type": "person", "degree": i % 7} for i in range(400)]
    edges = [{"from": f"n{i}", "to": f"n{(i * 7) % 400}", "confidence": "likely"} for i in range(400)]
    svg = network_svg(nodes, edges)
    assert svg.count("<circle") == 150 and svg == network_svg(nodes, edges)  # capped and deterministic
