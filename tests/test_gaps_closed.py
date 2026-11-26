"""The remaining gaps: analytics IDs, likely-candidate capture, audited views, imports on the timeline and
graph, mobile cells on the map, and PDF statements."""

from __future__ import annotations

import contextlib
import io
import time

from argus.api import subject_routes
from argus.core.models import Entity, EntityType, ScanConfig
from argus.evidence.capture import Capture
from argus.intel import imports as I
from argus.intel import subjects as S
from tests.test_imports import CDR
from tests.test_learning import INSTA, LearningScans
from tests.test_modules_offline import FakeResponse, FakeSession
from tests.test_person_graph import cand
from tests.test_subjects import run, wait

E = EntityType


# ---------------------------------------------------------------------------- analytics IDs
async def test_websites_sharing_an_analytics_id_group_their_accounts():
    from argus.modules.identity.deep_person import SiteTrackersModule

    profile = Entity.create(E.SOCIAL_PROFILE, "https://x.com/janed", depth=1, confidence=0.8,
                            metadata={"profile": {"website": "https://janedoe.dev"}})  # fmt: skip
    session = FakeSession({
        r"archive\.org/wayback/available": FakeResponse(200, {"archived_snapshots": {"closest": {"available": True,
                                                                                               "timestamp": "20250101"}}}),
        r"web/20250101id_/http://janedoe\.dev/": FakeResponse(200, "<script>gtag('config','G-ABCD1234EF')</script>"),
    })  # fmt: skip
    module = SiteTrackersModule()
    assert module.can_handle(profile)
    [x async for x in module.run(profile, session, ScanConfig(target="x", target_type=E.SOCIAL_PROFILE))]
    assert profile.metadata["site_trackers"]["ids"] == {"G-ABCD1234EF": "Google Analytics 4"}
    assert not module.can_handle(profile)  # read once
    a = cand("a", "confirmed", trackers={"site": "janedoe.dev", "ids": {"G-ABCD1234EF": "Google Analytics 4"}})
    b = cand("b", trackers={"site": "jane-shop.co", "ids": {"G-ABCD1234EF": "Google Analytics 4"}})
    data = {"known": S.clean_known({}), "candidates": {"a": a, "b": b}}
    groups = S.clusters(data)
    assert groups and "the same analytics ID on their websites (G-ABCD1234EF)" in groups[0]["links"][0]["reasons"]
    assert any("analytics ID" in r for r in S.cluster_reasons(data)["b"])


# ---------------------------------------------------------------------------- likely captures and audited views
def test_likely_candidates_can_be_preserved_and_views_are_audited(make_client, monkeypatch):
    captured = []

    async def fake_capture(url, settings, route=None):
        captured.append(url)
        files = {"page.html": ("text/html", b"<title>x</title>")}
        return Capture(
            {"kind": "web_capture", "url": url, "title": url, "files": list(files)}, "f" * 64, files, None, []
        )

    monkeypatch.setattr(subject_routes, "capture_url", fake_capture)
    monkeypatch.setattr(S, "AUTO_FOLLOW", 101)  # keep the run to one round
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-80", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe-Smith", "confirmed": True,
                 "known": {"names": ["Jane Doe-Smith"], "usernames": ["janedoe84"], "city": "Leeds"}}).json()["id"]  # fmt: skip
    base = f"/api/cases/{case_id}/subjects/{sid}"
    assert c.put(f"{base}/options", json={"capture_likely": True}).json()["options"] == {"capture_likely": True}
    run(c, case_id, sid, rounds=1)
    wait(c, case_id, sid)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not captured:
        time.sleep(0.05)
    assert captured == [INSTA]  # the likely match, before anyone confirmed it
    for path in ("graph", "timeline", "associates", "clusters", "dossier"):
        c.get(f"{base}/{path}")
    actions = {e["action"] for e in c.get("/api/audit?limit=200").json()}
    assert {"subject.options", "subject.view_graph", "subject.view_timeline", "subject.view_associates",
            "subject.view_groups", "subject.view_dossier"} <= actions  # fmt: skip
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ev = c.get(f"/api/cases/{case_id}").json()["captures"]
        if ev:
            break
        time.sleep(0.05)
    assert "likely match for Jane Doe-Smith (not confirmed)" in ev[0]["note"]


# ---------------------------------------------------------------------------- imports on the timeline, graph and map
def _imported_case(c):
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-81", "confirmed": True,
                                         "authorization": "Production order 2026/0412"}).json()["id"]  # fmt: skip
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "phones": ["+44 7700 900123"]}}).json()["id"]  # fmt: skip
    cdr = CDR.replace("234-15-1001", "234-15-1001-501").replace("234-15-1002", "234-15-1002-502")
    imported = c.post(f"/api/cases/{case_id}/imports", files={"file": ("cdr.csv", cdr.encode(), "text/csv")}).json()
    return case_id, sid, imported


def test_imported_data_joins_the_timeline_and_the_persons_graph(make_client):
    c = make_client()
    case_id, sid, _imported = _imported_case(c)
    timeline = c.get(f"/api/cases/{case_id}/timeline?facts=false").json()
    rows = [e["title"] for e in timeline if e["kind"] == "import"]
    assert rows == ["First of 3 in Call records: +447700900123 (known about Jane Doe)",
                    "Last of 3 in Call records: +447700900123 (known about Jane Doe)"]  # fmt: skip
    graph = c.get(f"/api/cases/{case_id}/subjects/{sid}/graph").json()
    node = next(n for n in graph["nodes"] if n["status"] == "import")
    assert node["label"] == "+447700900123: 3 in cdr.csv"
    edge = next(e for e in graph["edges"] if e["target"] == node["id"])
    known_phone = next(n for n in graph["nodes"] if n["status"] == "known" and "7700" in n["label"])
    assert edge["source"] == known_phone["id"] and edge["kind"] == "import"


def test_mobile_cells_go_on_the_map(make_client, monkeypatch):
    from argus.intel import account_watch

    asked = []

    class Http(FakeSession):
        def get(self, url, **kwargs):
            asked.append(kwargs.get("params"))
            return super().get(url, **kwargs)

    @contextlib.asynccontextmanager
    async def fake_client(settings, route):
        yield Http({r"opencellid\.org/cell/get": FakeResponse(200, {"lat": 53.8, "lon": -1.55, "range": 900})})

    monkeypatch.setattr(account_watch, "client", fake_client)
    c = make_client()
    case_id, _sid, imported = _imported_case(c)
    url = f"/api/cases/{case_id}/imports/{imported['id']}/cells"
    assert c.post(url).status_code == 409  # no key set
    c.app.state.settings.opencellid_api_key = __import__("pydantic").SecretStr("ocid-key")
    placed = c.post(url).json()
    assert placed == {"placed": 2, "unknown": 0, "cells": 2}
    assert asked[0]["mcc"] == "234" and asked[0]["cellid"] in ("501", "502") and asked[0]["key"] == "ocid-key"
    places = c.get(f"/api/cases/{case_id}/places").json()["places"]
    cell = next(p for p in places if p["label"].startswith("Cell 234-15-1001-501"))
    assert (cell["lat"], cell["lon"]) == (53.8, -1.55)
    assert c.post(url).json()["placed"] == 0  # already on the map
    assert I.phone_key("+44 7700 900123") == I.phone_key("07700900123")


# ---------------------------------------------------------------------------- PDF statements
def _statement_pdf() -> bytes:
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf)
    y = 800
    for line in (
        "Date Description Amount Balance",
        "01/01/2026 Opening balance 1,000.00 1,000.00",
        "02/01/2026 ACME LOGISTICS SALARY 1,250.00 2,250.00",
        "03/01/2026 Jane Doe rent 150.00 2,100.00",
        "05/01/2026 CARD PAYMENT TESCO 42.10 2,057.90",
    ):
        pdf.drawString(40, y, line)
        y -= 20
    pdf.save()
    return buf.getvalue()


def test_pdf_bank_statements():
    kind, records = I.parse(_statement_pdf(), "statement.pdf")
    assert kind == "transactions"
    amounts = {r["counterparty"]: r["amount"] for r in records}
    assert amounts["ACME LOGISTICS SALARY"] == 1250.0 and amounts["Jane Doe rent"] == -150.0
    assert amounts["CARD PAYMENT TESCO"] == -42.1
    assert all(r["detail"] == "read from a PDF: check against the original" for r in records)
