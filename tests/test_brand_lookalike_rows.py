"""Phase 80: brand-watch lookalikes in their own table, and watches saved the old way converted on read."""

from __future__ import annotations

from sqlalchemy import select

from argus.storage import brand_watch_repo
from argus.storage.db import BrandLookalikeRow, BrandWatchRow
from tests.test_brand_watch import bw  # noqa: F401  (fixture used by name)


def _finding(name, severity="medium"):
    return {"name": name, "display": name, "registrable": name, "technique": "combosquat", "detail": "x",
            "severity": severity, "issuer": "R11", "not_before": "2026-11-01T00:00:00", "link": "", "source": "crt.sh",
            "hosts": [name], "host_count": 1, "verdict": "", "reasons": [], "escalated_from": ""}  # fmt: skip


def test_old_watch_documents_are_converted_once(bw):  # noqa: F811
    c, _ = bw
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    legacy = {
        "allow": [], "cursor": 3, "web_check": "off", "baselined": True,
        "known": ["acmebank-login.com", "acmebank-pay.net"],
        "first_seen": {"acmebank-login.com": "2026-10-01T00:00:00+00:00"},
        "recent": [_finding("acmebank-login.com", "high")],
        "details": {"acmebank-pay.net": {"technique": "combosquat", "detail": "brand + 'pay'", "severity": "medium"}},
        "triage": {"acmebank-login.com": {"verdict": "phishing", "severity": "critical", "label": "Active phishing page",
                                          "checked_at": "2026-11-20T00:00:00+00:00"}},
        "takedowns": {"acmebank-login.com": {"status": "reported", "history": [{"event": "drafted"}]}},
    }  # fmt: skip

    async def write_legacy():
        async with c.app.state.db.session() as s, s.begin():
            (await s.get(BrandWatchRow, watch["id"])).data = legacy

    c.portal.call(write_legacy)
    listed = c.get("/api/brand-watches").json()[0]
    assert listed["known"] == 2 and listed["cursor"] == 3 and listed["baselined"]
    recent = {f["name"]: f for f in listed["recent"]}
    assert recent["acmebank-login.com"]["triage"]["verdict"] == "phishing"
    assert recent["acmebank-login.com"]["first_seen"].startswith("2026-10-01")
    assert recent["acmebank-pay.net"]["detail"] == "brand + 'pay'"
    assert listed["takedowns"]["acmebank-login.com"]["status"] == "reported"

    async def stored():
        async with c.app.state.db.session() as s:
            row = await s.get(BrandWatchRow, watch["id"])
            rows = (await s.scalars(select(BrandLookalikeRow).where(BrandLookalikeRow.watch_id == watch["id"]))).all()
            return row.data, {r.name: (r.verdict, r.takedown_status) for r in rows}

    data, rows = c.portal.call(stored)
    assert not set(brand_watch_repo.LEGACY_KEYS) & set(data)  # the document keeps only settings and state
    assert rows == {"acmebank-login.com": ("phishing", "reported"), "acmebank-pay.net": ("", None)}
    assert c.get("/api/brand-watches").json()[0]["known"] == 2  # converted once, not twice
    repo = c.app.state.brand_watches
    assert c.portal.call(repo.open_takedowns, watch["id"]) == ["acmebank-login.com"]


def test_the_cap_keeps_takedowns_and_stale_order(bw, monkeypatch):  # noqa: F811
    c, _ = bw
    monkeypatch.setattr(brand_watch_repo, "MAX_KNOWN", 3)
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com"}).json()
    repo = c.app.state.brand_watches
    first = [_finding(f"old{i}-acmebank.com") for i in range(3)]
    c.portal.call(lambda: repo.record(watch["id"], status="ok", sources={}, message="", new=first,
                                      triage={"old1-acmebank.com": {"verdict": "live", "severity": "medium",
                                                                    "checked_at": "2026-11-21T00:00:00+00:00"}}))  # fmt: skip
    c.portal.call(
        lambda: repo.put_takedown(watch["id"], None, "old0-acmebank.com", {"status": "reported"}, {"event": "x"})
    )
    assert c.portal.call(repo.stale, watch["id"], 2) == [
        "old0-acmebank.com",
        "old2-acmebank.com",
    ]  # never checked first
    c.portal.call(lambda: repo.record(watch["id"], status="ok", sources={}, message="",
                                      new=[_finding("new-acmebank.com")]))  # fmt: skip
    names = c.portal.call(
        repo.known_names, watch["id"], [f"old{i}-acmebank.com" for i in range(3)] + ["new-acmebank.com"]
    )
    assert names == {
        "old0-acmebank.com",
        "old2-acmebank.com",
        "new-acmebank.com",
    }  # old1 forgotten; old0 has a takedown
    assert c.delete(f"/api/brand-watches/{watch['id']}").status_code == 204
    assert c.portal.call(repo.known_names, watch["id"], names) == set()
