"""Phase 96: the integrity check finds damage, broken references, a broken audit chain and altered evidence."""

from __future__ import annotations

from sqlalchemy import text, update

from argus.cli.console import integrity_cli
from argus.observability import metrics
from argus.security import vault
from argus.storage.db import AuditEventRow, EvidenceFileRow


def _case_with_evidence(c):
    case = c.post(
        "/api/cases", json={"title": "Fraud ring", "purpose": "Integrity check test case", "confirmed": True}
    ).json()
    upload = c.post(
        f"/api/cases/{case['id']}/uploads", files={"file": ("chat.png", b"\x89PNG\r\n\x1a\nfake", "image/png")}
    )
    assert upload.status_code == 201, upload.text
    return case["id"], upload.json()["id"]


def _check(c):
    r = c.post("/api/integrity/check")
    assert r.status_code == 200, r.text
    return {k["name"]: k for k in r.json()["checks"]}, r.json()


def test_a_healthy_installation_is_whole(client):
    assert client.get("/api/integrity").json() is None  # not run yet
    _case_with_evidence(client)
    checks, result = _check(client)
    assert result["ok"] and result["problems"] == 0
    assert set(checks) == {"storage", "references", "audit_chain", "evidence"}
    assert checks["evidence"]["detail"] == "1 captures" and checks["references"]["detail"].endswith("foreign keys")
    assert client.get("/api/integrity").json()["ok"] is True
    assert metrics.REGISTRY.get_sample_value("argus_integrity_problems") == 0
    assert client.post("/api/integrity/check").status_code == 200
    assert client.post("/api/integrity/check").status_code == 429  # it reads everything: not on a loop


async def _tamper(db, capture_id):
    async with db.session() as s, s.begin():
        await s.execute(update(EvidenceFileRow).where(EvidenceFileRow.capture_id == capture_id)
                        .values(data=b"replaced"))  # fmt: skip
        await s.execute(update(AuditEventRow).where(AuditEventRow.id == 2).values(actor_name="someone else"))
    if db.dialect != "sqlite":
        return False  # PostgreSQL always enforces foreign keys: an orphan cannot exist there
    async with db.engine.connect() as conn:  # an orphan, as the 1.91.0 migration bug left them
        await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        await conn.execute(text("INSERT INTO case_items (id, case_id, kind, title, body, data, created_by, created_at, "
                                "updated_at) VALUES ('item_x', 'case_gone', 'note', 't', 'b', '{}', 'a', "
                                "'2026-01-01', '2026-01-01')"))  # fmt: skip
        await conn.commit()
        await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
    return True


def test_damage_is_found_and_reported(client):
    _case, capture = _case_with_evidence(client)
    orphan = client.portal.call(_tamper, client.app.state.db, capture)
    checks, result = _check(client)
    assert not result["ok"] and result["problems"] >= (3 if orphan else 2)
    assert "changed" in checks["evidence"]["problems"][0]
    if orphan:
        assert "case_items refer to a missing cases" in checks["references"]["problems"][0]
    assert checks["audit_chain"]["problems"] == ["Entry 2 does not match the chain"]
    assert checks["storage"]["ok"]
    assert metrics.REGISTRY.get_sample_value("argus_integrity_problems") == result["problems"]
    entry = next(e for e in client.get("/api/audit?limit=50").json() if e["action"] == "integrity.check")
    assert entry["outcome"] == "failure" and entry["details"]["evidence"] >= 1
    assert client.portal.call(integrity_cli) == 1  # argus --check agrees, and fails


def test_a_locked_vault_skips_what_it_cannot_read(client, monkeypatch):
    """The API refuses everything while the vault is locked (423); argus --check still runs and says so."""
    from argus.storage import integrity

    monkeypatch.setattr(vault, "locked", lambda: True)
    result = client.portal.call(integrity.run, client.app.state)
    checks = {k["name"]: k for k in result["checks"]}
    assert result["ok"] and checks["evidence"]["skipped"] and "vault is locked" in checks["audit_chain"]["detail"]
    assert checks["references"]["ok"] and not checks["references"].get("skipped")


def test_only_platform_administrators_can_check(client):
    viewer = client.post("/api/keys", json={"name": "v", "role": "admin"}).json()["key"]
    assert client.post("/api/integrity/check", headers={"Authorization": f"Bearer {viewer}"}).status_code == 403
