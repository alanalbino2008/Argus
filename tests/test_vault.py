"""The case vault: encrypted at rest, unreadable without the passphrase, and usable when unlocked.

The decisive checks open the database file directly, as a thief would, and look for the case's
words in it.
"""

from __future__ import annotations

import sqlite3
from functools import partial

import pytest
from fastapi.testclient import TestClient

from argus.api import server, vault_routes
from argus.core.settings import get_settings
from argus.security import vault
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.vault_store import encrypted_columns
from tests.conftest import ADMIN_KEY, PG_URL
from tests.test_cases import new_case

PASSPHRASE = "correct horse battery staple"
SECRET_WORDS = ("Hope Relief", "fake charity", "Jane Whistleblower", "the treasurer took the money")
needs_sqlite = pytest.mark.skipif(bool(PG_URL), reason="the vault is for single-computer (SQLite) installations")


@pytest.fixture(autouse=True)
def fast_vault(monkeypatch):
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)  # the real cost is 2**17; tests need not wait for it
    monkeypatch.setattr(vault_routes, "_attempts", SlidingWindowLimiter(limit=100, window=60))
    monkeypatch.setattr(vault_routes, "_attempts_all", SlidingWindowLimiter(limit=100, window=60))
    yield
    vault.reset()


def database_file(c) -> str:
    return c.app.state.db.url.database


def raw_dump(path: str) -> bytes:
    """Every byte of the database file and its write-ahead log, as a thief copying them would get."""
    import os

    data = b""
    for name in (path, path + "-wal", path + "-journal"):
        if os.path.exists(name):
            with open(name, "rb") as f:
                data += f.read()
    return data


def readable(path: str) -> bytes:
    """What SQLite itself returns: the current values."""
    con = sqlite3.connect(path)
    try:
        return "\n".join(con.iterdump()).encode()
    finally:
        con.close()


def fill(c) -> dict:
    case = new_case(c, title="Hope Relief appeal", summary="Looks like a fake charity").json()
    c.post(f"/api/cases/{case['id']}/items", json={"kind": "note", "title": "Source", "body": "Jane Whistleblower says "
                                                    "the treasurer took the money"})  # fmt: skip
    c.post(
        f"/api/cases/{case['id']}/items",
        json={"kind": "entity", "data": {"type": "person", "value": "Jane Whistleblower"}},
    )
    upload = c.post(f"/api/cases/{case['id']}/uploads",
                    files={"file": ("minutes.txt", b"Minutes: Hope Relief trustees met.", "text/plain")}).json()  # fmt: skip
    from argus.demo import load_demo

    c.portal.call(partial(load_demo, c.app.state.repo))
    return {"case": case, "upload": upload}


def test_every_sensitive_table_is_covered():
    covered = {model.__tablename__: set(cols) for model, cols in encrypted_columns()}
    assert covered["cases"] == {"title", "purpose", "summary"}
    assert covered["case_items"] == {"title", "body", "data"}
    assert covered["evidence_files"] == {"data"} and "manifest" in covered["evidence_captures"]
    assert covered["entities"] == {"value", "label", "data"} and covered["investigations"] == {"target", "data"}
    assert {"audit_events", "playbook_runs", "account_watches", "account_snapshots", "alerts", "report_files"} <= set(
        covered
    )


def test_keys_are_wrapped_and_codes_are_readable():
    record, code, key = vault.create(PASSPHRASE)
    assert len(key) == 32 and key.hex() not in str(record)
    assert vault.open_with(record, passphrase=PASSPHRASE) == key
    assert vault.open_with(record, recovery_code=code.lower().replace("-", " ")) == key  # however it is typed
    with pytest.raises(vault.VaultError, match="Wrong"):
        vault.open_with(record, passphrase="correct horse battery stapler")
    with pytest.raises(vault.VaultError, match="at least 12"):
        vault.create("short")
    assert len(code) == 29 and code.count("-") == 4 and not set(code) & set("01IO")
    record2 = vault.rewrap_passphrase(record, key, "a whole new passphrase")
    assert vault.open_with(record2, passphrase="a whole new passphrase") == key


@needs_sqlite
def test_the_vault_end_to_end(make_client):
    c = make_client(monitors_enabled="false")
    ids = fill(c)
    path = database_file(c)
    assert all(w.encode() in readable(path) for w in SECRET_WORDS)  # without the vault: readable by anyone

    assert c.post("/api/vault/enable", json={"passphrase": PASSPHRASE, "understood": False}).status_code == 422
    turned_on = c.post("/api/vault/enable", json={"passphrase": PASSPHRASE, "understood": True}).json()
    code = turned_on["recovery_code"]
    assert turned_on["enabled"] and not turned_on["locked"]
    dump = raw_dump(path)
    assert not any(w.encode() in dump for w in SECRET_WORDS), [w for w in SECRET_WORDS if w.encode() in dump]
    assert b"acme-corp.example" not in dump and b"Minutes: Hope Relief" not in dump  # scans and files too

    # Unlocked, everything works as before, and new writes are encrypted too.
    case = c.get(f"/api/cases/{ids['case']['id']}").json()
    assert case["title"] == "Hope Relief appeal" and "treasurer" in case["items"][0]["body"]
    assert c.get(f"/api/evidence/{ids['upload']['id']}/files/minutes.txt?download=true").content.startswith(b"Minutes")
    assert c.post(f"/api/evidence/{ids['upload']['id']}/verify").json()["intact"] is True
    c.post(
        f"/api/cases/{ids['case']['id']}/items", json={"kind": "note", "title": "Later", "body": "Met Tom Informant"}
    )
    assert b"Tom Informant" not in raw_dump(path) and b"Tom Informant" not in readable(path)
    assert c.get("/api/entities/search?q=acme-corp").json()  # search works on decrypted values
    assert [i["target"] for i in c.get("/api/investigations?target=ACME").json()]
    assert c.get("/api/audit/verify").json()["valid"] is True  # the tamper-evident chain still holds

    # Locked: nothing but the vault answers.
    assert c.post("/api/vault/lock").json()["locked"] is True
    r = c.get(f"/api/cases/{ids['case']['id']}")
    assert r.status_code == 423 and r.json()["vault_locked"] is True
    assert c.get("/api/investigations").status_code == 423 and c.get("/api/health").status_code == 200
    assert c.get("/api/me").status_code == 200  # the browser can still tell the key is good
    assert c.post("/api/vault/unlock", json={"passphrase": "not the passphrase at all"}).status_code == 403
    assert c.post("/api/vault/unlock", json={"recovery_code": code}).json()["locked"] is False
    unlock = next(e for e in c.get("/api/audit?limit=50").json() if e["action"] == "vault.unlock")
    assert unlock["details"]["failed_attempts_before"] == 1 and unlock["details"]["with"] == "recovery code"

    # A restart: the vault is locked again, and start-up recovery waits for the unlock.
    c.post("/api/vault/passphrase", json={"current": PASSPHRASE, "new": "my brand new passphrase"})
    get_settings.cache_clear()
    with TestClient(server.app) as again:
        again.headers["Authorization"] = f"Bearer {ADMIN_KEY}"
        assert again.get("/api/vault/status").json()["locked"] is True
        assert again.get("/api/cases").status_code == 423
        assert again.post("/api/vault/unlock", json={"passphrase": PASSPHRASE}).status_code == 403  # the old one
        assert again.post("/api/vault/unlock", json={"passphrase": "my brand new passphrase"}).status_code == 200
        assert again.get("/api/cases").json()[0]["title"] == "Hope Relief appeal"
        new_code = again.post("/api/vault/recovery-code", json={"passphrase": "my brand new passphrase"}).json()
        assert new_code["recovery_code"] != code

        # Turning it off decrypts everything.
        assert (
            again.post("/api/vault/disable", json={"passphrase": "my brand new passphrase"}).json()["enabled"] is False
        )
        assert all(w.encode() in readable(path) for w in SECRET_WORDS) and b"Tom Informant" in readable(path)
        assert again.get(f"/api/cases/{ids['case']['id']}").json()["summary"] == "Looks like a fake charity"


@needs_sqlite
def test_an_interrupted_encryption_finishes_at_the_next_unlock(make_client, monkeypatch):
    c = make_client(monitors_enabled="false")
    ids = fill(c)
    from argus.storage.vault_store import VaultService

    monkeypatch.setattr(VaultService, "_finish_encrypting", lambda self: _noop())  # "power cut" after the record
    c.post("/api/vault/enable", json={"passphrase": PASSPHRASE, "understood": True})
    assert b"Jane Whistleblower" in readable(database_file(c))  # not yet encrypted
    monkeypatch.undo()
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    c.post("/api/vault/lock")
    c.post("/api/vault/unlock", json={"passphrase": PASSPHRASE})
    assert b"Jane Whistleblower" not in raw_dump(database_file(c))
    assert c.get("/api/vault/status").json()["state"] == "ready"
    assert c.get(f"/api/cases/{ids['case']['id']}").json()["title"] == "Hope Relief appeal"


async def _noop() -> None:
    return None


@needs_sqlite
def test_locking_waits_for_running_work(make_client):
    c = make_client(monitors_enabled="false")
    c.post("/api/vault/enable", json={"passphrase": PASSPHRASE, "understood": True})

    class Busy:
        is_running = True

    c.app.state.scan_engines = lambda: [Busy()]
    r = c.post("/api/vault/lock")
    assert r.status_code == 409 and "scan(s) running" in r.json()["detail"]


def test_only_single_computer_databases_get_a_vault(make_client, monkeypatch):
    c = make_client(monitors_enabled="false")
    monkeypatch.setattr(type(c.app.state.vault), "available", property(lambda self: False))
    r = c.post("/api/vault/enable", json={"passphrase": PASSPHRASE, "understood": True})
    assert r.status_code == 422 and "single computer" in r.json()["detail"]


def test_values_are_bound_to_their_column():
    vault.STATE.enabled, vault.STATE.key = True, b"k" * 32
    sealed = vault.encrypt_text("Jane", "cases.title")
    assert vault.decrypt_text(sealed, "cases.title") == "Jane"
    with pytest.raises(vault.VaultError):
        vault.decrypt_text(sealed, "case_items.body")  # moved to another column: refused
    vault.lock()
    with pytest.raises(vault.VaultLocked):
        vault.decrypt_text(sealed, "cases.title")
