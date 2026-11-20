"""Backups: encrypted, checked, restored safely; and set up from Argus Personal's Settings."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from argus.cli import console
from argus.storage import backup
from argus.storage.backup_service import BackupService
from tests.conftest import PG_URL
from tests.test_plans import on_plan, personal  # noqa: F401 - the Argus Personal fixture

PASSWORD = "a long backup password"
sqlite_only = pytest.mark.skipif(bool(PG_URL), reason="backups made here are of SQLite databases")


@pytest.fixture
def install(tmp_path):
    """A small Argus data folder: a live database (WAL) with a few cases, and a key file."""
    data = tmp_path / "data"
    data.mkdir()
    db = sqlite3.connect(data / "argus.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE cases (id TEXT)")
    db.execute("CREATE TABLE alembic_version (version_num TEXT)")
    db.execute("INSERT INTO alembic_version VALUES ('0026')")
    db.executemany("INSERT INTO cases VALUES (?)", [(f"c{i}",) for i in range(3)])
    db.commit()
    (data / "secret.key").write_text("k" * 48)
    settings = SimpleNamespace(database_url=f"sqlite+aiosqlite:///{data / 'argus.db'}", encryption_key=None,
                               encryption_key_file=str(data / "secret.key"))  # fmt: skip
    yield settings, data, db
    db.close()


def test_a_backup_and_its_checks(install, tmp_path):
    settings, data, _live = install
    key = backup.new_key(PASSWORD)
    made = backup.create(settings, tmp_path / "backups", key)
    raw = Path(made["file"]).read_bytes()
    assert raw.startswith(backup.MAGIC) and b"c1" not in raw and b"k" * 48 not in raw  # nothing readable
    assert not [p for p in (tmp_path / "backups").iterdir() if p.suffix != backup.SUFFIX]  # no plaintext left there
    info = backup.check(Path(made["file"]), PASSWORD, work_dir=data, known_revisions={"0026"})
    assert info["counts"]["cases"] == 3 and info["has_key"]
    listed = backup.list_backups(tmp_path / "backups")
    assert listed[0]["name"] == made["name"] and listed[0]["argus_version"]  # without the password

    with pytest.raises(backup.BackupError, match="Wrong backup password"):
        backup.check(Path(made["file"]), "not the password", work_dir=data)
    altered = bytearray(raw)
    altered[-50] ^= 1
    (tmp_path / "altered.argusbackup").write_bytes(altered)
    with pytest.raises(backup.BackupError, match="altered"):
        backup.check(tmp_path / "altered.argusbackup", PASSWORD, work_dir=data)
    (tmp_path / "short.argusbackup").write_bytes(raw[: len(raw) - 10])
    with pytest.raises(backup.BackupError):
        backup.check(tmp_path / "short.argusbackup", PASSWORD, work_dir=data)
    (tmp_path / "other.argusbackup").write_bytes(b"PK\x03\x04 a zip file")
    with pytest.raises(backup.BackupError, match="isn't an Argus backup"):
        backup.check(tmp_path / "other.argusbackup", PASSWORD, work_dir=data)
    with pytest.raises(backup.BackupError, match="newer than this one"):
        backup.check(Path(made["file"]), PASSWORD, work_dir=data, known_revisions={"0001"})
    with pytest.raises(backup.BackupError, match="at least"):
        backup.new_key("short")
    assert not list(data.glob("argus-check-*"))  # checking leaves nothing behind


def test_restoring_keeps_the_old_data_aside(install, tmp_path):
    settings, data, live = install
    made = backup.create(settings, tmp_path / "backups", backup.new_key(PASSWORD))
    live.execute("DELETE FROM cases")
    live.commit()
    live.close()
    (data / "secret.key").write_text("n" * 48)
    with pytest.raises(backup.BackupError):
        backup.stage_restore(settings, Path(made["file"]), "wrong password!!")
    assert not backup.pending_restore(settings)  # a failed attempt leaves nothing waiting
    info = backup.stage_restore(settings, Path(made["file"]), PASSWORD, {"0026"})
    assert info["counts"]["cases"] == 3 and backup.pending_restore(settings)
    assert sqlite3.connect(data / "argus.db").execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0  # not yet
    aside = Path(backup.apply_pending_restore(settings))
    assert sqlite3.connect(data / "argus.db").execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 3
    assert (data / "secret.key").read_text() == "k" * 48
    assert (aside / "argus.db").is_file() and (aside / "secret.key").read_text() == "n" * 48  # kept, not deleted
    assert backup.apply_pending_restore(settings) is None and not backup.pending_restore(settings)


def test_a_server_key_in_its_configuration_must_match(install, tmp_path):
    settings, _data, _live = install
    made = backup.create(settings, tmp_path / "backups", backup.new_key(PASSWORD))
    server = SimpleNamespace(database_url=settings.database_url, encryption_key=SecretStr("s" * 48),
                             encryption_key_file=None)  # fmt: skip
    with pytest.raises(backup.BackupError, match="ARGUS_ENCRYPTION_KEY"):
        backup.stage_restore(server, Path(made["file"]), PASSWORD)
    assert not backup.pending_restore(server)


def test_keeping_the_latest(install, tmp_path):
    settings, _data, _live = install
    folder = tmp_path / "backups"
    key = backup.new_key(PASSWORD)
    for stamp in ("2026-01-01", "2026-01-02", "2026-01-03"):
        made = backup.create(settings, folder, key)
        Path(made["file"]).rename(folder / f"argus-backup-{stamp}-000000{backup.SUFFIX}")
    (folder / "holiday.jpg").write_bytes(b"not ours")
    assert backup.list_backups(folder)[0]["name"].startswith("argus-backup-2026-01-0")
    assert len(backup.prune(folder, 2)) == 1 and len(backup.list_backups(folder)) == 2
    assert (folder / "holiday.jpg").exists()  # only Argus's own files are ever removed
    assert backup.sqlite_path("postgresql+asyncpg://u:p@h/db") is None


class Memory:
    def __init__(self):
        self.values = {}

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value):
        self.values[key] = value


async def test_the_schedule(install, tmp_path):
    from argus.security.crypto import SecretBox

    settings, data, _live = install
    settings.backup_dir, settings.backup_password, settings.backup_every_hours, settings.backup_keep = "", None, 24, 3
    service = BackupService(settings, Memory(), SecretBox("b" * 40))
    assert not await service.due() and (await service.health())[0] == "warn"  # off: said so
    with pytest.raises(backup.BackupError, match="password"):
        await service.configure(folder=str(tmp_path / "b"), every_hours=24, keep=3, password=None)
    with pytest.raises(backup.BackupError, match="outside Argus's own data folder"):
        await service.configure(folder=str(data / "backups"), every_hours=24, keep=3, password=PASSWORD)
    with pytest.raises(backup.BackupError, match="full path"):
        await service.configure(folder="relative/folder", every_hours=24, keep=3, password=PASSWORD)
    await service.configure(folder=str(tmp_path / "b"), every_hours=24, keep=3, password=PASSWORD)
    assert "a long" not in str(service.state.values)  # the password is never stored
    assert await service.due()
    await service.run_now("scheduled")
    assert not await service.due() and (await service.health())[0] == "ok"
    stored = service.state.values["backups"]
    later = backup.datetime.fromisoformat(stored["last_attempt_at"]) + timedelta(hours=25)
    assert await service.due(later)
    (tmp_path / "b").rename(tmp_path / "unplugged")  # the USB drive is gone...
    (tmp_path / "b").write_text("now a file")  # ...and something else is in its place
    with pytest.raises(backup.BackupError):
        await service.run_now("scheduled")
    level, text = await service.health()
    assert level == "error" and "failed" in text
    retry = backup.datetime.fromisoformat(service.state.values["backups"]["last_attempt_at"]) + timedelta(hours=1)
    assert await service.due(retry)  # failures are retried within the hour


# ---------------------------------------------------------------------------- in Argus Personal
@sqlite_only
def test_backups_from_settings(personal, tmp_path_factory, monkeypatch):  # noqa: F811
    c, accounts = personal
    on_plan(c, accounts, "personal")
    status = c.get("/api/backups").json()
    assert status["available"] and not status["enabled"] and status["health"] == "warn"
    folder = tmp_path_factory.mktemp("usb-drive") / "Argus backups"  # outside Argus's data folder
    assert c.put("/api/backups", json={"folder": str(folder), "password": "short"}).status_code == 422
    r = c.put("/api/backups", json={"folder": str(folder), "password": PASSWORD, "every_hours": 24, "keep": 5})
    assert r.status_code == 200 and r.json()["enabled"] and r.json()["password_set"]
    assert (
        c.post("/api/cases", json={"title": "Story", "purpose": "Checking a story", "confirmed": True}).status_code
        == 201
    )
    made = c.post("/api/backups/run").json()
    assert made["health"] == "ok" and len(made["backups"]) == 1
    file = made["backups"][0]["file"]
    checked = c.post("/api/backups/check", json={"file": file, "password": PASSWORD}).json()
    assert checked["ok"] and checked["backup"]["counts"]["cases"] == 1
    assert c.post("/api/backups/check", json={"file": file, "password": "wrong one!!"}).status_code == 422
    assert c.post("/api/backups/check", json={"file": "/etc/passwd", "password": PASSWORD}).status_code == 422

    accounts.refuse_refresh = (401, "This computer was signed out")  # the subscription lapses...
    c.post("/api/personal/refresh")
    assert c.post("/api/cases", json={"title": "x", "purpose": "y", "confirmed": True}).status_code == 402
    assert c.post("/api/backups/run").status_code == 200  # ...backups still work

    restore = c.post("/api/backups/restore", json={"file": file, "password": PASSWORD}).json()
    assert restore["restarting"] is False and "Restart Argus" in restore["detail"]
    assert c.get("/api/backups").json()["restore_pending"] is True
    assert c.post("/api/backups/restore/cancel").json()["restore_pending"] is False
    stopping = SimpleNamespace(should_exit=False)
    monkeypatch.setattr(console, "SERVER", stopping)
    monkeypatch.setattr(console, "RESTART", False)
    again = c.post("/api/backups/restore", json={"file": file, "password": PASSWORD}).json()
    assert again["restarting"] and stopping.should_exit and console.RESTART  # the desktop app restarts itself
    c.post("/api/backups/restore/cancel")
    actions = [e["action"] for e in c.get("/api/audit?limit=50").json()]
    assert {"backup.configured", "backup.created", "backup.checked", "backup.restore"} <= set(actions)
    assert PASSWORD not in str(c.get("/api/audit?limit=50").json())


def test_only_administrators(make_client):
    c = make_client(monitors_enabled="false")
    created = c.post("/api/keys", json={"name": "analyst", "role": "analyst"}).json()
    c.headers["Authorization"] = f"Bearer {created['key']}"
    assert c.get("/api/backups").status_code == 403


def test_a_server_sets_backups_in_its_configuration(make_client, tmp_path):
    c = make_client(monitors_enabled="false", backup_dir=str(tmp_path / "server-backups"), backup_password=PASSWORD)
    status = c.get("/api/backups").json()
    assert status["managed"] and status["enabled"] == status["available"]
    assert c.put("/api/backups", json={"folder": str(tmp_path / "x"), "password": PASSWORD}).status_code == 403
    assert (
        c.post("/api/backups/restore", json={"file": str(tmp_path / "x.argusbackup"), "password": PASSWORD}).status_code
        == 403
    )
