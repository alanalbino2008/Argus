"""Phase 97: restore drills prove the newest backup actually restores."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from argus.observability import metrics
from argus.storage import backup
from tests.test_backups import PASSWORD, install, sqlite_only  # noqa: F401  (fixture used by name)


def test_a_drill_restores_and_checks_without_keeping_anything(install, tmp_path):  # noqa: F811
    settings, data, _live = install
    key = backup.new_key(PASSWORD)
    made = backup.create(settings, tmp_path / "backups", key)
    result = backup.drill(Path(made["file"]), work_dir=data, backup_key=key)  # the unattended key: no password
    assert result["counts"] == {"cases": 3} and result["schema"] == "0026" and result["backup"] == made["name"]
    assert backup.drill(Path(made["file"]), work_dir=data, password=PASSWORD)["counts"] == {"cases": 3}
    assert not list(data.glob("argus-drill-*"))  # nothing left behind
    with pytest.raises(backup.BackupError, match="different backup password"):
        backup.drill(Path(made["file"]), work_dir=data, backup_key=backup.new_key("another long password"))


def test_a_backup_that_would_not_restore_is_caught(install, tmp_path, monkeypatch):  # noqa: F811
    settings, data, _live = install
    key = backup.new_key(PASSWORD)
    real_snapshot = backup._snapshot

    def damaged(db, out):  # the copy taken lacks rows the backup says it has
        counts = real_snapshot(db, out)
        conn = sqlite3.connect(out)
        conn.execute("DELETE FROM cases")
        conn.commit()
        conn.close()
        return counts

    monkeypatch.setattr(backup, "_snapshot", damaged)
    made = backup.create(settings, tmp_path / "backups", key)
    with pytest.raises(backup.BackupError, match="does not hold what the backup recorded"):
        backup.drill(Path(made["file"]), work_dir=data, backup_key=key)


@sqlite_only
def test_the_server_drills_and_reports(make_client, tmp_path):
    c = make_client(monitors_enabled="false", backup_dir=str(tmp_path / "server-backups"), backup_password=PASSWORD)
    nothing = c.post("/api/backups/drill")
    assert nothing.status_code in (400, 409, 422) and "no backup" in nothing.text.lower()
    assert c.post("/api/backups/run").status_code == 200
    status = c.post("/api/backups/drill").json()
    drill = status["last_drill"]
    assert drill["ok"] and drill["reason"] == "manual" and drill["counts"]["cases"] >= 0
    assert metrics.REGISTRY.get_sample_value("argus_backup_drill_ok") == 1
    assert not c.portal.call(c.app.state.backups.drill_due)  # just drilled: not due for a week
    actions = [e["action"] for e in c.get("/api/audit?limit=50").json()]
    assert "backup.drill" in actions
