"""Automatic backups: when they run, where they go, and how they're doing.

* **Argus Personal**: the investigator sets it up in Settings (a folder and a backup password).
  The password itself is never stored: only the key made from it, sealed with this computer's
  encryption key, so backups run unattended while restoring always needs the password.
* **A server on SQLite**: ``ARGUS_BACKUP_DIR`` and ``ARGUS_BACKUP_PASSWORD`` (plus how often and how
  many to keep). Servers on PostgreSQL rely on their database provider's backups.

Every run is recorded (when, how big, or what went wrong) so Settings, the owner console and
the owner's alerts can say plainly whether backups are working.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from argus.storage import backup

logger = logging.getLogger("argus.backup")
STATE_KEY = "backups"
CONTEXT = "backup-key"
CHECK_EVERY = 300  # seconds between "is a backup due?" checks


def _now() -> datetime:
    return datetime.now(timezone.utc)


class BackupService:
    def __init__(self, settings: Any, app_state: Any, secret_box: Any):
        self.settings, self.state, self.box = settings, app_state, secret_box
        self.running = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ configuration
    @property
    def available(self) -> bool:
        return backup.sqlite_path(self.settings.database_url) is not None

    @property
    def from_settings(self) -> bool:
        """Configured by the deployment (a server), rather than in Settings (Argus Personal)."""
        return bool(self.settings.backup_dir)

    async def _stored(self) -> dict[str, Any]:
        return await self.state.get(STATE_KEY) or {}

    async def config(self) -> dict[str, Any]:
        s = self.settings
        if self.from_settings:
            return {"enabled": bool(s.backup_password) and self.available, "folder": s.backup_dir, "every_hours": s.backup_every_hours,
                    "keep": s.backup_keep, "managed": True}  # fmt: skip
        stored = await self._stored()
        return {"enabled": bool(stored.get("enabled") and stored.get("sealed_key")), "folder": stored.get("folder", ""),
                "every_hours": int(stored.get("every_hours", 24)), "keep": int(stored.get("keep", 14)),
                "managed": False}  # fmt: skip

    async def configure(self, *, folder: str, every_hours: int, keep: int, password: str | None,
                        enabled: bool = True) -> dict[str, Any]:  # fmt: skip
        if self.from_settings:
            raise backup.BackupError("Backups on this server are set in its configuration (ARGUS_BACKUP_DIR)")
        if not self.available:
            raise backup.BackupError("Only an Argus that keeps its database in a file (SQLite) can back itself up")
        stored = await self._stored()
        folder = folder.strip()
        if enabled:
            if not folder or not Path(folder).expanduser().is_absolute():  # noqa: ASYNC240 - no disk access
                raise backup.BackupError(
                    "Choose a folder (its full path), ideally on another drive or a synced cloud folder"
                )
            if self._inside_data_folder(Path(folder)):
                raise backup.BackupError(
                    "Choose a folder outside Argus's own data folder: a backup there is lost with it"
                )
        if password:
            if not self.box.available:
                raise backup.BackupError("This installation has no encryption key, so it can't keep a backup key")
            key = await asyncio.to_thread(backup.new_key, password)
            stored["sealed_key"] = self.box.seal(key, CONTEXT)
        elif enabled and not stored.get("sealed_key"):
            raise backup.BackupError("Choose a backup password: you'll need it to restore")
        stored.update({"enabled": enabled, "folder": folder, "every_hours": every_hours, "keep": keep})
        await self.state.set(STATE_KEY, stored)
        return await self.config()

    def _inside_data_folder(self, folder: Path) -> bool:
        db = backup.sqlite_path(self.settings.database_url)
        if db is None:
            return False
        try:
            folder.expanduser().resolve().relative_to(db.parent)
        except ValueError:
            return False
        return True

    async def _key(self) -> dict[str, Any] | None:
        if self.from_settings:
            if not self.settings.backup_password:
                return None
            if not hasattr(self, "_server_key"):  # derived once per start (it's deliberately slow)
                self._server_key = await asyncio.to_thread(
                    backup.new_key, self.settings.backup_password.get_secret_value()
                )
            return self._server_key
        sealed = (await self._stored()).get("sealed_key")
        if not sealed:
            return None
        try:
            return dict(self.box.open(sealed, CONTEXT))
        except Exception as exc:
            raise backup.BackupError("The saved backup key can't be read: set the backup password again") from exc

    # ------------------------------------------------------------------ running
    async def run_now(self, reason: str = "manual") -> dict[str, Any]:
        """Make a backup now and record how it went (raises BackupError with a plain reason)."""
        async with self._lock:
            self.running = True
            started = _now()
            try:
                conf = await self.config()
                key = await self._key()
                if not conf["folder"] or key is None:
                    raise backup.BackupError("Backups aren't set up yet: choose a folder and a backup password")
                result = await asyncio.to_thread(backup.create, self.settings, Path(conf["folder"]), key,
                                                 label=reason)  # fmt: skip
                removed = await asyncio.to_thread(backup.prune, Path(conf["folder"]), conf["keep"])
                await self._record(ok=True, at=started, result={**result, "removed": len(removed)})
                return result
            except backup.BackupError as exc:
                await self._record(ok=False, at=started, error=str(exc))
                raise
            except Exception as exc:
                logger.exception("Backup failed")
                await self._record(ok=False, at=started, error=f"Unexpected problem: {type(exc).__name__}")
                raise backup.BackupError(f"The backup failed unexpectedly ({type(exc).__name__}); see the log") from exc
            finally:
                self.running = False

    async def _record(self, *, ok: bool, at: datetime, result: dict[str, Any] | None = None,
                      error: str | None = None) -> None:  # fmt: skip
        stored = await self._stored()
        stored["last_attempt_at"] = at.isoformat()
        if ok and result:
            stored.update({"last_success_at": at.isoformat(), "last_error": None, "failures": 0,
                           "last_backup": {k: result.get(k) for k in ("name", "size", "counts", "removed")}})  # fmt: skip
        else:
            stored.update({"last_error": error, "failures": int(stored.get("failures", 0)) + 1})
        await self.state.set(STATE_KEY, stored)

    async def due(self, now: datetime | None = None) -> bool:
        conf = await self.config()
        if not conf["enabled"] or not self.available:
            return False
        stored = await self._stored()
        last = stored.get("last_attempt_at")
        if not last:
            return True
        wait = timedelta(hours=conf["every_hours"])
        if stored.get("last_error"):  # after a failure, try again sooner (a USB drive plugged back in...)
            wait = min(wait, timedelta(hours=1))
        return (now or _now()) - datetime.fromisoformat(last) >= wait

    async def run_forever(self) -> None:
        await asyncio.sleep(60)  # let Argus finish starting first
        while True:
            try:
                if await self.due():
                    await self.run_now("scheduled")
            except asyncio.CancelledError:
                raise
            except backup.BackupError as exc:
                logger.warning("Scheduled backup failed: %s", exc)
            except Exception:
                logger.exception("Backup scheduler failed")
            await asyncio.sleep(CHECK_EVERY)

    # ------------------------------------------------------------------ how it's going
    async def health(self, now: datetime | None = None) -> tuple[str, str]:
        """(ok | warn | error | off, a plain sentence) for Settings, the owner console and alerts."""
        if not self.available:
            return "off", "The database is PostgreSQL: backups are your database provider's (check they're switched on)"
        conf = await self.config()
        if not conf["enabled"]:
            return "warn", "Automatic backups are off: if this computer is lost or its disk fails, cases are lost too"
        stored = await self._stored()
        now = now or _now()
        last_ok = stored.get("last_success_at")
        if stored.get("last_error"):
            return "error", f"The last backup failed: {stored['last_error']}"
        if not last_ok:
            return "warn", "Set up: the first backup runs within a few minutes"
        age = now - datetime.fromisoformat(last_ok)
        if age > timedelta(hours=conf["every_hours"] * 2 + 1):
            return (
                "warn",
                f"No backup for {age.days or round(age.total_seconds() / 3600)} {'days' if age.days else 'hours'}",
            )
        return "ok", f"Last backup {datetime.fromisoformat(last_ok).strftime('%Y-%m-%d %H:%M')} UTC"

    async def status(self) -> dict[str, Any]:
        conf = await self.config()
        stored = await self._stored()
        level, text = await self.health()
        listing = await asyncio.to_thread(backup.list_backups, Path(conf["folder"])) if conf["folder"] else []
        return {
            "available": self.available, **conf, "running": self.running, "health": level, "summary": text,
            "last_success_at": stored.get("last_success_at"), "last_attempt_at": stored.get("last_attempt_at"),
            "last_error": stored.get("last_error"), "last_backup": stored.get("last_backup"),
            "password_set": bool(stored.get("sealed_key")) or bool(self.settings.backup_password),
            "backups": listing[:50], "restore_pending": backup.pending_restore(self.settings),
            "suggestions": [] if conf["managed"] else await asyncio.to_thread(backup.suggested_folders),
        }  # fmt: skip
