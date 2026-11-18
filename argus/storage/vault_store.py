"""The case vault's lifecycle: turning it on and off, unlocking, locking, changing the passphrase.

The cryptography is in :mod:`argus.security.vault`; this module stores the vault's record (the
wrapped data key, never the key itself) and re-saves the encrypted columns when the vault is
turned on (encrypting what was there) or off (decrypting it).

Turning the vault on or off is resumable: the record says ``encrypting`` or ``decrypting`` until
the pass has finished, and an interrupted pass is completed at the next unlock. Values in either
form can always be read, so a half-finished pass loses nothing.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import attributes

from argus.security import vault
from argus.storage.db import Base, Database
from argus.storage.subscriber_repo import AppStateRepository

logger = logging.getLogger("argus.vault")
BATCH = 50


def encrypted_columns() -> list[tuple[type, list[str]]]:
    """Every model with encrypted columns, and those columns' attribute names."""
    found = []
    for mapper in Base.registry.mappers:
        names = [a.key for a in mapper.column_attrs if isinstance(a.columns[0].type, vault.ENCRYPTED_TYPES)]
        if names:
            found.append((mapper.class_, names))
    return sorted(found, key=lambda pair: pair[0].__name__)


class VaultService:
    def __init__(self, db: Database, app_state: AppStateRepository):
        self.db, self.app_state = db, app_state
        self.on_unlock: list[Callable[[], Awaitable[None]]] = []  # e.g. start-up recovery deferred while locked

    @property
    def available(self) -> bool:
        """The vault is for one computer's own database (SQLite), as in Argus Personal."""
        return self.db.url.get_backend_name() == "sqlite"

    async def load(self) -> None:
        record = await self.app_state.get(vault.RECORD_KEY)
        vault.reset()
        if record:
            vault.STATE.enabled, vault.STATE.record = True, record

    def status(self) -> dict[str, Any]:
        return {"available": self.available, "enabled": vault.STATE.enabled, "locked": vault.locked(),
                "state": vault.STATE.record.get("state") if vault.STATE.enabled else None,
                "created_at": vault.STATE.record.get("created_at")}  # fmt: skip

    async def _rewrite_all(self) -> int:
        """Re-save every encrypted column: encrypted, or plain while ``plain_writes`` is set."""
        total = 0
        for model, names in encrypted_columns():
            keys = list(model.__table__.primary_key.columns)  # type: ignore[attr-defined]
            offset = 0
            while True:
                async with self.db.session() as s, s.begin():
                    rows: Any = (await s.scalars(select(model).order_by(*keys).limit(BATCH).offset(offset))).all()
                    for row in rows:
                        for name in names:
                            attributes.flag_modified(row, name)
                if not rows:
                    break
                offset += len(rows)
                total += len(rows)
        return total

    async def _compact(self) -> None:
        """Rewrite the database file so no earlier (plain or encrypted) copy of any value is left in it.

        SQLite keeps freed pages and, in WAL mode, older page versions in the ``-wal`` file. Zeroing
        deletions (``secure_delete``), checkpointing the log into the file and emptying it, and
        rebuilding the file (``VACUUM``) leave only the current values.
        """
        if not self.available:
            return
        async with self.db.engine.connect() as raw:
            conn = await raw.execution_options(isolation_level="AUTOCOMMIT")
            await conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            await conn.exec_driver_sql("VACUUM")
            await conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")

    async def _save(self) -> None:
        await self.app_state.set(vault.RECORD_KEY, vault.STATE.record)

    async def enable(self, passphrase: str) -> str:
        """Turn the vault on and encrypt everything: returns the recovery code, shown once."""
        if not self.available:
            raise vault.VaultError("The case vault is for a single computer's own database (Argus Personal)")
        if vault.STATE.enabled:
            raise vault.VaultError("The vault is already set up")
        record, code, key = vault.create(passphrase)
        vault.STATE.enabled, vault.STATE.record = True, record
        vault.unlock_with(key)
        await self._save()
        await self._finish_encrypting()
        return code

    async def _finish_encrypting(self) -> None:
        count = await self._rewrite_all()
        vault.STATE.record = {**vault.STATE.record, "state": "ready"}
        await self._save()
        await self._compact()
        logger.info("Case vault: %d record(s) encrypted", count)

    async def unlock(self, *, passphrase: str | None = None, recovery_code: str | None = None) -> None:
        if not vault.STATE.enabled:
            raise vault.VaultError("No vault is set up")
        try:
            key = vault.open_with(vault.STATE.record, passphrase=passphrase, recovery_code=recovery_code)
        except vault.VaultError:
            vault.STATE.failed_attempts += 1
            raise
        failed = vault.STATE.failed_attempts
        vault.unlock_with(key)
        vault.STATE.failed_attempts = failed  # reported once by the caller, then cleared
        state = vault.STATE.record.get("state")
        if state == "encrypting":
            await self._finish_encrypting()
        elif state == "decrypting":
            await self._finish_decrypting()
            return
        waiting, self.on_unlock = self.on_unlock, []
        for callback in waiting:
            await self._run(callback)

    @staticmethod
    async def _run(callback: Callable[[], Awaitable[None]]) -> None:
        try:
            await callback()
        except Exception:
            logger.exception("A task waiting for the vault to unlock failed")

    def lock(self) -> None:
        vault.lock()

    async def change_passphrase(self, current: str, new: str) -> None:
        key = vault.open_with(vault.STATE.record, passphrase=current)
        vault.STATE.record = vault.rewrap_passphrase(vault.STATE.record, key, new)
        await self._save()

    async def new_recovery_code(self, passphrase: str) -> str:
        key = vault.open_with(vault.STATE.record, passphrase=passphrase)
        vault.STATE.record, code = vault.rewrap_recovery(vault.STATE.record, key)
        await self._save()
        return code

    async def disable(self, passphrase: str) -> None:
        """Decrypt everything and remove the vault."""
        key = vault.open_with(vault.STATE.record, passphrase=passphrase)
        vault.unlock_with(key)
        vault.STATE.record = {**vault.STATE.record, "state": "decrypting"}
        await self._save()
        await self._finish_decrypting()

    async def _finish_decrypting(self) -> None:
        vault.STATE.plain_writes = True
        try:
            count = await self._rewrite_all()
        finally:
            vault.STATE.plain_writes = False
        await self.app_state.delete(vault.RECORD_KEY)
        vault.reset()
        await self._compact()
        logger.info("Case vault turned off: %d record(s) decrypted", count)
