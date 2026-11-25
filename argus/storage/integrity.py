"""Integrity check: is everything Argus holds still whole? (Phase 96)

Run with ``argus --check``, from Settings (platform administrators, ``POST /api/integrity/check``),
and automatically every week. It looks for:

* **storage damage**: SQLite's ``PRAGMA integrity_check`` (PostgreSQL checks its own pages);
* **broken references**: rows pointing at a parent that no longer exists, for every foreign key in
  the schema (for example case items without their case, the trace the 1.91.0 migration bug left);
* **the audit trail**: the whole hash chain, recomputed;
* **evidence**: every captured file against its recorded SHA-256, every manifest against its digest,
  and every chain of custody.

The result is kept (``GET /api/integrity``), exported as ``argus_integrity_problems``, audited, and
alerted on (``ArgusIntegrityProblems``). Checking reads everything once; it never changes anything.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import inspect, select, text

from argus.storage.db import Base, Database, EvidenceCaptureRow

STATE_KEY = "integrity_check"
MAX_LISTED = 20  # problems listed per check (all are counted)


def _check(name: str, problems: list[str], detail: str, started: float, **extra: Any) -> dict[str, Any]:
    return {"name": name, "ok": not problems, "problems": problems[:MAX_LISTED], "count": len(problems),
            "detail": detail, "seconds": round(time.monotonic() - started, 2), **extra}  # fmt: skip


async def storage(db: Database) -> dict[str, Any]:
    started = time.monotonic()
    if db.dialect != "sqlite":
        return _check("storage", [], "PostgreSQL verifies its own pages (data checksums)", started)
    async with db.engine.connect() as conn:
        rows = [r[0] for r in (await conn.exec_driver_sql("PRAGMA integrity_check")).fetchall()]
    problems = [] if rows == ["ok"] else rows
    return _check("storage", problems, "SQLite integrity_check", started)


async def references(db: Database) -> dict[str, Any]:
    """Every foreign key: child rows whose parent is gone."""
    started = time.monotonic()
    problems: list[str] = []
    checked = 0
    async with db.engine.connect() as conn:
        existing = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue
            for fk in table.foreign_keys:
                parent = fk.column.table
                if parent.name not in existing:
                    continue
                checked += 1
                child_col, parent_col = fk.parent.name, fk.column.name
                orphans: int = (await conn.execute(text(
                    f'SELECT COUNT(*) FROM "{table.name}" c WHERE c."{child_col}" IS NOT NULL AND NOT EXISTS '  # noqa: S608
                    f'(SELECT 1 FROM "{parent.name}" p WHERE p."{parent_col}" = c."{child_col}")'  # names from the schema
                ))).scalar_one()  # fmt: skip
                if orphans:
                    problems.append(f"{orphans} row(s) in {table.name} refer to a missing {parent.name} ({child_col})")
    return _check("references", problems, f"{checked} foreign keys", started)


async def audit_chain(audit: Any) -> dict[str, Any]:
    started = time.monotonic()
    result = await audit.verify()
    problems = [] if result["valid"] else [f"Entry {result['first_invalid_id']} does not match the chain"]
    return _check("audit_chain", problems, f"{result['checked']} entries", started)


async def evidence(db: Database, cases: Any) -> dict[str, Any]:
    started = time.monotonic()
    async with db.session() as s:
        ids = list((await s.scalars(select(EvidenceCaptureRow.id).order_by(EvidenceCaptureRow.captured_at))).all())
    problems: list[str] = []
    for capture_id in ids:
        try:
            result = await cases.verify(capture_id)
        except Exception as exc:  # noqa: BLE001  (a locked vault or a damaged row: report it, keep checking)
            problems.append(f"Capture {capture_id} could not be read ({type(exc).__name__})")
            continue
        problems += [f"Capture {capture_id}: {p}" for p in result["problems"]]
    return _check("evidence", problems, f"{len(ids)} captures", started)


async def run(app_state: Any) -> dict[str, Any]:
    """Every check, and an overall verdict. With the case vault locked, the encrypted parts (the audit
    details and the evidence) cannot be read: those checks are skipped and say so."""
    from argus.security import vault

    db = app_state.db
    checks = [await storage(db), await references(db)]
    if vault.locked():
        skipped = "Skipped: the case vault is locked. Unlock it, then check again."
        checks += [_check("audit_chain", [], skipped, time.monotonic(), skipped=True),
                   _check("evidence", [], skipped, time.monotonic(), skipped=True)]  # fmt: skip
    else:
        checks += [await audit_chain(app_state.audit), await evidence(db, app_state.cases)]
    return {"ok": all(c["ok"] for c in checks), "checked_at": datetime.now(timezone.utc).isoformat(),
            "problems": sum(c["count"] for c in checks), "checks": checks}  # fmt: skip


# ---------------------------------------------------------------------------- recording and scheduling
POLL_SECONDS = 7 * 24 * 3600
LOCK = 0x4152_4755_494E_5447  # "ARGUINTG": one replica checks at a time


async def check_and_record(app: Any, principal: Any = None) -> dict[str, Any]:
    """Run every check, keep the result, export it as a metric and write it to the audit log."""
    from argus.api.scheduler import SCHEDULER
    from argus.observability import metrics

    async with app.state.db.cluster_lock(LOCK):
        result = await run(app.state)
    await app.state.app_state.set(STATE_KEY, result)
    metrics.INTEGRITY_PROBLEMS.set(result["problems"])
    metrics.INTEGRITY_LAST_RUN.set(time.time())
    await app.state.audit.record(principal or SCHEDULER, "integrity.check", None, "success" if result["ok"] else "failure",
                                 details={c["name"]: c["count"] for c in result["checks"]})  # fmt: skip
    return result


async def run_forever(app: Any, poll_seconds: float = POLL_SECONDS) -> None:
    import asyncio
    import logging

    logger = logging.getLogger("argus.integrity")
    await asyncio.sleep(600)  # not during start-up
    while True:
        try:
            result = await check_and_record(app)
            if not result["ok"]:
                logger.error("Integrity check found %s problem(s): %s", result["problems"],
                             [c["problems"][:3] for c in result["checks"] if not c["ok"]])  # fmt: skip
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Integrity check failed to run")
        await asyncio.sleep(poll_seconds)
