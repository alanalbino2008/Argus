"""Backups: their status, setting them up (Argus Personal), backing up now, checking and restoring.

Only an administrator of the whole installation can use these (in Argus Personal: the person
signed in). Every action is in the audit log; passwords never are.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import audit, require_platform_admin
from argus.security.auth import Principal
from argus.storage import backup

router = APIRouter(prefix="/api/backups", tags=["backups"])
ADMIN = Depends(require_platform_admin)


class BackupSettings(BaseModel):
    enabled: bool = True
    folder: str = Field(default="", max_length=1000)
    every_hours: int = Field(default=24, ge=1, le=168)
    keep: int = Field(default=14, ge=1, le=365)
    password: str | None = Field(default=None, max_length=256)


class BackupFile(BaseModel):
    file: str = Field(min_length=1, max_length=2000)
    password: str = Field(min_length=1, max_length=256)


def _problem(exc: backup.BackupError, status: int = 422) -> HTTPException:
    return HTTPException(status_code=status, detail=str(exc))


def _backup_file(raw: str) -> Path:
    path = Path(raw.strip().strip('"')).expanduser()
    if not path.is_absolute() or not path.name.endswith(backup.SUFFIX) or not path.is_file():
        raise HTTPException(
            status_code=422, detail=f"Choose an Argus backup file (a {backup.SUFFIX} file, its full path)"
        )
    return path


@router.get("")
async def backup_status(request: Request, _principal: Principal = ADMIN):
    """Whether backups are set up and working, and the backups in the folder."""
    return await request.app.state.backups.status()


@router.put("")
async def backup_configure(body: BackupSettings, request: Request, principal: Principal = ADMIN):
    """Set up automatic backups: a folder and a backup password (Argus Personal)."""
    if request.app.state.settings.edition != "personal":
        raise HTTPException(
            status_code=403, detail="On a server, backups are set in its configuration (ARGUS_BACKUP_DIR)"
        )
    try:
        await request.app.state.backups.configure(folder=body.folder, every_hours=body.every_hours, keep=body.keep,
                                                  password=body.password or None, enabled=body.enabled)  # fmt: skip
    except backup.BackupError as exc:
        raise _problem(exc) from exc
    await audit(request, principal, "backup.configured", None,
                details={"enabled": body.enabled, "folder": body.folder, "every_hours": body.every_hours,
                         "keep": body.keep, "password_changed": bool(body.password)})  # fmt: skip
    return await request.app.state.backups.status()


@router.post("/run")
async def backup_run(request: Request, principal: Principal = ADMIN):
    """Make a backup now."""
    service = request.app.state.backups
    if service.running:
        raise HTTPException(status_code=409, detail="A backup is already running")
    try:
        result = await service.run_now("manual")
    except backup.BackupError as exc:
        await audit(request, principal, "backup.created", None, outcome="failure", details={"error": str(exc)})
        raise _problem(exc) from exc
    await audit(request, principal, "backup.created", result["name"], details={"size": result["size"]})
    return await service.status()


@router.post("/check")
async def backup_check(body: BackupFile, request: Request, principal: Principal = ADMIN):
    """Open a backup completely with its password and check every file (nothing is changed)."""
    path = _backup_file(body.file)
    work = backup.sqlite_path(request.app.state.settings.database_url)
    try:
        info = await asyncio.to_thread(backup.check, path, body.password,
                                       work_dir=work.parent if work else Path.home(),
                                       known_revisions=backup.known_revisions())  # fmt: skip
    except backup.BackupError as exc:
        await audit(request, principal, "backup.checked", path.name, outcome="failure", details={"error": str(exc)})
        raise _problem(exc) from exc
    await audit(request, principal, "backup.checked", path.name)
    return {"ok": True, "backup": info}


@router.post("/drill")
async def backup_drill(request: Request, principal: Principal = ADMIN):
    """Restore the newest backup into a scratch folder and prove it works (nothing is changed or kept)."""
    try:
        result = await request.app.state.backups.drill("manual")
    except backup.BackupError as exc:
        await audit(request, principal, "backup.drill", None, outcome="failure", details={"error": str(exc)})
        raise _problem(exc) from exc
    await audit(request, principal, "backup.drill", result["backup"], details={"counts": result["counts"]})
    return await request.app.state.backups.status()


@router.post("/restore")
async def backup_restore(body: BackupFile, request: Request, principal: Principal = ADMIN):
    """Prepare a restore: checked now, swapped in when Argus next starts (the current data is kept aside)."""
    settings = request.app.state.settings
    if settings.edition != "personal":
        raise HTTPException(status_code=403, detail="On a server, restore with the command line: argus backup restore")
    path = _backup_file(body.file)
    try:
        info = await asyncio.to_thread(backup.stage_restore, settings, path, body.password, backup.known_revisions())
    except backup.BackupError as exc:
        await audit(request, principal, "backup.restore", path.name, outcome="failure", details={"error": str(exc)})
        raise _problem(exc) from exc
    await audit(request, principal, "backup.restore", path.name, details={"made": info.get("created_at")})
    from argus.cli import console

    restarting = console.SERVER is not None
    if restarting:  # the desktop app: close, and start again straight away with the restored data
        console.RESTART = True
        console.SERVER.should_exit = True
    return {"backup": info, "restarting": restarting,
            "detail": "Argus is restarting with the restored data." if restarting else
            "Restart Argus to finish: the restored data takes over at the next start."}  # fmt: skip


@router.post("/restore/cancel")
async def backup_restore_cancel(request: Request, principal: Principal = ADMIN):
    """Forget a prepared restore that hasn't happened yet."""
    backup.cancel_restore(request.app.state.settings)
    await audit(request, principal, "backup.restore_cancelled", None)
    return await request.app.state.backups.status()
