"""The case vault's API: set it up, unlock and lock it, change the passphrase, turn it off.

While the vault is locked, :func:`vault_gate` answers every other API request with
``423 Locked`` (``{"vault_locked": true}``), so the web interface shows the unlock screen and
nothing reads or writes case data. Only these endpoints, sign-in and health checks stay open.

Unlock attempts are rate-limited (by caller and overall), each one takes about a second of
deliberately slow key derivation, and failures are counted and written to the audit log after the
next successful unlock (the audit log itself is encrypted, so it cannot be written while locked).
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argus.api.deps import audit, client_ip, require_platform_admin
from argus.security import vault
from argus.security.auth import Principal
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/vault", tags=["vault"])
ADMIN = Depends(require_platform_admin)
OPEN_WHILE_LOCKED = ("/api/vault", "/api/health", "/api/live", "/api/auth/config", "/api/auth/logout", "/api/personal/")
_attempts = SlidingWindowLimiter(limit=5, window=60)  # per caller
_attempts_all = SlidingWindowLimiter(limit=20, window=300)  # everyone together


class Passphrase(BaseModel):
    passphrase: str = Field(min_length=1, max_length=1024)


class EnableRequest(Passphrase):
    understood: bool = Field(description="Confirms the investigator knows a lost passphrase and recovery code "
                                         "means the data cannot be recovered")  # fmt: skip


class UnlockRequest(BaseModel):
    passphrase: str | None = Field(default=None, max_length=1024)
    recovery_code: str | None = Field(default=None, max_length=64)


class ChangeRequest(BaseModel):
    current: str = Field(min_length=1, max_length=1024)
    new: str = Field(min_length=1, max_length=1024)


def _service(request: Request) -> Any:
    return request.app.state.vault


def _busy(request: Request) -> str | None:
    """Why the vault cannot be locked right now (work in progress needs the key), or None."""
    from argus.api.playbook_routes import RUNS

    running = [e for e in request.app.state.scan_engines() if e.is_running]
    if running:
        return f"{len(running)} scan(s) running"
    if any(not t.done() for t in RUNS.values()):
        return "a playbook is running"
    return None


async def vault_gate(request: Request, call_next: Any) -> Any:
    """Middleware: while the vault is locked, the API answers 423 (except the vault's own endpoints)."""
    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)
    if vault.locked() and not path.startswith(OPEN_WHILE_LOCKED) and path != "/api/me":  # who is signed in
        return JSONResponse({"detail": "The case vault is locked: unlock it to continue", "vault_locked": True},
                            status_code=423)  # fmt: skip
    if not path.startswith("/api/vault/status"):
        vault.touch()  # activity keeps an unlocked vault open
    return await call_next(request)


@router.get("/status")
async def vault_status(request: Request, principal: Principal = ADMIN):
    return {**_service(request).status(), "idle_minutes": request.app.state.settings.vault_idle_minutes}


@router.post("/enable")
async def enable_vault(body: EnableRequest, request: Request, principal: Principal = ADMIN):
    """Set up the vault and encrypt everything. The recovery code is returned once and never again."""
    if not body.understood:
        raise HTTPException(status_code=422, detail="Confirm you understand that if both the passphrase and the "
                                                    "recovery code are lost, nobody can recover the data")  # fmt: skip
    try:
        code = await _service(request).enable(body.passphrase)
    except vault.VaultError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await audit(request, principal, "vault.enable", None, details={"ip": client_ip(request)})
    return {"recovery_code": code, **_service(request).status()}


@router.post("/unlock")
async def unlock_vault(body: UnlockRequest, request: Request, principal: Principal = ADMIN):
    if not vault.STATE.enabled:
        raise HTTPException(status_code=409, detail="No vault is set up")
    if not vault.locked():
        return _service(request).status()
    if not _attempts.hit(principal.key_id) or not _attempts_all.hit("all"):
        raise HTTPException(status_code=429, detail="Too many attempts: wait a few minutes")
    started = time.monotonic()
    try:
        await _service(request).unlock(passphrase=body.passphrase, recovery_code=body.recovery_code)
    except vault.VaultError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    failed = vault.STATE.failed_attempts
    vault.STATE.failed_attempts = 0
    await audit(request, principal, "vault.unlock", None,
                details={"with": "recovery code" if body.recovery_code and not body.passphrase else "passphrase",
                         "failed_attempts_before": failed, "seconds": round(time.monotonic() - started, 2),
                         "ip": client_ip(request)})  # fmt: skip
    return _service(request).status()


@router.post("/lock")
async def lock_vault(request: Request, principal: Principal = ADMIN):
    if not vault.STATE.enabled:
        raise HTTPException(status_code=409, detail="No vault is set up")
    if vault.locked():
        return _service(request).status()
    busy = _busy(request)
    if busy:
        raise HTTPException(status_code=409, detail=f"Can't lock while {busy}: wait for it to finish, or stop it")
    await audit(request, principal, "vault.lock", None, details={"by": "hand"})
    _service(request).lock()
    return _service(request).status()


@router.post("/passphrase")
async def change_passphrase(body: ChangeRequest, request: Request, principal: Principal = ADMIN):
    if not _attempts.hit(principal.key_id):
        raise HTTPException(status_code=429, detail="Too many attempts: wait a minute")
    try:
        await _service(request).change_passphrase(body.current, body.new)
    except vault.VaultError as exc:
        raise HTTPException(status_code=403 if "Wrong" in str(exc) else 422, detail=str(exc)) from exc
    await audit(request, principal, "vault.passphrase_changed", None)
    return {"changed": True}


@router.post("/recovery-code")
async def new_recovery_code(body: Passphrase, request: Request, principal: Principal = ADMIN):
    """Replace the recovery code (the old one stops working). Shown once."""
    if not _attempts.hit(principal.key_id):
        raise HTTPException(status_code=429, detail="Too many attempts: wait a minute")
    try:
        code = await _service(request).new_recovery_code(body.passphrase)
    except vault.VaultError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    await audit(request, principal, "vault.recovery_code_replaced", None)
    return {"recovery_code": code}


@router.post("/disable")
async def disable_vault(body: Passphrase, request: Request, principal: Principal = ADMIN):
    """Decrypt everything and turn the vault off."""
    if not vault.STATE.enabled:
        raise HTTPException(status_code=409, detail="No vault is set up")
    if not _attempts.hit(principal.key_id):
        raise HTTPException(status_code=429, detail="Too many attempts: wait a minute")
    busy = _busy(request)
    if busy:
        raise HTTPException(status_code=409, detail=f"Can't turn the vault off while {busy}")
    try:
        await _service(request).disable(body.passphrase)
    except vault.VaultError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    await audit(request, principal, "vault.disable", None, details={"ip": client_ip(request)})
    return _service(request).status()
