"""Integrity check endpoints (Phase 96). See :mod:`argus.storage.integrity`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from argus.api.deps import require_platform_admin, throttle
from argus.security.auth import Principal
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage import integrity

router = APIRouter(prefix="/api", tags=["security"])
_limiter = SlidingWindowLimiter(limit=2, window=600, name="integrity_check")  # it reads everything once


@router.get("/integrity")
async def last_integrity_check(request: Request, _: Principal = Depends(require_platform_admin)):
    """The last integrity check's result (None if none has run yet)."""
    return await request.app.state.app_state.get(integrity.STATE_KEY)


@router.post("/integrity/check")
async def run_integrity_check(request: Request, admin: Principal = Depends(require_platform_admin)):
    """Check storage, references, the audit chain and every piece of evidence now."""
    await throttle(_limiter, admin.key_id, "An integrity check ran a moment ago; wait a few minutes")
    return await integrity.check_and_record(request.app, admin)
