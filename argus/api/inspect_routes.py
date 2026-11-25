"""Inspecting evidence files: hidden metadata, signs of editing, and tools to check time and place.

Every inspection is written to the evidence's chain of custody. Derived files (an error level
analysis, a copy without metadata) are downloads, never new evidence: the original stays exactly
as it was captured.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from argus.api.case_routes import _capture, _repo
from argus.api.deps import WorkspaceContext, in_workspace
from argus.evidence.inspect import clean_copy, error_level, inspect_file
from argus.intel.sun import sun_position
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
INSPECT_TIMEOUT = 60
_limiter = SlidingWindowLimiter(limit=30, window=60, name="inspect")


async def _file(request: Request, ws: WorkspaceContext, capture_id: str, name: str, action: str) -> tuple[str, bytes]:
    await _capture(request, ws, capture_id)
    if not await _limiter.allow(ws.principal.key_id):
        raise HTTPException(status_code=429, detail="Too many inspections; wait a minute")
    found = await _repo(request).file(capture_id, name, by=ws.principal.name, action=action)
    if found is None:
        raise HTTPException(status_code=404, detail="File not found")
    return found


def _download(data: bytes, media: str, filename: str) -> Response:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)[:120]
    return Response(data, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{safe}"', "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox; default-src 'none'", "Cache-Control": "no-store"})  # fmt: skip


@router.get("/evidence/{capture_id}/files/{name}/inspect")
async def inspect_evidence_file(capture_id: str, name: str, request: Request, ws: WorkspaceContext = VIEWER):
    """What the file reveals: metadata (camera, GPS, authors, software, dates) and signs of editing."""
    capture, _case = await _capture(request, ws, capture_id)
    media, data = await _file(request, ws, capture_id, name, "inspected")
    manifest = capture.get("manifest") or {}
    # The image's own public address, when the capture was of the image itself: reverse search can use it.
    source = manifest.get("final_url") or manifest.get("url") if name == "response.bin" else None
    try:
        return await asyncio.wait_for(asyncio.to_thread(inspect_file, name, media, data, source_url=source),
                                      INSPECT_TIMEOUT)  # fmt: skip
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=422, detail="The file took too long to read; it may be malformed") from exc


@router.get("/evidence/{capture_id}/files/{name}/error-level")
async def evidence_error_level(capture_id: str, name: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Error level analysis of a JPEG (a PNG): edited areas often stand out. A guide, not proof."""
    _media, data = await _file(request, ws, capture_id, name, "analysed (error level)")
    try:
        png = await asyncio.wait_for(asyncio.to_thread(error_level, data), INSPECT_TIMEOUT)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Error level analysis works on JPEG images") from exc
    return Response(png, media_type="image/png", headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                                                          "Content-Security-Policy": "sandbox; default-src 'none'"})  # fmt: skip


@router.get("/evidence/{capture_id}/files/{name}/clean")
async def evidence_clean_copy(capture_id: str, name: str, request: Request, ws: WorkspaceContext = VIEWER):
    """A copy of an image with every piece of metadata removed (for publishing or sharing safely)."""
    _media, data = await _file(request, ws, capture_id, name, "exported a copy without metadata")
    try:
        clean, media, ext = await asyncio.wait_for(asyncio.to_thread(clean_copy, data), INSPECT_TIMEOUT)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Only images can be cleaned") from exc
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return _download(clean, media, f"{stem}-clean.{ext}")


@router.get("/tools/sun")
async def sun_tool(
    request: Request,
    lat: float = Query(ge=-90, le=90),
    lon: float = Query(ge=-180, le=180),
    at: datetime = Query(description="ISO 8601 time with its UTC offset, e.g. 2024-06-21T13:00:00+01:00"),
    ws: WorkspaceContext = VIEWER,
):
    """Where the sun was at a place and time: compare with the shadows in a photo."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return sun_position(lat, lon, at)
