"""The legal documents, as public web pages (on the server that runs the Argus account service)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from argus.accounts import legal
from argus.api.deps import public_base_url

router = APIRouter(tags=["legal"])


def _enabled(request: Request) -> None:
    if not request.app.state.settings.account_service_enabled:
        raise HTTPException(status_code=404, detail="Not found")


@router.get("/api/legal")
async def legal_index(request: Request):
    """The documents, their addresses, and the published version (empty while still a draft)."""
    _enabled(request)
    settings = request.app.state.settings
    return {"version": legal.published(settings) or None, "documents": legal.links(public_base_url(request)),
            "titles": legal.DOCS, "accepted_with_terms": list(legal.ACCEPTED_WITH_TERMS)}  # fmt: skip


@router.get("/legal", include_in_schema=False)
async def legal_home(request: Request):
    _enabled(request)
    return RedirectResponse("/legal/terms", status_code=307)


@router.get("/legal/{doc}", response_class=HTMLResponse, include_in_schema=False)
async def legal_page(doc: str, request: Request):
    _enabled(request)
    if doc not in legal.DOCS:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(legal.page(doc, request.app.state.settings), headers={"Cache-Control": "no-cache"})
