"""A read-only TAXII 2.1 server: other security tools pull Argus's indicators on their own schedule.

Each workspace is its own **API root**, ``/taxii2/{workspace}/``, so a TAXII client needs no custom
header to say which team's data it wants. Clients authenticate with an Argus API key, as a Bearer
token or as the password of HTTP Basic (the user name is ignored), which is what most TAXII clients
(OpenCTI, MISP, Sentinel's TAXII connector) can send. A viewer key is enough; use one bound to the
workspace. See :mod:`argus.intel.taxii` for what the collections contain.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response

from argus.api.deps import WorkspaceContext, audit, get_principal, resolve_workspace, throttle
from argus.intel import taxii
from argus.intel.stix import ARGUS_IDENTITY
from argus.security.auth import Principal
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/taxii2", tags=["threat intelligence"])
MAX_PAGE = 1000
DEFAULT_PAGE = 100
ACCEPTABLE = ("application/taxii+json", "application/json", "*/*", "application/*")


def _reply(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return Response(json.dumps(body), status_code=status, media_type=taxii.MEDIA_TYPE, headers=headers)


def _error(status: int, title: str, description: str = "") -> Response:
    return _reply({"title": title, "description": description, "http_status": str(status)}, status)


def _acceptable(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return not accept or any(a in accept for a in ACCEPTABLE)


_limiter = SlidingWindowLimiter(
    limit=120, window=60, name="taxii"
)  # per key: plenty for scheduled pulls, not for a flood


async def _workspace(
    workspace: str, request: Request, principal: Principal = Depends(get_principal)
) -> WorkspaceContext:
    await throttle(_limiter, principal.key_id, "Too many TAXII requests; wait a minute")
    return await resolve_workspace(request, principal, ref=workspace)


WORKSPACE = Depends(_workspace)


@router.get("/")
async def discovery(request: Request, principal: Principal = Depends(get_principal)):
    """TAXII discovery: one API root per workspace this key can read."""
    repo = request.app.state.workspaces
    if principal.workspace_id:
        spaces = [w for w in [await repo.get(principal.workspace_id)] if w]
    elif principal.user_id:
        spaces = await repo.list_for_user(principal.user_id)
    elif principal.platform_admin:
        spaces = await repo.list_all()
    else:
        spaces = []
    base = str(request.base_url).rstrip("/")
    roots = [f"{base}/taxii2/{w['id']}/" for w in spaces]
    body = {"title": "Argus", "description": "Indicators from Argus OSINT, one API root per workspace",
            "contact": "", "api_roots": roots}  # fmt: skip
    if roots:
        body["default"] = roots[0]
    return _reply(body)


@router.get("/{workspace}/")
async def api_root(request: Request, ws: WorkspaceContext = WORKSPACE):
    if not _acceptable(request):
        return _error(406, "Not acceptable", f"This server answers {taxii.MEDIA_TYPE}")
    return _reply({"title": f"Argus: {ws.workspace.get('name') or ws.id}", "versions": [taxii.MEDIA_TYPE],
                   "max_content_length": 10 * 1024 * 1024})  # fmt: skip


@router.get("/{workspace}/collections/")
async def list_collections(request: Request, ws: WorkspaceContext = WORKSPACE):
    return _reply({"collections": taxii.collections(ws.id)})


@router.get("/{workspace}/collections/{collection}/")
async def get_collection(collection: str, request: Request, ws: WorkspaceContext = WORKSPACE):
    kind = taxii.kind_of(ws.id, collection)
    if kind is None:
        return _error(404, "Collection not found")
    return _reply(next(c for c in taxii.collections(ws.id) if c["alias"] == kind))


async def _objects(request: Request, ws: WorkspaceContext, kind: str, version: int) -> list[tuple[str, dict[str, Any]]]:
    """The collection's objects, recomputed only when the workspace's data changed (shared: read only)."""
    from argus.api.campaign_routes import derived_cache
    from argus.observability import metrics

    cache = derived_cache(request.app)
    hit = cache.get(("taxii", ws.id, kind), version)
    if hit is not None:
        metrics.DERIVED_CACHE.labels("taxii", "hit").inc()
        return hit
    metrics.DERIVED_CACHE.labels("taxii", "miss").inc()
    found = await _compute(request, ws, kind, version)
    cache.put(("taxii", ws.id, kind), version, found)
    return found


async def _compute(request: Request, ws: WorkspaceContext, kind: str, version: int) -> list[tuple[str, dict[str, Any]]]:
    state = request.app.state
    if kind == "tagged":
        found = taxii.tagged(ws.id, await state.annotations.all(ws.id))
    elif kind == "lookalikes":
        found = taxii.lookalikes(ws.id, await state.brand_watches.first_seen(ws.id, triage=False, takedowns=False))
    elif kind == "fingerprint-servers":
        found = taxii.fingerprint_servers(ws.id, await state.fingerprint_watches.first_seen(ws.id))
    else:
        from argus.api.campaign_routes import computed

        every = [*taxii.tagged(ws.id, await state.annotations.all(ws.id)),
                 *taxii.lookalikes(ws.id, await state.brand_watches.first_seen(ws.id, triage=False, takedowns=False)),
                 *taxii.fingerprint_servers(ws.id, await state.fingerprint_watches.first_seen(ws.id))]  # fmt: skip
        campaigns = (await computed(request, ws.id, version))["campaigns"]
        found = taxii.campaign_objects(ws.id, campaigns, {o["id"]: (a, o) for a, o in every})
    if found:  # the identity the indicators' created_by_ref points to, as a member of the collection
        identity = json.loads(ARGUS_IDENTITY.serialize())
        found.append((identity["created"], identity))
    return found


def _cursor(value: str | None) -> int:
    if not value:
        return 0
    try:
        return max(0, int(base64.urlsafe_b64decode(value.encode() + b"==").decode()))
    except (ValueError, UnicodeDecodeError):
        return -1


def _token(start: int) -> str:
    return base64.urlsafe_b64encode(str(start).encode()).decode().rstrip("=")


async def _page(collection: str, request: Request, ws: WorkspaceContext, *, added_after: str | None, limit: int,
                next_: str | None, object_id: str | None = None) -> tuple[Response | None, Any]:  # fmt: skip
    kind = taxii.kind_of(ws.id, collection)
    if kind is None:
        return _error(404, "Collection not found"), None
    if not _acceptable(request):
        return _error(406, "Not acceptable", f"This server answers {taxii.MEDIA_TYPE}"), None
    start = _cursor(next_)
    if start < 0:
        return _error(400, "Bad next", "The 'next' value is not one this server gave"), None
    from argus.api.campaign_routes import _conditional
    from argus.storage import data_version

    version = await data_version.current(request.app.state.db, ws.id)
    tag, unchanged = _conditional(request, version, "taxii")
    if unchanged is not None:
        await audit(request, ws.principal, "taxii.read", kind, details={"objects": 0, "not_modified": True})
        return unchanged, None
    params = request.query_params
    ids = {object_id} if object_id else set(filter(None, params.get("match[id]", "").split(",")))
    types = set(filter(None, params.get("match[type]", "").split(",")))
    objects = await _objects(request, ws, kind, version)
    window, following = taxii.page(objects, added_after=added_after, limit=limit, start=start,
                                   match_ids=ids or None, match_types=types or None)  # fmt: skip
    headers = {"ETag": tag, "Cache-Control": "private, no-cache"}
    if window:
        headers |= {"X-TAXII-Date-Added-First": window[0][0], "X-TAXII-Date-Added-Last": window[-1][0]}
    await audit(request, ws.principal, "taxii.read", kind, details={"objects": len(window)})
    return None, (window, following, headers)


@router.get("/{workspace}/collections/{collection}/objects/")
async def get_objects(
    collection: str, request: Request, ws: WorkspaceContext = WORKSPACE,
    added_after: str | None = Query(None), limit: int = Query(DEFAULT_PAGE, ge=1, le=MAX_PAGE),
    next: str | None = Query(None),
):  # fmt: skip
    """The collection's STIX objects, oldest first; ``added_after`` and ``next`` page through them."""
    failure, result = await _page(collection, request, ws, added_after=added_after, limit=limit, next_=next)
    if failure:
        return failure
    window, following, headers = result
    body: dict[str, Any] = {"more": following is not None, "objects": [o for _, o in window]}
    if following is not None:
        body["next"] = _token(following)
    return _reply(body, headers=headers)


@router.get("/{workspace}/collections/{collection}/objects/{object_id}/")
async def get_object(collection: str, object_id: str, request: Request, ws: WorkspaceContext = WORKSPACE):
    failure, result = await _page(collection, request, ws, added_after=None, limit=1, next_=None, object_id=object_id)
    if failure:
        return failure
    window, _following, headers = result
    if not window:
        return _error(404, "Object not found")
    return _reply({"objects": [window[0][1]]}, headers=headers)


@router.get("/{workspace}/collections/{collection}/manifest/")
async def get_manifest(
    collection: str, request: Request, ws: WorkspaceContext = WORKSPACE,
    added_after: str | None = Query(None), limit: int = Query(DEFAULT_PAGE, ge=1, le=MAX_PAGE),
    next: str | None = Query(None),
):  # fmt: skip
    failure, result = await _page(collection, request, ws, added_after=added_after, limit=limit, next_=next)
    if failure:
        return failure
    window, following, headers = result
    body: dict[str, Any] = {
        "more": following is not None,
        "objects": [
            {"id": o["id"], "date_added": added, "version": o["modified"], "media_type": taxii.STIX_MEDIA_TYPE}
            for added, o in window
        ],
    }
    if following is not None:
        body["next"] = _token(following)
    return _reply(body, headers=headers)
