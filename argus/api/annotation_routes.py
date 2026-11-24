"""The team's tags and notes on entities: shared by the workspace, applied in every investigation.

Entity ids are derived from an entity's type and value, so tagging ``vpn.acme.example`` once tags
it in every scan that finds it, past and future. Tags and notes can be queried in AQL (``tag:c2``,
``note~"invoice"``), so they also drive hunts and saved-query alerts.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.core.models import EntityType
from argus.security.auth import Role
from argus.storage.annotation_repo import MAX_NOTE_LENGTH, MAX_TAGS, AnnotationLimit

router = APIRouter(prefix="/api", tags=["query"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ENTITY_ID = re.compile(r"^[a-z_]{2,32}_[0-9a-f]{12}$")  # see argus.core.models.generate_entity_id


class AnnotationBody(BaseModel):
    entity_type: EntityType
    value: str = Field(min_length=1, max_length=2000, description="The entity's value, for display")
    tags: list[str] = Field(default_factory=list, max_length=MAX_TAGS)
    note: str = Field(default="", max_length=MAX_NOTE_LENGTH)


def _repo(request: Request) -> Any:
    return request.app.state.annotations


@router.get("/annotations")
async def list_annotations(request: Request, ws: WorkspaceContext = VIEWER):
    """Every tagged or noted entity in the workspace."""
    return sorted((await _repo(request).all(ws.id)).values(), key=lambda a: a["updated_at"], reverse=True)


@router.get("/annotations/tags")
async def list_tags(request: Request, ws: WorkspaceContext = VIEWER):
    """Every tag in use, with how many entities carry it."""
    return await _repo(request).tags(ws.id)


@router.put("/annotations/{entity_id}")
async def put_annotation(entity_id: str, body: AnnotationBody, request: Request, ws: WorkspaceContext = ANALYST):
    """Set an entity's tags and note (both empty removes them). Applies in every investigation."""
    if not ENTITY_ID.match(entity_id) or not entity_id.startswith(f"{body.entity_type.value}_"):
        raise HTTPException(status_code=422, detail="Not an entity id of that type")
    try:
        saved = await _repo(request).put(
            ws.id, entity_id, entity_type=body.entity_type.value, value=body.value.strip(), tags=body.tags,
            note=body.note, by=ws.principal.name,
        )  # fmt: skip
    except AnnotationLimit as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await audit(
        request, ws.principal, "entity.annotate", entity_id,
        details={"tags": len(saved["tags"]) if saved else 0, "note": bool(saved and saved["note"])},
    )  # fmt: skip
    return saved or {"entity_id": entity_id, "tags": [], "note": "", "removed": True}
