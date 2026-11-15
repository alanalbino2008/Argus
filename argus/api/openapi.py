"""The published OpenAPI document: security schemes, the workspace header and tags.

FastAPI generates the operations; this adds what a client author needs and FastAPI cannot
infer from Argus's own authentication dependencies:

* the two ways to send an API key (``Authorization: Bearer`` and ``X-API-Key``), declared on
  exactly the operations that require one (health checks and report verification are public);
* the optional ``X-Argus-Workspace`` header on every workspace-scoped operation, with the role
  each one requires;
* a tag for every operation, so the reference reads by area rather than by source file.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute

try:  # FastAPI >= 0.162 includes routers lazily
    from fastapi.routing import iter_route_contexts
except ImportError:  # pragma: no cover - older FastAPI flattens them into app.routes
    iter_route_contexts = None  # type: ignore[assignment]

from argus.api.deps import get_principal

SECURITY: list[dict[str, list[str]]] = [{"ApiKeyBearer": []}, {"ApiKeyHeader": []}]
WORKSPACE_HEADER = {
    "name": "X-Argus-Workspace",
    "in": "header",
    "required": False,
    "description": "Workspace slug or id to act in (default: your default workspace). Foreign workspaces answer 404.",
    "schema": {"type": "string", "examples": ["red-team"]},
}
PATH_TAGS = (  # for the operations defined directly on the app
    ("/api/investigation/{inv_id}/rating", "ratings"),
    ("/api/investigation/{inv_id}/report", "reports"),
    ("/api/demo", "getting started"),
    ("/api/investigation", "investigations"),
    ("/api/scan", "investigations"),
    ("/api/entities", "investigations"),
    ("/api/", "platform"),
)
ERROR = {
    "description": "Error",
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
}


def _api_routes(app: FastAPI) -> list[Any]:
    if iter_route_contexts is None:  # pragma: no cover
        return [r for r in app.routes if isinstance(r, APIRoute)]
    return [c for c in iter_route_contexts(app.routes) if isinstance(c.original_route, APIRoute)]


def _walk(dependant: Dependant) -> list[Any]:
    calls = []
    for dep in dependant.dependencies:
        calls.append(dep.call)
        calls += _walk(dep)
    return calls


def build_openapi(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        summary=app.summary,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
        license_info=app.license_info,
    )
    components = schema.setdefault("components", {})
    components["securitySchemes"] = {
        "ApiKeyBearer": {"type": "http", "scheme": "bearer", "description": "An Argus API key: `Bearer argus_…`"},
        "ApiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
    }
    components.setdefault("schemas", {})["Error"] = {
        "type": "object",
        "properties": {"detail": {"description": "A message that can be shown to a person"}},
        "required": ["detail"],
    }
    for route in _api_routes(app):
        if not route.include_in_schema:
            continue
        calls = _walk(route.dependant)
        authenticated = get_principal in calls
        role = next((getattr(c, "workspace_role", None) for c in calls if hasattr(c, "workspace_role")), None)
        for method in route.methods:
            op = schema["paths"].get(route.path_format, {}).get(method.lower())
            if op is None:
                continue
            if not op.get("tags"):
                op["tags"] = [next((t for prefix, t in PATH_TAGS if route.path_format.startswith(prefix)), "platform")]
            if not authenticated:
                op["security"] = []
                continue
            op["security"] = SECURITY
            responses = op.setdefault("responses", {})
            responses.setdefault("401", {**ERROR, "description": "Missing or invalid API key"})
            responses.setdefault("429", {**ERROR, "description": "Rate limit exceeded (see Retry-After)"})
            if role is not None:
                op.setdefault("parameters", []).append(WORKSPACE_HEADER)
                op["x-argus-role"] = role.value
                op["description"] = (op.get("description") or "").rstrip() + f"\n\nRequires the **{role.value}** role."
                responses.setdefault("403", {**ERROR, "description": f"Requires the {role.value} role"})
                responses.setdefault("404", {**ERROR, "description": "Not found (or in another workspace)"})
    app.openapi_schema = schema
    return schema
