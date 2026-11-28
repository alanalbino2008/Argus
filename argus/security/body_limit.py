"""Request body size limit (protection against memory-exhaustion attacks).

Without a limit, anyone — even without an API key — could send a request body of gigabytes and have the
server buffer it while parsing JSON or a form, before any route (or authentication) runs. This pure ASGI
middleware refuses an oversized body up front when it declares its ``Content-Length``, and counts the
bytes of a streamed (chunked) body, cutting it off with **413 Content Too Large** as soon as it crosses the
limit — so the server never holds more than the limit in memory.

Two limits:

* ordinary requests (JSON, forms): ``max_request_kb`` (default 4 MB — far above any real API call);
* file uploads (``multipart/form-data``): the evidence upload limit plus 1 MB for the form envelope.

Limits are read from the running app's settings on each request, so a change applies without a restart.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MULTIPART_ENVELOPE = 1024 * 1024
DEFAULT_LIMIT = 4096 * 1024


class BodyTooLarge(HTTPException):
    """Raised inside the app when a streamed body crosses the limit.

    An HTTPException, so FastAPI's body parsing lets it through (it turns other errors into 400) and the
    app answers 413; if anything else swallows it first, the middleware answers 413 itself."""

    def __init__(self, limit: int) -> None:
        super().__init__(status_code=413, detail=f"Request body too large (the limit is {limit // 1024} KB)")


def _limit_for(scope: Scope, content_type: str) -> int:
    settings: Any = getattr(getattr(scope.get("app"), "state", None), "settings", None)
    json_limit = int(getattr(settings, "max_request_kb", 4096)) * 1024 if settings is not None else DEFAULT_LIMIT
    if content_type.startswith("multipart/form-data"):
        upload_mb = int(getattr(settings, "evidence_max_upload_mb", 25)) if settings is not None else 25
        return max(json_limit, upload_mb * 1024 * 1024 + MULTIPART_ENVELOPE)
    return json_limit


async def _refuse(send: Send, limit: int) -> None:
    body = json.dumps({"detail": f"Request body too large (the limit is {limit // 1024} KB)"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        content_type = headers.get(b"content-type", b"").decode("latin-1").lower()
        limit = _limit_for(scope, content_type)
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = -1
            if size < 0 or size > limit:
                await _refuse(send, limit)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not started:
                await _refuse(send, limit)
