"""Per-request observability: request id, metrics and a structured access log.

Pure ASGI (not BaseHTTPMiddleware) so it adds no buffering and leaves WebSockets
untouched. Metrics use the *route template* (``/api/investigation/{inv_id}``), never
the concrete path, so label cardinality stays bounded; the access log likewise never
records query strings, which may carry single-use WebSocket tickets.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from argus.observability import metrics
from argus.observability.logs import new_request_id, request_id

access_log = logging.getLogger("argus.access")
KNOWN_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
QUIET_ROUTES = {"/api/health", "/api/live", "/metrics"}  # probes and scrapes: DEBUG, not INFO


def route_template(scope: dict[str, Any]) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return str(path)
    return "unmatched"  # 404s: one series, not one per probed URL


class ObservabilityMiddleware:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        rid = new_request_id(incoming)
        token = request_id.set(rid)
        status = 500
        started = time.perf_counter()

        async def send_with_id(message: dict[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] = [*message.get("headers", []), (b"x-request-id", rid.encode())]
            await send(message)

        metrics.HTTP_IN_FLIGHT.inc()
        try:
            await self.app(scope, receive, send_with_id)
        finally:
            metrics.HTTP_IN_FLIGHT.dec()
            elapsed = time.perf_counter() - started
            method = scope.get("method", "GET") if scope.get("method") in KNOWN_METHODS else "OTHER"
            route = route_template(scope)
            metrics.HTTP_REQUESTS.labels(method, route, str(status)).inc()
            metrics.HTTP_DURATION.labels(method, route).observe(elapsed)
            level = logging.DEBUG if route in QUIET_ROUTES and status < 500 else logging.INFO
            access_log.log(
                level,
                "%s %s %s %.1fms",
                method,
                route,
                status,
                elapsed * 1000,
                extra={"method": method, "route": route, "status": status, "duration_ms": round(elapsed * 1000, 1)},
            )
            request_id.reset(token)
