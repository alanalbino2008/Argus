"""HTTP security headers (defence in depth for the web UI and API)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# Everything is served by Argus itself (Cytoscape and the fonts are vendored), so every directive is
# locked to 'self': an investigator's browser contacts no third party at all, and even if an XSS bug
# slipped through, injected <script> or inline handlers would be refused. Inline *styles* remain
# allowed (used by the UI markup). Violations are reported to /api/csp-report (Phase 99).
CSP_REPORT_PATH = "/api/csp-report"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
    "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    f"frame-ancestors 'none'; report-uri {CSP_REPORT_PATH}; report-to csp"
)

# Swagger/ReDoc pages load their own CDN assets and contain no investigation data.
CSP_EXEMPT_PREFIXES = ("/docs", "/redoc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if not request.url.path.startswith(CSP_EXEMPT_PREFIXES):
            h.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            h.setdefault("Reporting-Endpoints", f'csp="{CSP_REPORT_PATH}"')
        if request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")  # investigation data must not be cached
        rate = getattr(request.state, "rate_limit", None)
        if rate is not None:
            limit, remaining, reset = rate
            h.setdefault("RateLimit-Limit", str(limit))
            h.setdefault("RateLimit-Remaining", str(max(0, remaining)))
            h.setdefault("RateLimit-Reset", str(reset))
        if request.url.scheme == "https":
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
