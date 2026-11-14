"""OpenID Connect sign-in (Authorization Code flow with PKCE).

Works with any standards-compliant identity provider: Google Workspace, Microsoft
Entra ID, Okta, Auth0, Keycloak, Authentik...

Security properties
-------------------
* **Authorization Code + PKCE (S256)**: the browser only ever sees a one-time code;
  tokens are exchanged server-to-server with the client secret, and PKCE ties the code
  to the login that requested it.
* **state** (CSRF on the callback) and **nonce** (replay of an ID token) are random,
  single-use and stored server-side (hashed) for 10 minutes, so any replica can finish
  a login another started.
* **ID token validation**: signature against the provider's published JWKS (asymmetric
  algorithms only - ``none`` and HMAC are refused), exact issuer, audience = our client
  id (and ``azp`` when several audiences), expiry/issued-at with 60 s leeway, nonce.
* **Identity policy**: verified email required (configurable), optional email-domain
  allow-list, roles from a groups/roles claim or a default role (or refusal).
* Provider endpoints must be HTTPS (plain HTTP only for loopback development servers).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode, urlsplit

import aiohttp
import jwt

from argus.core.settings import Settings

ALLOWED_ALGORITHMS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
LEEWAY_SECONDS = 60
METADATA_TTL = 3600.0
JWKS_REFRESH_MIN_INTERVAL = 60.0

JsonFetcher = Callable[[str], Awaitable[dict[str, Any]]]
FormPoster = Callable[[str, dict[str, str], tuple[str, str] | None], Awaitable[dict[str, Any]]]


class OidcError(Exception):
    """A login that must be refused. ``code`` is safe to show to the user."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def _secure_endpoint(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def new_login_secrets() -> tuple[str, str, str]:
    """(state, nonce, code_verifier) - all from the OS CSPRNG."""
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)


def safe_return_path(value: str | None) -> str:
    """Only same-site relative paths: never an open redirect to another site."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return "/"
    return value[:512]


# ---------------------------------------------------------------------------- policy (pure)
def check_identity(claims: dict[str, Any], settings: Settings) -> str | None:
    """The user's email after policy checks (None if the provider sent none). Raises OidcError."""
    email = str(claims.get("email") or "").strip().lower() or None
    if settings.oidc_require_verified_email and email and claims.get("email_verified") is not True:
        raise OidcError("unverified_email", "the provider did not confirm this email address")
    allowed = {d.lower().lstrip("@") for d in settings.oidc_allowed_domains}
    if allowed:
        domain = email.rsplit("@", 1)[-1] if email else None
        hosted = str(claims.get("hd") or "").lower() or None  # Google Workspace's verified domain claim
        if not (domain in allowed or hosted in allowed):
            raise OidcError("domain_not_allowed", f"{domain or 'unknown domain'} is not allowed to sign in")
    if settings.oidc_allowed_domains and not email:
        raise OidcError("domain_not_allowed", "no email address to check against the allowed domains")
    return email


def groups_configured(settings: Settings) -> bool:
    return bool(settings.oidc_admin_groups or settings.oidc_analyst_groups or settings.oidc_viewer_groups)


def resolve_role(claims: dict[str, Any], email: str | None, settings: Settings) -> str | None:
    """Highest role granted by the claims; None means 'refuse this user'."""
    if email and email in {e.lower() for e in settings.oidc_admin_emails}:
        return "admin"
    raw = claims.get(settings.oidc_role_claim)
    values = {raw} if isinstance(raw, str) else {str(v) for v in raw} if isinstance(raw, list) else set()
    for role, groups in (
        ("admin", settings.oidc_admin_groups),
        ("analyst", settings.oidc_analyst_groups),
        ("viewer", settings.oidc_viewer_groups),
    ):
        if values & set(groups):
            return role
    return None if settings.oidc_default_role == "none" else settings.oidc_default_role


# ---------------------------------------------------------------------------- provider
async def _http_get_json(url: str) -> dict[str, Any]:
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as s, s.get(url) as resp:
        if resp.status != 200:
            raise OidcError("provider_unreachable", f"GET {url}: HTTP {resp.status}")
        return dict(await resp.json(content_type=None))


async def _http_post_form(url: str, data: dict[str, str], auth: tuple[str, str] | None) -> dict[str, Any]:
    timeout = aiohttp.ClientTimeout(total=10)
    basic = aiohttp.BasicAuth(*auth) if auth else None
    async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as s, s.post(url, data=data, auth=basic) as resp:
        body = await resp.json(content_type=None)
        if resp.status != 200:
            raise OidcError("token_exchange_failed", f"token endpoint: HTTP {resp.status} {body.get('error', '')}")
        return dict(body)


class OidcProvider:
    def __init__(
        self,
        settings: Settings,
        fetch_json: JsonFetcher = _http_get_json,
        post_form: FormPoster = _http_post_form,
    ):
        if not (settings.oidc_issuer and settings.oidc_client_id):
            raise ValueError("OIDC is not configured")
        self.settings = settings
        self.issuer = settings.oidc_issuer.rstrip("/")
        self.client_id = settings.oidc_client_id
        self._fetch_json = fetch_json
        self._post_form = post_form
        self._metadata: dict[str, Any] | None = None
        self._metadata_at = 0.0
        self._keys: dict[str, Any] = {}
        self._keys_at = 0.0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ discovery
    async def metadata(self) -> dict[str, Any]:
        async with self._lock:
            if self._metadata is None or time.monotonic() - self._metadata_at > METADATA_TTL:
                meta = await self._fetch_json(f"{self.issuer}/.well-known/openid-configuration")
                # OIDC Discovery 1.0 §4.3: the document must be for exactly this issuer.
                if str(meta.get("issuer", "")).rstrip("/") != self.issuer:
                    raise OidcError("provider_misconfigured", "discovery document issuer does not match")
                for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                    if not meta.get(key) or not _secure_endpoint(str(meta[key])):
                        raise OidcError("provider_misconfigured", f"{key} missing or not HTTPS")
                self._metadata, self._metadata_at = meta, time.monotonic()
            return self._metadata

    async def _signing_key(self, kid: str | None) -> Any:
        if kid in self._keys:
            return self._keys[kid]
        # Unknown key id: the provider may have rotated keys. Refresh, but not more than once a minute.
        if time.monotonic() - self._keys_at > JWKS_REFRESH_MIN_INTERVAL or not self._keys:
            jwks = await self._fetch_json(str((await self.metadata())["jwks_uri"]))
            keys: dict[str, Any] = {}
            for jwk in jwks.get("keys", []):
                if jwk.get("use", "sig") != "sig":
                    continue
                try:
                    keys[jwk.get("kid")] = jwt.PyJWK(jwk)
                except jwt.PyJWKError:
                    continue  # unsupported key type: ignore it, don't fail every login
            self._keys, self._keys_at = keys, time.monotonic()
        if kid in self._keys:
            return self._keys[kid]
        if kid is None and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        raise OidcError("invalid_token", "ID token signed with an unknown key")

    # ------------------------------------------------------------------ flow
    async def authorization_url(self, state: str, nonce: str, verifier: str, redirect_uri: str) -> str:
        meta = await self.metadata()
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        return f"{meta['authorization_endpoint']}?{urlencode(query)}"

    async def exchange_code(self, code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
        meta = await self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        secret = self.settings.oidc_client_secret.get_secret_value() if self.settings.oidc_client_secret else None
        methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        auth = None
        if secret and "client_secret_basic" in methods:
            auth = (self.client_id, secret)
        else:
            data["client_id"] = self.client_id
            if secret:
                data["client_secret"] = secret
        tokens = await self._post_form(str(meta["token_endpoint"]), data, auth)
        if not tokens.get("id_token"):
            raise OidcError("invalid_token", "the provider returned no ID token")
        return tokens

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError("invalid_token", f"malformed ID token: {exc}") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise OidcError("invalid_token", f"refused signing algorithm {alg!r}")
        key = await self._signing_key(header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=[alg],
                audience=self.client_id,
                issuer=self.issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("invalid_token", str(exc)) from exc
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if len(audiences) > 1 and claims.get("azp") != self.client_id:
            raise OidcError("invalid_token", "azp does not match this client")
        if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("invalid_token", "nonce mismatch (replayed or foreign ID token)")
        return claims

    async def end_session_url(self, post_logout_redirect: str) -> str | None:
        meta = await self.metadata()
        endpoint = meta.get("end_session_endpoint")
        if not endpoint or not _secure_endpoint(str(endpoint)):
            return None
        return (
            f"{endpoint}?{urlencode({'client_id': self.client_id, 'post_logout_redirect_uri': post_logout_redirect})}"
        )
