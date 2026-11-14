"""Single sign-on against a fake OpenID Connect provider with real keys and signed tokens."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from argus.core.settings import Settings
from argus.security.oidc import (
    OidcError,
    OidcProvider,
    check_identity,
    pkce_challenge,
    resolve_role,
    safe_return_path,
)

ISSUER = "https://idp.example"
CLIENT_ID = "argus-test-client"
SECRET = "client-secret-123"


class FakeIdP:
    """Discovery, JWKS and a token endpoint that enforces PKCE and client authentication."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.claims: dict[str, Any] = {}
        self.jwks_fetches = 0

    def jwk(self) -> dict[str, Any]:
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {**public, "kid": self.kid, "use": "sig", "alg": "RS256"}

    async def fetch_json(self, url: str) -> dict[str, Any]:
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks",
                "end_session_endpoint": f"{ISSUER}/logout",
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            }
        if url == f"{ISSUER}/jwks":
            self.jwks_fetches += 1
            return {"keys": [self.jwk()]}
        raise AssertionError(url)

    def authorize(self, authorization_url: str, **claims: Any) -> tuple[str, str]:
        """What the provider does after the user signs in: returns (code, state)."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(authorization_url).query).items()}
        assert q["response_type"] == "code" and q["client_id"] == CLIENT_ID and q["code_challenge_method"] == "S256"
        code = f"code-{len(self.codes)}"
        self.codes[code] = {"nonce": q["nonce"], "challenge": q["code_challenge"], "claims": claims}
        return code, q["state"]

    def sign(self, claims: dict[str, Any], **header: Any) -> str:
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid, **header})

    async def post_form(self, url: str, data: dict[str, str], auth: tuple[str, str] | None) -> dict[str, Any]:
        assert url == f"{ISSUER}/token" and auth == (CLIENT_ID, SECRET)
        grant = self.codes.pop(data["code"], None)
        if grant is None or pkce_challenge(data["code_verifier"]) != grant["challenge"]:
            raise OidcError("token_exchange_failed", "invalid_grant")
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-42", "iat": now, "exp": now + 300,
                  "nonce": grant["nonce"], "email": "dana@acme.example", "email_verified": True,
                  "name": "Dana Whitfield", **grant["claims"]}  # fmt: skip
        return {"id_token": self.sign({k: v for k, v in claims.items() if v is not None}), "access_token": "x"}


@pytest.fixture
def sso(make_client):
    """An API client with SSO configured against the fake provider; returns (client, idp, login())."""
    idp = FakeIdP()

    def make(**env):
        client = make_client(
            oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret=SECRET, monitors_enabled="false", **env
        )
        client.app.state.oidc = OidcProvider(client.app.state.settings, idp.fetch_json, idp.post_form)
        return client

    def login(client, return_to="/", **claims):
        start = client.get("/auth/oidc/login", params={"return_to": return_to}, follow_redirects=False)
        assert start.status_code == 303
        code, state = idp.authorize(start.headers["location"], **claims)
        return client.get("/auth/oidc/callback", params={"code": code, "state": state}, follow_redirects=False)

    return make, idp, login


def browser(client):
    """Drop the test API key: from now on only the session cookie authenticates."""
    client.headers.pop("Authorization", None)
    return client


# ---------------------------------------------------------------------------- the happy path
def test_full_login_creates_a_secure_session(sso):
    make, _, login = sso
    client = make()
    assert client.get("/api/auth/config").json()["sso"] == {"enabled": True, "name": "Single sign-on"}
    done = login(client, return_to="/?inv=inv_demo_acme#/people")
    assert done.status_code == 303 and done.headers["location"] == "/?inv=inv_demo_acme#/people"
    cookie = done.headers["set-cookie"].lower()
    assert "argus_session=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    me = browser(client).get("/api/me").json()
    assert {k: me[k] for k in ("name", "role", "auth", "platform_admin")} == {
        "name": "dana@acme.example",
        "role": "viewer",
        "auth": "session",
        "platform_admin": False,
    }
    assert [(w["slug"], w["role"]) for w in me["workspaces"]] == [("default", "viewer")]  # joined on first sign-in
    assert client.get(
        "/api/audit", params={"action": "auth.login"}, headers={"Authorization": f"Bearer {ADMIN}"}
    ).json()


def test_cookie_writes_require_same_origin(sso):
    make, _, login = sso
    client = make(oidc_admin_emails='["dana@acme.example"]')
    login(client)
    browser(client)
    assert client.post("/api/ws-ticket").status_code == 403  # no Origin: refused (CSRF defence)
    assert client.post("/api/ws-ticket", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/ws-ticket", headers={"Origin": "http://testserver"}).status_code == 200
    assert client.get("/api/investigations").status_code == 200  # reads need no Origin


def test_logout_ends_the_session_and_offers_provider_sign_out(sso):
    make, _, login = sso
    client = make()
    login(client)
    browser(client)
    out = client.post("/api/auth/logout").json()
    assert out["signed_out"] is True and out["end_session_url"].startswith(f"{ISSUER}/logout?")
    assert client.get("/api/me").status_code == 401


# ---------------------------------------------------------------------------- attacks
def test_state_is_single_use_and_unknown_state_is_refused(sso):
    make, idp, _ = sso
    client = make()
    start = client.get("/auth/oidc/login", follow_redirects=False)
    code, state = idp.authorize(start.headers["location"])
    first = client.get("/auth/oidc/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert first.headers["location"] == "/"
    replay = client.get("/auth/oidc/callback", params={"code": code, "state": state}, follow_redirects=False)
    assert replay.headers["location"] == "/?sso_error=expired"
    forged = client.get("/auth/oidc/callback", params={"code": "x", "state": "forged"}, follow_redirects=False)
    assert forged.headers["location"] == "/?sso_error=expired"


def test_open_redirects_are_neutralised(sso):
    make, _, login = sso
    for evil in ("//evil.example/x", "https://evil.example", "/\\evil.example"):
        assert login(make(), return_to=evil).headers["location"] == "/"
    assert safe_return_path("/#/paths") == "/#/paths" and safe_return_path(None) == "/"


async def test_id_token_validation_refuses_forgeries():
    idp = FakeIdP()
    settings = Settings(oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID)
    provider = OidcProvider(settings, idp.fetch_json, idp.post_form)
    now = int(time.time())
    good = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 300, "nonce": "n1"}
    assert (await provider.verify_id_token(idp.sign(good), "n1"))["sub"] == "u"

    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forgeries = {
        "nonce": (idp.sign(good), "other-nonce"),
        "audience": (idp.sign({**good, "aud": "someone-else"}), "n1"),
        "issuer": (idp.sign({**good, "iss": "https://evil.example"}), "n1"),
        "expired": (idp.sign({**good, "exp": now - 3600, "iat": now - 7200}), "n1"),
        "signature": (jwt.encode(good, attacker, algorithm="RS256", headers={"kid": "key-1"}), "n1"),
        "alg none": (jwt.encode(good, None, algorithm="none"), "n1"),
        "hmac": (
            jwt.encode(good, "a-shared-secret-of-at-least-32-bytes!", algorithm="HS256", headers={"kid": "key-1"}),
            "n1",
        ),
        "azp": (idp.sign({**good, "aud": [CLIENT_ID, "other"], "azp": "other"}), "n1"),
        "missing sub": (idp.sign({k: v for k, v in good.items() if k != "sub"}), "n1"),
    }
    for name, (token, nonce) in forgeries.items():
        with pytest.raises(OidcError) as exc:
            await provider.verify_id_token(token, nonce)
        assert exc.value.code == "invalid_token", name


async def test_key_rotation_refreshes_jwks_but_not_on_every_request():
    idp = FakeIdP()
    provider = OidcProvider(Settings(oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID), idp.fetch_json, idp.post_form)
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 300, "nonce": "n"}
    await provider.verify_id_token(idp.sign(claims), "n")
    idp.key, idp.kid = rsa.generate_private_key(public_exponent=65537, key_size=2048), "key-2"  # provider rotates
    provider._keys_at = 0  # pretend the minimum refresh interval has passed
    assert (await provider.verify_id_token(idp.sign(claims), "n"))["sub"] == "u"
    with pytest.raises(OidcError):  # unknown kid again right away: no refetch storm
        await provider.verify_id_token(idp.sign(claims, kid="key-3"), "n")
    assert idp.jwks_fetches == 2


async def test_pkce_binds_the_code_to_its_login():
    idp = FakeIdP()
    provider = OidcProvider(
        Settings(oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret=SECRET), idp.fetch_json, idp.post_form
    )
    url = await provider.authorization_url("state", "nonce", "the-real-verifier-" + "x" * 40, "http://testserver/cb")
    code, _ = idp.authorize(url)
    with pytest.raises(OidcError):  # a stolen code is useless without the verifier
        await provider.exchange_code(code, "attacker-verifier-" + "y" * 40, "http://testserver/cb")


def test_misconfigured_provider_is_refused():
    async def bad_discovery(url: str) -> dict[str, Any]:
        return {"issuer": "https://other.example", "authorization_endpoint": "https://x", "token_endpoint": "https://x",
                "jwks_uri": "https://x"}  # fmt: skip

    import asyncio

    provider = OidcProvider(Settings(oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID), bad_discovery)
    with pytest.raises(OidcError) as exc:
        asyncio.run(provider.metadata())
    assert exc.value.code == "provider_misconfigured"


# ---------------------------------------------------------------------------- identity policy
def test_identity_policy():
    s = Settings(oidc_allowed_domains=["acme.example"])
    assert check_identity({"email": "Dana@Acme.example", "email_verified": True}, s) == "dana@acme.example"
    for claims, code in (
        ({"email": "dana@acme.example", "email_verified": False}, "unverified_email"),
        ({"email": "eve@evil.example", "email_verified": True}, "domain_not_allowed"),
        ({}, "domain_not_allowed"),
    ):
        with pytest.raises(OidcError) as exc:
            check_identity(claims, s)
        assert exc.value.code == code
    google = {"email": "dana@gmail.com", "email_verified": True, "hd": "acme.example"}  # Workspace-hosted domain
    assert check_identity(google, s) == "dana@gmail.com"
    relaxed = Settings(oidc_require_verified_email=False)  # e.g. Microsoft Entra omits email_verified
    assert check_identity({"email": "x@y.example"}, relaxed) == "x@y.example"


def test_role_mapping():
    s = Settings(
        oidc_admin_groups=["argus-admins"], oidc_analyst_groups=["secops"], oidc_admin_emails=["boss@a.example"]
    )
    assert resolve_role({"groups": ["secops", "argus-admins"]}, None, s) == "admin"  # highest wins
    assert resolve_role({"groups": "secops"}, None, s) == "analyst"
    assert resolve_role({"groups": []}, None, s) == "viewer"  # default role
    assert resolve_role({}, "boss@a.example", s) == "admin"
    assert resolve_role({}, None, Settings(oidc_default_role="none")) is None


def test_login_refusals_are_explained_and_audited(sso):
    make, _, login = sso
    client = make(oidc_allowed_domains='["corp.example"]')
    assert login(client).headers["location"] == "/?sso_error=domain_not_allowed"
    client = make(oidc_allowed_domains="[]", oidc_default_role="none")
    assert login(client).headers["location"] == "/?sso_error=no_role"
    reasons = [e["details"]["reason"] for e in client.get("/api/audit", params={"action": "auth.sso_failed"}).json()]
    assert {"domain_not_allowed", "no_role"} <= set(reasons)


def test_roles_follow_the_provider_when_groups_are_mapped(sso):
    make, _, login = sso
    client = make(oidc_admin_groups='["argus-admins"]', oidc_analyst_groups='["secops"]')
    login(client, groups=["secops"])
    users = client.get("/api/users").json()
    assert [u["role"] for u in users] == ["analyst"]
    login(client, groups=["argus-admins"])  # promoted in the provider -> promoted here at next sign-in
    assert [u["role"] for u in client.get("/api/users").json()] == ["admin"]


# ---------------------------------------------------------------------------- administration
def test_disabling_a_user_ends_their_sessions_and_blocks_sign_in(sso):
    make, _, login = sso
    client = make()
    login(client)
    user_id = client.get("/api/users").json()[0]["id"]  # admin API key still attached
    assert client.patch(f"/api/users/{user_id}", json={"disabled": True}).json()["disabled"] is True
    probe = client.get("/api/me", headers={"Authorization": ""})  # only the session cookie
    assert probe.status_code == 401
    assert login(client).headers["location"] == "/?sso_error=disabled"
    assert client.get("/api/audit", params={"action": "user.update"}).json()[0]["details"] == {"disabled": True}


def test_admins_cannot_lock_themselves_out(sso):
    make, _, login = sso
    client = make(oidc_admin_emails='["dana@acme.example"]')
    login(client)
    me = browser(client).get("/api/me").json()
    user_id = me["key_id"].removeprefix("user:")
    origin = {"Origin": "http://testserver"}
    assert client.patch(f"/api/users/{user_id}", json={"disabled": True}, headers=origin).status_code == 409
    assert client.patch(f"/api/users/{user_id}", json={"role": "viewer"}, headers=origin).status_code == 409


def test_sso_endpoints_404_when_not_configured(client):
    assert client.get("/api/auth/config").json()["sso"]["enabled"] is False
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 404


ADMIN = "argus_test-admin-key-0123456789abcdefghijklmnopqrstu"


def test_identity_provider_groups_map_to_workspaces(sso):
    make, _, login = sso
    client = make(oidc_workspace_groups='{"red-team": "red-team"}', oidc_analyst_groups='["red-team"]')
    client.post("/api/workspaces", json={"name": "Red Team"})
    login(client, groups=["red-team"])
    user = client.get("/api/users").json()[0]
    members = client.get("/api/workspaces/red-team/members").json()
    assert [(m["user_id"], m["role"]) for m in members] == [(user["id"], "analyst")]
    login(client, groups=[])  # left the team in the identity provider
    assert client.get("/api/workspaces/red-team/members").json() == []
