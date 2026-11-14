# 13 — Single Sign-On (Plain-English Guide)

> Purpose: explain how people sign in to Argus with their company account, and why each security
> step exists — useful for "explain OAuth/OIDC" and "how do you secure a login flow?" questions.

## 1. What single sign-on gives an organisation

Instead of handing out API keys, Argus trusts the company's **identity provider** (Google Workspace,
Microsoft Entra ID, Okta, Keycloak…): people sign in with the account they already have, with the
company's MFA and password policies, and when someone leaves, disabling their company account
removes their access to Argus too. Roles come from the groups the company already manages.

## 2. The flow (OpenID Connect, authorization code + PKCE)

1. The user clicks **Continue with Microsoft**. Argus generates three random secrets — **state**,
   **nonce** and a **PKCE verifier** — stores them (hashed) for 10 minutes, and redirects the browser
   to the provider with the state, nonce and a *hash* of the verifier.
2. The user signs in **at the provider** (Argus never sees their password) and is sent back with a
   one-time **code** and the state.
3. Argus checks the state is one it issued and **deletes it** (it can never be used twice), then
   exchanges the code for tokens **server-to-server**, proving itself with its client secret *and*
   the PKCE verifier. A code stolen from a URL is useless without the verifier.
4. Argus **verifies the ID token**: signature against the provider's published keys, issuer,
   audience (it was issued *for Argus*), expiry, and the nonce (it was issued *for this login*).
5. Policy checks: verified email, allowed email domain, a role from the user's groups.
6. Argus creates a **session** and sends the browser home.

## 3. Why each defence exists

| Defence | Stops |
|---|---|
| `state`, single-use | Login CSRF (an attacker logging you into *their* account) and replayed callbacks |
| `nonce` | Replaying an ID token obtained elsewhere |
| PKCE (S256) | Authorization-code interception |
| Signature + issuer + audience checks | Forged tokens, tokens from another provider, tokens meant for another app |
| Only asymmetric algorithms | The classic `alg: none` and RS→HS key-confusion attacks |
| HTTPS-only provider endpoints | Tampering with discovery or keys in transit |
| Return-path allow-list | Open redirects (`?return_to=https://evil.example`) |

## 4. Sessions

The session id is a 256-bit random value in a cookie that is **HttpOnly** (JavaScript — and therefore
an XSS bug — cannot read it), **SameSite=Lax** and **Secure** over HTTPS. The server stores only its
SHA-256 hash, so a database leak does not leak sessions. Because cookies are sent automatically,
every *write* made with a cookie must come from Argus's own pages (`Origin` check) — the standard
CSRF defence. Sessions live in the database, so any replica can serve any user, and disabling a user
signs them out **everywhere at once**.

## 5. Tested two ways

* **Automatically**: a fake provider with a real RSA key signs real tokens; tests prove the login
  works and that forged signatures, wrong audiences or issuers, expired tokens, `alg: none`, HMAC
  confusion, nonce replays, reused state, stolen codes without the PKCE verifier, open redirects and
  cross-site writes are all refused — on SQLite and PostgreSQL, including logins that start on one
  replica and finish on another.
* **For real**: against **Keycloak** in a browser — an admin (from the `argus-admins` group), a viewer
  (no group) and an outsider (refused by the domain allow-list), sign-out via the provider's single
  logout, and a check that the session cookie is invisible to JavaScript. That live test also caught
  the OAuth code appearing in the web server's own access log; query strings are now stripped from it.
