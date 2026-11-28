# Production readiness

Before the first production deployment, Argus was built, run and loaded the way production runs it.
This release fixes what that turned up.

## A server that refuses to start unsafely

A setting that is harmless on a laptop can be a breach in production. The container image and the Helm
chart now run with `ARGUS_ENVIRONMENT=production`, and in that mode the server checks its configuration
every time it starts. It **will not start** if:

- authentication is off;
- `FORWARDED_ALLOW_IPS` is `*`;
- replicas share no encryption key;
- the public URL is plain HTTP;
- CORS allows `*`.

The pod log names each problem and the fix. Advice (SQLite, text logs, no SMTP, no metrics token) is
logged as a warning and does not stop the start. `argus --preflight` runs the same checks on demand,
and exits with 1 if it finds an error. On a developer machine (the default `development` mode) only
real problems are mentioned, and nothing is refused.

## The same image every time

Before, the image installed whatever versions of its 71 dependencies were newest on the day it was
built. Two builds of the same commit could differ, and a compromised release on PyPI would have gone
straight in. Now:

- **`requirements.lock`** pins every package to an exact version and its SHA-256 hashes. The image
  installs with `--require-hashes`, so a package that does not match is refused.
- The **base image is pinned by digest**. Dependabot proposes updates, including security patches.
- **CI** fails if the lock no longer matches `pyproject.toml`, and audits the locked versions for known
  CVEs.
- **No package installer in the image.** pip is removed, so nothing can be installed into a running
  container.

## A CI check that could never fail

The check "the image contains no secrets, source tree or git history" was written as
`! docker run ... | grep ...`. CI shells run with `pipefail`, so the `docker run` exit code decided
the result, and the step passed whatever the image held. It now captures the listing first and then
tests it. The new checks (no installer, unsafe configuration refused) use the same pattern.

## The drill

| Test | Result |
|---|---|
| Image as production runs it (read-only, no capabilities, no privilege escalation, UID 10001) | Healthy; encryption key created with mode 0600 on the data volume |
| Unsafe configuration | Refused to start (exit 3), naming each fix |
| SIGTERM | Clean shutdown in 0.6 s |
| Two replicas on PostgreSQL 16, 60 s of mixed reads, writes and scans from 40 clients | 10,917 requests, **0 errors**, p95 under 0.41 s (0.9 s to launch a scan), memory flat at ~282 MB per replica |

The [go-live checklist](../PRODUCTION.md) lists what to set up around Argus: database, TLS, secrets,
SSO, monitoring and the drills to run before launch.
