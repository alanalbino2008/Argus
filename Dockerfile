# syntax=docker/dockerfile:1
# Multi-stage build: the runtime image contains only an installed wheel in a virtualenv -
# no source tree, tests, git history or build tools. Includes the PostgreSQL driver, so the
# same image runs single-node (SQLite) or clustered (PostgreSQL, Kubernetes).

# ---------------------------------------------------------------------------- build stage
# The base image is pinned by digest (Dependabot proposes updates), so a rebuild is the same image.
FROM python:3.12-slim@sha256:5b5fe805d367f8f5a359ded6ab2652b7f9a206453ee6ee789c0045ba6ec15016 AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src

# Dependencies: exactly the versions in requirements.lock, each checked against its SHA-256 hash, so
# a compromised or re-published package on PyPI cannot slip into the image.
COPY requirements.lock ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock

COPY pyproject.toml README.md ./
COPY argus ./argus
# Argus itself: built with a throw-away build tool outside the runtime virtualenv, installed without
# dependencies (they are all in place). Then pip is removed: the running image cannot install anything.
RUN pip install build && python -m build --wheel --outdir /dist . \
    && /opt/venv/bin/pip install --no-deps /dist/*.whl \
    && /opt/venv/bin/pip check \
    && /opt/venv/bin/pip uninstall -y pip

# -------------------------------------------------------------------------- runtime stage
FROM python:3.12-slim@sha256:5b5fe805d367f8f5a359ded6ab2652b7f9a206453ee6ee789c0045ba6ec15016

ARG VERSION=dev
LABEL org.opencontainers.image.title="Argus OSINT" \
      org.opencontainers.image.description="Autonomous OSINT reconnaissance and graph link analysis platform" \
      org.opencontainers.image.source="https://github.com/alanalbino2008/Argus" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.version="${VERSION}"

# DejaVu fonts: PDF reports render names in any script (the PDF base fonts only cover Latin-1).
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip   # the base image's own installer: nothing to install at run time

# Fixed numeric UID/GID so Kubernetes can enforce runAsNonRoot (it cannot verify user *names*).
RUN groupadd --system --gid 10001 argus \
    && useradd --system --uid 10001 --gid argus --home-dir /app argus \
    && mkdir -p /app/data && chown argus:argus /app/data

COPY --from=builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARGUS_DATABASE_URL=sqlite+aiosqlite:////app/data/argus.db \
    ARGUS_ENCRYPTION_KEY_FILE=/app/data/encryption.key \
    ARGUS_ENVIRONMENT=production \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /app
USER 10001:10001
VOLUME ["/app/data"]
EXPOSE 8000

# Health check bypasses HTTP(S)_PROXY: on corporate networks a proxy must never see localhost.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request as u,sys; sys.exit(u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:8000/api/health').status != 200)"

# 0.0.0.0 inside the container is required for port publishing; access is still API-key protected.
# --proxy-headers: read the real client IP from X-Forwarded-For, but ONLY when the connection comes from a
# trusted proxy (FORWARDED_ALLOW_IPS, read by uvicorn). Trusting every peer ("*") would let anyone forge
# their IP and slip past network allow-lists, per-IP rate limits and sign-in lockouts. Default: loopback
# only. Behind a load balancer, set FORWARDED_ALLOW_IPS to its address or subnet (CIDR), e.g. 10.0.0.0/8.
# --no-server-header: don't advertise the server software and version.
# --no-access-log: Argus writes its own access log (route templates, request ids, no query strings).
CMD ["uvicorn", "argus.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header", "--timeout-graceful-shutdown", "20", "--no-access-log"]
