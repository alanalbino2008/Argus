# syntax=docker/dockerfile:1
# Multi-stage build: the runtime image contains only an installed wheel in a virtualenv -
# no source tree, tests, git history or build tools. Includes the PostgreSQL driver, so the
# same image runs single-node (SQLite) or clustered (PostgreSQL, Kubernetes).

# ---------------------------------------------------------------------------- build stage
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY pyproject.toml README.md ./
COPY argus ./argus
RUN pip install build && python -m build --wheel --outdir /dist . \
    && pip install "$(ls /dist/*.whl)[postgres]"

# -------------------------------------------------------------------------- runtime stage
FROM python:3.12-slim

ARG VERSION=dev
LABEL org.opencontainers.image.title="Argus OSINT" \
      org.opencontainers.image.description="Autonomous OSINT reconnaissance and graph link analysis platform" \
      org.opencontainers.image.source="https://github.com/alanalbino2008/Argus" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.version="${VERSION}"

# Fixed numeric UID/GID so Kubernetes can enforce runAsNonRoot (it cannot verify user *names*).
RUN groupadd --system --gid 10001 argus \
    && useradd --system --uid 10001 --gid argus --home-dir /app argus \
    && mkdir -p /app/data && chown argus:argus /app/data

COPY --from=builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARGUS_DATABASE_URL=sqlite+aiosqlite:////app/data/argus.db

WORKDIR /app
USER 10001:10001
VOLUME ["/app/data"]
EXPOSE 8000

# Health check bypasses HTTP(S)_PROXY: on corporate networks a proxy must never see localhost.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request as u,sys; sys.exit(u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:8000/api/health').status != 200)"

# 0.0.0.0 inside the container is required for port publishing; access is still API-key protected.
# --proxy-headers: trust X-Forwarded-* from the ingress so audit logs record real client IPs.
# --no-access-log: Argus writes its own access log (route templates, request ids, no query strings).
CMD ["uvicorn", "argus.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--timeout-graceful-shutdown", "20", "--no-access-log"]
