# syntax=docker/dockerfile:1
# Multi-stage build: the runtime image contains only an installed wheel in a virtualenv -
# no source tree, tests, git history or build tools.

# ---------------------------------------------------------------------------- build stage
FROM python:3.15-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY pyproject.toml README.md ./
COPY argus ./argus
RUN pip install build && python -m build --wheel --outdir /dist . \
    && pip install /dist/*.whl

# -------------------------------------------------------------------------- runtime stage
FROM python:3.15-slim

ARG VERSION=dev
LABEL org.opencontainers.image.title="Argus OSINT" \
      org.opencontainers.image.description="Autonomous OSINT reconnaissance and graph link analysis platform" \
      org.opencontainers.image.source="https://github.com/alanalbino2008/Argus" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# Non-root user; the only writable location is the data volume.
RUN groupadd --system argus && useradd --system --gid argus --home-dir /app argus \
    && mkdir -p /app/data && chown argus:argus /app/data

COPY --from=builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARGUS_DATABASE_URL=sqlite+aiosqlite:////app/data/argus.db

WORKDIR /app
USER argus
VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://localhost:8000/api/health').status != 200)"

# 0.0.0.0 inside the container is required for port publishing; access is still API-key protected.
CMD ["argus", "--serve", "--host", "0.0.0.0", "--port", "8000"]
