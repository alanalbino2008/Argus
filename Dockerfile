# Multi-stage Docker build for Argus OSINT Platform
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runner stage
FROM python:3.11-slim

WORKDIR /app

# Non-root user for security best practice
RUN groupadd -r argus && useradd -r -g argus argus \
    && mkdir -p /app/data && chown argus:argus /app/data

COPY --from=builder /root/.local /home/argus/.local
COPY --chown=argus:argus . .

ENV PATH=/home/argus/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
# Investigation history lives on the /app/data volume (override for PostgreSQL)
ENV ARGUS_DATABASE_URL=sqlite+aiosqlite:////app/data/argus.db

USER argus

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://localhost:8000/api/health').status != 200)"

# Default to launching the Argus web dashboard
ENTRYPOINT ["python", "-m", "argus.cli.console"]
CMD ["--serve", "--host", "0.0.0.0", "--port", "8000"]
