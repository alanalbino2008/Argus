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
RUN groupadd -r argus && useradd -r -g argus argus

COPY --from=builder /root/.local /home/argus/.local
COPY --chown=argus:argus . .

ENV PATH=/home/argus/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

USER argus

EXPOSE 8000

# Default to launching the Argus web dashboard
ENTRYPOINT ["python", "-m", "argus.cli.console"]
CMD ["--serve", "--host", "0.0.0.0", "--port", "8000"]
