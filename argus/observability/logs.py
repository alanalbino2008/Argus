"""Structured logging with request and investigation correlation.

``ARGUS_LOG_FORMAT=json`` emits one JSON object per line - what log platforms
(Loki, Elasticsearch, CloudWatch, Datadog) ingest natively. Every line carries:

* ``request_id`` - from the ``X-Request-ID`` header (or generated), echoed in the
  response, so a user's error report leads straight to the server's log lines;
* ``investigation_id`` - set for everything a scan does, including its modules;
* ``instance`` - which replica wrote it.

Secrets are redacted by the engine before they reach a log line; this module also
never logs query strings (they can carry single-use WebSocket tickets).
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

request_id: ContextVar[str | None] = ContextVar("argus_request_id", default=None)
investigation_id: ContextVar[str | None] = ContextVar("argus_investigation_id", default=None)

_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_STANDARD = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


def new_request_id(incoming: str | None) -> str:
    """Trust a caller's (or load balancer's) id only if it is short and harmless."""
    return incoming if incoming and _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex


class ContextFilter(logging.Filter):
    def __init__(self, instance: str):
        super().__init__()
        self.instance = instance

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get()
        record.investigation_id = investigation_id.get()
        record.instance = self.instance
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        entry.update(  # request_id, instance and any `extra=` fields
            {k: v for k, v in record.__dict__.items() if k not in _STANDARD and v is not None and not k.startswith("_")}
        )
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        tags = [f"{k}={getattr(record, k)}" for k in ("request_id", "investigation_id") if getattr(record, k, None)]
        return f"{line} [{' '.join(tags)}]" if tags else line


def configure(fmt: str = "text", level: str = "INFO", instance: str = "") -> None:
    """Install one handler on the ``argus`` logger tree (idempotent; leaves uvicorn's own loggers alone)."""
    root = logging.getLogger("argus")
    for handler in list(root.handlers):
        if getattr(handler, "_argus", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler._argus = True  # type: ignore[attr-defined]
    handler.addFilter(ContextFilter(instance))
    handler.setFormatter(
        JsonFormatter() if fmt == "json" else TextFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level.upper())
    root.propagate = False
