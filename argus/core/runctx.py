"""Per-module-run error reporting.

Modules intentionally catch errors from individual data sources so that one
broken source (say crt.sh) doesn't throw away results from another
(HackerTarget). The downside is that failures become invisible: a module that
found nothing because every source was down looked identical to one that
found nothing because there was nothing to find.

This module fixes that with a :class:`contextvars.ContextVar`. The engine
opens a :class:`ModuleRunReport` for every module run; anything executing
inside that run - the module itself, the shared ``HttpClient``, or helper
tasks the module spawns - can record source successes and failures without
the report being passed around explicitly. ``asyncio`` copies context into
child tasks, so concurrent runs never see each other's reports.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field

from argus.security.secrets import redact

MAX_RECORDED_ERRORS = 10


@dataclass
class ModuleRunReport:
    """Outcome bookkeeping for one module run against one entity."""

    module: str
    entity: str
    source_ok: int = 0
    source_errors: int = 0
    items: int = 0
    errors: list[str] = field(default_factory=list)

    def record_error(self, source: str, error: object) -> None:
        self.source_errors += 1
        if len(self.errors) < MAX_RECORDED_ERRORS:
            text = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
            self.errors.append(redact(f"{source}: {text}".strip()))

    def record_ok(self) -> None:
        self.source_ok += 1

    @property
    def outcome(self) -> str:
        """``success`` | ``degraded`` (partial source failure) | ``failed`` (nothing worked)."""
        if self.source_errors == 0:
            return "success"
        if self.source_ok > 0 or self.items > 0:
            return "degraded"
        return "failed"


current_run: ContextVar[ModuleRunReport | None] = ContextVar("argus_module_run", default=None)


def report_error(source: str, error: object) -> None:
    """Record a failed data source for the module run in progress (no-op outside a run)."""
    run = current_run.get()
    if run is not None:
        run.record_error(source, error)


def report_ok() -> None:
    """Record a data source that answered successfully."""
    run = current_run.get()
    if run is not None:
        run.record_ok()
