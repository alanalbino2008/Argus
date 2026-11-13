"""Third-party collector plugins via Python entry points.

A plugin is an installed package that advertises a ``BaseModule`` subclass::

    # the plugin's pyproject.toml
    [project.entry-points."argus.modules"]
    crtsh_plus = "argus_crtsh_plus:CrtShPlusModule"

Security model - a plugin is arbitrary code running with the server's privileges:

* **Off by default.** Nothing loads unless its entry-point name is listed in
  ``ARGUS_PLUGINS`` (e.g. ``ARGUS_PLUGINS='["crtsh_plus"]'``). Installing a
  package is not enough to activate it.
* **Validated.** It must subclass ``BaseModule``, have a unique, well-formed
  name that does not shadow a built-in module, and declare only real ATT&CK
  technique IDs.
* **Isolated failures.** A plugin that fails to import or validate is reported
  (``GET /api/plugins``) instead of preventing Argus from starting.
* **Audited.** Plugins loaded at startup are written to the audit log.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from importlib.metadata import entry_points

from argus.core.settings import get_settings
from argus.intel.attack import TECHNIQUES
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.plugins")

ENTRY_POINT_GROUP = "argus.modules"
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,47}$")


@dataclass
class PluginReport:
    allowed: list[str] = field(default_factory=list)
    loaded: dict[str, str] = field(default_factory=dict)  # module name -> "package:object"
    errors: dict[str, str] = field(default_factory=dict)  # entry point name -> reason
    available: list[str] = field(default_factory=list)  # installed but not allowlisted


def _validate(cls: object, builtin_names: set[str]) -> str | None:
    """Return a reason the class is unacceptable, or None if it is a valid module."""
    if not isinstance(cls, type) or not issubclass(cls, BaseModule) or cls is BaseModule:
        return "entry point is not a BaseModule subclass"
    if not NAME_PATTERN.match(cls.name or ""):
        return f"invalid module name {cls.name!r} (lowercase letters, digits and _ only)"
    if cls.name in builtin_names:
        return f"module name {cls.name!r} would shadow a built-in module"
    if not cls.supported_entity_types:
        return "module declares no supported_entity_types"
    unknown = [t for t in cls.attack_techniques if t not in TECHNIQUES]
    if unknown:
        return f"unknown ATT&CK technique id(s): {unknown}"
    return None


def discover_plugins(builtin_names: set[str]) -> tuple[list[type[BaseModule]], PluginReport]:
    """Load allowlisted plugin modules. Never raises: problems are reported instead."""
    allowed = set(get_settings().plugins)
    report = PluginReport(allowed=sorted(allowed))
    classes: list[type[BaseModule]] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name not in allowed:
            report.available.append(ep.name)
            continue
        try:
            cls = ep.load()
        except Exception as exc:
            report.errors[ep.name] = f"failed to import: {exc!r}"
            logger.error("Plugin %s failed to import: %r", ep.name, exc)
            continue
        problem = _validate(cls, builtin_names | {c.name for c in classes})
        if problem:
            report.errors[ep.name] = problem
            logger.error("Plugin %s rejected: %s", ep.name, problem)
            continue
        cls.origin = f"plugin:{ep.value}"
        classes.append(cls)
        report.loaded[cls.name] = ep.value
        logger.warning("Loaded third-party plugin module %r from %s", cls.name, ep.value)
    for name in sorted(allowed - {ep.name for ep in entry_points(group=ENTRY_POINT_GROUP)}):
        report.errors[name] = "allowlisted but no such plugin is installed"
    return classes, report
