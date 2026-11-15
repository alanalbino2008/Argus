"""Supplier (third-party) risk: policy, risk matrix and register import.

A supplier's **risk** combines how exposed it looks from outside (its security rating) with how
much harm a compromise of it would do to *you* (its criticality and the data it handles).
A D-rated catering firm and a D-rated payroll provider are not the same problem.

* **Tiers** set the minimum acceptable grade and how often the supplier is re-assessed:

  | Tier | Minimum grade | Re-assessed |
  |---|---|---|
  | critical | B | weekly |
  | high | C | every 2 weeks |
  | medium | D | monthly |
  | low | none | quarterly |

* **Impact** = tier (1-4) + data handled (personal +1, sensitive or special-category +2), max 5.
* **Likelihood** = from the grade (A 1 … F 5).
* **Risk** = likelihood * impact, read on a 5-by-5 matrix: 1-4 low, 5-9 medium, 10-14 high, 15+
  critical, the convention of ISO 27005-style risk registers.

Supplier assessments are **always passive**: a supplier is a third party that has not agreed
to be tested, so Argus only consults public sources about it (the same outside-in approach as
commercial rating services) and never contacts its systems.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

TIERS: dict[str, dict[str, Any]] = {
    "critical": {"min_grade": "B", "interval_hours": 24 * 7, "impact": 4},
    "high": {"min_grade": "C", "interval_hours": 24 * 14, "impact": 3},
    "medium": {"min_grade": "D", "interval_hours": 24 * 30, "impact": 2},
    "low": {"min_grade": None, "interval_hours": 24 * 90, "impact": 1},
}
DATA_ACCESS = {"none": 0, "internal": 0, "personal": 1, "sensitive": 2}
GRADE_LIKELIHOOD = {"A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
GRADE_ORDER = "ABCDF"
MAX_IMPORT_ROWS = 500

HEADER_ALIASES = {
    "name": ("name", "supplier", "vendor", "company", "supplier name", "vendor name", "organisation", "organization"),
    "domain": ("domain", "website", "url", "web", "site", "domain name"),
    "tier": ("tier", "criticality", "critical", "importance", "risk tier"),
    "data_access": ("data", "data access", "data_access", "data handled", "data classification"),
    "owner": ("owner", "contact", "relationship owner", "business owner"),
    "notes": ("notes", "comment", "comments", "description", "service"),
}
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise_domain(value: str) -> str | None:
    """'https://www.Acme.com/about' -> 'acme.com'; None if it is not a domain."""
    text = value.strip().lower()
    if not text:
        return None
    host = urlsplit(text if "://" in text else f"//{text}").hostname or ""
    host = host.removeprefix("www.").rstrip(".")
    return host if _DOMAIN.match(host) else None


def min_grade(tier: str, override: str | None = None) -> str | None:
    return override or TIERS[tier]["min_grade"]


def worse(grade: str, than: str) -> bool:
    return GRADE_ORDER.index(grade) > GRADE_ORDER.index(than)


def impact(tier: str, data_access: str) -> int:
    return min(5, TIERS[tier]["impact"] + DATA_ACCESS.get(data_access, 0))


def risk(tier: str, data_access: str, grade: str | None) -> dict[str, Any]:
    if grade is None:
        return {"likelihood": None, "impact": impact(tier, data_access), "score": None, "level": "unknown"}
    likelihood, imp = GRADE_LIKELIHOOD[grade], impact(tier, data_access)
    score = likelihood * imp
    level = "critical" if score >= 15 else "high" if score >= 10 else "medium" if score >= 5 else "low"
    return {"likelihood": likelihood, "impact": imp, "score": score, "level": level}


def status(tier: str, grade: str | None, override: str | None = None) -> str:
    if grade is None:
        return "not_assessed"
    floor = min_grade(tier, override)
    return "below_minimum" if floor and worse(grade, floor) else "within_tolerance"


@dataclass
class ImportResult:
    rows: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


def parse_register(text: str) -> ImportResult:
    """A supplier register exported from a spreadsheet (CSV), with forgiving column names."""
    result = ImportResult()
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        result.errors.append({"line": 1, "error": "The file is empty"})
        return result
    columns = {
        key: next((i for i, h in enumerate(header) if h in aliases), None) for key, aliases in HEADER_ALIASES.items()
    }
    if columns["domain"] is None:
        result.errors.append({"line": 1, "error": "No domain/website column found"})
        return result
    seen: set[str] = set()
    for line, row in enumerate(reader, start=2):
        if not any(cell.strip() for cell in row):
            continue
        if len(result.rows) >= MAX_IMPORT_ROWS:
            result.errors.append({"line": line, "error": f"Only the first {MAX_IMPORT_ROWS} suppliers are imported"})
            break

        def cell(key: str, row: list[str] = row) -> str:
            index = columns[key]
            return row[index].strip() if index is not None and index < len(row) else ""

        domain = normalise_domain(cell("domain"))
        if not domain:
            result.errors.append({"line": line, "error": f"Not a domain: {cell('domain')!r}"})
            continue
        if domain in seen:
            result.errors.append({"line": line, "error": f"Duplicate supplier domain {domain}"})
            continue
        tier = cell("tier").lower() or "medium"
        if tier not in TIERS:
            result.errors.append({"line": line, "error": f"Unknown tier {tier!r} (use critical, high, medium or low)"})
            continue
        access = cell("data_access").lower() or "none"
        access = {"special category": "sensitive", "special-category": "sensitive", "confidential": "sensitive",
                  "pii": "personal", "personal data": "personal"}.get(access, access)  # fmt: skip
        if access not in DATA_ACCESS:
            result.errors.append({"line": line, "error": f"Unknown data access {access!r}"})
            continue
        seen.add(domain)
        result.rows.append({"name": (cell("name") or domain)[:200], "domain": domain, "tier": tier,
                            "data_access": access, "owner": cell("owner")[:200], "notes": cell("notes")[:500]})  # fmt: skip
    return result
