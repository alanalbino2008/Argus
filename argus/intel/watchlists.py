"""Sanctions lists by name: the United States, the United Kingdom and the United Nations.

| List | Publisher | File |
|---|---|---|
| SDN | US Treasury (OFAC) | ``sdn.csv`` and ``alt.csv`` (aliases) |
| UK Sanctions List | UK government (FCDO / OFSI) | CSV, current and previous layouts both read |
| Consolidated List | UN Security Council | XML |

All three are official, free and public. Argus downloads them when first needed, caches them for
a day, and can read saved copies instead (``ARGUS_SANCTIONS_FILE``, a folder holding ``sdn.csv``,
``alt.csv``, ``UK-Sanctions-List.csv`` and ``consolidated.xml``).

Screening compares a name with every listed name and alias (see ``names.py``) and returns the
closest, with a score and the details that let a person rule a match in or out (date of birth,
nationality, programme). A similar name is not the same person.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
import weakref
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeXML

from argus.core.settings import get_settings
from argus.intel.names import blocking_keys, similarity

logger = logging.getLogger("argus.watchlists")
MAX_FILE = 60 * 1024 * 1024
TTL = 24 * 3600
THRESHOLD = 0.88


@dataclass
class Listing:
    source: str  # "US OFAC SDN" | "UK Sanctions List" | "UN Consolidated List"
    ref: str
    name: str
    kind: str  # "person" | "company" | "other"
    programs: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"list": self.source, "ref": self.ref, "name": self.name, "kind": self.kind,
                "programs": self.programs, "aliases": self.aliases[:10], "details": self.details}  # fmt: skip


@dataclass
class _State:
    listings: list[Listing] = field(default_factory=list)
    index: dict[tuple[str, str], set[int]] = field(default_factory=dict)
    loaded_at: float = 0.0
    sources: dict[str, Any] = field(default_factory=dict)


_state = _State()
_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _locks:
        _locks[loop] = asyncio.Lock()
    return _locks[loop]


# ---------------------------------------------------------------------------- parsers
def parse_ofac(sdn_csv: str, alt_csv: str = "") -> list[Listing]:
    found: dict[str, Listing] = {}
    for row in csv.reader(io.StringIO(sdn_csv)):
        if len(row) < 12 or not row[0].strip().isdigit():
            continue
        kind = {"individual": "person", "-0-": "company"}.get(row[2].strip().lower(), "other")
        programs = [p.strip() for p in row[3].replace("]", "").split("[") if p.strip() and p.strip() != "-0-"]
        found[row[0].strip()] = Listing("US OFAC SDN", row[0].strip(), row[1].strip(), kind, programs,
                                        details=_ofac_details(row[11]))  # fmt: skip
    for row in csv.reader(io.StringIO(alt_csv)):
        if len(row) >= 4 and row[0].strip() in found and row[3].strip() not in ("", "-0-"):
            found[row[0].strip()].aliases.append(row[3].strip())
    return list(found.values())


def _ofac_details(remarks: str) -> dict[str, str]:
    details = {}
    for part in remarks.split(";"):
        part = part.strip()
        for key, label in (("DOB ", "Date of birth"), ("POB ", "Place of birth"), ("nationality ", "Nationality"),
                           ("Nationality ", "Nationality")):  # fmt: skip
            if part.startswith(key) and label not in details:
                details[label] = part[len(key) :].strip(" .")[:80]
    return details


def parse_uk(text: str) -> list[Listing]:
    """The UK list, in the FCDO layout ("Unique ID", "Designation Type") or the OFSI one ("Group ID")."""
    rows = list(csv.reader(io.StringIO(text)))
    header_at = next((i for i, r in enumerate(rows[:5]) if "Name 6" in r), None)
    if header_at is None:
        raise ValueError("the UK sanctions file has no recognisable header")
    header = rows[header_at]

    def col(*names: str) -> int | None:
        return next((header.index(n) for n in names if n in header), None)

    c_id = col("Unique ID", "Group ID")
    c_type = col("Designation Type", "Group Type")
    c_regime = col("Regime Name", "Regime")
    c_alias = col("Name type", "Alias Type")
    c_dob = col("D.O.B", "DOB")
    c_nat = col("Nationality(/ies)", "Nationality")
    name_cols = [col(f"Name {i}") for i in (1, 2, 3, 4, 5, 6)]
    groups: dict[str, Listing] = {}
    for row in rows[header_at + 1 :]:
        if c_id is None or len(row) <= c_id or not row[c_id].strip():
            continue

        def get(i: int | None, current: list[str] = row) -> str:
            return current[i].strip() if i is not None and i < len(current) else ""

        given = " ".join(get(i) for i in name_cols[:5] if get(i))
        surname = get(name_cols[5])
        kind_text = get(c_type).lower()
        kind = "person" if "individual" in kind_text else "company" if "entity" in kind_text else "other"
        name = f"{surname}, {given}" if kind == "person" and given and surname else (surname or given)
        if not name:
            continue
        ref = get(c_id)
        primary = get(c_alias).lower() in ("primary name", "") or "primary" in get(c_alias).lower()
        listing = groups.get(ref)
        if listing is None:
            listing = groups[ref] = Listing("UK Sanctions List", ref, name, kind, [p for p in [get(c_regime)] if p])
        elif primary and listing.name != name:
            listing.aliases.append(listing.name)
            listing.name = name
        elif name != listing.name and name not in listing.aliases:
            listing.aliases.append(name)
        for label, idx in (("Date of birth", c_dob), ("Nationality", c_nat)):
            if get(idx) and label not in listing.details:
                listing.details[label] = get(idx)[:80]
    return list(groups.values())


def parse_un(xml: bytes) -> list[Listing]:
    root = SafeXML.fromstring(xml)
    found: list[Listing] = []
    for tag, kind in (("INDIVIDUAL", "person"), ("ENTITY", "company")):
        for node in root.iter(tag):
            parts = [
                (node.findtext(t) or "").strip() for t in ("FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME")
            ]
            name = " ".join(p for p in parts if p)
            if not name:
                continue
            aliases = [(a.findtext("ALIAS_NAME") or "").strip() for a in node.iter(f"{tag}_ALIAS")]
            details = {}
            dob = node.find(f"{tag}_DATE_OF_BIRTH")
            if dob is not None:
                details["Date of birth"] = (dob.findtext("DATE") or dob.findtext("YEAR") or "").strip()[:20]
            nationality = node.find("NATIONALITY")
            if nationality is not None and nationality.findtext("VALUE"):
                details["Nationality"] = (nationality.findtext("VALUE") or "").strip()[:80]
            found.append(Listing("UN Consolidated List", (node.findtext("REFERENCE_NUMBER") or node.findtext("DATAID") or "").strip(),
                                 name, kind, [p for p in [(node.findtext("UN_LIST_TYPE") or "").strip()] if p],
                                 [a for a in aliases if a], {k: v for k, v in details.items() if v}))  # fmt: skip
    return found


# ---------------------------------------------------------------------------- loading
def _install(listings: list[Listing]) -> None:
    index: dict[tuple[str, str], set[int]] = defaultdict(set)
    for i, listing in enumerate(listings):
        kind = "person" if listing.kind == "person" else "company"
        for name in [listing.name, *listing.aliases]:
            for key in blocking_keys(name, kind=kind):
                index[(kind, key)].add(i)
    _state.listings, _state.index = listings, dict(index)


async def load(http: Any) -> None:
    """Load every configured list (each on its own: one failing never stops the others). Never raises."""
    settings = get_settings()
    async with _lock():
        if _state.loaded_at and time.monotonic() - _state.loaded_at < TTL:
            return
        folder = Path(settings.sanctions_file) if settings.sanctions_file else None
        jobs = {
            "US OFAC SDN": (settings.sanctions_sdn_url, ("sdn.csv", "alt.csv")),
            "UK Sanctions List": (settings.uk_sanctions_url, ("UK-Sanctions-List.csv",)),
            "UN Consolidated List": (settings.un_sanctions_url, ("consolidated.xml",)),
        }
        listings: list[Listing] = []
        status: dict[str, Any] = {}
        for source, (url, files) in jobs.items():
            if not url and not folder:
                status[source] = {"status": "off"}
                continue
            try:
                raw = await _read(http, folder, files, url, settings.sanctions_alt_url)
                parsed = await asyncio.to_thread(_parse, source, raw)
                listings += parsed
                status[source] = {"status": "ok", "listings": len(parsed)}
            except Exception as exc:  # noqa: BLE001 - reported per list; screening continues with the others
                status[source] = {"status": "unavailable", "error": f"{type(exc).__name__}: {str(exc)[:120]}"}
                logger.warning("Sanctions list %s unavailable: %s", source, status[source]["error"])
        _install(listings)
        _state.sources = status
        failed = any(s["status"] == "unavailable" for s in status.values())
        _state.loaded_at = time.monotonic() - (TTL - 900 if failed else 0)  # retry a failed list sooner


def _parse(source: str, raw: list[bytes]) -> list[Listing]:
    if source == "US OFAC SDN":
        return parse_ofac(raw[0].decode("latin-1"), raw[1].decode("latin-1") if len(raw) > 1 else "")
    if source == "UK Sanctions List":
        return parse_uk(raw[0].decode("utf-8-sig", errors="replace"))
    return parse_un(raw[0])


async def _read(http: Any, folder: Path | None, files: tuple[str, ...], url: str, alt_url: str) -> list[bytes]:
    if folder is not None:
        out = []
        for name in files:
            path = folder / name
            if path.exists():
                out.append(await asyncio.to_thread(path.read_bytes))
            elif name == files[0]:
                raise FileNotFoundError(str(path))
        return out
    out = [await _download(http, url)]
    if files[0] == "sdn.csv" and alt_url:
        out.append(await _download(http, alt_url))
    return out


async def _download(http: Any, url: str) -> bytes:
    async with http.get(url, headers={"Accept": "*/*"}) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        body = await resp.content.read(MAX_FILE + 1)
    if len(body) > MAX_FILE:
        raise ValueError("the file is too large")
    return bytes(body)


# ---------------------------------------------------------------------------- screening
def screen(name: str, *, kind: str, threshold: float = THRESHOLD, limit: int = 5) -> list[dict[str, Any]]:
    """Listed people (or companies) whose name or an alias resembles ``name``, best first."""
    key_kind = "person" if kind == "person" else "company"
    candidates: set[int] = set()
    for key in blocking_keys(name, kind=key_kind):
        candidates |= _state.index.get((key_kind, key), set())
    results = []
    for i in candidates:
        listing = _state.listings[i]
        if (listing.kind == "person") != (key_kind == "person"):
            continue
        best_name, best = listing.name, 0.0
        for candidate in [listing.name, *listing.aliases]:
            score = similarity(name, candidate, kind=key_kind)
            if score > best:
                best_name, best = candidate, score
        if best >= threshold:
            results.append({**listing.public(), "matched_name": best_name, "score": best})
    results.sort(key=lambda r: -r["score"])
    return results[:limit]


def status() -> dict[str, Any]:
    return {"listings": len(_state.listings), "sources": dict(_state.sources)}


def reset() -> None:
    global _state
    _state = _State()
