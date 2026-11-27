"""Breach intelligence: where a person's identifiers appear in data breaches, and whether the same
password was reused across them — without Argus ever storing a plaintext password.

An email, username or phone number that turns up in a breach is strong, lawful evidence for an
investigator: it shows exposure, and it can tie two accounts together. The single most useful signal
is **password reuse**: if the same (unusual) password sits behind ``jane@gmail.com`` in one breach and
``jdoe@yahoo.com`` in another, they are very likely the same person. That link is proved from a one-way
hash of the password; the password itself is never needed for it.

So Argus keeps, for each exposure, only:

* the **breach** it came from (name, date, the kinds of data it leaked);
* the identifier it concerns (email, username, phone);
* a **masked** password (``s•••••3`` — first and last character and the length) for eyeballing a match;
* a **SHA-256** of the password, for the reuse correlation.

The plaintext is dropped the moment a record is read from the provider: it is never written to the
database, the dossier or a report. A plaintext password is a working credential, and showing it is how
account takeover happens, so it is available only through a separate, approval-gated reveal that
re-fetches it live, records why, and is audited (see the API). Breach *metadata* works with a Have I
Been Pwned key; the masked password, hash and reveal need a credential provider (your own key).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

IDENT_KINDS = ("email", "username", "phone")
# Signs that a provider record is an infostealer log (credentials captured by malware) rather than a
# plain data-breach row. Stealer logs are the richest signal: they list the exact sites a person's
# saved logins unlock, so they surface accounts you did not know about.
_STEALER_TYPES = {"stealer", "stealer_log", "stealer_logs", "stealerlog", "infostealer", "logs", "ulp"}


def _host(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    host = urlsplit(text if "://" in text else f"//{text}").hostname or text
    return host.removeprefix("www.").rstrip(".")[:200]


def _site(record: dict[str, Any]) -> str | None:
    """The site a captured credential unlocks (stealer logs), as a bare host."""
    for key in ("url", "website", "site", "domain", "uri", "origin"):
        if record.get(key):
            return _host(str(record[key])) or None
    return None


def _is_stealer(record: dict[str, Any], site: str | None) -> bool:
    if any(record.get(k) for k in ("stealer", "malware", "stealer_family", "malware_path")):
        return True
    rtype = " ".join(str(record.get(k) or "") for k in ("type", "category")).lower().replace("-", "_")
    if any(t in rtype.split() for t in _STEALER_TYPES):
        return True
    name = " ".join(str(record.get(k) or "") for k in ("database", "breach", "source")).lower()
    return ("stealer" in name or "infostealer" in name or name.split() == ["ulp"]) and bool(site)


def mask(password: str) -> str:
    """A password shown so a match can be recognised but the password cannot be used: the first and
    last character and the length (``s•••••3``). Short ones are fully hidden."""
    pw = str(password or "")
    if len(pw) <= 3:
        return "•" * len(pw)
    return f"{pw[0]}{'•' * (len(pw) - 2)}{pw[-1]}  ({len(pw)} chars)"


def password_hash(password: str) -> str:
    """A one-way fingerprint of a password, for spotting the same password in two places. Not reversible."""
    return hashlib.sha256(("argus-breach-v1:" + str(password or "")).encode()).hexdigest()


def exposure(identifier: str, kind: str, record: dict[str, Any]) -> dict[str, Any]:
    """One exposure, with the plaintext password reduced to a mask and a hash and then dropped.

    ``record`` is one result from a credential provider; its ``password`` (if any) is used to compute
    the mask and hash and is **not** returned."""
    password = str(record.get("password") or "")
    has_password = bool(password) or bool(record.get("password_hash") or record.get("hashed_password"))
    out = {
        "identifier": identifier.strip().lower(),
        "kind": kind,
        "breach": str(record.get("database") or record.get("breach") or record.get("source") or "unknown")[:200],
        "date": _year(record.get("date") or record.get("breach_date") or record.get("obtained")),
        "email": str(record.get("email") or (identifier if kind == "email" else "")).strip().lower()[:200] or None,
        "username": str(record.get("username") or (identifier if kind == "username" else "")).strip()[:200] or None,
        "has_password": has_password,
        "password_masked": mask(password) if password else None,
        "password_sha256": password_hash(password)
        if password
        else (str(record.get("password_hash") or "")[:128] or None),
        "hash_only": bool(not password and (record.get("password_hash") or record.get("hashed_password"))),
        "extra": {k: str(v)[:200] for k, v in record.items() if k in ("ip_address", "name", "address", "phone") and v},
    }
    site = _site(record)
    out["site"] = site
    out["is_stealer"] = _is_stealer(record, site)
    out["stealer"] = (
        str(record.get("stealer") or record.get("malware") or record.get("stealer_family") or "").strip()[:80] or None
    )
    out["computer"] = (
        str(record.get("computer") or record.get("machine") or record.get("hostname") or "").strip()[:120] or None
    )
    out["infected_at"] = _year(record.get("compromised") or record.get("infected") or record.get("log_date"))
    return out


def _year(value: Any) -> str | None:
    match = re.search(r"(19|20)\d\d(?:-\d\d(?:-\d\d)?)?", str(value or ""))
    return match.group(0) if match else None


def reuse(exposures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Groups of identifiers that share a password (by hash): probably the same person. A hash shared
    by only one identifier is not a link and is left out."""
    by_hash: dict[str, list[dict[str, Any]]] = {}
    for e in exposures:
        if e.get("password_sha256"):
            by_hash.setdefault(e["password_sha256"], []).append(e)
    groups = []
    for digest, items in by_hash.items():
        idents = sorted({i["identifier"] for i in items})
        if len(idents) < 2:
            continue
        groups.append({"identifiers": idents, "masked": next((i["password_masked"] for i in items if i.get("password_masked")), None),
                       "breaches": sorted({i["breach"] for i in items}), "hash": digest})  # fmt: skip
    return sorted(groups, key=lambda g: -len(g["identifiers"]))


def shared_with(exposures: list[dict[str, Any]], identifier: str, others: set[str]) -> list[str]:
    """The identifiers in ``others`` that share a password with ``identifier`` (for the person scoring)."""
    identifier = identifier.strip().lower()
    mine = {e["password_sha256"] for e in exposures if e["identifier"] == identifier and e.get("password_sha256")}
    if not mine:
        return []
    out = {e["identifier"] for e in exposures if e["identifier"] in others and e["identifier"] != identifier
           and e.get("password_sha256") in mine}  # fmt: skip
    return sorted(out)


def stealer_summary(exposures: list[dict[str, Any]]) -> dict[str, Any]:
    """Infostealer intelligence: the sites a person's captured logins unlock, and which infections.

    The single most useful OSINT signal in a stealer log is the **list of sites** the victim had saved
    credentials for — it reveals accounts (banks, email, social, work portals) you did not know about."""
    st = [e for e in exposures if e.get("is_stealer")]
    sites = sorted({e["site"] for e in st if e.get("site")})
    idents = sorted({e["identifier"] for e in st})
    return {
        "infections": len(st),
        "identifiers": idents,
        "sites": sites,
        "site_count": len(sites),
        "families": sorted({e["stealer"] for e in st if e.get("stealer")}),
        "latest": max((e.get("infected_at") or e.get("date") or "" for e in st), default="") or None,
    }


def summary(exposures: list[dict[str, Any]]) -> dict[str, Any]:
    breaches = sorted({e["breach"] for e in exposures})
    return {"exposures": len(exposures), "breaches": breaches, "with_password": sum(1 for e in exposures if e["has_password"]),
            "identifiers": sorted({e["identifier"] for e in exposures}), "reuse": reuse(exposures),
            "stealer": stealer_summary(exposures)}  # fmt: skip
