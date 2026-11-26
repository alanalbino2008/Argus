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

IDENT_KINDS = ("email", "username", "phone")


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


def summary(exposures: list[dict[str, Any]]) -> dict[str, Any]:
    breaches = sorted({e["breach"] for e in exposures})
    return {"exposures": len(exposures), "breaches": breaches, "with_password": sum(1 for e in exposures if e["has_password"]),
            "identifiers": sorted({e["identifier"] for e in exposures}), "reuse": reuse(exposures)}  # fmt: skip
