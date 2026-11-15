"""Companies, the people who run and own them, sanctions and offshore leaks."""

from __future__ import annotations


def person_name(raw: str) -> str:
    """Registers write "SMITH, John Paul": return "John Paul Smith" in normal capitalisation."""
    raw = " ".join(raw.split())
    if "," in raw:
        surname, _, given = raw.partition(",")
        raw = f"{given.strip()} {surname.strip()}"
    return " ".join(w.capitalize() if w.isupper() or w.islower() else w for w in raw.split())


def company_name(raw: str) -> str:
    raw = " ".join(raw.split())
    if raw.isupper():
        small = {"OF", "AND", "THE", "FOR", "IN"}
        keep = {"LTD", "PLC", "LLP", "LLC", "UK", "USA", "AG", "SA", "BV", "NV", "GMBH", "INC"}
        return " ".join(w if w in keep else w.lower() if w in small else w.capitalize() for w in raw.split())
    return raw
