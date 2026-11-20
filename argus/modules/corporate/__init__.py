"""Companies, the people who run and own them, sanctions and offshore leaks."""

from __future__ import annotations


def person_name(raw: str) -> str:
    """Registers write "SMITH, John Paul": return "John Paul Smith" in normal capitalisation."""
    raw = " ".join(raw.split())
    if "," in raw:
        surname, _, given = raw.partition(",")
        raw = f"{given.strip()} {surname.strip()}"
    return " ".join(_cap(w) if w.isupper() or w.islower() else w for w in raw.split())


def _cap(word: str) -> str:
    """Capitalise each part of a hyphenated or apostrophe name: Chapoulaud-Floquet, O'Brien."""
    out = "-".join(part[:1].upper() + part[1:].lower() for part in word.split("-"))
    return "'".join(p[:1].upper() + p[1:] for p in out.split("'")) if "'" in out else out


def company_name(raw: str) -> str:
    raw = " ".join(raw.split())
    if raw.isupper():
        small = {"OF", "AND", "THE", "FOR", "IN"}
        keep = {"LTD", "PLC", "LLP", "LLC", "UK", "USA", "AG", "SA", "BV", "NV", "GMBH", "INC", "AS", "ASA", "AB", "SE",
                "SAS", "SARL", "SCI", "SNC", "SRL", "SPA", "KG", "OHG", "ApS", "A/S"}  # fmt: skip
        mixed = {"OY": "Oy", "OYJ": "Oyj", "GMBH": "GmbH", "APS": "ApS"}  # written this way by their own registers
        return " ".join(mixed.get(w, w) if w in mixed else w if w in keep else w.lower() if w in small else _cap(w)
                        for w in raw.split())  # fmt: skip
    return raw
