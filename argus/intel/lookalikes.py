"""Lookalike domains: the names an attacker would register to impersonate a brand.

Phishing rarely uses the real domain; it uses one that *looks* right in an inbox or address
bar: ``acme-login.com``, ``acrne.com``, ``acme.co``, or "acme.com" spelled with a Cyrillic
"a" (U+0430). This module generates those candidates; ``modules/threat_intel/lookalike_domains.py`` checks which
exist and judges them, and the attack-path engine turns the dangerous ones into findings.

Techniques (each candidate records which one produced it):

* **typo**: omission, repetition, transposition, adjacent-key replacement and insertion
  (QWERTY), vowel swap, hyphenation;
* **homoglyph**: ASCII look-alikes (``rn``/``m``, ``vv``/``w``, ``cl``/``d``, ``0``/``o``,
  ``1``/``l``) and **IDN homographs**, Unicode letters that render like Latin ones (Cyrillic
  a, e, o, p, c, x, y and i: U+0430, U+0435, U+043E, U+0440, U+0441, U+0445, U+0443, U+0456),
  encoded as punycode (``xn--…``);
* **bitsquat**: one flipped bit in one character (memory errors misdirect real traffic);
* **tld**: the same name under another ending (``.co``, ``.net``, ``.io``, ``.co.uk``…);
* **combosquat**: the brand plus a word that lends credibility (``-login``, ``-secure``,
  ``-support``, ``-hr``, ``pay``…), the most common pattern in real phishing campaigns;
* **doppelganger**: a missing dot (``wwwacme.com``, ``mailacme.com``).

Generation is deterministic and bounded: the most dangerous techniques come first, so a
cap keeps the useful candidates.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "com.br", "co.in", "com.mx", "co.za", "com.sg", "com.tr", "com.cn", "co.kr",
}  # fmt: skip
ALTERNATIVE_TLDS = (
    "com", "net", "org", "co", "io", "info", "biz", "app", "online", "site", "xyz", "top", "shop", "store",
    "live", "support", "services", "tech", "cloud", "co.uk", "uk", "eu", "us", "me", "cc", "pro",
)  # fmt: skip
COMBO_WORDS = (
    "login", "secure", "sso", "auth", "account", "verify", "support", "help", "helpdesk", "it", "hr", "pay",
    "payment", "billing", "invoice", "mail", "webmail", "portal", "online", "app", "my", "admin", "update",
    "security", "service", "team", "corp", "group", "careers", "jobs",
)  # fmt: skip
SENSITIVE_WORDS = {"login", "secure", "sso", "auth", "account", "verify", "pay", "payment", "billing", "invoice",
                   "webmail", "portal", "admin", "update", "security", "helpdesk", "it", "hr", "mail"}  # fmt: skip
ASCII_HOMOGLYPHS = {"m": ["rn"], "w": ["vv"], "d": ["cl"], "o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "rn": ["m"]}
# Written as escapes on purpose: the characters are indistinguishable from Latin in source code.
UNICODE_HOMOGLYPHS = {
    "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441", "x": "\u0445", "y": "\u0443", "i": "\u0456",
}  # fmt: skip
KEYBOARD = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg", "y": "tugh", "u": "yihj", "i": "uojk",
    "o": "ipkl", "p": "ol", "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk", "1": "2q", "2": "13wq", "3": "24ew", "4": "35re",
    "5": "46tr", "6": "57yt", "7": "68uy", "8": "79iu", "9": "80oi", "0": "9po",
}  # fmt: skip
VOWELS = "aeiou"
VALID = set("abcdefghijklmnopqrstuvwxyz0123456789-")
# Most dangerous first: a cap keeps these.
TECHNIQUE_ORDER = ("combosquat", "homoglyph", "tld", "typo", "doppelganger", "bitsquat")


@dataclass(frozen=True)
class Candidate:
    domain: str  # ASCII (punycode for IDN homographs)
    technique: str
    display: str  # how it looks to a person (Unicode for homographs)
    detail: str


def split_domain(domain: str) -> tuple[str, str]:
    """('acme', 'co.uk') for acme.co.uk; subdomains are reduced to the registrable name."""
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    raise ValueError(f"{domain!r} is not a domain name")


def _valid(label: str) -> bool:
    return 1 <= len(label) <= 63 and set(label) <= VALID and not label.startswith("-") and not label.endswith("-")


def _typos(label: str) -> Iterator[tuple[str, str]]:
    n = len(label)
    for i in range(n):
        yield label[:i] + label[i + 1 :], f"missing '{label[i]}'"
        yield label[:i] + label[i] + label[i:], f"repeated '{label[i]}'"
        for key in KEYBOARD.get(label[i], ""):
            yield label[:i] + key + label[i + 1 :], f"'{label[i]}' → '{key}' (adjacent key)"
            yield label[:i] + key + label[i:], f"extra '{key}' (adjacent key)"
        if label[i] in VOWELS:
            for v in VOWELS:
                if v != label[i]:
                    yield label[:i] + v + label[i + 1 :], f"vowel '{label[i]}' → '{v}'"
        if 0 < i < n:
            yield label[:i] + "-" + label[i:], "hyphen added"
    for i in range(n - 1):
        if label[i] != label[i + 1]:
            yield label[:i] + label[i + 1] + label[i] + label[i + 2 :], f"'{label[i]}{label[i + 1]}' swapped"
    if "-" in label:
        yield label.replace("-", ""), "hyphen removed"


def _ascii_homoglyphs(label: str) -> Iterator[tuple[str, str]]:
    for original, replacements in ASCII_HOMOGLYPHS.items():
        start = label.find(original)
        while start != -1:
            for r in replacements:
                yield label[:start] + r + label[start + len(original) :], f"'{original}' looks like '{r}'"
            start = label.find(original, start + 1)


def _idn_homoglyphs(label: str) -> Iterator[tuple[str, str, str]]:
    """(punycode label, unicode label, detail): one substituted letter, and all substitutable letters."""
    positions = [i for i, ch in enumerate(label) if ch in UNICODE_HOMOGLYPHS]
    variants = [[i] for i in positions] + ([positions] if len(positions) > 1 else [])
    for chosen in variants:
        chars = list(label)
        for i in chosen:
            chars[i] = UNICODE_HOMOGLYPHS[label[i]]
        unicode_label = "".join(chars)
        try:
            encoded = unicode_label.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        letters = ", ".join(sorted({label[i] for i in chosen}))
        yield encoded, unicode_label, f"Cyrillic look-alike for {letters}"


def _bitsquats(label: str) -> Iterator[tuple[str, str]]:
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit)).lower()
            if flipped != ch and flipped in VALID and flipped != "-":
                yield label[:i] + flipped + label[i + 1 :], f"bit flip '{ch}' → '{flipped}'"


def generate(domain: str, limit: int = 1500) -> list[Candidate]:
    label, suffix = split_domain(domain)
    original = f"{label}.{suffix}"
    found: dict[str, Candidate] = {}

    def add(name: str, technique: str, detail: str, display: str | None = None) -> None:
        if name != original and name not in found:
            found[name] = Candidate(name, technique, display or name, detail)

    buckets: dict[str, list[tuple[str, str, str | None]]] = {t: [] for t in TECHNIQUE_ORDER}
    for word in COMBO_WORDS:
        for joined in (f"{label}-{word}", f"{word}-{label}", f"{label}{word}", f"{word}{label}"):
            if _valid(joined):
                buckets["combosquat"].append((f"{joined}.{suffix}", f"brand + '{word}'", None))
    for variant, detail in _ascii_homoglyphs(label):
        if _valid(variant):
            buckets["homoglyph"].append((f"{variant}.{suffix}", detail, None))
    for encoded, unicode_label, detail in _idn_homoglyphs(label):
        buckets["homoglyph"].append((f"{encoded}.{suffix}", detail, f"{unicode_label}.{suffix}"))
    for tld in ALTERNATIVE_TLDS:
        if tld != suffix:
            buckets["tld"].append((f"{label}.{tld}", f".{suffix} → .{tld}", None))
    for variant, detail in _typos(label):
        if _valid(variant):
            buckets["typo"].append((f"{variant}.{suffix}", detail, None))
    for prefix in ("www", "mail", "smtp", "webmail", "login"):
        buckets["doppelganger"].append((f"{prefix}{label}.{suffix}", f"missing dot after '{prefix}'", None))
    for variant, detail in _bitsquats(label):
        if _valid(variant):
            buckets["bitsquat"].append((f"{variant}.{suffix}", detail, None))
    for technique in TECHNIQUE_ORDER:
        for name, detail, display in buckets[technique]:
            add(name, technique, detail, display)
    return list(found.values())[:limit]


def registrable(domain: str) -> str:
    label, suffix = split_domain(domain)
    return f"{label}.{suffix}"


def has_sensitive_word(candidate: Candidate) -> bool:
    return candidate.technique == "combosquat" and any(f"'{w}'" in candidate.detail for w in SENSITIVE_WORDS)
