"""Known details: start from everything already known about a person, and find what else is theirs.

An investigator rarely starts from nothing. They usually know a name, perhaps a username or two,
an email address from a message, a phone number, a profile link, the town the person lives in and
where they work. A **subject** holds all of that in one place, inside a case, and one run searches
from every piece of it at once:

* each known username (and its likely variants), email address, phone number, name and website
  is searched with the same sources as the matching playbook; a profile link is searched by its
  handle;
* every account, address and record found is a **candidate**, scored against what is known: the
  same name, the same photo, the same town or employer, a link to a known account or website, a
  known address shown on the profile. Contradictions (a different name, another town, a
  different year of birth) count against it, and are shown;
* candidates that match very well (80 or more) are searched in turn, up to the depth chosen;
  everything else waits for the investigator;
* the investigator **confirms** or **rejects** each candidate. A confirmed one becomes a known
  detail, so everything else is scored again against it (and it can be searched); a rejected one
  is never suggested again.

Scores are aids to judgement, never identifications: two people can share a name, a town and even
a photo. The date of birth is only used to rule matches out, and Argus refuses a subject whose
known year of birth makes them a child.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType
from argus.intel.identity import _link_grade, _profile_facts
from argus.intel.names import similarity
from argus.intel.profiles import GENERIC_HOSTS, _host, _norm_url, _urls, compare

LISTS = ("names", "usernames", "emails", "phones", "profiles", "websites")
MAX_EACH = 20
ADULT_AGE = 18
AUTO_FOLLOW = 80  # candidates this good are searched in turn
LIKELY, POSSIBLE = 70, 40
GRADE_POINTS = {"verified": 60, "strong": 45, "probable": 25, "possible": 10}
CANDIDATE_TYPES = {EntityType.SOCIAL_PROFILE: "profile", EntityType.USERNAME: "username", EntityType.EMAIL: "email",
                   EntityType.PHONE: "phone", EntityType.PERSON: "record"}  # fmt: skip

# What each kind of known detail is searched with: the same sources as the matching playbook.
SEARCHES: dict[str, dict[str, Any]] = {
    "username": {"type": EntityType.USERNAME, "modules": ("username_hunter", "github_hunter", "profile_enricher",
                                                          "git_identity", "developer_footprint", "web_mentions",
                                                          "profile_history", "social_pages", "profile_viewer"), "depth": 1,
                 "variants": True},
    "email": {"type": EntityType.EMAIL, "modules": ("email_recon", "hibp", "pgp_keyserver", "username_hunter",
                                                    "github_hunter", "profile_enricher", "web_mentions",
                                                    "git_identity"), "depth": 2},
    "phone": {"type": EntityType.PHONE, "modules": ("phone_recon", "web_mentions"), "depth": 1},
    "name": {"type": EntityType.PERSON, "modules": ("companies_house", "offshore_leaks", "sanctions_screen",
                                                    "name_guesser", "public_records", "web_mentions", "social_pages",
                                                    "profile_history", "profile_viewer"), "depth": 1},
    "profile": {"type": EntityType.SOCIAL_PROFILE, "modules": ("profile_enricher", "profile_history", "social_pages",
                                                               "profile_viewer"),
                "depth": 1},
    "website": {"type": EntityType.DOMAIN, "modules": ("whois_lookup", "site_crawler", "profile_enricher"), "depth": 1},
}  # fmt: skip

HANDLE_HOSTS_SKIP = {
    "google.com",
    "t.co",
    "bit.ly",
    "goo.gl",
    "facebook.com",
    "linkedin.com",
}  # paths that are no handle
NOT_HANDLES = {
    "about",
    "contact",
    "blog",
    "home",
    "index",
    "index.html",
    "en",
    "posts",
    "p",
    "pages",
    "page",
    "me",
    "search",
    "watch",
    "share",
    "status",
    "photo",
    "photos",
    "video",
    "videos",
    "groups",
    "events",
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class KnownDetailsError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------- normalising what is known
def norm_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return ("+" if value.strip().startswith("+") else "") + digits


def norm_username(value: str) -> str:
    return value.strip().lstrip("@").lower()


def key_of(kind: str, value: str) -> str:
    """One identifier, normalised, so the same thing found twice (or already known) is recognised."""
    value = value.strip()
    if kind in ("profile", "website"):
        value = _norm_url(value)
    elif kind == "phone":
        value = norm_phone(value).lstrip("+")
    elif kind == "username":
        value = norm_username(value)
    else:
        value = value.lower()
    return f"{kind}:{value}"


def candidate_id(key: str) -> str:
    return "c_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def handle_from_url(url: str) -> str | None:
    """The handle in a profile link (github.com/jdoe, x.com/@jdoe), when it has one."""
    parts = urlsplit(url if "//" in url else f"https://{url}")
    host = (parts.hostname or "").lower().removeprefix("www.")
    segments = [s for s in parts.path.split("/") if s]
    if not segments or host in HANDLE_HOSTS_SKIP:
        return None
    if segments[0].lower() in ("u", "user", "users", "in", "people", "profile", "@") and len(segments) > 1:
        segments = segments[1:]
    handle = segments[0].lstrip("@")
    if handle.lower() in NOT_HANDLES:
        return None
    return handle if re.fullmatch(r"[A-Za-z0-9._-]{2,40}", handle) else None


def clean_known(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and tidy the known details; raises :class:`KnownDetailsError` with a readable reason."""
    out: dict[str, Any] = {name: [] for name in LISTS}
    for name in LISTS:
        values = data.get(name) or []
        if isinstance(values, str):
            values = [values]
        seen: set[str] = set()
        for raw in values:
            value = str(raw or "").strip()[:300]
            if not value:
                continue
            if name == "emails" and not EMAIL_RE.match(value):
                raise KnownDetailsError(f"{value!r} is not an email address")
            if name == "phones":
                if sum(c.isdigit() for c in value) < 7:
                    raise KnownDetailsError(f"{value!r} is not a phone number (include the country code)")
                value = norm_phone(value)
            if name == "usernames":
                value = value.lstrip("@")
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
                    raise KnownDetailsError(f"{value!r} is not a username")
            if name in ("profiles", "websites"):
                if not _host(value) or "." not in _host(value):
                    raise KnownDetailsError(f"{value!r} is not a web address")
                if "//" not in value:
                    value = f"https://{value}"
            key = key_of(name[:-1], value)
            if key not in seen:
                seen.add(key)
                out[name].append(value)
        if len(out[name]) > MAX_EACH:
            raise KnownDetailsError(f"At most {MAX_EACH} {name}")
    for name in ("city", "employer"):
        out[name] = str(data.get(name) or "").strip()[:200]
    year = data.get("birth_year")
    if year in (None, ""):
        out["birth_year"] = None
    else:
        try:
            year = int(year)
        except (TypeError, ValueError):
            raise KnownDetailsError("The year of birth must be a year, e.g. 1984") from None
        this_year = _now().year
        if not 1900 <= year <= this_year:
            raise KnownDetailsError("The year of birth must be a year, e.g. 1984")
        if this_year - year < ADULT_AGE:
            raise KnownDetailsError("Argus is not used to research children: this person would be under 18")
        out["birth_year"] = year
    offset = str(data.get("utc_offset") or "").strip()
    if offset and not re.fullmatch(r"[+-](0\d|1[0-4]):(00|30|45)", offset):
        raise KnownDetailsError("The time zone must be a UTC offset such as +01:00 or -05:00")
    out["utc_offset"] = offset or None
    out["photo_hash"] = data.get("photo_hash") if re.fullmatch(r"[0-9a-f]{16}", str(data.get("photo_hash") or "")) \
        else None  # fmt: skip
    return out


def known_keys(known: dict[str, Any]) -> set[str]:
    keys = set()
    for name in LISTS:
        kind = name[:-1]  # names -> name, profiles -> profile...
        keys |= {key_of(kind, v) for v in known.get(name) or []}
    for url in known.get("profiles") or []:
        handle = handle_from_url(url)
        if handle:
            keys.add(key_of("username", handle))
    return keys


PROVIDER_DOMAINS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
                    "me.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "mail.com"}  # fmt: skip


def hints(known: dict[str, Any]) -> dict[str, Any]:
    """What modules can use from the known details: the year of birth, and the person's own domains
    (their websites, and the domains of their non-webmail addresses) to guess addresses at."""
    domains = [_host(u) for u in known.get("websites") or []]
    domains += [e.rsplit("@", 1)[-1].lower() for e in known.get("emails") or [] if "@" in e]
    own = [d for d in dict.fromkeys(domains) if d and d not in PROVIDER_DOMAINS and d not in GENERIC_HOSTS]
    out: dict[str, Any] = {"domains": own[:5]}
    for field in ("city", "employer"):
        if known.get(field):
            out[field] = str(known[field])
    if known.get("birth_year"):
        out["birth_year"] = int(known["birth_year"])
    return out


def searches(known: dict[str, Any], searched: set[str]) -> list[dict[str, Any]]:
    """What a run searches: every known identifier not searched before (profile links by their handle)."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(kind: str, value: str, origin: str) -> None:
        key = key_of(kind, value)
        if key in searched or key in seen:
            return
        seen.add(key)
        out.append({"kind": kind, "value": value, "key": key, "origin": origin})

    for name in known.get("names") or []:
        add("name", name, "known")
    for value in known.get("usernames") or []:
        add("username", value, "known")
    for url in known.get("profiles") or []:
        add("profile", url, "known")
        handle = handle_from_url(url)
        if handle:
            add("username", handle, f"handle in {url}")
    for value in known.get("emails") or []:
        add("email", value, "known")
    for value in known.get("phones") or []:
        add("phone", value, "known")
    for url in known.get("websites") or []:
        host = _host(url)
        if host and host not in GENERIC_HOSTS:
            add("website", host, "known")
    return out


# ---------------------------------------------------------------------------- candidates and their scores
def reference(known: dict[str, Any]) -> dict[str, Any]:
    """What is known, shaped as a profile, so it can be compared with each one found."""
    names = known.get("names") or []
    return {"url": None, "avatar_hash": known.get("photo_hash"),
            "facts": {"display_name": names[0] if names else "", "location": known.get("city") or "",
                      "bio": known.get("employer") or "",
                      "links": [*(known.get("profiles") or []), *(known.get("websites") or [])]}}  # fmt: skip


def _born_year(value: Any) -> int | None:
    match = re.search(r"(19|20)\d\d", str(value or ""))
    return int(match.group(0)) if match else None


def _facts_text(facts: dict[str, Any]) -> str:
    parts = [str(facts.get(k) or "") for k in ("bio", "display_name", "public_email", "email", "website", "company")]
    parts += _urls(facts.get("links"))
    return " ".join(parts).lower()


def score(candidate: dict[str, Any], known: dict[str, Any]) -> dict[str, Any]:
    """How well a candidate fits what is known: a score from 0 to 100, a verdict, and the reasons."""
    facts = candidate.get("facts") or {}
    agree: list[str] = []
    conflict: list[str] = []
    kind = candidate["kind"]
    if kind == "profile":
        result = compare(reference(known), {"url": candidate["value"], "facts": facts,
                                            "avatar_hash": candidate.get("avatar_hash")})  # fmt: skip
        agree += result["agree"]
        conflict += result["conflict"]
    else:
        names = known.get("names") or []
        shown = candidate["value"] if kind == "record" else str(facts.get("display_name") or "")
        if names and shown and similarity(shown, names[0], kind="person") >= 0.9:
            agree.append(f"the same name ({names[0]})")
    text = _facts_text(facts)
    for email in known.get("emails") or []:
        if email.lower() in text:
            agree.append(f"shows a known email address ({email})")
    for phone in known.get("phones") or []:
        if len(norm_phone(phone)) >= 8 and norm_phone(phone).lstrip("+")[-8:] in re.sub(r"\D", "", text):
            agree.append(f"shows a known phone number ({phone})")
    employer = (known.get("employer") or "").strip().lower()
    if employer and len(employer) >= 3 and kind != "profile" and employer in text:
        agree.append(f"names the known employer ({known['employer']})")
    if kind == "profile" and employer and employer in str(facts.get("company") or "").lower():
        agree.append(f"names the known employer ({known['employer']})")
    names = known.get("names") or []
    archived = [n for n in facts.get("archived_names") or [] if str(n) != str(facts.get("display_name") or "")]
    if names and any(similarity(str(n), names[0], kind="person") >= 0.9 for n in archived):
        agree.append(f"showed the same name in an archived copy ({names[0]})")
    zone = (facts.get("timezone") or {}).get("usual_offset") if isinstance(facts.get("timezone"), dict) else None
    if known.get("utc_offset") and zone:
        apart = abs(_minutes(zone) - _minutes(known["utc_offset"]))
        if apart <= 60:
            agree.append(f"works in the same time zone (UTC{zone})")
        elif apart >= 180:
            conflict.append(f"works in UTC{zone}, not UTC{known['utc_offset']}")
    birth = known.get("birth_year")
    found_birth = _born_year(facts.get("born") or facts.get("birth_year"))
    if birth and found_birth:
        if abs(found_birth - birth) <= 1:
            agree.append(f"born about the same year ({found_birth})")
        else:
            conflict.append(f"born in {found_birth}, not {birth}")
    agree = list(dict.fromkeys(agree))
    points = GRADE_POINTS.get(candidate.get("grade") or "probable", 25)
    points += 20 * min(3, len(agree)) - 30 * len(conflict)
    points = max(0, min(100, points))
    if conflict and (not agree or points < POSSIBLE):
        verdict = "unlikely"
    elif points >= LIKELY:
        verdict = "likely"
    elif points >= POSSIBLE:
        verdict = "possible"
    else:
        verdict = "weak"
    return {"score": points, "verdict": verdict, "agree": agree, "conflict": conflict}


def _minutes(offset: str) -> int:
    sign = -1 if offset.startswith("-") else 1
    hours, _, minutes = offset.lstrip("+-").partition(":")
    return sign * (int(hours) * 60 + int(minutes or 0))


def _platform(entity: Entity, url: str) -> str:
    return str(entity.metadata.get("platform") or _host(url) or "")


def from_graph(graph: IntelligenceGraph, search: dict[str, Any], investigation_id: str) -> list[dict[str, Any]]:
    """The candidates one search found: accounts, addresses, numbers and register records."""
    out = []
    entities = {e.id: e for e in graph.get_all_entities()}
    linked_orgs: dict[str, list[str]] = {}
    for rel in graph.get_all_relations():
        a, b = entities.get(rel.source_id), entities.get(rel.target_id)
        if a and b and a.type == EntityType.PERSON and b.type == EntityType.ORGANIZATION:
            linked_orgs.setdefault(a.id, []).append(b.value)
    for entity in entities.values():
        kind = CANDIDATE_TYPES.get(entity.type)
        if kind is None:
            continue
        md = entity.metadata or {}
        facts: dict[str, Any] = {}
        if kind == "profile":
            facts = {k: v for k, v in _profile_facts(entity).items() if isinstance(v, (str, int, float, list))}
            if md.get("public_email"):
                facts.setdefault("public_email", md["public_email"])
        elif kind == "record":
            if not md.get("born") and entity.id not in linked_orgs:
                continue  # a bare name: nothing to weigh it by
            facts = {"born": md.get("born"), "company": ", ".join(linked_orgs.get(entity.id, [])[:5])}
        elif md.get("gravatar_name"):  # an address whose public profile shows a name
            facts = {"display_name": md["gravatar_name"]}
        if md.get("guessed"):
            facts["guessed"] = True
        if md.get("timezone"):
            facts["timezone"] = md["timezone"]
        history = md.get("history") or {}
        if history.get("names_shown"):
            facts["archived_names"] = history["names_shown"][:5]
        if history.get("first_archived"):
            facts["first_archived"] = history["first_archived"]
        value = entity.value
        out.append({
            "id": candidate_id(key_of(kind, value)), "key": key_of(kind, value), "kind": kind, "value": value,
            "label": entity.label or value, "platform": _platform(entity, value) if kind == "profile" else "",
            "url": value if kind == "profile" else None, "grade": _link_grade(entity),
            "avatar_hash": md.get("avatar_hash"), "facts": _trim(facts), "source": entity.source_module,
            "found_from": [{"kind": search["kind"], "value": search["value"], "investigation_id": investigation_id}],
        })  # fmt: skip
    return out


def _trim(facts: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in facts.items():
        if v in (None, "", []):
            continue
        out[k] = v[:20] if isinstance(v, list) else (v[:1000] if isinstance(v, str) else v)
    return out


def merge(existing: dict[str, dict[str, Any]], found: list[dict[str, Any]], *, skip: set[str],
          known: dict[str, Any]) -> list[dict[str, Any]]:  # fmt: skip
    """Add newly found candidates to ``existing`` (by id), merging duplicates; returns those that are new."""
    new = []
    for cand in found:
        if cand["key"] in skip:
            continue
        current = existing.get(cand["id"])
        if current is None:
            cand.update(status="open", first_seen=_now().isoformat())
            existing[cand["id"]] = cand
            new.append(cand)
        else:
            current["found_from"] = (current.get("found_from") or []) + [
                f for f in cand["found_from"] if f not in (current.get("found_from") or [])][:10]  # fmt: skip
            for k, v in cand["facts"].items():
                current.setdefault("facts", {}).setdefault(k, v)
            current["avatar_hash"] = current.get("avatar_hash") or cand.get("avatar_hash")
            if GRADE_POINTS.get(cand["grade"], 0) > GRADE_POINTS.get(current.get("grade") or "", 0):
                current["grade"] = cand["grade"]
    rescore(existing, known)
    return new


def rescore(candidates: dict[str, dict[str, Any]], known: dict[str, Any]) -> None:
    for cand in candidates.values():
        if cand.get("status") == "open":
            cand.update(score(cand, known))


def follow_up(cand: dict[str, Any]) -> dict[str, Any] | None:
    """The search a candidate leads to, if it is searchable (an account by its handle)."""
    if cand["kind"] in ("username", "email", "phone"):
        return {"kind": cand["kind"], "value": cand["value"], "key": key_of(cand["kind"], cand["value"]),
                "origin": f"found: {cand['label']}"}  # fmt: skip
    if cand["kind"] == "profile":
        handle = handle_from_url(cand["value"])
        if handle:
            return {"kind": "username", "value": handle, "key": key_of("username", handle),
                    "origin": f"handle in {cand['value']}"}  # fmt: skip
    return None


def add_to_known(known: dict[str, Any], cand: dict[str, Any]) -> dict[str, Any]:
    """A confirmed candidate becomes a known detail."""
    field = {"profile": "profiles", "username": "usernames", "email": "emails", "phone": "phones"}.get(cand["kind"])
    known = {**known}
    if field:
        values = list(known.get(field) or [])
        if key_of(field[:-1], cand["value"]) not in {key_of(field[:-1], v) for v in values}:
            values.append(cand["value"])
        known[field] = values[:MAX_EACH]
    if cand["kind"] == "record" and not known.get("birth_year"):
        known["birth_year"] = _born_year((cand.get("facts") or {}).get("born"))
    zone = (cand.get("facts") or {}).get("timezone")
    if isinstance(zone, dict) and zone.get("usual_offset") and not known.get("utc_offset"):
        known["utc_offset"] = zone["usual_offset"]
    if cand["kind"] == "profile" and not known.get("photo_hash") and cand.get("avatar_hash"):
        known["photo_hash"] = cand["avatar_hash"]
    return known


CASE_ITEM_TYPES = {"profile": "account", "username": "username", "email": "email", "phone": "phone",
                   "record": "person"}  # fmt: skip
