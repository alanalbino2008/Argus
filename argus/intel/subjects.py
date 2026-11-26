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
from itertools import pairwise
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
                   EntityType.PHONE: "phone", EntityType.PERSON: "record", EntityType.URL: "page"}  # fmt: skip
PAGE_CATEGORIES = {"mention", "image_match"}  # pages about the person; not every address a website search lists

# What each kind of known detail is searched with: the same sources as the matching playbook.
SEARCHES: dict[str, dict[str, Any]] = {
    "username": {"type": EntityType.USERNAME, "modules": ("username_hunter", "github_hunter", "profile_enricher",
                                                          "git_identity", "developer_footprint", "web_mentions",
                                                          "profile_history", "social_pages", "profile_viewer",
                                                          "archived_accounts", "person_documents"), "depth": 1,
                 "variants": True},
    "email": {"type": EntityType.EMAIL, "modules": ("email_recon", "hibp", "pgp_keyserver", "username_hunter",
                                                    "github_hunter", "profile_enricher", "web_mentions",
                                                    "git_identity"), "depth": 2},
    "phone": {"type": EntityType.PHONE, "modules": ("phone_recon", "web_mentions"), "depth": 1},
    "name": {"type": EntityType.PERSON, "modules": ("companies_house", "offshore_leaks", "sanctions_screen",
                                                    "name_guesser", "public_records", "web_mentions", "social_pages",
                                                    "profile_history", "profile_viewer", "person_documents",
                                                    "gazette_insolvency", "court_records"), "depth": 1},
    "profile": {"type": EntityType.SOCIAL_PROFILE, "modules": ("profile_enricher", "profile_history", "social_pages",
                                                               "profile_viewer"),
                "depth": 1},
    "website": {"type": EntityType.DOMAIN, "modules": ("whois_lookup", "site_crawler", "profile_enricher",
                                                       "infrastructure_pivot", "site_history"), "depth": 1},
    "photo": {"type": EntityType.URL, "modules": ("reverse_image",), "depth": 1, "hints": {"image_search": True}},
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
    out["photo_urls"] = [str(u) for u in (data.get("photo_urls") or []) if str(u).startswith("https://")
                         and len(str(u)) <= 2000][:5]  # fmt: skip
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
    for url in known.get("photo_urls") or []:
        add("photo", url, "a confirmed profile picture")
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


def score(candidate: dict[str, Any], known: dict[str, Any], extra: list[str] | None = None) -> dict[str, Any]:
    """How well a candidate fits what is known: a score from 0 to 100, a verdict, and the reasons.
    ``extra``: what it strongly shares with confirmed accounts (a picture, a link), counted as agreements."""
    facts = candidate.get("facts") or {}
    agree: list[str] = list(extra or [])
    conflict: list[str] = []
    kind = candidate["kind"]
    if kind == "profile":
        result = compare(reference(known), {"url": candidate["value"], "facts": facts,
                                            "avatar_hash": candidate.get("avatar_hash")})  # fmt: skip
        agree += result["agree"]
        conflict += result["conflict"]
    else:
        names = known.get("names") or []
        shown = str(facts.get("display_name") or (candidate["value"] if kind == "record" else ""))
        if names and shown and similarity(shown, names[0], kind="person") >= 0.9:
            agree.append(f"the same name ({names[0]})")
    if facts.get("same_picture"):
        agree.append("uses the same picture (reverse image search)")
    text = _facts_text(facts)
    city = str(known.get("city") or "").strip().lower()
    if kind != "profile" and len(city) >= 3 and re.search(r"\b" + re.escape(city) + r"\b", text):
        agree.append(f"mentions the known town ({known['city']})")
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
    officers: dict[str, list[str]] = {}  # organisation -> the people linked to it
    for rel in graph.get_all_relations():
        a, b = entities.get(rel.source_id), entities.get(rel.target_id)
        if a and b and a.type == EntityType.PERSON and b.type == EntityType.ORGANIZATION:
            linked_orgs.setdefault(a.id, []).append(b.value)
            officers.setdefault(b.value, []).append(a.value)
    co_officers = {pid: sorted({f"{name} ({org})" for org in orgs for name in officers.get(org, [])
                                if name != entities[pid].value}) for pid, orgs in linked_orgs.items()}  # fmt: skip
    for entity in entities.values():
        kind = CANDIDATE_TYPES.get(entity.type)
        if kind is None:
            continue
        md = entity.metadata or {}
        if entity.type == EntityType.PERSON:
            out += _record_candidates(entity, search, investigation_id)
        if kind == "page" and md.get("category") not in PAGE_CATEGORIES:
            continue
        facts: dict[str, Any] = {}
        if kind == "profile":
            facts = {k: v for k, v in _profile_facts(entity).items() if isinstance(v, (str, int, float, list))}
            for field in ("public_email", "public_phone"):
                if md.get(field):
                    facts.setdefault(field, md[field])
        elif kind == "record":
            if not md.get("born") and entity.id not in linked_orgs:
                continue  # a bare name: nothing to weigh it by
            facts = {"born": md.get("born"), "company": ", ".join(linked_orgs.get(entity.id, [])[:5])}
        elif kind == "page":
            doc = md.get("document") or {}
            authors = [a for a in doc.get("authors") or [] if len(str(a).split()) >= 2]
            facts = {"bio": " ".join(x for x in (str(md.get("snippet") or ""), " ".join(doc.get("emails") or [])) if x),
                     "display_name": authors[0] if authors else "", "company": doc.get("company") or "",
                     "created": doc.get("created"), "links": doc.get("links") or [], "title": doc.get("title")}  # fmt: skip
        elif md.get("gravatar_name"):  # an address whose public profile shows a name
            facts = {"display_name": md["gravatar_name"]}
        if md.get("guessed"):
            facts["guessed"] = True
        if md.get("timezone"):
            facts["timezone"] = md["timezone"]
        if md.get("same_picture"):
            facts["same_picture"] = True
        snaps = (md.get("history") or {}).get("snapshots") or {}
        if snaps:
            facts["name_history"] = [{"date": v.get("date"), "name": v.get("name")} for v in snaps.values()
                                     if isinstance(v, dict) and v.get("name")]  # fmt: skip
        channel = md.get("telegram_channel") or {}
        if channel:
            facts["channel"] = {"first_shown": channel.get("first_shown"), "last_post": channel.get("last_post"),
                                "subscribers": channel.get("subscribers"),
                                "post_hours_utc": channel.get("post_hours_utc") or {}}  # fmt: skip
            facts["mentions"] = channel.get("mentions") or []
        if md.get("coauthors"):
            facts["coauthors"] = md["coauthors"][:15]
        if kind == "record" and entity.id in linked_orgs:
            facts["co_officers"] = co_officers.get(entity.id, [])[:15]
        if md.get("archived"):
            facts["archived"] = md["archived"]
        history = md.get("history") or {}
        if history.get("names_shown"):
            facts["archived_names"] = history["names_shown"][:5]
        if history.get("first_archived"):
            facts["first_archived"] = history["first_archived"]
        value = entity.value
        out.append({
            "id": candidate_id(key_of(kind, value)), "key": key_of(kind, value), "kind": kind, "value": value,
            "label": entity.label or value, "platform": _platform(entity, value) if kind == "profile" else "",
            "url": value if kind in ("profile", "page") else None, "grade": _grade(entity, kind),
            "avatar_hash": md.get("avatar_hash"), "facts": _trim(facts), "source": entity.source_module,
            "found_from": [{"kind": search["kind"], "value": search["value"], "investigation_id": investigation_id}],
        })  # fmt: skip
    return out


def _grade(entity: Entity, kind: str) -> str:
    md = entity.metadata or {}
    if md.get("same_picture"):
        return "strong"  # the same picture: someone could have copied it, so not "verified"
    if kind == "page":
        return "possible"  # a page naming them: a namesake's as easily as theirs
    if md.get("archived") and entity.source_module == "archived_accounts":
        return "possible"  # a handle once used there: maybe by someone else
    return _link_grade(entity)


def _record_candidates(entity: Entity, search: dict[str, Any], investigation_id: str) -> list[dict[str, Any]]:
    """Insolvency notices and court cases in the person's name: each a record to check."""
    md = entity.metadata or {}
    out = []
    items = [("Insolvency notice", n) for n in md.get("insolvency_notices") or []]
    items += [("Court case", c) for c in md.get("court_cases") or []]
    for label, item in items[:15]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        about = str(item.get("about") or item.get("name") or item.get("case_name") or item.get("caption") or "")
        when = str(item.get("date") or item.get("filed") or item.get("date_filed") or "")[:10]
        value = url or f"{label}: {about} {when}".strip()
        key = key_of("record", value)
        out.append({
            "id": candidate_id(key), "key": key, "kind": "record", "value": value,
            "label": f"{label}: {about[:120]}{f' ({when})' if when else ''}", "platform": "",
            "url": url or None, "grade": "possible", "avatar_hash": None, "source": entity.source_module,
            "facts": _trim({"display_name": entity.value, "bio": f"{about} {item.get('summary') or ''}".strip(),
                            "date": when, "record": label,
                            "court": item.get("court"), "type": item.get("type")}),
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
    shared = cluster_reasons({"candidates": candidates})
    for cand in candidates.values():
        if cand.get("status") == "open":
            cand.update(score(cand, known, extra=shared.get(cand["id"])))


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
    picture = (cand.get("facts") or {}).get("avatar_url")
    if cand["kind"] == "profile" and isinstance(picture, str) and picture.startswith("https://"):
        known["photo_urls"] = list(dict.fromkeys([*(known.get("photo_urls") or []), picture]))[:5]
    if cand["kind"] == "profile" and not known.get("photo_hash") and cand.get("avatar_hash"):
        known["photo_hash"] = cand["avatar_hash"]
    return known


CASE_ITEM_TYPES = {"profile": "account", "username": "username", "email": "email", "phone": "phone",
                   "record": "document", "page": "document"}  # fmt: skip


# ---------------------------------------------------------------------------- learning from confirmed accounts
BIO_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BIO_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')|]+", re.I)
BIO_SOCIAL = re.compile(
    r"(?<![\w./])(?:(?:www|m)\.)?(?:tiktok\.com|instagram\.com|x\.com|twitter\.com|facebook\.com|t\.me|"
    r"snapchat\.com|youtube\.com|threads\.net|linkedin\.com|pinterest\.com)/[^\s<>\"')|,]+",
    re.I,
)
SUGGESTION_LABELS = {"names": "Name", "city": "Town or city", "employer": "Employer", "websites": "Website",
                     "profiles": "Account", "emails": "Email address", "phones": "Phone number"}  # fmt: skip


def _real_name(name: str) -> bool:
    words = name.split()
    return 2 <= len(words) <= 5 and not any(c.isdigit() for c in name) and len(name) <= 80


def suggestions(cand: dict[str, Any], known: dict[str, Any]) -> list[dict[str, Any]]:
    """What a confirmed account shows about the person that is not known yet, for the investigator to
    tick: another name, the town, the employer, websites and other accounts it links to, and contact
    details it shows publicly. Suggestions only: a bio can mention a friend's account or an old job."""
    from argus.modules.identity.web_mentions import social_profile

    facts = cand.get("facts") or {}
    have = known_keys(known)
    names = known.get("names") or []
    out: list[dict[str, Any]] = []

    def add(field: str, value: Any, why: str) -> None:
        value = str(value or "").strip()
        if not value or len(value) > 300:
            return
        if field in LISTS and key_of(field[:-1], value) in have:
            return
        if any(s["field"] == field and s["value"].lower() == value.lower() for s in out):
            return
        sid = "s_" + hashlib.sha256(f"{cand['id']}|{field}|{value.lower()}".encode()).hexdigest()[:12]
        out.append({"id": sid, "field": field, "label": SUGGESTION_LABELS[field], "value": value, "why": why,
                    "from": cand.get("label") or cand["value"], "candidate": cand["id"], "status": "pending"})  # fmt: skip

    shown = str(facts.get("display_name") or "").strip()

    def plain(n: str) -> str:
        return re.sub(r"[^a-z]", "", n.lower())

    if shown and _real_name(shown) and plain(shown) not in {plain(n) for n in names}:
        add("names", shown, "the name the account shows")
    if facts.get("location") and not known.get("city"):
        add("city", str(facts["location"]).split(",")[0], "where the account says they are")
    if facts.get("company") and not known.get("employer"):
        add(
            "employer",
            str(facts["company"]).split(",")[0],
            "a company the register record links them to"
            if cand.get("kind") == "record"
            else "the employer the account shows",
        )
    text = " ".join(str(facts.get(k) or "") for k in ("bio", "public_email", "email", "website"))
    links = [str(u) for u in _urls(facts.get("links"))] + [str(facts.get("website") or "")]
    bio = str(facts.get("bio") or "")
    links += [
        u if u.lower().startswith("http") else f"https://{u}" for u in BIO_URL.findall(bio) + BIO_SOCIAL.findall(bio)
    ]
    own = _norm_url(cand["value"]) if cand.get("kind") == "profile" else ""
    for link in links:
        link = link.strip().rstrip(".,;")
        if not link or (own and _norm_url(link) == own):
            continue
        found = social_profile(link if "//" in link else f"https://{link}")
        if found:
            add("profiles", found[1], f"linked from the account ({found[0]})")
        elif _host(link) and _host(link) not in GENERIC_HOSTS and "." in _host(link):
            add("websites", link if "//" in link else f"https://{link}", "the website the account links to")
    for address in BIO_EMAIL.findall(text):
        add("emails", address.lower(), "an address the account shows publicly")
    for field in ("public_phone", "phone"):
        if facts.get(field) and sum(c.isdigit() for c in str(facts[field])) >= 7:
            add("phones", norm_phone(str(facts[field])), "a number the account shows publicly")
    return out[:12]


def accept_suggestions(known: dict[str, Any], picked: list[dict[str, Any]]) -> dict[str, Any]:
    """Add the ticked suggestions to the known details (lists extended, empty fields filled)."""
    data = {**known}
    for s in picked:
        field = s["field"]
        if field in LISTS:
            data[field] = [*(data.get(field) or []), s["value"]]
        elif not data.get(field):
            data[field] = s["value"]
    return clean_known(data)


# ---------------------------------------------------------------------------- timeline, associates, dossier
def _day(value: Any) -> str | None:
    match = re.match(r"(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", str(value or ""))
    if not match:
        return None
    return "-".join(p for p in match.groups() if p)


def timeline(data: dict[str, Any], *, include_open: bool = False) -> list[dict[str, Any]]:
    """The person's online life from what was found: when accounts were created, first and last archived,
    renamed, posted, and when documents and records are dated. Confirmed findings by default."""
    events: list[dict[str, Any]] = []
    wanted = {"confirmed"} | ({"open"} if include_open else set())
    for cand in (data.get("candidates") or {}).values():
        if cand.get("status") not in wanted:
            continue
        facts = cand.get("facts") or {}
        what = cand.get("label") or cand["value"]

        def add(date: Any, title: str, kind: str, cand: dict[str, Any] = cand) -> None:
            day = _day(date)
            if day:
                events.append({"date": day, "title": title, "kind": kind, "candidate": cand["id"],
                               "status": cand.get("status"), "url": cand.get("url")})  # fmt: skip

        add(facts.get("created_at"), f"Account created: {what}", "created")
        archived = facts.get("archived") or {}
        add(archived.get("first"), f"First archived copy: {what}", "archived")
        if archived.get("last") and archived.get("last") != archived.get("first"):
            add(archived.get("last"), f"Last archived copy: {what}", "archived")
        if not archived:
            add(facts.get("first_archived"), f"First archived copy: {what}", "archived")
        names = [n for n in facts.get("name_history") or [] if n.get("date")]
        ordered = sorted(names, key=lambda n: n["date"])
        for older, newer in pairwise(ordered):
            if older["name"] != newer["name"]:
                add(newer["date"], f'Shown as "{newer["name"]}" (was "{older["name"]}"): {what}', "renamed")
        for n in names[:1]:
            add(n["date"], f'Shown as "{n["name"]}": {what}', "name")
        channel = facts.get("channel") or {}
        add(channel.get("last_post"), f"Latest post in their Telegram channel: {what}", "posted")
        add(facts.get("created"), f"Document created: {facts.get('title') or what}", "document")
        add(facts.get("date"), what, "record")
        add(facts.get("born"), f"Born (per {what})", "born")
    events.sort(key=lambda e: e["date"])
    return events


def contradictions(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Where confirmed findings disagree with each other or with what is known: towns, years of birth,
    time zones. Either one of them is wrong, or one of them is not this person."""
    known = data.get("known") or {}
    confirmed = [c for c in (data.get("candidates") or {}).values() if c.get("status") == "confirmed"]
    out: list[dict[str, Any]] = []
    places: dict[str, list[str]] = {}
    for c in confirmed:
        loc = str((c.get("facts") or {}).get("location") or "").split(",")[0].strip()
        if loc:
            places.setdefault(loc.lower(), []).append(c.get("label") or c["value"])
    if known.get("city"):
        places.setdefault(str(known["city"]).lower(), []).append("known details")
    if len(places) > 1:
        out.append(
            {"what": "different towns", "detail": "; ".join(f"{p.title()}: {', '.join(v)}" for p, v in places.items())}
        )
    years = {}
    for c in confirmed:
        year = _born_year((c.get("facts") or {}).get("born"))
        if year:
            years[c.get("label") or c["value"]] = year
    if known.get("birth_year"):
        years["known details"] = int(known["birth_year"])
    if years and max(years.values()) - min(years.values()) > 1:
        out.append({"what": "different years of birth", "detail": "; ".join(f"{k}: {v}" for k, v in years.items())})
    zones = {}
    for c in confirmed:
        zone = (c.get("facts") or {}).get("timezone")
        if isinstance(zone, dict) and zone.get("usual_offset"):
            zones[c.get("label") or c["value"]] = zone["usual_offset"]
    if known.get("utc_offset"):
        zones["known details"] = known["utc_offset"]
    if zones and max(_minutes(z) for z in zones.values()) - min(_minutes(z) for z in zones.values()) >= 180:
        out.append({"what": "different time zones", "detail": "; ".join(f"{k}: UTC{v}" for k, v in zones.items())})
    return out


def associates(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Other people connected to the person through confirmed findings: co-authors, fellow company
    officers, accounts their channel mentions. Listed, never researched: they are not the subject."""
    found: dict[str, dict[str, Any]] = {}
    for c in (data.get("candidates") or {}).values():
        if c.get("status") != "confirmed":
            continue
        facts = c.get("facts") or {}
        via = c.get("label") or c["value"]
        for relation, names in (("co-author", facts.get("coauthors")), ("fellow company officer", facts.get("co_officers")),
                                ("mentioned in their Telegram channel", [f"@{m}" for m in facts.get("mentions") or []])):  # fmt: skip
            for name in names or []:
                entry = found.setdefault(str(name).lower(), {"name": str(name), "relations": [], "via": []})
                if relation not in entry["relations"]:
                    entry["relations"].append(relation)
                if via not in entry["via"]:
                    entry["via"].append(via)
    return sorted(found.values(), key=lambda a: (-len(a["via"]), a["name"]))[:60]


def dossier_material(name: str, data: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    """The person's material for the AI analyst, each part with a reference the dossier cites."""
    known = data.get("known") or {}
    sources: dict[str, dict[str, Any]] = {}
    lines = [f"PERSON: {name}", "", "KNOWN DETAILS (entered or accepted by the investigator):"]
    n = 0
    for key, label in (("names", "Name"), ("usernames", "Username"), ("emails", "Email"), ("phones", "Phone"),
                       ("profiles", "Account"), ("websites", "Website")):  # fmt: skip
        for value in known.get(key) or []:
            n += 1
            sources[f"K{n}"] = {"kind": "known", "label": f"{label}: {value}"}
            lines.append(f"[K{n}] {label}: {value}")
    for key, label in (("city", "Town"), ("employer", "Employer"), ("birth_year", "Year of birth"),
                       ("utc_offset", "Usual time zone (UTC)")):  # fmt: skip
        if known.get(key):
            n += 1
            sources[f"K{n}"] = {"kind": "known", "label": f"{label}: {known[key]}"}
            lines.append(f"[K{n}] {label}: {known[key]}")
    cands = list((data.get("candidates") or {}).values())

    def describe(c: dict[str, Any]) -> str:
        facts = c.get("facts") or {}
        shown = {k: facts[k] for k in ("display_name", "location", "company", "bio", "website", "born", "created_at",
                                       "positions", "education") if facts.get(k)}  # fmt: skip
        parts = [f"{c.get('label') or c['value']} ({c['kind']}, score {c.get('score')}/100)"]
        if c.get("url"):
            parts.append(f"address: {c['url']}")
        if c.get("agree"):
            parts.append("for: " + "; ".join(c["agree"]))
        if c.get("conflict"):
            parts.append("against: " + "; ".join(c["conflict"]))
        if shown:
            parts.append("shows: " + "; ".join(f"{k}={str(v)[:300]}" for k, v in shown.items()))
        return " | ".join(parts)

    lines += ["", "CONFIRMED BY THE INVESTIGATOR:"]
    for i, c in enumerate([c for c in cands if c.get("status") == "confirmed"][:40], 1):
        sources[f"C{i}"] = {"kind": "confirmed", "label": c.get("label") or c["value"], "candidate": c["id"]}
        lines.append(f"[C{i}] {describe(c)}")
    lines += ["", "OPEN CANDIDATES (not reviewed; possibilities only):"]
    open_ = sorted([c for c in cands if c.get("status") == "open" and c.get("verdict") in ("likely", "possible")],
                   key=lambda c: -(c.get("score") or 0))[:30]  # fmt: skip
    for i, c in enumerate(open_, 1):
        sources[f"P{i}"] = {"kind": "open", "label": c.get("label") or c["value"], "candidate": c["id"]}
        lines.append(f"[P{i}] {describe(c)}")
    rejected = sum(1 for c in cands if c.get("status") == "rejected")
    lines += ["", f"RULED OUT BY THE INVESTIGATOR: {rejected} (not listed)", "", "TIMELINE (confirmed findings):"]
    for i, e in enumerate(timeline(data)[:60], 1):
        sources[f"T{i}"] = {"kind": "timeline", "label": f"{e['date']}: {e['title']}"}
        lines.append(f"[T{i}] {e['date']}: {e['title']}")
    clashes = contradictions(data)
    if clashes:
        lines += ["", "CONTRADICTIONS FOUND:"] + [f"- {c['what']}: {c['detail']}" for c in clashes]
    lines += ["", f"OTHER PEOPLE CONNECTED (not to be described): {len(associates(data))}"]
    return "\n".join(lines), sources


def check_dossier(output: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Citations resolved; a finding citing nothing real is marked unsupported; an open candidate is never
    presented as established."""

    def resolve(findings: list[dict[str, Any]], section: str) -> list[dict[str, Any]]:
        out = []
        for f in findings:
            cited = [{"ref": r, **sources[r]} for r in f.get("sources") or [] if r in sources]
            item = {**f, "sources": cited, "unsupported": not cited}
            if section == "established" and cited and all(c["kind"] == "open" for c in cited):
                item["confidence"] = "possible"  # only open candidates behind it: not established
                item["downgraded"] = True
            out.append(item)
        return out

    return {**output, "established": resolve(output.get("established") or [], "established"),
            "likely": resolve(output.get("likely") or [], "likely"),
            "conflicts": resolve(output.get("conflicts") or [], "conflicts")}  # fmt: skip


# ---------------------------------------------------------------------------- clusters and the person's graph
STRONG_LINKS = {"the same profile picture", "one links to the other"}


def _bio_words(facts: dict[str, Any]) -> set[str]:
    from argus.intel.profiles import _words

    return _words(str(facts.get("bio") or ""))


def _hosts(cand: dict[str, Any]) -> set[str]:
    facts = cand.get("facts") or {}
    urls = [*_urls(facts.get("links")), str(facts.get("website") or "")]
    return {_host(u) for u in urls if u and _host(u) and _host(u) not in GENERIC_HOSTS and "." in _host(u)}


def _pair_reasons(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    """What two candidates share that suggests one owner."""
    from argus.intel.avatars import same_picture

    fa, fb = a.get("facts") or {}, b.get("facts") or {}
    reasons = []
    if same_picture(a.get("avatar_hash"), b.get("avatar_hash")):
        reasons.append("the same profile picture")
    la, lb = {_norm_url(u) for u in _urls(fa.get("links"))}, {_norm_url(u) for u in _urls(fb.get("links"))}
    if (a.get("url") and _norm_url(a["url"]) in lb) or (b.get("url") and _norm_url(b["url"]) in la):
        reasons.append("one links to the other")
    shared_hosts = _hosts(a) & _hosts(b)
    if shared_hosts:
        reasons.append(f"both link to {', '.join(sorted(shared_hosts)[:2])}")
    na, nb = str(fa.get("display_name") or "").strip(), str(fb.get("display_name") or "").strip()
    if na and nb and _real_name(na) and na.lower() == nb.lower():
        reasons.append(f"the same name ({na})")
    words = _bio_words(fa) & _bio_words(fb)
    if len(words) >= 3:
        reasons.append(f"similar bios ({', '.join(sorted(words)[:4])})")
    ea = {str(fa.get(k) or "").lower() for k in ("public_email", "email") if fa.get(k)}
    eb = {str(fb.get(k) or "").lower() for k in ("public_email", "email") if fb.get(k)}
    if ea & eb:
        reasons.append("the same public email address")
    return reasons


def clusters(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Groups of candidates that share a picture, links, a website, a name, bio wording or an address:
    probably one owner. A group that includes a confirmed account points at more of the person's accounts."""
    cands = [c for c in (data.get("candidates") or {}).values() if c.get("status") in ("open", "confirmed")]
    cands = cands[:400]
    parent = {c["id"]: c["id"] for c in cands}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    links: list[dict[str, Any]] = []
    for i, a in enumerate(cands):
        for b in cands[i + 1 :]:
            reasons = _pair_reasons(a, b)
            if not reasons:
                continue
            strong = any(r in STRONG_LINKS for r in reasons) or len(reasons) >= 2
            links.append({"a": a["id"], "b": b["id"], "reasons": reasons, "strong": strong})
            if strong:  # a single weak signal (a shared website or similar bios) is shown, not grouped
                parent[find(a["id"])] = find(b["id"])
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in cands:
        groups.setdefault(find(c["id"]), []).append(c)
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        ids = {m["id"] for m in members}
        out.append({
            "members": [{"id": m["id"], "label": m.get("label") or m["value"], "status": m.get("status")}
                        for m in members],
            "links": [x for x in links if x["a"] in ids and x["b"] in ids],
            "includes_confirmed": any(m.get("status") == "confirmed" for m in members),
        })  # fmt: skip
    out.sort(key=lambda g: (not g["includes_confirmed"], -len(g["members"])))  # type: ignore[arg-type]
    return out


def cluster_reasons(data: dict[str, Any]) -> dict[str, list[str]]:
    """For each open candidate, what it strongly shares with a confirmed account (for the score)."""
    cands = data.get("candidates") or {}
    confirmed = [c for c in cands.values() if c.get("status") == "confirmed"]
    out: dict[str, list[str]] = {}
    for cand in cands.values():
        if cand.get("status") != "open":
            continue
        for other in confirmed:
            reasons = [r for r in _pair_reasons(cand, other) if r in STRONG_LINKS]
            if reasons:
                out.setdefault(cand["id"], []).append(
                    f"shares {reasons[0]} with a confirmed account ({other.get('label')})"
                )
    return out


def graph(name: str, data: dict[str, Any], *, include_rejected: bool = False) -> dict[str, Any]:
    """The person at the centre; what is known; the candidates, linked to the detail they were found from;
    links between candidates (shared picture, links, websites); shared websites; and connected people."""
    known = data.get("known") or {}
    nodes: list[dict[str, Any]] = [{"id": "person", "label": name, "type": "person", "status": "subject"}]
    edges: list[dict[str, Any]] = []
    by_value: dict[str, str] = {}
    confirmed_keys = {
        c["key"]: c["id"] for c in (data.get("candidates") or {}).values() if c.get("status") == "confirmed"
    }
    n = 0
    for field in LISTS:
        for value in known.get(field) or []:
            if key_of(field[:-1], value) in confirmed_keys:  # shown once, as the confirmed account
                by_value[key_of(field[:-1], value)] = confirmed_keys[key_of(field[:-1], value)]
                continue
            n += 1
            node_id = f"k{n}"
            nodes.append({"id": node_id, "label": value, "type": field[:-1], "status": "known"})
            edges.append({"source": "person", "target": node_id, "label": "known"})
            by_value[key_of(field[:-1], value)] = node_id
            if field == "profiles":
                handle = handle_from_url(value)
                if handle:
                    by_value.setdefault(key_of("username", handle), node_id)
            if field == "websites":
                by_value.setdefault(key_of("website", _host(value)), node_id)
    shown = [c for c in (data.get("candidates") or {}).values()
             if c.get("status") in ("open", "confirmed") or (include_rejected and c.get("status") == "rejected")]  # fmt: skip
    shown.sort(key=lambda c: (c.get("status") != "confirmed", -(c.get("score") or 0)))
    shown = shown[:150]
    ids = {c["id"] for c in shown}
    for c in shown:
        nodes.append({"id": c["id"], "label": c.get("label") or c["value"], "type": c["kind"], "status": c.get("status"),
                      "verdict": c.get("verdict"), "score": c.get("score"), "url": c.get("url")})  # fmt: skip
        source = "person"
        for f in c.get("found_from") or []:
            source = by_value.get(key_of(f.get("kind", ""), str(f.get("value") or "")), source)
            if source != "person":
                break
        edges.append(
            {"source": source, "target": c["id"], "label": "confirmed" if c.get("status") == "confirmed" else "found"}
        )
    edges.extend(
        {"source": link["a"], "target": link["b"], "label": "; ".join(link["reasons"]), "kind": "shared"}
        for group in clusters({"candidates": {c["id"]: c for c in shown}})
        for link in group["links"]
    )
    host_users: dict[str, list[str]] = {}
    for c in shown:
        for host in _hosts(c):
            host_users.setdefault(host, []).append(c["id"])
    for host, users in host_users.items():
        if len(users) >= 2:
            node_id = f"site:{host}"
            nodes.append({"id": node_id, "label": host, "type": "domain", "status": "shared"})
            edges += [{"source": u, "target": node_id, "label": "links to", "kind": "shared"} for u in users]
    via_label = {c.get("label") or c["value"]: c["id"] for c in shown}
    for i, a in enumerate(associates(data)[:40], 1):
        node_id = f"a{i}"
        nodes.append({"id": node_id, "label": a["name"], "type": "associate", "status": "associate"})
        for via in a["via"]:
            if via in via_label and via_label[via] in ids:
                edges.append(
                    {
                        "source": via_label[via],
                        "target": node_id,
                        "label": ", ".join(a["relations"]),
                        "kind": "associate",
                    }
                )
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------- one timeline, activity, gaps
GAP_DAYS = 365


def _moment(day: str) -> tuple[datetime, str] | None:
    parts = day.split("-")
    try:
        if len(parts) == 1:
            return datetime(int(parts[0]), 1, 1, tzinfo=timezone.utc), "year"
        if len(parts) == 2:
            return datetime(int(parts[0]), int(parts[1]), 1, tzinfo=timezone.utc), "month"
        return datetime(int(parts[0]), int(parts[1]), int(parts[2]), tzinfo=timezone.utc), "day"
    except ValueError:
        return None


def case_timeline_entries(subject_id: str, name: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    """The person's confirmed online life as entries of the case's own timeline."""
    out = []
    for e in timeline(data):
        found = _moment(e["date"])
        if found is None:
            continue
        at, precision = found
        out.append({"at": at, "precision": precision, "kind": "person", "title": f"{name}: {e['title']}",
                    "detail": e.get("url") or "", "ref": {"type": "subject", "id": subject_id, "candidate": e["candidate"]},
                    "by": None})  # fmt: skip
    return out


def activity(data: dict[str, Any]) -> dict[str, Any]:
    """When the person is active: posting hours (UTC) from their channels and account dates, the busiest
    hours, and the long stretches with nothing found (gaps of a year or more between dated findings)."""
    hours: dict[int, int] = {}
    for c in (data.get("candidates") or {}).values():
        if c.get("status") != "confirmed":
            continue
        facts = c.get("facts") or {}
        for hour, count in ((facts.get("channel") or {}).get("post_hours_utc") or {}).items():
            hours[int(hour)] = hours.get(int(hour), 0) + int(count)
        created = str(facts.get("created_at") or "")
        if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}", created):
            hours[int(created[11:13])] = hours.get(int(created[11:13]), 0) + 1
    total = sum(hours.values())
    busiest = sorted(hours, key=lambda h: -hours[h])[:3] if total else []
    events = [(m[0], e) for e in timeline(data) if (m := _moment(e["date"])) is not None]
    events.sort(key=lambda x: x[0])
    gaps = []
    for (a, ea), (b, eb) in pairwise(events):
        days = (b - a).days
        if days >= GAP_DAYS:
            gaps.append({"from": ea["date"], "to": eb["date"], "days": days,
                         "after": ea["title"], "before": eb["title"]})  # fmt: skip
    zone = (data.get("known") or {}).get("utc_offset")
    return {"hours_utc": {str(h): hours[h] for h in sorted(hours)}, "samples": total, "busiest_utc": busiest,
            "utc_offset": zone, "gaps": gaps,
            "note": "Hours are in UTC; with a known time zone, local time = UTC + offset. A few samples say little."}  # fmt: skip
