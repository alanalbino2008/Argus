"""A case in time and space: one timeline of everything dated, one map of everything placed.

**Timeline.** Everything in a case that has a date goes on one line:
* events the investigator added;
* changes to watched accounts;
* every capture and upload;
* the scans linked to the case;
* the moment each photo in the evidence was taken, read from its own metadata.

Each entry says where it came from, so it can be traced to the evidence.

**Map.** Everything with a position:
* people's addresses and places given coordinates;
* photos whose GPS says where they were taken;
* addresses the investigator chose to look up (geocode).

Coordinates are read from the forms people paste:
* decimal: ``51.5007, -0.1246``;
* degrees, minutes and seconds: ``51°30'02.5"N 0°07'28.6"W``;
* map links from OpenStreetMap and Google Maps.

**Exports.** KML opens in Google Earth and most mapping tools. CSV opens in spreadsheets, with
cells that begin with ``= + - @`` neutralised so a hostile value cannot run as a formula.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

PLACE_TYPES = {"location", "address"}
_DECIMAL = re.compile(r"^\s*\(?\s*(-?\d{1,2}(?:\.\d+)?)\s*[, ]\s*(-?\d{1,3}(?:\.\d+)?)\s*\)?\s*$")
_DMS = re.compile(
    r"(\d{1,3}(?:\.\d+)?)\s*[\u00b0\u00ba:\s]?\s*(?:(\d{1,2})\s*['\u2032:\s]\s*)?(?:(\d{1,2}(?:\.\d+)?)\s*[\"\u2033]?\s*)?([NSEW])\b",
    re.IGNORECASE,
)
_MAP_LINK = re.compile(r"(?:mlat=|@|q=|query=|ll=)(-?\d{1,2}\.\d+)(?:&mlon=|,|%2C)(-?\d{1,3}\.\d+)")


def _valid(lat: float, lon: float) -> tuple[float, float] | None:
    if -90 <= lat <= 90 and -180 <= lon <= 180 and not (lat == 0 and lon == 0):
        return round(lat, 6), round(lon, 6)
    return None


def parse_coordinates(text: str | None) -> tuple[float, float] | None:
    """Latitude and longitude from decimal, degrees-minutes-seconds or a map link; None if absent."""
    if not text:
        return None
    text = str(text).strip()[:300]
    if match := _DECIMAL.match(text):
        return _valid(float(match.group(1)), float(match.group(2)))
    if match := _MAP_LINK.search(text):
        return _valid(float(match.group(1)), float(match.group(2)))
    parts = _DMS.findall(text)
    if len(parts) == 2:
        values = {}
        for deg, minutes, seconds, hemi in parts:
            value = float(deg) + float(minutes or 0) / 60 + float(seconds or 0) / 3600
            hemi = hemi.upper()
            values["lat" if hemi in "NS" else "lon"] = -value if hemi in "SW" else value
        if set(values) == {"lat", "lon"}:
            return _valid(values["lat"], values["lon"])
    return None


def entity_position(data: dict[str, Any]) -> tuple[float, float, str] | None:
    """Where an entity is, and how that is known ("given" or "looked up")."""
    attrs = {str(k).lower(): v for k, v in (data.get("attributes") or {}).items()}
    for lat_key, lon_key in (("lat", "lon"), ("latitude", "longitude"), ("lat", "lng")):
        if lat_key in attrs and lon_key in attrs:
            try:
                found = _valid(float(attrs[lat_key]), float(attrs[lon_key]))
            except (TypeError, ValueError):
                found = None
            if found:
                return (*found, "looked up" if attrs.get("geocoded_by") else "given")
    for key in ("coordinates", "gps", "position", "map"):
        found = parse_coordinates(attrs.get(key))
        if found:
            return (*found, "given")
    found = parse_coordinates(data.get("value"))
    return (*found, "given") if found else None


# ---------------------------------------------------------------------------- the timeline
def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def build_timeline(items: list[dict[str, Any]], captures: list[dict[str, Any]], scans: list[dict[str, Any]],
                   photos: list[dict[str, Any]]) -> list[dict[str, Any]]:  # fmt: skip
    """Every dated thing in the case, oldest first."""
    entries: list[dict[str, Any]] = []
    photo_events = set()
    for item in items:
        at = _when(item.get("occurred_at"))
        if at is None:
            continue
        data = item.get("data") or {}
        kind = "account" if data.get("watch_id") else "event"
        if item["title"].startswith("Photo taken: "):
            photo_events.add(item["title"].removeprefix("Photo taken: "))
        entries.append({"at": at, "kind": kind, "title": item["title"], "detail": item.get("body") or "",
                        "ref": {"type": "item", "id": item["id"]}, "by": item.get("created_by")})  # fmt: skip
    for c in captures:
        at = _when(c.get("captured_at"))
        if at is None:
            continue
        upload = c.get("kind") == "upload"
        entries.append({"at": at, "kind": "upload" if upload else "capture",
                        "title": f"{'Added' if upload else 'Captured'}: {c.get('title') or c.get('url') or 'evidence'}",
                        "detail": c.get("url") or c.get("note") or "", "ref": {"type": "capture", "id": c["id"]},
                        "by": c.get("captured_by")})  # fmt: skip
    for s in scans:
        at = _when(s.get("started_at"))
        if at is not None:
            entries.append({"at": at, "kind": "scan", "title": f"Scan of {s['target']}", "detail": s.get("status", ""),
                            "ref": {"type": "investigation", "id": s["id"]}, "by": s.get("created_by")})  # fmt: skip
    for p in photos:
        at = _when(p.get("taken_at"))
        if at is None or p["file"] in photo_events:
            continue  # the investigator already put it on the timeline
        detail = "From the photo's own metadata" + ("" if p.get("time_zone_known") else " (camera time zone unknown)")
        entries.append({"at": at, "kind": "photo", "title": f"Photo taken: {p['file']}", "detail": detail,
                        "ref": {"type": "capture", "id": p["capture_id"], "file": p["file"]},
                        "approximate": not p.get("time_zone_known")})  # fmt: skip
    entries.sort(key=lambda e: e["at"])
    return [{**e, "at": e["at"].isoformat()} for e in entries]


# ---------------------------------------------------------------------------- places
def build_places(items: list[dict[str, Any]], photos: list[dict[str, Any]]) -> dict[str, Any]:
    places: list[dict[str, Any]] = []
    unplaced: list[dict[str, Any]] = []
    for item in items:
        data = item.get("data") or {}
        if item.get("kind") != "entity":
            continue
        position = entity_position(data)
        if position is not None:
            lat, lon, how = position
            places.append({"kind": "entity", "type": data.get("type"), "label": data.get("value") or item["title"],
                           "lat": lat, "lon": lon, "how": how, "ref": {"type": "item", "id": item["id"]},
                           "detail": (data.get("attributes") or {}).get("geocoded_name") or item.get("body") or ""})  # fmt: skip
        elif data.get("type") in PLACE_TYPES:
            unplaced.append({"id": item["id"], "type": data.get("type"), "label": data.get("value") or item["title"]})
    places.extend(
        {"kind": "photo", "type": "photo", "label": p["file"], "lat": p["lat"], "lon": p["lon"], "how": "photo GPS",
         "ref": {"type": "capture", "id": p["capture_id"], "file": p["file"]},
         "detail": "Taken " + p["taken_at"][:16].replace("T", " ") if p.get("taken_at") else ""}
        for p in photos if p.get("lat") is not None
    )  # fmt: skip
    return {"places": places, "unplaced": unplaced}


def _placemark(p: dict[str, Any]) -> str:
    description = "{} ({}). {}".format(p["type"], p["how"], p.get("detail") or "")
    return (f"<Placemark><name>{escape(str(p['label']))[:200]}</name>"
            f"<description>{escape(description)[:1000]}</description>"
            f"<Point><coordinates>{p['lon']},{p['lat']},0</coordinates></Point></Placemark>")  # fmt: skip


def kml(case_title: str, places: list[dict[str, Any]]) -> bytes:
    marks = "".join(_placemark(p) for p in places)
    return (f'<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            f"<name>{escape(case_title)[:200]}</name>{marks}</Document></kml>").encode()  # fmt: skip


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def timeline_csv(entries: list[dict[str, Any]]) -> bytes:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time (UTC offset as recorded)", "kind", "title", "detail", "by", "approximate"])
    for e in entries:
        writer.writerow([_cell(e["at"]), e["kind"], _cell(e["title"]), _cell(e.get("detail")), _cell(e.get("by")),
                         "yes" if e.get("approximate") else ""])  # fmt: skip
    return out.getvalue().encode("utf-8-sig")  # the BOM makes Excel read UTF-8 correctly
