"""What a file gives away: hidden metadata in photos and documents, and signs of editing.

Photos and documents carry far more than they show. A photo can hold the camera, its serial
number, the moment it was taken and the GPS position; a Word file the author's name, who last
edited it, the company and how long it was worked on; a PDF the software that made it and whether
it was changed afterwards. For an investigator that is evidence. For a source it can be a danger,
which is why Argus can also produce a **clean copy** with the metadata removed.

Everything here runs on Argus's server, on a file that may be hostile:

* sizes are capped and decompression bombs refused (Pillow's limits, a pixel cap, bounded reads
  from ZIP members);
* XML is parsed with ``defusedxml`` (no external entities, no entity expansion);
* PDFs are read without running anything they contain, and their JavaScript and attachments are
  reported, never executed;
* every parser's failure is reported as "could not read", never as a crash.

**Findings are leads, not verdicts.** Missing metadata is normal for anything that passed through
social media; editing software does not mean deception; a matching thumbnail does not prove a
photo is authentic. Each finding says what it suggests and why.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import re
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from defusedxml import ElementTree as SafeXML
from PIL import ExifTags, Image, ImageChops, ImageOps, UnidentifiedImageError

from argus.intel.avatars import distance, fingerprint
from argus.intel.sun import sun_position

MAX_PIXELS = 60_000_000
MAX_XML = 5 * 1024 * 1024
MAX_PDF_SCAN = 50 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # larger images raise DecompressionBombError instead of exhausting memory

EDITORS = ("photoshop", "gimp", "lightroom", "snapseed", "canva", "pixelmator", "affinity", "paint.net", "picsart",
           "facetune", "meitu", "photopea", "luminar", "capture one", "darktable", "krita")  # fmt: skip
AI_SOURCE_TYPES = ("trainedalgorithmicmedia", "compositewithtrainedalgorithmicmedia", "algorithmicmedia")
AI_TEXT_KEYS = ("parameters", "prompt", "workflow", "invokeai_metadata", "sd-metadata", "dream")
TYPES = {
    "image/jpeg": "JPEG image", "image/png": "PNG image", "image/gif": "GIF image", "image/webp": "WebP image",
    "image/tiff": "TIFF image", "image/heic": "HEIC photo (iPhone)", "application/pdf": "PDF document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel workbook",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint presentation",
    "application/zip": "ZIP archive",
}  # fmt: skip
EXTENSIONS = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp",
              "tif": "image/tiff", "tiff": "image/tiff", "heic": "image/heic", "pdf": "application/pdf",
              "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
              "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
              "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
              "zip": "application/zip"}  # fmt: skip
CLEANABLE = {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/gif"}


class Report:
    """What one file reveals, grouped for display."""

    def __init__(self) -> None:
        self.groups: dict[str, list[dict[str, Any]]] = {}
        self.findings: list[dict[str, str]] = []
        self.data: dict[str, Any] = {}

    def add(self, group: str, label: str, value: Any) -> None:
        if value in (None, "", [], b""):
            return
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        text = " ".join(str(value).replace("\x00", "").split())[:500]
        if text:
            self.groups.setdefault(group, []).append({"label": label, "value": text})

    def finding(self, level: str, text: str) -> None:
        if not any(f["text"] == text for f in self.findings):
            self.findings.append({"level": level, "text": text})


# ---------------------------------------------------------------------------- the file type
def detect_type(data: bytes) -> str | None:
    """The real type from the first bytes, whatever the file is called."""
    head = data[:64]
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if head[4:8] == b"ftyp" and head[8:12] in (b"heic", b"heix", b"mif1", b"heim", b"heis", b"hevc"):
        return "image/heic"
    if b"%PDF-" in data[:1024]:
        return "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            names = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
        except (zipfile.BadZipFile, OSError, ValueError):
            return "application/zip"
        for folder, media in (("word/", "wordprocessingml.document"), ("xl/", "spreadsheetml.sheet"),
                              ("ppt/", "presentationml.presentation")):  # fmt: skip
            if any(n.startswith(folder) for n in names):
                return f"application/vnd.openxmlformats-officedocument.{media}"
        return "application/zip"
    return None


def inspect_file(name: str, media_type: str, data: bytes, *, source_url: str | None = None) -> dict[str, Any]:
    """Everything Argus can tell about one file."""
    report = Report()
    real = detect_type(data)
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    claimed = EXTENSIONS.get(extension) or (media_type if media_type in TYPES else None)
    report.add("File", "Name", name)
    report.add("File", "Size", f"{len(data):,} bytes")
    report.add("File", "Type", TYPES.get(real or "", real or "unknown"))
    report.add("File", "SHA-256", hashlib.sha256(data).hexdigest())
    report.add("File", "MD5", hashlib.md5(data, usedforsecurity=False).hexdigest())  # what many databases index
    if (
        real
        and claimed
        and real != claimed
        and not (real == "application/zip" and claimed.startswith("application/vnd"))
    ):
        report.finding("warning", f"The file is named or labelled as {TYPES.get(claimed, claimed)}, but it is really "
                                  f"a {TYPES.get(real, real)}. Someone may have disguised it.")  # fmt: skip
    kind = "other"
    try:
        if real and real.startswith("image/"):
            kind = "image"
            _image(data, real, report)
        elif real == "application/pdf":
            kind = "pdf"
            _pdf(data, report)
        elif real and real.startswith("application/vnd.openxmlformats"):
            kind = "office"
            _office(data, report)
        else:
            report.finding("info", "Argus reads metadata from photos, PDFs and Word, Excel and PowerPoint files.")
    except Image.DecompressionBombError:
        report.finding("warning", "The image is too large to open safely (a possible decompression bomb).")
    except (OSError, ValueError, SyntaxError, KeyError, IndexError, struct.error, zipfile.BadZipFile) as exc:
        report.finding("notice", f"Part of the file could not be read ({type(exc).__name__}); it may be damaged.")
    return {
        "name": name, "kind": kind, "type": real, "type_label": TYPES.get(real or "", "Unknown"),
        "groups": [{"group": g, "fields": f} for g, f in report.groups.items()],
        "findings": report.findings, "gps": report.data.get("gps"), "taken_at": report.data.get("taken_at"),
        "sun": report.data.get("sun"), "image": report.data.get("image"),
        "cleanable": real in CLEANABLE, "error_level": real == "image/jpeg",
        "reverse_search": reverse_search(source_url) if kind == "image" else [],
    }  # fmt: skip


# ---------------------------------------------------------------------------- images
EXIF_FIELDS = {
    "Camera": [("Make", "Make"), ("Model", "Model"), ("LensMake", "Lens maker"), ("LensModel", "Lens"),
               ("BodySerialNumber", "Camera serial number"), ("LensSerialNumber", "Lens serial number"),
               ("CameraOwnerName", "Camera owner")],
    "Settings": [("FNumber", "Aperture (f/)"), ("ExposureTime", "Exposure (s)"), ("ISOSpeedRatings", "ISO"),
                 ("FocalLength", "Focal length (mm)"), ("FocalLengthIn35mmFilm", "Focal length (35 mm equiv.)"),
                 ("Flash", "Flash"), ("Orientation", "Orientation")],
    "Dates": [("DateTimeOriginal", "Taken"), ("OffsetTimeOriginal", "Taken (UTC offset)"),
              ("DateTimeDigitized", "Digitised"), ("DateTime", "Last changed")],
    "Software and people": [("Software", "Software"), ("Artist", "Artist"), ("Copyright", "Copyright"),
                            ("ImageDescription", "Description"), ("XPAuthor", "Author (Windows)"),
                            ("XPComment", "Comment (Windows)"), ("UserComment", "User comment"),
                            ("HostComputer", "Computer"), ("ImageUniqueID", "Unique image ID")],
}  # fmt: skip


def _exif_values(img: Image.Image) -> dict[str, Any]:
    exif = img.getexif()
    values: dict[str, Any] = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}
    with contextlib.suppress(KeyError, ValueError, TypeError, struct.error):
        values.update({ExifTags.TAGS.get(k, str(k)): v for k, v in exif.get_ifd(ExifTags.IFD.Exif).items()})
    try:
        values["_gps"] = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in exif.get_ifd(ExifTags.IFD.GPSInfo).items()}
    except (KeyError, ValueError, TypeError, struct.error):
        values["_gps"] = {}
    for key in ("XPAuthor", "XPComment"):
        raw = values.get(key)
        if isinstance(raw, (bytes, tuple)):
            values[key] = bytes(raw).decode("utf-16-le", "replace").rstrip("\x00")
    if isinstance(values.get("UserComment"), bytes):
        values["UserComment"] = values["UserComment"][8:].decode("utf-8", "replace").strip("\x00 ")
    return values


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _gps(raw: dict[str, Any]) -> dict[str, Any] | None:
    def degrees(dms: Any, ref: Any) -> float | None:
        try:
            d, m, s = (float(x) for x in dms)
        except (TypeError, ValueError, ZeroDivisionError):
            return None
        value = d + m / 60 + s / 3600
        return -value if str(ref).upper().startswith(("S", "W")) else value

    lat = degrees(raw.get("GPSLatitude"), raw.get("GPSLatitudeRef"))
    lon = degrees(raw.get("GPSLongitude"), raw.get("GPSLongitudeRef"))
    if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    out: dict[str, Any] = {"latitude": round(lat, 6), "longitude": round(lon, 6),
                           "map_url": f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=17/{lat:.6f}/{lon:.6f}"}  # fmt: skip
    alt = _number(raw.get("GPSAltitude"))
    if alt is not None:
        out["altitude_m"] = round(-alt if raw.get("GPSAltitudeRef") in (1, b"\x01") else alt, 1)
    direction = _number(raw.get("GPSImgDirection"))
    if direction is not None:
        out["camera_facing"] = round(direction, 1)
    try:
        h, m, s = (float(x) for x in raw["GPSTimeStamp"])
        day = datetime.strptime(str(raw["GPSDateStamp"]).strip("\x00"), "%Y:%m:%d").replace(tzinfo=timezone.utc)
        out["time_utc"] = (day + timedelta(hours=h, minutes=m, seconds=s)).isoformat()
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        pass
    return out


def _taken(values: dict[str, Any]) -> tuple[datetime | None, bool]:
    """When the photo was taken, and whether the time zone is known."""
    raw = values.get("DateTimeOriginal") or values.get("DateTimeDigitized")
    if not raw:
        return None, False
    try:
        local = datetime.strptime(str(raw).strip("\x00 ")[:19], "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None, False
    offset = str(values.get("OffsetTimeOriginal") or values.get("OffsetTime") or "").strip("\x00 ")
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", offset)
    if match:
        sign = -1 if match.group(1) == "-" else 1
        tz = timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))
        return local.replace(tzinfo=tz), True
    return local, False


def _image(data: bytes, media: str, report: Report) -> None:
    if media == "image/heic":
        report.finding("notice", "HEIC photos (iPhone) cannot be read here yet: convert to JPEG on the phone with "
                                 "metadata kept, or export the original, to inspect it.")  # fmt: skip
        return
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except UnidentifiedImageError as exc:
        raise ValueError("unreadable image") from exc
    width, height = img.size
    report.add("Image", "Dimensions", f"{width} x {height} pixels")
    report.add("Image", "Colour mode", img.mode)
    frames = getattr(img, "n_frames", 1)
    if frames > 1:
        report.add("Image", "Frames", frames)
    phash = fingerprint(data)
    report.data["image"] = {"width": width, "height": height, "perceptual_hash": phash}
    report.add("Image", "Perceptual hash", phash)

    values = _exif_values(img)
    for group, fields in EXIF_FIELDS.items():
        for key, label in fields:
            value = values.get(key)
            if isinstance(value, float):
                value = round(value, 4)
            report.add(group, label, value)
    gps = _gps(values.get("_gps") or {})
    camera = values.get("Make") or values.get("Model")
    text = _image_text(img, data)
    for key, value in text.items():
        report.add("Embedded text", key, value[:500])

    if gps:
        report.data["gps"] = gps
        report.add("Location", "Latitude, longitude", f"{gps['latitude']}, {gps['longitude']}")
        report.add("Location", "Altitude (m)", gps.get("altitude_m"))
        report.add("Location", "Camera facing (°)", gps.get("camera_facing"))
        report.add("Location", "GPS time (UTC)", gps.get("time_utc"))
        report.finding("notice", "The photo records where it was taken. That can confirm a claimed location, or "
                                 "reveal someone's home: handle it carefully, and never publish it with this metadata.")  # fmt: skip
    if not camera and not values.get("DateTimeOriginal") and not gps:
        report.finding("info", "No camera details or date. Social networks and messaging apps remove them, so this "
                               "is normal for images saved from the web; it says nothing about authenticity either way.")  # fmt: skip
    software = str(values.get("Software") or "").strip("\x00 ")
    editor = next((e for e in EDITORS if e in software.lower() or e in text.get("CreatorTool", "").lower()), None)
    if editor:
        report.finding("notice", f"Saved by editing software ({software or text.get('CreatorTool')}). Editing is "
                                 "often harmless (cropping, brightness), but the image is not as the camera took it.")  # fmt: skip

    taken, zoned = _taken(values)
    if taken is not None:
        report.data["taken_at"] = {"value": taken.isoformat(), "time_zone_known": zoned}
        changed = values.get("DateTime")
        try:
            changed_at = datetime.strptime(str(changed).strip("\x00 ")[:19], "%Y:%m:%d %H:%M:%S") if changed else None
        except ValueError:
            changed_at = None
        if changed_at and changed_at - taken.replace(tzinfo=None) > timedelta(minutes=5):
            report.finding("notice", f"Changed on {changed_at:%d %b %Y %H:%M}, after it was taken on "
                                     f"{taken:%d %b %Y %H:%M}: it was edited or re-saved later.")  # fmt: skip
    if gps and gps.get("time_utc") and taken is not None:
        gps_time = datetime.fromisoformat(gps["time_utc"])
        if zoned:
            gap = abs((taken - gps_time).total_seconds())
            if gap > 300:
                report.finding("notice", f"The camera clock and the GPS disagree by {gap / 60:.0f} minutes. Clocks drift, "
                                         "but a large gap can mean the date was changed.")  # fmt: skip
        else:
            hours = (taken.replace(tzinfo=timezone.utc) - gps_time).total_seconds() / 3600
            if abs(hours) <= 14:
                report.add("Dates", "Camera time zone (from GPS)", f"UTC{round(hours * 4) / 4:+g}")
    when = (datetime.fromisoformat(gps["time_utc"]) if gps and gps.get("time_utc")
            else taken if taken is not None and zoned else None)  # fmt: skip
    if gps and when is not None:
        report.data["sun"] = sun_position(gps["latitude"], gps["longitude"], when)
    _thumbnail(data, phash, report)
    _ai_and_credentials(data, text, report)


def photo_facts(data: bytes) -> dict[str, Any]:
    """Only where and when a photo was taken (for the case map and timeline). Never raises."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            values = _exif_values(img)
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, struct.error, Image.DecompressionBombError):
        return {}
    facts: dict[str, Any] = {}
    gps = _gps(values.get("_gps") or {})
    if gps:
        facts.update(lat=gps["latitude"], lon=gps["longitude"])
    taken, zoned = _taken(values)
    if taken is None and gps and gps.get("time_utc"):
        taken, zoned = datetime.fromisoformat(gps["time_utc"]), True
    if taken is not None:
        facts.update(taken_at=taken.isoformat(), time_zone_known=zoned)
    return facts


def _image_text(img: Image.Image, data: bytes) -> dict[str, str]:
    """PNG text chunks, and the few XMP fields worth showing."""
    info = getattr(img, "text", None) or {}
    out: dict[str, str] = {k: v for k, v in list(info.items())[:30]
                           if isinstance(v, str) and k.lower() != "xml:com.adobe.xmp"}  # fmt: skip
    start = data.find(b"<x:xmpmeta")
    if start != -1:
        end = data.find(b"</x:xmpmeta>", start, start + 2_000_000)
        xmp = data[start : end + 12 if end != -1 else start + 200_000].decode("utf-8", "replace")
        for key in ("CreatorTool", "DigitalSourceType", "DateCreated", "Credit", "Headline", "City", "Country",
                    "History"):  # fmt: skip
            match = re.search(rf'(?:\w+:)?{key}="([^"]{{1,500}})"|<(?:\w+:)?{key}>([^<]{{1,500}})<', xmp)
            if match:
                out[key] = match.group(1) or match.group(2)
        agents = sorted(set(re.findall(r'softwareAgent="([^"]{1,200})"', xmp)))
        if agents:
            out["Edit history (software)"] = ", ".join(agents)
    return out


def _thumbnail(data: bytes, phash: str | None, report: Report) -> None:
    """A JPEG's embedded preview, made by the camera: if it shows a different picture, the image changed."""
    thumb = jpeg_thumbnail(data)
    if thumb is None:
        return
    report.add("Image", "Embedded preview", f"{len(thumb):,} bytes")
    small = fingerprint(thumb)
    if phash and small and distance(phash, small) > 16:
        report.finding("warning", "The camera's embedded preview shows a different picture from the image itself. "
                                  "The image was most likely edited after it was taken while the preview was not "
                                  "updated; compare them side by side before relying on it.")  # fmt: skip


def jpeg_thumbnail(data: bytes) -> bytes | None:
    """The thumbnail in a JPEG's EXIF block (IFD1), if any. Bounds-checked: the file may be hostile."""
    if not data.startswith(b"\xff\xd8"):
        return None
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker, size = data[pos + 1], struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if marker == 0xE1 and data[pos + 4 : pos + 10] == b"Exif\x00\x00":
            return _ifd1_thumbnail(data[pos + 10 : pos + 2 + size])
        if marker in (0xDA, 0xD9):  # image data starts: no more metadata
            return None
        pos += 2 + size
    return None


def _ifd1_thumbnail(tiff: bytes) -> bytes | None:
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return None
    order = "<" if tiff[:2] == b"II" else ">"
    ifd0 = struct.unpack(order + "I", tiff[4:8])[0]
    if ifd0 + 2 > len(tiff):
        return None
    count = struct.unpack(order + "H", tiff[ifd0 : ifd0 + 2])[0]
    next_at = ifd0 + 2 + 12 * count
    if next_at + 4 > len(tiff):
        return None
    ifd1 = struct.unpack(order + "I", tiff[next_at : next_at + 4])[0]
    if not ifd1 or ifd1 + 2 > len(tiff):
        return None
    entries = struct.unpack(order + "H", tiff[ifd1 : ifd1 + 2])[0]
    offset = length = None
    for i in range(min(entries, 64)):
        at = ifd1 + 2 + 12 * i
        if at + 12 > len(tiff):
            break
        tag = struct.unpack(order + "H", tiff[at : at + 2])[0]
        value = struct.unpack(order + "I", tiff[at + 8 : at + 12])[0]
        if tag == 0x0201:
            offset = value
        elif tag == 0x0202:
            length = value
    if offset is None or not length or offset + length > len(tiff) or length > 1_000_000:
        return None
    return tiff[offset : offset + length]


def _ai_and_credentials(data: bytes, text: dict[str, str], report: Report) -> None:
    source_type = text.get("DigitalSourceType", "").lower()
    if any(t in source_type.rsplit("/", 1)[-1] for t in AI_SOURCE_TYPES):
        report.finding("warning", "The image is labelled as made or changed by AI (IPTC digital source type: "
                                  f"{source_type.rsplit('/', 1)[-1]}).")  # fmt: skip
    if any(k.lower() in AI_TEXT_KEYS for k in text):
        report.finding("warning", "The image contains AI image-generator settings (such as a prompt). It was very "
                                  "likely generated by AI (Stable Diffusion, ComfyUI or similar).")  # fmt: skip
    if b"c2pa" in data[:2_000_000] and b"jumb" in data[:2_000_000]:
        report.finding("info", "The image carries Content Credentials (C2PA): a signed record of how it was made "
                               "and edited. Check it at https://contentcredentials.org/verify.")  # fmt: skip


def error_level(data: bytes, quality: int = 90) -> bytes:
    """Error level analysis: re-save a JPEG and show where it changes most, amplified.

    Areas pasted in or edited after the last save often re-compress differently from the rest and
    stand out. It is a guide for the eye, not proof: edges, text and smooth skies also stand out.
    """
    with Image.open(io.BytesIO(data)) as img:
        if img.format != "JPEG":
            raise ValueError("error level analysis works on JPEG images")
        original = ImageOps.exif_transpose(img).convert("RGB")
    if max(original.size) > 2400:
        original.thumbnail((2400, 2400))
    buffer = io.BytesIO()
    original.save(buffer, "JPEG", quality=quality)
    resaved = Image.open(io.BytesIO(buffer.getvalue()))
    diff = ImageChops.difference(original, resaved)
    extrema: Any = diff.getextrema()  # one (low, high) pair per colour band
    peak = max(int(high) for _low, high in extrema) or 1
    scale = 255.0 / peak
    amplified = diff.point(lambda v: min(255, int(v * scale)))
    out = io.BytesIO()
    amplified.save(out, "PNG")
    return out.getvalue()


def clean_copy(data: bytes) -> tuple[bytes, str, str]:
    """The picture alone: no EXIF, GPS, XMP, text chunks or colour profile. Returns (bytes, media, extension)."""
    with Image.open(io.BytesIO(data)) as img:
        fmt = img.format or "PNG"
        upright = ImageOps.exif_transpose(img)  # keep it the right way up once the orientation tag is gone
        pixels = upright.copy()
        pixels.info = {}  # no EXIF, XMP, ICC profile or text: only what is passed to save() is written
    out = io.BytesIO()
    if fmt in ("JPEG", "MPO"):
        pixels.convert("RGB").save(out, "JPEG", quality=95)
        return out.getvalue(), "image/jpeg", "jpg"
    if fmt == "WEBP":
        pixels.save(out, "WEBP", quality=95)
        return out.getvalue(), "image/webp", "webp"
    if pixels.mode not in ("RGB", "RGBA", "L", "LA", "P"):
        pixels = pixels.convert("RGBA")
    pixels.save(out, "PNG")
    return out.getvalue(), "image/png", "png"


def reverse_search(url: str | None) -> list[dict[str, str]]:
    """Reverse image search engines: by address when the image is public, else their upload pages."""
    from urllib.parse import quote

    engines = [
        ("Google Lens", "https://lens.google.com/uploadbyurl?url={}", "https://lens.google.com/"),
        ("Bing Visual Search", "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{}",
         "https://www.bing.com/visualsearch"),
        ("Yandex Images", "https://yandex.com/images/search?rpt=imageview&url={}", "https://yandex.com/images/"),
        ("TinEye", "https://tineye.com/search?url={}", "https://tineye.com/"),
    ]  # fmt: skip
    public = url if url and url.startswith(("https://", "http://")) else None
    return [{"engine": name, "url": by_url.format(quote(public, safe="")) if public else upload,
             "mode": "address" if public else "upload"} for name, by_url, upload in engines]  # fmt: skip


# ---------------------------------------------------------------------------- PDF
def _pdf_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    match = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", str(value))
    if not match:
        return str(value)[:40]
    parts = [p or "01" if i < 3 else p or "00" for i, p in enumerate(match.groups())]
    return f"{parts[0]}-{parts[1]}-{parts[2]} {parts[3]}:{parts[4]}:{parts[5]}"


def _pdf(data: bytes, report: Report) -> None:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    scan = data[:MAX_PDF_SCAN]
    saves = scan.count(b"%%EOF")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except (PdfReadError, ValueError, OSError) as exc:
        raise ValueError("unreadable PDF") from exc
    if reader.is_encrypted:
        report.finding("notice", "The PDF is encrypted: its contents and most of its metadata cannot be read.")
        try:
            reader.decrypt("")
        except (PdfReadError, ValueError, NotImplementedError):
            return
    info: Any = reader.metadata or {}
    for key, label in (("/Title", "Title"), ("/Author", "Author"), ("/Subject", "Subject"), ("/Keywords", "Keywords"),
                       ("/Creator", "Made with"), ("/Producer", "Converted to PDF by")):  # fmt: skip
        report.add("Document", label, info.get(key))
    created, modified = _pdf_date(info.get("/CreationDate")), _pdf_date(info.get("/ModDate"))
    report.add("Dates", "Created", created)
    report.add("Dates", "Modified", modified)
    try:
        report.add("Document", "Pages", len(reader.pages))
        version = reader.pdf_header.replace("%PDF-", "")
    except (PdfReadError, ValueError, KeyError, TypeError):
        version = ""
    report.add("Document", "PDF version", version)
    try:
        xmp = reader.xmp_metadata
    except (PdfReadError, ValueError, KeyError, TypeError, SyntaxError):
        xmp = None
    if xmp is not None:
        report.add("XMP", "Made with (XMP)", _xmp(xmp, "xmp_creator_tool"))
        report.add("XMP", "Producer (XMP)", _xmp(xmp, "pdf_producer"))
        report.add("XMP", "Document ID", _xmp(xmp, "xmpmm_document_id"))
        report.add("XMP", "Version ID", _xmp(xmp, "xmpmm_instance_id"))
    if saves > 1:
        report.finding("notice", f"The PDF was saved {saves} times: it was changed after it was first made "
                                 "(each later save is appended, and earlier versions may still be inside).")  # fmt: skip
    if created and modified and modified > created:
        report.finding("info", f"Modified ({modified}) after it was created ({created}).")
    if re.search(rb"/(JavaScript|JS)\b", scan):
        report.finding("warning", "The PDF contains JavaScript. Argus does not run it, but be careful opening the "
                                  "file elsewhere: scripts in PDFs are used to track readers or attack them.")  # fmt: skip
    if b"/EmbeddedFile" in scan:
        report.finding("notice", "The PDF has files attached inside it. They may hold more evidence (or malware).")
    if re.search(rb"/(OpenAction|Launch|URI)\b", scan) and re.search(rb"/(Launch|URI)\b", scan):
        report.finding("info", "The PDF contains links or actions that can contact websites when opened, which can "
                               "tell its author who read it and when.")  # fmt: skip
    author, creator = str(info.get("/Author") or ""), str(info.get("/Creator") or "")
    for value in (author, creator, str(info.get("/Title") or "")):
        _paths(value, report)


def _xmp(xmp: Any, attr: str) -> Any:
    try:
        return getattr(xmp, attr, None)
    except (ValueError, KeyError, TypeError, SyntaxError):
        return None


# ---------------------------------------------------------------------------- Word, Excel, PowerPoint
NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/", "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}  # fmt: skip


def _member(archive: zipfile.ZipFile, name: str, cap: int = MAX_XML) -> bytes | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.file_size > cap:  # declared size: refuse zip bombs before reading
        raise ValueError(f"{name} is too large")
    with archive.open(info) as handle:
        return handle.read(cap + 1)[:cap]


def _office(data: bytes, report: Report) -> None:
    archive = zipfile.ZipFile(io.BytesIO(data))
    core = _member(archive, "docProps/core.xml")
    if core:
        root = SafeXML.fromstring(core)
        for path, label, group in (("dc:title", "Title", "Document"), ("dc:subject", "Subject", "Document"),
                                   ("cp:keywords", "Keywords", "Document"), ("dc:description", "Comments", "Document"),
                                   ("dc:creator", "Author", "People"), ("cp:lastModifiedBy", "Last edited by", "People"),
                                   ("cp:revision", "Revision", "Document"), ("dcterms:created", "Created", "Dates"),
                                   ("dcterms:modified", "Last saved", "Dates"),
                                   ("cp:lastPrinted", "Last printed", "Dates")):  # fmt: skip
            node = root.find(path, NS)
            report.add(group, label, node.text if node is not None else None)
        author = (root.findtext("dc:creator", "", NS) or "").strip()
        editor = (root.findtext("cp:lastModifiedBy", "", NS) or "").strip()
        if author and editor and author.lower() != editor.lower():
            report.finding("notice", f"Written by “{author}” but last edited by “{editor}”: more than one person "
                                     "handled it.")  # fmt: skip
        if author or editor:
            report.finding("info", "The file names the people who wrote and edited it. Remove this before sharing "
                                   "anything a source gave you.")  # fmt: skip
    app = _member(archive, "docProps/app.xml")
    if app:
        root = SafeXML.fromstring(app)
        for tag, label, group in (("Application", "Made with", "Software"), ("AppVersion", "Version", "Software"),
                                  ("Company", "Company", "People"), ("Manager", "Manager", "People"),
                                  ("Template", "Template", "Software"), ("TotalTime", "Editing time (minutes)", "Document"),
                                  ("Pages", "Pages", "Document"), ("Words", "Words", "Document"),
                                  ("Slides", "Slides", "Document")):  # fmt: skip
            report.add(group, label, root.findtext(f"ep:{tag}", None, NS))
        for value in (root.findtext("ep:Template", "", NS) or "",):
            _paths(value, report)
    comments = _member(archive, "word/comments.xml")
    if comments:
        root = SafeXML.fromstring(comments)
        authors = sorted({c.get(f"{{{NS['w']}}}author", "") for c in root.iter(f"{{{NS['w']}}}comment")} - {""})
        count = sum(1 for _ in root.iter(f"{{{NS['w']}}}comment"))
        if count:
            report.add("People", "Comment authors", ", ".join(authors))
            report.finding("notice", f"The document has {count} comment(s) by {', '.join(authors) or 'unknown'}. "
                                     "Open it in Word with comments shown to read them.")  # fmt: skip
    document = _member(archive, "word/document.xml", cap=40 * 1024 * 1024)
    if document:
        root = SafeXML.fromstring(document)
        changes = [n for tag in ("ins", "del") for n in root.iter(f"{{{NS['w']}}}{tag}")]
        if changes:
            authors = sorted({c.get(f"{{{NS['w']}}}author", "") for c in changes} - {""})
            report.add("People", "Tracked-change authors", ", ".join(authors))
            report.finding("warning", f"The document still contains {len(changes)} tracked change(s) by "
                                      f"{', '.join(authors) or 'unknown'}: deleted text may be recoverable.")  # fmt: skip
    hidden = [n for n in archive.namelist() if n.startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/"))]
    if hidden:
        report.finding("notice", f"{len(hidden)} other file(s) are embedded inside this one.")


def _paths(value: str, report: Report) -> None:
    match = re.search(r"[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\]+)|/(?:Users|home)/([^/]+)", value)
    if match:
        user = match.group(1) or match.group(2)
        report.add("People", "User name in a file path", user)
        report.finding("notice", f"A file path inside reveals a computer user name: “{user}”.")
