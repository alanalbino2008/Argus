"""The evidence bundle: a case, exported so that anyone can check it without Argus.

The ZIP holds, for every capture, its files, its manifest, its chain of custody and its RFC 3161
timestamp token, plus the case notes, entities, links and timeline. ``SHA256SUMS`` lists every
file, so ``sha256sum -c SHA256SUMS`` proves nothing was changed after export. ``README.txt``
explains, in plain words, how to check each layer.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any

from argus import __version__
from argus.core import csvsafe
from argus.evidence.capture import sha256

README = """EVIDENCE BUNDLE: {title}
Exported {exported} by {by} with Argus {version}.

WHAT IS HERE
  case.json            The case: purpose, notes, people and other entities, links, timeline.
  timeline.csv         Every dated event and capture, in order. A cell a spreadsheet would run as a
                       formula starts with a ' (CSV-injection guard); case.json holds the exact text.
  captures/<id>/       One folder per piece of evidence:
     files/            The preserved files (page.html, screenshot.png, text.txt, ...).
     manifest.json     What was captured, from where, when, and the SHA-256 of every file.
     custody.json      Chain of custody: who captured, viewed, downloaded or exported it.
     timestamp.tsr     (If present) an RFC 3161 trusted timestamp of the capture digest.
  SHA256SUMS           The SHA-256 of every file in this bundle.

HOW TO CHECK IT
  1. Nothing changed since export:     sha256sum -c SHA256SUMS
  2. The files match their capture:    compare each file's SHA-256 with manifest.json.
  3. The capture digest:               the SHA-256 of manifest.json written as canonical JSON
                                       (keys sorted, no spaces) equals the "digest" in custody.json.
  4. It existed at the stated time:    openssl ts -verify -digest <digest> -in timestamp.tsr \\
                                         -CAfile <the timestamp authority's certificate>
                                       This needs no trust in Argus or in whoever captured it.
  5. Chain of custody: each entry's hash = SHA-256 of
       previous hash | seq | time | person | action | detail | digest
     so a removed or edited entry breaks every hash after it.

Captured HTML can contain scripts written by whoever published the page. Open it in a text editor,
or a browser with scripts disabled.
"""


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "file"


def build_bundle(case: dict[str, Any], items: list[dict[str, Any]], captures: list[dict[str, Any]],
                 *, by: str) -> bytes:  # fmt: skip
    """``captures``: each with ``manifest``, ``digest``, ``files`` {name: (media, bytes)}, ``custody`` and ``token``."""
    exported = datetime.now(timezone.utc)
    buffer = io.BytesIO()
    sums: list[str] = []

    def add(zf: zipfile.ZipFile, path: str, data: bytes) -> None:
        zf.writestr(path, data)
        sums.append(f"{sha256(data)}  {path}")

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        add(zf, "README.txt", README.format(title=case["title"], exported=exported.isoformat(), by=by,
                                           version=__version__).encode())  # fmt: skip
        add(zf, "case.json", json.dumps({"case": case, "items": items, "exported_at": exported.isoformat(),
                                         "exported_by": by}, indent=2, ensure_ascii=False).encode())  # fmt: skip
        timeline = io.StringIO()
        writer = csvsafe.writer(timeline)
        writer.writerow(["When", "Kind", "Title", "Details"])
        events = [(i["occurred_at"], i["kind"], i["title"], i["body"][:500]) for i in items if i.get("occurred_at")]
        events += [(c["captured_at"], "capture", c["title"] or c.get("url") or c["id"], f"digest {c['digest']}")
                   for c in captures]  # fmt: skip
        for row in sorted(events, key=lambda e: e[0] or ""):
            writer.writerow(row)
        add(zf, "timeline.csv", timeline.getvalue().encode())
        for c in captures:
            base = f"captures/{c['id']}"
            for name, (_media, data) in sorted(c["files"].items()):
                add(zf, f"{base}/files/{_safe(name)}", data)
            add(
                zf,
                f"{base}/manifest.json",
                json.dumps(c["manifest"], indent=2, sort_keys=True, ensure_ascii=False).encode(),
            )
            add(zf, f"{base}/custody.json", json.dumps({"capture": c["id"], "digest": c["digest"],
                                                        "custody": c["custody"]}, indent=2).encode())  # fmt: skip
            if c.get("token"):
                add(zf, f"{base}/timestamp.tsr", c["token"])
        zf.writestr("SHA256SUMS", "\n".join(sums) + "\n")
    return buffer.getvalue()
