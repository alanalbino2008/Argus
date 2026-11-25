"""Audit log exports that can be checked offline (Phase 92).

An auditor, regulator or court wants the audit trail as a file, and wants to know it was not edited
after it left Argus. A JSON Lines export holds one entry per line, each with its place in the
hash chain (``id``, ``prev_hash``, ``hash``), and ends with a **manifest** line:

* the SHA-256 of every line before it, the number of entries, the filters used, who exported it;
* the chain's head (newest id and hash) at export time, so the export can be matched later against
  the live chain;
* an Ed25519 signature by this server's report-signing key (the key whose public half is at
  ``/api/report-signing-key``) over all of that.

:func:`verify` (``argus --verify-audit export.jsonl``) checks, without Argus:

1. every line's ``hash`` is SHA-256(``prev_hash`` + the entry), so no entry was altered;
2. where ids follow one another, each ``prev_hash`` is the previous line's ``hash``, so nothing was
   removed or inserted between them. A workspace's export skips other workspaces' entries; the
   gaps are reported, not treated as errors. A platform-wide export with no filter has none;
3. the manifest's digest matches the lines, and its signature is valid (and, given a trusted key,
   made by that key).
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from typing import Any

PREFIX = b"argus-audit-export-v1\n"
ENTRY_FIELDS = ("ts", "actor_id", "actor_name", "action", "resource", "outcome", "ip", "details")
GENESIS = "0" * 64


class VerificationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def entry_of(line: dict[str, Any]) -> dict[str, Any]:
    """The hashed part of an exported line (exactly what the audit log hashed)."""
    scope = {"workspace_id": line["workspace_id"]} if line.get("workspace_id") else {}
    return {**scope, **{k: line.get(k) for k in ENTRY_FIELDS}}


def digest(prev_hash: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(entry)).hexdigest()


def _manifest_message(manifest: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    return PREFIX + hashlib.sha256(_canonical(unsigned)).digest()


def jsonl(rows: list[dict[str, Any]], manifest: dict[str, Any], signer: Any) -> bytes:
    """The export: one entry per line, then the signed manifest."""
    body = b"".join(json.dumps(r, sort_keys=True, default=str, ensure_ascii=False).encode() + b"\n" for r in rows)
    manifest = {
        **manifest, "format": "argus-audit-export-v1", "entries": len(rows),
        "first_id": rows[0]["id"] if rows else None, "last_id": rows[-1]["id"] if rows else None,
        "sha256": hashlib.sha256(body).hexdigest(), "algorithm": "Ed25519",
        "public_key": signer.public_key, "key_id": signer.key_id,
    }  # fmt: skip
    manifest["signature"] = base64.b64encode(signer.private.sign(_manifest_message(manifest))).decode()
    return body + json.dumps({"manifest": manifest}, sort_keys=True).encode() + b"\n"


def to_csv(rows: list[dict[str, Any]]) -> bytes:
    """A spreadsheet view (not signed: use JSON Lines for evidence)."""
    out = io.StringIO()
    columns = ["id", "ts", "workspace_id", "actor_id", "actor_name", "action", "resource", "outcome", "ip",
               "details", "prev_hash", "hash"]  # fmt: skip
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        cells = {**row, "details": json.dumps(row.get("details") or {}, sort_keys=True, default=str)}
        # A cell starting with = + - @ is a formula to a spreadsheet: neutralise it (CSV injection).
        writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v)
                         for k, v in cells.items()})  # fmt: skip
    return out.getvalue().encode()


def verify(data: bytes, trusted_key: str | None = None) -> dict[str, Any]:
    """Check an export. Returns a summary; raises VerificationError on the first problem found."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    lines = data.splitlines(keepends=True)
    if not lines:
        raise VerificationError("The file is empty")
    try:
        manifest = json.loads(lines[-1])["manifest"]
    except (ValueError, KeyError, TypeError) as exc:
        raise VerificationError("The last line is not an Argus audit export manifest") from exc
    body = b"".join(lines[:-1])
    if hashlib.sha256(body).hexdigest() != manifest.get("sha256"):
        raise VerificationError("The entries do not match the manifest: lines were changed, added or removed")
    if trusted_key and trusted_key.strip() != manifest.get("public_key"):
        raise VerificationError("The export was signed by a different key than the one you trust")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(manifest["public_key"]))
        public.verify(base64.b64decode(manifest["signature"]), _manifest_message(manifest))
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise VerificationError("The manifest's signature is not valid") from exc

    previous: dict[str, Any] | None = None
    gaps = 0
    for number, raw in enumerate(lines[:-1], start=1):
        line = json.loads(raw)
        if digest(line["prev_hash"], entry_of(line)) != line["hash"]:
            raise VerificationError(f"Entry {line.get('id')} (line {number}) was altered")
        if previous is not None:
            if line["id"] == previous["id"] + 1:
                if line["prev_hash"] != previous["hash"]:
                    raise VerificationError(f"The chain breaks before entry {line['id']} (line {number})")
            elif line["id"] <= previous["id"]:
                raise VerificationError(f"Entries are out of order at line {number}")
            else:
                gaps += 1  # entries of other workspaces, or outside the filters
        elif line["id"] == 1 and line["prev_hash"] != GENESIS:
            raise VerificationError("The first entry of the chain does not start from the genesis hash")
        previous = line
    if len(lines) - 1 != manifest.get("entries"):
        raise VerificationError("The number of entries does not match the manifest")
    return {
        "valid": True, "entries": manifest["entries"], "first_id": manifest.get("first_id"),
        "last_id": manifest.get("last_id"), "gaps": gaps, "complete_chain": gaps == 0,
        "head": manifest.get("head"), "exported_at": manifest.get("exported_at"),
        "exported_by": manifest.get("exported_by"), "scope": manifest.get("scope"), "filters": manifest.get("filters"),
        "key_id": manifest.get("key_id"), "trusted_key_checked": bool(trusted_key),
    }  # fmt: skip
