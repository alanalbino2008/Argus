"""Backups: everything Argus holds, in one encrypted file, and a safe way back.

**What's in a backup.** A consistent copy of the database (cases, evidence and its files,
custody records, settings, audit log), taken while Argus keeps working, and this installation's
encryption key, without which the encrypted parts of the database can't be read.

**How it's protected.** The file is encrypted with a password the investigator chooses
(scrypt to turn the password into a key, then AES-256-GCM in 4 MB pieces, each bound to its
place in the file, so nothing can be removed, reordered or altered unnoticed). A backup
copied to a cloud folder or a USB stick is useless without that password. Nothing readable
is ever written to the backup folder: the work is done in Argus's own data folder and only
the finished, encrypted file is moved there.

**Restoring** never overwrites anything on the spot. The backup is decrypted and checked
(every file's fingerprint) into a waiting area; at the next start, before the database is
opened, the current database and key are moved aside (kept, in ``before-restore-<time>``)
and the restored ones take their place.

File layout::

    ARGUSBAK\\x01 | header length (4 bytes) | header (JSON) | pieces: length (4 bytes) + sealed piece

The header (not secret) records when and with which Argus version the backup was made, and
the scrypt parameters. The sealed contents are a gzip'd tar of ``argus.db``, ``encryption.key``
(when there is one) and ``manifest.json``.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import logging
import os
import platform
import secrets
import shutil
import sqlite3
import tarfile
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy.engine import make_url

from argus import __version__

logger = logging.getLogger("argus.backup")

MAGIC = b"ARGUSBAK\x01"
SUFFIX = ".argusbackup"
CHUNK = 4 * 1024 * 1024
SCRYPT = {"n": 2**16, "r": 8, "p": 1}
MIN_PASSWORD = 10
RESTORE_DIR = "argus-restore"
MAX_HEADER = 64 * 1024


class BackupError(Exception):
    """A backup could not be made, read or restored (the message is meant for people)."""


# ---------------------------------------------------------------------------- keys
def new_key(password: str) -> dict[str, Any]:
    """A backup key from a password: what scheduled backups keep (sealed) so they run unattended."""
    if len(password) < MIN_PASSWORD:
        raise BackupError(f"Choose a backup password of at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    return {"salt": base64.b64encode(salt).decode(), "key": base64.b64encode(_derive(password, salt)).decode(),
            **SCRYPT}  # fmt: skip


def _derive(password: str, salt: bytes, n: int = SCRYPT["n"], r: int = SCRYPT["r"], p: int = SCRYPT["p"]) -> bytes:
    if not (2**14 <= n <= 2**20 and 1 <= r <= 16 and 1 <= p <= 4):
        raise BackupError("This backup uses settings Argus doesn't accept")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode())


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _aad(header_digest: bytes, index: int) -> bytes:
    return header_digest + index.to_bytes(8, "big")


# ---------------------------------------------------------------------------- what to back up
def sqlite_path(database_url: str) -> Path | None:
    """The database file, when the database is SQLite (PostgreSQL is backed up by its provider)."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    return Path(url.database).expanduser().resolve()


def key_material(settings: Any) -> tuple[str | None, Path | None]:
    """This installation's encryption key, and the file it lives in (if it does)."""
    if settings.encryption_key:
        return settings.encryption_key.get_secret_value(), None
    if settings.encryption_key_file:
        path = Path(settings.encryption_key_file).expanduser()
        with contextlib.suppress(OSError):
            return path.read_text(encoding="utf-8").strip(), path
        return None, path
    return None, None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot(db: Path, out: Path) -> dict[str, int]:
    """A consistent copy of a live SQLite database (other connections keep working meanwhile)."""
    source = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        source.execute("VACUUM INTO ?", (str(out),))
    finally:
        source.close()
    copy = sqlite3.connect(out)
    try:
        counts = {}
        for table in ("cases", "evidence_captures", "investigations"):
            with contextlib.suppress(sqlite3.Error):
                counts[table] = int(copy.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608 - fixed names
        revision = None
        with contextlib.suppress(sqlite3.Error):
            row = copy.execute("SELECT version_num FROM alembic_version").fetchone()
            revision = row[0] if row else None
    finally:
        copy.close()
    return {**counts, "schema": revision}  # type: ignore[dict-item]


# ---------------------------------------------------------------------------- writing
def create(settings: Any, folder: Path, backup_key: dict[str, Any], *, work_dir: Path | None = None,
           label: str = "") -> dict[str, Any]:  # fmt: skip
    """Make one encrypted backup in ``folder``. Blocking: run it in a thread."""
    db = sqlite_path(settings.database_url)
    if db is None or not db.is_file():
        raise BackupError("Only an Argus that keeps its database in a file (SQLite) can back itself up here")
    folder = Path(folder).expanduser()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"Can't use the backup folder {folder}: {exc.strerror or exc}") from exc
    work = Path(work_dir or db.parent)
    now = datetime.now(timezone.utc)
    name = f"argus-backup-{now.strftime('%Y-%m-%d-%H%M%S')}{SUFFIX}"
    with tempfile.TemporaryDirectory(prefix="argus-backup-", dir=work) as tmp:
        tmpdir = Path(tmp)
        snapshot = tmpdir / "argus.db"
        counts = _snapshot(db, snapshot)
        key, _key_file = key_material(settings)
        manifest: dict[str, Any] = {
            "format": 1, "created_at": now.isoformat(), "argus_version": __version__, "schema": counts.pop("schema"),
            "counts": counts, "files": {"argus.db": _sha256(snapshot)}, "computer": platform.node()[:100],
        }  # fmt: skip
        payload = tmpdir / "payload.tar.gz"
        with tarfile.open(payload, "w:gz", compresslevel=6) as tar:
            tar.add(snapshot, arcname="argus.db")
            if key:
                data = key.encode()
                manifest["files"]["encryption.key"] = hashlib.sha256(data).hexdigest()
                _add_bytes(tar, "encryption.key", data)
            _add_bytes(tar, "manifest.json", json.dumps(manifest, indent=2).encode())
        header = {"format": 1, "created_at": now.isoformat(), "argus_version": __version__, "label": label[:100],
                  "kdf": {"name": "scrypt", "salt": backup_key["salt"], "n": backup_key["n"], "r": backup_key["r"],
                          "p": backup_key["p"]}, "nonce": base64.b64encode(secrets.token_bytes(7)).decode()}  # fmt: skip
        sealed = tmpdir / name
        with payload.open("rb") as src, sealed.open("wb") as dst:
            _seal(src, dst, header, base64.b64decode(backup_key["key"]))
        size = sealed.stat().st_size
        final = folder / name
        try:
            partial = folder / (name + ".partial")
            shutil.copyfile(sealed, partial)  # (possibly another drive: copy, then rename into place)
            os.replace(partial, final)
        except OSError as exc:
            with contextlib.suppress(OSError):
                partial.unlink()
            raise BackupError(f"Couldn't write to the backup folder {folder}: {exc.strerror or exc}") from exc
    logger.info("Backup written: %s (%d bytes)", final, size)
    return {"file": str(final), "name": name, "size": size, "created_at": now.isoformat(), "counts": counts}


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o600, int(datetime.now(timezone.utc).timestamp())
    tar.addfile(info, io.BytesIO(data))


def _seal(src: BinaryIO, dst: BinaryIO, header: dict[str, Any], key: bytes) -> None:
    head = json.dumps(header, sort_keys=True).encode()
    dst.write(MAGIC + len(head).to_bytes(4, "big") + head)
    digest, prefix, aead = hashlib.sha256(MAGIC + head).digest(), base64.b64decode(header["nonce"]), AESGCM(key)
    index, piece = 0, src.read(CHUNK)
    while True:
        following = src.read(CHUNK)
        last = not following
        box = aead.encrypt(_nonce(prefix, index, last), piece, _aad(digest, index))
        dst.write(len(box).to_bytes(4, "big") + box)
        if last:
            return
        index, piece = index + 1, following


# ---------------------------------------------------------------------------- reading
def read_header(path: Path) -> dict[str, Any]:
    """What a backup says about itself (no password needed: when, which version)."""
    try:
        with Path(path).open("rb") as fh:
            return _header(fh)[0]
    except OSError as exc:
        raise BackupError(f"Can't open {path}: {exc.strerror or exc}") from exc


def _header(fh: BinaryIO) -> tuple[dict[str, Any], bytes]:
    if fh.read(len(MAGIC)) != MAGIC:
        raise BackupError("This isn't an Argus backup file")
    size = int.from_bytes(fh.read(4), "big")
    if not 0 < size <= MAX_HEADER:
        raise BackupError("This backup file is damaged")
    head = fh.read(size)
    try:
        header = json.loads(head)
    except ValueError as exc:
        raise BackupError("This backup file is damaged") from exc
    if not isinstance(header, dict) or header.get("format") != 1:
        raise BackupError("This backup was made by a newer Argus: update Argus first")
    return header, head


def _open_pieces(fh: BinaryIO, header: dict[str, Any], head: bytes, password: str | None,
                 backup_key: dict[str, Any] | None = None) -> Iterator[bytes]:  # fmt: skip
    kdf = header.get("kdf") or {}
    try:
        if backup_key is not None:  # the unattended key backups are made with: no password needed
            if kdf.get("salt") != backup_key.get("salt"):
                raise BackupError("This backup was made with a different backup password")
            key = base64.b64decode(backup_key["key"])
        else:
            key = _derive(password or "", base64.b64decode(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        prefix = base64.b64decode(header["nonce"])
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupError("This backup file is damaged") from exc
    digest, aead, index = hashlib.sha256(MAGIC + head).digest(), AESGCM(key), 0
    while True:
        size_bytes = fh.read(4)
        if len(size_bytes) < 4:
            raise BackupError("This backup file is incomplete (it may still be copying, or was cut short)")
        box = fh.read(int.from_bytes(size_bytes, "big"))
        last = fh.peek(1)[:1] == b""  # type: ignore[attr-defined]
        try:
            yield aead.decrypt(_nonce(prefix, index, last), box, _aad(digest, index))
        except InvalidTag as exc:
            if index == 0:
                raise BackupError("Wrong backup password (or the file was altered)") from exc
            raise BackupError("This backup file was altered or damaged") from exc
        if last:
            return
        index += 1


def open_backup(
    path: Path, password: str | None, into: Path, *, backup_key: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Decrypt and check a backup into ``into`` (argus.db, encryption.key); returns its manifest."""
    into.mkdir(parents=True, exist_ok=True)
    payload = into / "payload.tar.gz"
    try:
        with Path(path).open("rb") as fh, payload.open("wb") as out:
            header, head = _header(fh)
            for piece in _open_pieces(fh, header, head, password, backup_key):
                out.write(piece)
    except OSError as exc:
        raise BackupError(f"Can't read {path}: {exc.strerror or exc}") from exc
    try:
        with tarfile.open(payload, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name not in ("argus.db", "encryption.key", "manifest.json") or not member.isfile():
                    raise BackupError("This backup contains something unexpected")
                tar.extract(member, into, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError("This backup file is damaged") from exc
    finally:
        payload.unlink(missing_ok=True)
    try:
        manifest = json.loads((into / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("This backup file is damaged") from exc
    for name, digest in (manifest.get("files") or {}).items():
        if not (into / name).is_file() or _sha256(into / name) != digest:
            raise BackupError(f"This backup failed its check ({name} doesn't match its fingerprint)")
    if not (into / "argus.db").is_file():
        raise BackupError("This backup has no database in it")
    return manifest


def check(path: Path, password: str, *, work_dir: Path, known_revisions: set[str] | None = None) -> dict[str, Any]:
    """Open a backup completely and check it, keeping nothing (the 'Check a backup' button)."""
    with tempfile.TemporaryDirectory(prefix="argus-check-", dir=work_dir) as tmp:
        manifest = open_backup(path, password, Path(tmp))
    _check_schema(manifest, known_revisions)
    return _describe(manifest)


def _check_schema(manifest: dict[str, Any], known: set[str] | None) -> None:
    if known is not None and manifest.get("schema") and manifest["schema"] not in known:
        raise BackupError(f"This backup was made by Argus {manifest.get('argus_version')}, newer than this one "
                          f"({__version__}): update Argus, then restore it")  # fmt: skip


def _describe(manifest: dict[str, Any]) -> dict[str, Any]:
    return {"created_at": manifest.get("created_at"), "argus_version": manifest.get("argus_version"),
            "computer": manifest.get("computer"), "counts": manifest.get("counts") or {},
            "has_key": "encryption.key" in (manifest.get("files") or {})}  # fmt: skip


def drill(path: Path, *, work_dir: Path, password: str | None = None,
          backup_key: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """Restore a backup into a scratch folder and prove it works, keeping nothing (Phase 97).

    Beyond :func:`check` (decrypt, every file's fingerprint), the restored database is opened: SQLite's
    integrity check, its foreign keys, its schema revision, and the number of cases, captures and
    investigations against what the backup recorded when it was made."""
    import time

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="argus-drill-", dir=work_dir) as tmp:
        manifest = open_backup(path, password, Path(tmp), backup_key=backup_key)
        conn = sqlite3.connect(f"file:{Path(tmp) / 'argus.db'}?mode=ro", uri=True)
        try:
            integrity = [r[0] for r in conn.execute("PRAGMA integrity_check")]
            if integrity != ["ok"]:
                raise BackupError(f"The restored database is damaged: {'; '.join(integrity[:3])}")
            orphans = conn.execute("PRAGMA foreign_key_check").fetchall()
            if orphans:
                raise BackupError(f"The restored database has {len(orphans)} row(s) referring to missing records")
            revision = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            counts = {}
            for table in manifest.get("counts") or {}:
                if table == "schema":
                    continue
                counts[table] = int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])  # noqa: S608 - manifest names
        except sqlite3.Error as exc:
            raise BackupError(f"The restored database cannot be read ({exc})") from exc
        finally:
            conn.close()
    expected = {k: v for k, v in (manifest.get("counts") or {}).items() if k != "schema"}
    if counts != expected:
        raise BackupError(f"The restored database does not hold what the backup recorded ({counts} vs {expected})")
    return {"backup": Path(path).name, "created_at": manifest.get("created_at"), "schema": revision[0] if revision else None,
            "counts": counts, "seconds": round(time.monotonic() - started, 2)}  # fmt: skip


# ---------------------------------------------------------------------------- restoring
def stage_restore(settings: Any, path: Path, password: str, known_revisions: set[str] | None = None) -> dict[str, Any]:
    """Decrypt and check a backup into the waiting area; it replaces the current data at the next start."""
    db = sqlite_path(settings.database_url)
    if db is None:
        raise BackupError("Only an Argus that keeps its database in a file (SQLite) can be restored here")
    staging = db.parent / RESTORE_DIR
    shutil.rmtree(staging, ignore_errors=True)
    try:
        manifest = open_backup(path, password, staging)
        _check_schema(manifest, known_revisions)
        key, key_file = key_material(settings)
        restored_key = (
            (staging / "encryption.key").read_text().strip() if (staging / "encryption.key").is_file() else None
        )
        if restored_key and key_file is None and restored_key != key:
            raise BackupError("This server's encryption key is set in its configuration (ARGUS_ENCRYPTION_KEY) and "
                              "differs from the backup's: set it to the backup's key, then restore")  # fmt: skip
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    (staging / "READY").write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    return _describe(manifest)


def pending_restore(settings: Any) -> bool:
    db = sqlite_path(settings.database_url)
    return bool(db and (db.parent / RESTORE_DIR / "READY").is_file())


def cancel_restore(settings: Any) -> None:
    db = sqlite_path(settings.database_url)
    if db:
        shutil.rmtree(db.parent / RESTORE_DIR, ignore_errors=True)


def apply_pending_restore(settings: Any) -> str | None:
    """At start-up, before the database opens: swap in a staged restore. Returns where the old data went."""
    db = sqlite_path(settings.database_url)
    if db is None:
        return None
    staging = db.parent / RESTORE_DIR
    if not (staging / "READY").is_file():
        return None
    _key, key_file = key_material(settings)
    aside = db.parent / f"before-restore-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')}"
    aside.mkdir(parents=True)
    for suffix in ("", "-wal", "-shm"):
        current = db.with_name(db.name + suffix)
        if current.exists():
            os.replace(current, aside / current.name)
    os.replace(staging / "argus.db", db)
    if key_file is not None and (staging / "encryption.key").is_file():
        if key_file.exists():
            shutil.copy2(key_file, aside / key_file.name)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging / "encryption.key", key_file)
        with contextlib.suppress(OSError):
            key_file.chmod(0o600)
    shutil.rmtree(staging, ignore_errors=True)
    logger.warning("Restored a backup; the previous data was kept in %s", aside)
    return str(aside)


def known_revisions() -> set[str]:
    """Every database version this Argus knows (a backup from a newer one can't be restored here)."""
    from alembic.script import ScriptDirectory

    from argus.storage.migrate import MIGRATIONS_DIR

    return {rev.revision for rev in ScriptDirectory(str(MIGRATIONS_DIR)).walk_revisions()}


# ---------------------------------------------------------------------------- the backup folder
def list_backups(folder: Path) -> list[dict[str, Any]]:
    """Backups in a folder, newest first (what each says about itself; no password needed)."""
    folder = Path(folder).expanduser()
    paths: list[Path] = []
    with contextlib.suppress(OSError):
        paths = list(folder.glob(f"argus-backup-*{SUFFIX}"))
    found = [entry for entry in map(_entry, paths) if entry]
    return sorted(found, key=lambda b: str(b["created_at"]), reverse=True)


def _entry(path: Path) -> dict[str, Any] | None:
    try:
        header = read_header(path)
        size = path.stat().st_size
    except (BackupError, OSError):
        return None
    return {"name": path.name, "file": str(path), "size": size, "created_at": header.get("created_at"),
            "argus_version": header.get("argus_version")}  # fmt: skip


def prune(folder: Path, keep: int) -> list[str]:
    """Remove the oldest backups beyond ``keep`` (only Argus's own backup files are ever touched)."""
    removed = []
    for old in list_backups(folder)[max(keep, 1) :]:
        with contextlib.suppress(OSError):
            Path(old["file"]).unlink()
            removed.append(old["name"])
    return removed


def suggested_folders() -> list[dict[str, str]]:
    """Folders worth offering: synced cloud folders (a copy off this computer) and Documents."""
    home = Path.home()
    candidates = [
        (
            "OneDrive",
            os.environ.get("OneDrive")  # noqa: SIM112 - Windows sets it with this spelling
            or str(home / "OneDrive"),
        ),
        ("iCloud Drive", str(home / "Library" / "Mobile Documents" / "com~apple~CloudDocs")),
        ("Dropbox", str(home / "Dropbox")),
        ("Google Drive", str(home / "Google Drive" / "My Drive")),
        ("Google Drive", str(home / "My Drive")),
        ("Documents", str(home / "Documents")),
    ]
    seen, out = set(), []
    for label, path in candidates:
        if path and path not in seen and Path(path).is_dir():
            seen.add(path)
            out.append({"label": label, "path": str(Path(path) / "Argus backups"), "cloud": str(label != "Documents")})
    return out
