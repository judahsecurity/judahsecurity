"""Hardened parser for infostealer logs.

Stealer-log archives are hostile input: they carry malware, zip bombs, and
path-traversal entries. This module never executes, opens, or writes any file
from an archive. It only reads a small allowlist of known plain-text credential
files, each under strict size and count limits, and returns structured records.

Design rules:
  - Read only; nothing is extracted to disk.
  - Only basenames on ``CREDENTIAL_FILES`` are read. Executables, scripts,
    documents, images and everything else are ignored by name.
  - Zip entries that are directories, symlinks, absolute paths, or contain
    ``..`` are skipped.
  - Per-file, total, entry-count and compression-ratio caps bound the work, so
    a zip bomb cannot exhaust memory.
  - Parsing is pure text handling: no eval, no imports driven by content.

Scope filtering and secret fingerprinting happen in the ingest layer, not here.
"""

from __future__ import annotations

import io
import logging
import re
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

# Plain-text credential files produced by common stealers (RedLine, Lumma,
# StealC, Vidar, Raccoon). Matched case-insensitively on the basename.
CREDENTIAL_FILE_RX = re.compile(
    r"^(?:all ?passwords?|passwords?|_?passwords?|password[_-]?list|"
    r"logins?|credentials?|accounts?|soft[_-]?passwords?)\.txt$",
    re.IGNORECASE,
)

# Hard limits. A stealer log's password file is a few hundred KB at most.
MAX_FILE_BYTES = 8 * 1024 * 1024          # per credential file
MAX_TOTAL_BYTES = 64 * 1024 * 1024        # across all read files
MAX_ENTRIES = 50_000                       # zip entries to inspect
MAX_READ_FILES = 2_000                     # credential files to read
MAX_COMPRESSION_RATIO = 200                # uncompressed/compressed per entry
MAX_RECORDS = 500_000                      # parsed credential blocks


class StealerLogError(Exception):
    pass


@dataclass
class CredentialRecord:
    """One saved login from a stealer log."""

    url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    application: Optional[str] = None
    source_file: Optional[str] = None

    def is_usable(self) -> bool:
        return bool((self.url or self.application) and (self.username or self.password))


@dataclass
class ParseResult:
    records: List[CredentialRecord] = field(default_factory=list)
    files_read: int = 0
    entries_seen: int = 0
    bytes_read: int = 0
    skipped_unsafe: int = 0
    skipped_other: int = 0
    truncated: bool = False
    machine_time: Optional[datetime] = None


# ── Safe archive reading ─────────────────────────────────────────────────────

def _is_unsafe_zip_name(name: str) -> bool:
    if not name or "\x00" in name:
        return True
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized):
        return True
    return any(part == ".." for part in normalized.split("/"))


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix mode is stored in the high 16 bits of external_attr.
    mode = (info.external_attr >> 16) & 0xFFFF
    return bool(mode) and stat.S_ISLNK(mode)


def _iter_credential_files(zf: zipfile.ZipFile, result: ParseResult) -> Iterator[tuple[str, str]]:
    """Yield (name, text) for allowlisted, size-bounded entries. Read-only."""
    for info in zf.infolist():
        result.entries_seen += 1
        if result.entries_seen > MAX_ENTRIES:
            result.truncated = True
            return
        if info.is_dir() or _is_symlink(info) or _is_unsafe_zip_name(info.filename):
            result.skipped_unsafe += 1
            continue
        basename = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
        if not CREDENTIAL_FILE_RX.match(basename):
            result.skipped_other += 1
            continue
        if info.file_size > MAX_FILE_BYTES:
            result.skipped_unsafe += 1
            continue
        if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            # Decompression bomb: skip rather than expand.
            result.skipped_unsafe += 1
            continue
        if result.bytes_read + info.file_size > MAX_TOTAL_BYTES or result.files_read >= MAX_READ_FILES:
            result.truncated = True
            return
        try:
            with zf.open(info, "r") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            # RuntimeError covers encrypted entries (no password supplied).
            logger.debug("Skipping unreadable zip entry %s: %s", info.filename, exc)
            result.skipped_unsafe += 1
            continue
        if len(raw) > MAX_FILE_BYTES:
            result.skipped_unsafe += 1
            continue
        result.files_read += 1
        result.bytes_read += len(raw)
        yield basename, raw.decode("utf-8", errors="replace")


# ── Text parsing ─────────────────────────────────────────────────────────────

_FIELD_RX = re.compile(
    r"^\s*(url|host|hostname|soft|software|application|app|username|user|login|"
    r"email|password|pass|pwd)\s*[:=]\s*(.*?)\s*$",
    re.IGNORECASE,
)

_FIELD_MAP = {
    "url": "url", "host": "url", "hostname": "url",
    "soft": "application", "software": "application", "application": "application", "app": "application",
    "username": "username", "user": "username", "login": "username", "email": "username",
    "password": "password", "pass": "password", "pwd": "password",
}


def _flush(record: Dict[str, str], source_file: str, out: List[CredentialRecord]) -> None:
    if record:
        rec = CredentialRecord(
            url=record.get("url"),
            username=record.get("username"),
            password=record.get("password"),
            application=record.get("application"),
            source_file=source_file,
        )
        if rec.is_usable():
            out.append(rec)


def parse_credential_text(text: str, source_file: str = "") -> List[CredentialRecord]:
    """Parse the ``URL:/Username:/Password:`` block format common to stealers.

    Blocks are separated by blank lines or by the start of a new ``URL``/``Soft``
    field. A new ``url`` while one is already set starts a new record.
    """
    out: List[CredentialRecord] = []
    current: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            _flush(current, source_file, out)
            current = {}
            continue
        match = _FIELD_RX.match(line)
        if not match:
            continue
        field_name = _FIELD_MAP[match.group(1).lower()]
        value = match.group(2).strip()
        if not value or value in ("UNKNOWN", "N/A", "null"):
            continue
        if field_name in current and field_name in ("url", "application"):
            _flush(current, source_file, out)
            current = {}
        current.setdefault(field_name, value)
    _flush(current, source_file, out)
    return out


def parse_zip_bytes(data: bytes) -> ParseResult:
    """Parse credential files from an in-memory zip archive. Read-only."""
    result = ParseResult()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise StealerLogError(f"Not a valid zip archive: {exc}") from exc
    with zf:
        for basename, text in _iter_credential_files(zf, result):
            for record in parse_credential_text(text, basename):
                result.records.append(record)
                if len(result.records) >= MAX_RECORDS:
                    result.truncated = True
                    return result
    return result


def parse_text_bytes(data: bytes, source_file: str = "passwords.txt") -> ParseResult:
    """Parse a single already-extracted credential text file."""
    result = ParseResult()
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
        result.truncated = True
    result.files_read = 1
    result.bytes_read = len(data)
    result.records = parse_credential_text(data.decode("utf-8", errors="replace"), source_file)
    return result
