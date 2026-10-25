"""Encrypted, execution-owned browser captures kept beside redacted evidence.

Only a capture ID is exposed to agents. The private URL and bodies are bound to
the evidence namespace and ID, and never written to the redacted JSON ledger.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


_MAGIC = b"PROWL_CAPTURE_1\0"
_MAX_FILE_BYTES = 1024 * 1024
_ID = re.compile(r"[0-9a-f]{32}\Z")


def _path(namespace: str, artifact_id: str) -> Path | None:
    directory = (os.environ.get("AEGIS_EVIDENCE_DIR") or "").strip()
    if not directory or not _ID.fullmatch(artifact_id) or not _ID.fullmatch(namespace):
        return None
    return Path(directory) / namespace / f"{artifact_id}.capture"


def _key() -> bytes:
    return hashlib.sha256(
        b"prowl-private-browser-capture-v1\0" + settings.SECRET_KEY.encode()
    ).digest()


def persist_capture(namespace: str, artifact_id: str, row: dict) -> None:
    path = _path(namespace, artifact_id)
    if path is None:
        return
    if path.parent.is_symlink():
        raise OSError("Capture namespace cannot be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps({
        "identity": row["identity"],
        "verifier_run_id": row.get("verifier_run_id"),
        "private": base64.b64encode(row["private"]).decode("ascii"),
    }, sort_keys=True).encode()
    nonce = os.urandom(12)
    aad = f"{namespace}:{artifact_id}".encode()
    blob = _MAGIC + nonce + AESGCM(_key()).encrypt(nonce, encoded, aad)
    if len(blob) > _MAX_FILE_BYTES:
        raise ValueError("Browser capture exceeds private storage limit")
    temporary = path.parent / f".{artifact_id}.{uuid.uuid4().hex}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_capture(namespace: str, artifact_id: str) -> dict | None:
    path = _path(namespace, artifact_id)
    if path is None:
        return None
    try:
        if path.parent.is_symlink() or path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        blob = path.read_bytes()
        if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + 12 + 16:
            return None
        nonce = blob[len(_MAGIC):len(_MAGIC) + 12]
        aad = f"{namespace}:{artifact_id}".encode()
        payload = AESGCM(_key()).decrypt(nonce, blob[len(_MAGIC) + 12:], aad)
        row = json.loads(payload)
        private = base64.b64decode(row["private"], validate=True)
        if not isinstance(row["identity"], str) or not isinstance(row.get("verifier_run_id"), (str, type(None))):
            return None
        return {"identity": row["identity"], "verifier_run_id": row.get("verifier_run_id"),
                "private": private}
    except (OSError, InvalidTag, ValueError, KeyError, TypeError):
        return None


def delete_capture(namespace: str, artifact_id: str) -> None:
    path = _path(namespace, artifact_id)
    if path is not None:
        path.unlink(missing_ok=True)
