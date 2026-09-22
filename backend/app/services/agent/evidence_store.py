"""Execution-owned evidence, scoped to one tools manager and verifier run.

The model may cite artifact IDs; it cannot manufacture an execution record.
Redacted artifacts can optionally be persisted under AEGIS_EVIDENCE_DIR.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class VerificationRun:
    id: str
    candidate_id: str
    revision: int
    nonce: str


verification_run: ContextVar[VerificationRun | None] = ContextVar(
    "verification_run", default=None
)


def re_full_artifact_id(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{32}", value))


def origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError(
            "An absolute HTTP(S) URL without embedded credentials is required"
        )
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80)


class _RecordsView(Mapping):
    """Read-only snapshots; consumers cannot mutate the execution-owned ledger."""

    def __init__(self, store):
        self._store = store

    def __getitem__(self, key):
        record = self._store._get_record(key)
        if record is None:
            raise KeyError(key)
        return deepcopy(record)

    def __iter__(self):
        return iter(self._store._records)

    def __len__(self):
        return len(self._store._records)

    def __contains__(self, key):
        return self._store._get_record(key) is not None


def redact_artifact(value):
    from app.services.agent.observability import redact_value

    if isinstance(value, dict):
        return {
            key: redact_value(redact_artifact(item), key) for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_artifact(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return redact_value(value)
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact_artifact(parsed), default=str)
    return redact_value(value)


class EvidenceStore:
    def __init__(self, max_records: int = 512, namespace: str = ""):
        self._records: OrderedDict[str, dict] = OrderedDict()
        self.records = _RecordsView(self)
        self.max_records = max_records
        self.id = uuid.uuid4().hex
        self.namespace = (
            namespace if re.fullmatch(r"[0-9a-z_-]{8,64}", namespace) else self.id
        )
        self.total_bytes = 0
        self.max_bytes = 64 * 1024 * 1024
        self._lock = threading.RLock()
        self._load_persisted()

    def _root(self) -> Path | None:
        directory = (os.environ.get("AEGIS_EVIDENCE_DIR") or "").strip()
        return Path(directory) if directory else None

    def _persisted_path(self, artifact_id: str) -> Path | None:
        root = self._root()
        return root / self.namespace / f"{artifact_id}.json" if root else None

    @staticmethod
    def _valid_record(record: Any, artifact_id: str) -> bool:
        structurally_valid = bool(
            isinstance(record, dict)
            and record.get("id") == artifact_id
            and isinstance(record.get("payload"), (dict, list, str, int, float, bool, type(None)))
            and isinstance(record.get("created_at"), (int, float))
            and isinstance(record.get("size_bytes"), int)
            and isinstance(record.get("storage_sha256"), str)
        )
        if not structurally_valid:
            return False
        encoded = json.dumps(record["payload"], default=str, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest() == record["storage_sha256"]

    def _load_file(self, path: Path, artifact_id: str) -> dict | None:
        try:
            if path.is_symlink() or path.stat().st_size > 3 * 1024 * 1024:
                return None
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        return record if self._valid_record(record, artifact_id) else None

    def _remember(self, record: dict) -> None:
        artifact_id = record["id"]
        previous = self._records.pop(artifact_id, None)
        if previous:
            self.total_bytes -= int(previous.get("size_bytes") or 0)
        self._records[artifact_id] = deepcopy(record)
        self.total_bytes += int(record.get("size_bytes") or 0)

    def _get_record(self, artifact_id: str) -> dict | None:
        artifact_id = str(artifact_id or "")
        if not re_full_artifact_id(artifact_id):
            return None
        with self._lock:
            record = self._records.get(artifact_id)
            if record is not None:
                return record
            path = self._persisted_path(artifact_id)
            candidates = [path] if path and path.exists() else []
            for candidate in candidates:
                record = self._load_file(candidate, artifact_id)
                if record is not None:
                    self._remember(record)
                    return record
        return None

    def _load_persisted(self) -> None:
        root = self._root()
        if root is None or not root.exists():
            return
        retention = max(3600, int(os.environ.get("AEGIS_EVIDENCE_RETENTION_SECONDS", "86400")))
        cutoff = time.time() - retention
        namespace_root = root / self.namespace
        paths = list(namespace_root.glob("*.json")) if namespace_root.exists() else []
        loaded: list[dict] = []
        for path in paths:
            artifact_id = path.stem
            record = self._load_file(path, artifact_id)
            if record is None:
                continue
            if record["created_at"] < cutoff:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            loaded.append(record)
        for record in sorted(loaded, key=lambda item: item["created_at"]):
            self._remember(record)
        while len(self._records) > self.max_records or self.total_bytes > self.max_bytes:
            _, removed = self._records.popitem(last=False)
            self.total_bytes -= int(removed.get("size_bytes") or 0)

    def _delete_persisted(self, artifact_id: str) -> None:
        path = self._persisted_path(artifact_id)
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def clear(self) -> None:
        """Erase session evidence from memory and configured private persistence."""
        with self._lock:
            for artifact_id in list(self.records):
                self._delete_persisted(artifact_id)
                removed = self._records.pop(artifact_id, None)
                if removed:
                    self.total_bytes -= int(removed.get("size_bytes") or 0)
            root = self._root()
            if root:
                try:
                    (root / self.namespace).rmdir()
                except OSError:
                    pass

    def record(
        self,
        kind: str,
        payload: Any,
        *,
        target: str = "",
        identity: str = "anonymous",
        hypothesis_id: str = "",
        operation_id: str = "",
        coverage_cell_id: str = "",
        tenant: str = "",
        parameter: str = "",
        test_type: str = "",
        capture_id: str = "",
        proof_run_id: str = "",
        verifier_run_id: str = "",
        finding_id: str = "",
        success: bool = True,
    ) -> str:
        run = verification_run.get()
        clean = redact_artifact(payload)
        encoded = json.dumps(clean, default=str, sort_keys=True)
        truncated = len(encoded.encode()) > 2 * 1024 * 1024
        if truncated:
            clean = {
                "truncated": True,
                "preview": encoded[: 1024 * 1024],
                "note": "Oversized artifact; run a bounded follow-up for confirmation",
            }
        artifact_id = uuid.uuid4().hex
        record = {
            "id": artifact_id,
            "kind": kind,
            "target": target,
            "identity": identity,
            "tenant": tenant,
            "hypothesis_id": hypothesis_id,
            "operation_id": operation_id,
            "coverage_cell_id": coverage_cell_id,
            "parameter": parameter,
            "test_type": test_type,
            "capture_id": capture_id,
            "proof_run_id": proof_run_id,
            "verifier_run_id": verifier_run_id or (run.id if run else ""),
            "finding_id": str(finding_id or ""),
            "success": bool(success),
            "created_at": time.time(),
            "run_id": run.id if run else "",
            "candidate_id": run.candidate_id if run else "",
            "revision": run.revision if run else 0,
            "sha256": hashlib.sha256(encoded.encode()).hexdigest(),
            "payload": clean,
            "truncated": truncated,
            "size_bytes": len(json.dumps(clean, default=str).encode()),
            "storage_sha256": hashlib.sha256(
                json.dumps(clean, default=str, sort_keys=True).encode()
            ).hexdigest(),
        }
        with self._lock:
            self._remember(record)
            while len(self.records) > self.max_records or self.total_bytes > self.max_bytes:
                removed_id, removed = self._records.popitem(last=False)
                self.total_bytes -= removed["size_bytes"]
                self._delete_persisted(removed_id)
            root = self._root()
            if root:
                root = root / self.namespace
                root.mkdir(parents=True, exist_ok=True, mode=0o700)
                path = root / f"{artifact_id}.json"
                temporary = root / f".{artifact_id}.{uuid.uuid4().hex}.tmp"
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    json.dump(record, stream, default=str)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
        return artifact_id

    def read(self, artifact_id: str, offset: int = 0, limit: int = 6000) -> dict:
        record = self.records.get(artifact_id)
        if record is None:
            raise ValueError("Unknown or expired evidence artifact")
        text = json.dumps(record["payload"], default=str)
        offset = max(0, int(offset))
        limit = max(1, min(int(limit), 12000))
        return {
            **{k: v for k, v in record.items() if k != "payload"},
            "content": text[offset : offset + limit],
            "offset": offset,
            "total_chars": len(text),
            "next_offset": offset + limit if offset + limit < len(text) else None,
        }

    def validate(
        self,
        ids: list[str],
        *,
        candidate_id: str,
        revision: int,
        run_id: str,
        target: str,
        max_age: int = 3600,
    ) -> tuple[bool, str]:
        if not ids or not run_id:
            return False, "Fresh verifier execution artifacts are required"
        has_response = False
        has_callback = False
        target_path_seen = False
        for artifact_id in ids:
            row = self.records.get(artifact_id)
            if (
                not row
                or row["candidate_id"] != candidate_id
                or row["revision"] != revision
                or row["run_id"] != run_id
            ):
                return (
                    False,
                    "Evidence belongs to a different candidate, revision, or verifier run",
                )
            if row.get("truncated"):
                return (
                    False,
                    "Oversized evidence cannot confirm a finding; run a bounded follow-up",
                )
            if time.time() - row["created_at"] > max_age:
                return False, "Evidence has expired; rerun verification"
            if row["kind"] in ("oob_register", "oob_poll"):
                has_callback |= bool(
                    row["kind"] == "oob_poll"
                    and row["success"]
                    and row["payload"].get("interactions")
                )
                continue
            if row["kind"] == "browser_xss":
                try:
                    if origin(row["target"]) != origin(target):
                        return False, "Browser evidence left candidate origin"
                except ValueError:
                    return False, "Invalid browser evidence target"
                target_path_seen |= (
                    urlsplit(row["target"]).path == urlsplit(target).path
                )
                has_response |= bool(
                    row["success"] and row["payload"].get("dialog_triggered")
                )
                continue
            if row["kind"] != "http_exchange":
                return (
                    False,
                    "Confirmation requires recorded transport or browser evidence",
                )
            try:
                if origin(row["target"]) != origin(target):
                    return False, "Evidence target does not match the candidate origin"
            except ValueError:
                return False, "Invalid evidence target"
            target_path_seen |= urlsplit(row["target"]).path == urlsplit(target).path
            response = row["payload"].get("response") or {}
            try:
                if origin(response.get("url") or row["target"]) != origin(target):
                    return False, "Redirected evidence left candidate origin"
            except ValueError:
                return False, "Invalid response URL"
            # Errors and empty successes are observations, not demonstrated impact.
            has_response |= bool(
                row["success"]
                and 200 <= response.get("status", 0) < 300
                and response.get("body")
            )
        if urlsplit(target).path not in ("", "/") and not target_path_seen:
            return False, "No evidence for the claimed endpoint"
        return (
            (True, "")
            if has_response or has_callback
            else (False, "No successful response body demonstrates the claimed impact")
        )


def evidence_store(manager: Any) -> EvidenceStore:
    if getattr(manager, "_evidence_store", None) is None:
        from app.services.agent.tools import current_organization_id, current_session_id

        session = current_session_id.get()
        if not session:
            session = getattr(manager, "_evidence_namespace_seed", "") or uuid.uuid4().hex
            manager._evidence_namespace_seed = session
        scope = f"{current_organization_id.get()}:{session}"
        namespace = hashlib.sha256(scope.encode()).hexdigest()[:32]
        manager._evidence_store = EvidenceStore(namespace=namespace)
    return manager._evidence_store
