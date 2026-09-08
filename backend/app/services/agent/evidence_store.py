"""Execution-owned evidence, scoped to one tools manager and verifier run.

The model may cite artifact IDs; it cannot manufacture an execution record.
Redacted artifacts can optionally be persisted under AEGIS_EVIDENCE_DIR.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from contextvars import ContextVar
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


def origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError(
            "An absolute HTTP(S) URL without embedded credentials is required"
        )
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80)


class _RecordsView(Mapping):
    """Read-only snapshots; consumers cannot mutate the execution-owned ledger."""
    def __init__(self, records):
        self._records = records

    def __getitem__(self, key):
        return deepcopy(self._records[key])

    def __iter__(self):
        return iter(self._records)

    def __len__(self):
        return len(self._records)

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
    def __init__(self, max_records: int = 512):
        self._records: OrderedDict[str, dict] = OrderedDict()
        self.records = _RecordsView(self._records)
        self.max_records = max_records
        self.id = uuid.uuid4().hex
        self.total_bytes = 0
        self.max_bytes = 64 * 1024 * 1024

    def record(
        self,
        kind: str,
        payload: Any,
        *,
        target: str = "",
        identity: str = "anonymous",
        hypothesis_id: str = "",
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
            "hypothesis_id": hypothesis_id,
            "success": bool(success),
            "created_at": time.time(),
            "run_id": run.id if run else "",
            "candidate_id": run.candidate_id if run else "",
            "revision": run.revision if run else 0,
            "sha256": hashlib.sha256(encoded.encode()).hexdigest(),
            "payload": clean,
            "truncated": truncated,
            "size_bytes": len(json.dumps(clean, default=str).encode()),
        }
        self._records[artifact_id] = deepcopy(record)
        self.total_bytes += record["size_bytes"]
        while len(self.records) > self.max_records or self.total_bytes > self.max_bytes:
            _, removed = self._records.popitem(last=False)
            self.total_bytes -= removed["size_bytes"]
        directory = os.environ.get("AEGIS_EVIDENCE_DIR")
        if directory:
            root = Path(directory) / self.id
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = root / f"{artifact_id}.json"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(record, stream, default=str)
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
        manager._evidence_store = EvidenceStore()
    return manager._evidence_store
