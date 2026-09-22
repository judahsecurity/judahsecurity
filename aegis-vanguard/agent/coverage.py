"""Machine-readable security coverage planning and evidence tracking.

The coverage ledger is deliberately stricter than an agent's prose summary.
Rows move out of ``pending`` only when a deterministic tool result identifies
the endpoint, parameter, vulnerability class, and (when applicable) identity
that it exercised.  This makes gaps visible instead of rewarding activity.
"""

from __future__ import annotations

import copy
import re
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit


COVERAGE_STATES = frozenset({
    "pending",
    "in_progress",
    "tested_negative",
    "candidate",
    "validated",
    "rejected",
    "error",
    "skipped",
})

_TESTED_STATES = frozenset({"tested_negative", "candidate", "validated", "rejected"})
_IDENTITY_CLASSES = frozenset({"auth", "authz", "csrf", "business_logic"})

_URLISH_RE = re.compile(
    r"(?:url|uri|href|src|callback|webhook|fetch|proxy|remote|avatar|image|feed)", re.I
)
_REDIRECT_RE = re.compile(r"(?:redirect|return|next|continue|dest|destination|relay)", re.I)
_PATH_RE = re.compile(r"(?:file|path|folder|directory|template|page|download|document)", re.I)
_COMMAND_RE = re.compile(r"(?:cmd|command|exec|shell|host|hostname|ip|ping|lookup)", re.I)
_OBJECT_RE = re.compile(
    r"(?:^id$|_id$|id_|uuid|object|user|account|tenant|org|order|invoice|project|owner)", re.I
)
_AUTH_RE = re.compile(
    r"(?:login|signin|sign-in|logout|register|password|reset|session|token|jwt|mfa|auth)", re.I
)
_WORKFLOW_RE = re.compile(
    r"(?:cart|checkout|order|payment|coupon|promo|redeem|transfer|balance|inventory|approve|workflow)", re.I
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _endpoint(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme and parts.netloc:
        path = parts.path or "/"
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))
    return raw.split("?", 1)[0].split("#", 1)[0] or "/"


def _parameter_spec(value: Any, method: str = "GET", content_type: str = "") -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if ":" in raw:
        location, name = raw.split(":", 1)
        if location.lower() in {"query", "form", "json", "graphql", "header", "cookie", "path"}:
            return f"{location.lower()}:{name}"
    if method.upper() == "GET":
        location = "query"
    elif "json" in content_type.lower():
        location = "json"
    else:
        location = "form"
    return f"{location}:{raw}"


def _vuln_classes(endpoint: str, method: str, parameter: str) -> List[str]:
    """Infer a bounded, high-value plan from a request input."""
    name = parameter.split(":", 1)[-1]
    blob = f"{endpoint} {name}"
    classes = {"sqli", "xss"}
    if _URLISH_RE.search(blob):
        classes.add("ssrf")
    if _REDIRECT_RE.search(blob):
        classes.add("open_redirect")
    if _PATH_RE.search(blob):
        classes.add("path_traversal")
    if _COMMAND_RE.search(blob):
        classes.add("command_injection")
    if _OBJECT_RE.search(blob):
        classes.add("authz")
    if _AUTH_RE.search(endpoint):
        classes.add("auth")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        classes.add("csrf")
    if _WORKFLOW_RE.search(blob):
        classes.add("business_logic")
    return sorted(classes)


def _normalize_class(value: Any) -> str:
    raw = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "idor": "authz",
        "broken_access_control": "authz",
        "path_traversal_lfi": "path_traversal",
        "os_command_injection": "command_injection",
    }
    return aliases.get(raw, raw)


class CoverageLedger:
    """Coverage plan plus evidence-backed state transitions."""

    def __init__(self, records: Optional[Iterable[dict]] = None):
        self._records: Dict[tuple, dict] = {}
        self._lock = threading.RLock()
        self._planned_identities: List[str] = []
        for record in records or []:
            self._upsert(dict(record), planned=bool(record.get("planned", True)))

    @classmethod
    def from_input_surface(
        cls,
        input_surface: Optional[dict],
        identities: Optional[Sequence[dict]] = None,
    ) -> "CoverageLedger":
        ledger = cls()
        labels = [
            str(item.get("label") or item.get("username") or "identity").strip()
            for item in (identities or [])
            if isinstance(item, dict)
        ]
        labels = list(dict.fromkeys(label for label in labels if label))
        ledger._planned_identities = labels
        default_identity = labels[0] if labels else "anonymous"

        surface = input_surface if isinstance(input_surface, dict) else {}
        items = list(surface.get("forms") or []) + list(surface.get("request_templates") or [])
        for item in items:
            if not isinstance(item, dict):
                continue
            endpoint = _endpoint(item.get("action_url") or item.get("url"))
            method = str(item.get("method") or "GET").upper()
            content_type = str(item.get("content_type") or "")
            for raw_param in item.get("eligible_parameters") or []:
                parameter = _parameter_spec(raw_param, method, content_type)
                if not endpoint or not parameter:
                    continue
                for vuln_class in _vuln_classes(endpoint, method, parameter):
                    row_identities = labels if labels and vuln_class in _IDENTITY_CLASSES else [default_identity]
                    for identity in row_identities:
                        ledger._upsert({
                            "endpoint": endpoint,
                            "method": method,
                            "identity": identity,
                            "parameter": parameter,
                            "vulnerability_class": vuln_class,
                            "state": "pending",
                            "planned": True,
                            "source": "input_surface",
                            "evidence": "",
                        }, planned=True)
        return ledger

    @staticmethod
    def _key(record: dict) -> tuple:
        return (
            _endpoint(record.get("endpoint")),
            str(record.get("method") or "GET").upper(),
            str(record.get("identity") or "unspecified"),
            _parameter_spec(record.get("parameter"), str(record.get("method") or "GET")),
            _normalize_class(record.get("vulnerability_class")),
        )

    def _upsert(self, record: dict, *, planned: bool) -> dict:
        state = str(record.get("state") or "pending")
        if state not in COVERAGE_STATES:
            raise ValueError(f"invalid coverage state: {state}")
        key = self._key(record)
        now = _now()
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                existing = {
                    "endpoint": key[0],
                    "method": key[1],
                    "identity": key[2],
                    "parameter": key[3],
                    "vulnerability_class": key[4],
                    "state": state,
                    "planned": bool(planned),
                    "source": str(record.get("source") or ""),
                    "evidence": str(record.get("evidence") or ""),
                    "created_at": now,
                    "updated_at": now,
                }
                self._records[key] = existing
            elif planned:
                existing["planned"] = True
            return existing

    @staticmethod
    def _can_transition(current: str, new: str) -> bool:
        if current == new:
            return True
        if current == "validated":
            return False
        if current == "rejected":
            return new == "validated"
        if current == "candidate":
            return new in {"validated", "rejected", "error"}
        if current == "tested_negative":
            return new in {"candidate", "validated"}
        return True

    def update(
        self,
        *,
        endpoint: str,
        method: str,
        identity: str,
        parameter: str,
        vulnerability_class: str,
        state: str,
        source: str = "",
        evidence: str = "",
    ) -> dict:
        if state not in COVERAGE_STATES:
            raise ValueError(f"invalid coverage state: {state}")
        record = {
            "endpoint": endpoint,
            "method": method,
            "identity": identity,
            "parameter": parameter or "endpoint",
            "vulnerability_class": vulnerability_class,
            "state": state,
            "source": source,
            "evidence": evidence,
        }
        with self._lock:
            row = self._upsert(record, planned=False)
            if self._can_transition(row["state"], state):
                row["state"] = state
                row["updated_at"] = _now()
                if source:
                    row["source"] = source
                if evidence:
                    row["evidence"] = str(evidence)[:1000]
            return copy.deepcopy(row)

    def record_probe_result(
        self,
        payload: dict,
        *,
        source: str,
        identity: Optional[str] = None,
        default_class: Optional[str] = None,
    ) -> int:
        """Apply one structured probe result and return rows touched."""
        if not isinstance(payload, dict):
            return 0
        endpoint = _endpoint(
            payload.get("target") or payload.get("url") or payload.get("endpoint")
        )
        method = str(payload.get("method") or "GET").upper()
        vuln_class = _normalize_class(
            payload.get("probe") or default_class or self._infer_payload_class(payload)
        )
        chosen_identity = str(
            identity or payload.get("identity") or payload.get("identity_label")
            or ("anonymous" if not self._planned_identities else "unspecified")
        )
        touched = 0

        coverage = payload.get("coverage")
        if isinstance(coverage, list):
            for item in coverage:
                if not isinstance(item, dict):
                    continue
                parameter = item.get("parameter_spec") or item.get("parameter") or "endpoint"
                item_identity = str(item.get("identity") or chosen_identity)
                state = str(item.get("status") or "tested_negative")
                if state not in COVERAGE_STATES:
                    state = "candidate" if item.get("signals") else "tested_negative"
                self.update(
                    endpoint=endpoint,
                    method=method,
                    identity=item_identity,
                    parameter=str(parameter),
                    vulnerability_class=vuln_class,
                    state=state,
                    source=source,
                    evidence=", ".join(str(v) for v in item.get("signals") or []),
                )
                touched += 1
        else:
            tested = payload.get("tested_params") or payload.get("params_tested") or []
            if isinstance(tested, str):
                tested = [part.strip() for part in tested.split(",") if part.strip()]
            candidates = payload.get("candidates") or payload.get("findings") or []
            candidate_params = {
                _parameter_spec(
                    item.get("parameter_spec") or item.get("param") or item.get("parameter"),
                    method,
                )
                for item in candidates
                if isinstance(item, dict)
            }
            for parameter in tested if isinstance(tested, list) else []:
                spec = _parameter_spec(parameter, method)
                state = "candidate" if spec in candidate_params else "tested_negative"
                self.update(
                    endpoint=endpoint,
                    method=method,
                    identity=chosen_identity,
                    parameter=spec,
                    vulnerability_class=vuln_class,
                    state=state,
                    source=source,
                )
                touched += 1

        if payload.get("error") and not touched:
            self.update(
                endpoint=endpoint or "unknown",
                method=method,
                identity=chosen_identity,
                parameter="endpoint",
                vulnerability_class=vuln_class,
                state="error",
                source=source,
                evidence=str(payload.get("error")),
            )
            touched += 1
        return touched

    @staticmethod
    def _infer_payload_class(payload: dict) -> str:
        candidates = payload.get("candidates") or payload.get("findings") or []
        for item in candidates if isinstance(candidates, list) else []:
            if isinstance(item, dict) and (item.get("vuln_type") or item.get("type")):
                return str(item.get("vuln_type") or item.get("type"))
        if isinstance(payload.get("coverage"), list) and payload.get("params_tested") is not None:
            return "sqli"
        return "unknown"

    def apply_findings(self, findings: Iterable[dict], state: str, *, source: str) -> int:
        touched = 0
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            endpoint = finding.get("endpoint") or finding.get("url") or finding.get("matched_at")
            vuln_class = finding.get("vuln_type") or finding.get("type") or "unknown"
            parameter = (
                finding.get("parameter_spec") or finding.get("param")
                or finding.get("parameter") or "endpoint"
            )
            identity = (
                finding.get("identity") or finding.get("identity_label")
                or ("anonymous" if not self._planned_identities else "unspecified")
            )
            self.update(
                endpoint=str(endpoint or "unknown"),
                method=str(finding.get("method") or "GET"),
                identity=str(identity),
                parameter=str(parameter),
                vulnerability_class=str(vuln_class),
                state=state,
                source=source,
                evidence=str(finding.get("evidence") or finding.get("validation_reason") or ""),
            )
            touched += 1
        return touched

    def summary(self) -> dict:
        with self._lock:
            records = list(self._records.values())
        states = Counter(row["state"] for row in records)
        planned = [row for row in records if row.get("planned")]
        tested = sum(1 for row in planned if row["state"] in _TESTED_STATES)
        return {
            "records_total": len(records),
            "planned_total": len(planned),
            "planned_tested": tested,
            "coverage_rate": round(tested / len(planned), 4) if planned else 0.0,
            "states": {state: states.get(state, 0) for state in sorted(COVERAGE_STATES)},
            "unplanned_observations": sum(1 for row in records if not row.get("planned")),
        }

    def pending(self, limit: int = 100) -> List[dict]:
        with self._lock:
            rows = [
                copy.deepcopy(row) for row in self._records.values()
                if row.get("planned") and row.get("state") in {"pending", "in_progress", "error"}
            ]
        rows.sort(key=lambda row: (
            row["vulnerability_class"], row["endpoint"], row["parameter"], row["identity"]
        ))
        return rows[:max(0, limit)]

    def snapshot(self, limit: Optional[int] = None) -> List[dict]:
        with self._lock:
            rows = [copy.deepcopy(row) for row in self._records.values()]
        rows.sort(key=lambda row: (
            row["endpoint"], row["method"], row["parameter"],
            row["vulnerability_class"], row["identity"],
        ))
        return rows if limit is None else rows[:max(0, limit)]
