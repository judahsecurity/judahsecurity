"""Machine-readable security coverage planning and evidence tracking.

The coverage ledger is deliberately stricter than an agent's prose summary.
Rows move out of ``pending`` only when a deterministic tool result identifies
the endpoint, parameter, vulnerability class, and (when applicable) identity
that it exercised.  This makes gaps visible instead of rewarding activity.
"""

from __future__ import annotations

import copy
import json
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
_IDENTITY_CLASSES = frozenset({"auth", "authz", "csrf", "business_logic", "oauth", "saml_sso"})

# Which coverage vulnerability classes each parallel hunter owns, keyed by the
# category slug derived from its name (`injection_hunter` -> `injection`). Used
# to lease a focused, disjoint worklist to each specialist. A category that is
# absent, or maps to an empty set, simply leases nothing and the hunter falls
# back to the shared recon brief — so this map is a hint, never a gate.
HUNTER_COVERAGE_CLASSES: Dict[str, frozenset] = {
    "injection": frozenset({"sqli", "nosql", "command_injection", "ssti", "xxe", "crlf"}),
    "xss": frozenset({"xss", "stored_xss"}),
    "auth": frozenset({"auth"}),
    "authz": frozenset({"authz"}),
    "ssrf": frozenset({"ssrf"}),
    "csrf": frozenset({"csrf"}),
    "cors": frozenset({"cors"}),
    "file_upload": frozenset({"file_upload"}),
    "open_redirect": frozenset({"open_redirect", "path_traversal"}),
    "race_condition": frozenset({"race_condition"}),
    "business_logic": frozenset({"business_logic"}),
    "oauth": frozenset({"oauth"}),
    "llm_ai": frozenset({"llm_ai"}),
    "saml_sso": frozenset({"saml_sso"}),
    "host_header": frozenset({"crlf"}),
}


def coverage_classes_for(category: str) -> frozenset:
    """Coverage classes a hunter category owns (empty set when unmapped)."""
    return HUNTER_COVERAGE_CLASSES.get(str(category or "").strip().lower(), frozenset())

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
_DATA_RE = re.compile(r"(?:query|search|filter|where|user|email|login|account|id|sort)", re.I)
_TEMPLATE_RE = re.compile(r"(?:template|render|view|theme|layout|message|subject|body|content)", re.I)
_TEXT_RE = re.compile(r"(?:comment|review|post|message|body|content|description|bio|profile|name|text)", re.I)
_UPLOAD_RE = re.compile(r"(?:upload|attachment|avatar|image|document|import)", re.I)
_AI_RE = re.compile(r"(?:/chat|/completions|/messages|/mcp|chatbot|copilot|assistant|prompt)", re.I)


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
    if raw == "endpoint":
        return raw
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


def _vuln_classes(endpoint: str, method: str, parameter: str, content_type: str = "") -> List[str]:
    """Plan classes with matching input probes or an observed sink signal."""
    location = parameter.split(":", 1)[0]
    name = parameter.split(":", 1)[-1]
    blob = f"{endpoint} {name}"
    classes = {"sqli", "xss"}
    if location in {"json", "graphql"} or _DATA_RE.search(blob):
        classes.add("nosql")
    if _TEMPLATE_RE.search(blob):
        classes.add("ssti")
    if location == "header" or _REDIRECT_RE.search(blob) or _PATH_RE.search(blob):
        classes.add("crlf")
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
        if _TEXT_RE.search(blob):
            classes.add("stored_xss")
    if _WORKFLOW_RE.search(blob):
        classes.add("business_logic")
    return sorted(classes)


def _endpoint_classes(endpoint: str, method: str, content_type: str) -> List[str]:
    """Plan request or workflow checks once per observed endpoint."""
    blob = f"{endpoint} {content_type}".lower()
    classes = set()
    if "xml" in content_type.lower() or re.search(r"(?:/soap|/xml|\.xml\b)", endpoint, re.I):
        classes.add("xxe")
    if "json" in content_type.lower():
        classes.add("prototype_pollution")
    if "multipart" in content_type.lower() or _UPLOAD_RE.search(endpoint):
        classes.add("file_upload")
    if "/api/" in endpoint.lower() or "graphql" in blob:
        classes.add("cors")
    if "graphql" in blob:
        classes.add("graphql")
    if "oauth" in blob or "oidc" in blob or "/authorize" in blob:
        classes.add("oauth")
    if "saml" in blob or "/sso" in blob:
        classes.add("saml_sso")
    if _AI_RE.search(endpoint):
        classes.add("llm_ai")
    if method in {"POST", "PUT", "PATCH", "DELETE"} and _WORKFLOW_RE.search(endpoint):
        classes.add("race_condition")
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
        "nosql_injection": "nosql",
        "server_side_template_injection": "ssti",
        "http_response_splitting": "crlf",
        "crlf_injection": "crlf",
        "xml_external_entity": "xxe",
        "xml_external_entities": "xxe",
        "unrestricted_file_upload": "file_upload",
    }
    return aliases.get(raw, raw)


class CoverageLedger:
    """Coverage plan plus evidence-backed state transitions."""

    def __init__(self, records: Optional[Iterable[dict]] = None):
        self._records: Dict[tuple, dict] = {}
        self._lock = threading.RLock()
        self._planned_identities: List[str] = []
        self._leases: Dict[str, List[tuple]] = {}
        # Concrete baseline request per (endpoint, method), reconstructed from
        # the observed input so a specialist mutates one value off the real
        # request instead of reconstructing it from prose.
        self._baselines: Dict[tuple, dict] = {}
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
            if endpoint:
                ledger._baselines.setdefault(
                    (endpoint, method), cls._baseline_request(item)
                )
            if not endpoint:
                continue
            for vuln_class in _endpoint_classes(endpoint, method, content_type):
                row_identities = labels if labels and vuln_class in _IDENTITY_CLASSES else [default_identity]
                for identity in row_identities:
                    ledger._upsert({
                        "endpoint": endpoint,
                        "method": method,
                        "identity": identity,
                        "parameter": "endpoint",
                        "vulnerability_class": vuln_class,
                        "state": "pending",
                        "planned": True,
                        "source": "input_surface",
                    }, planned=True)
            for raw_param in item.get("eligible_parameters") or []:
                parameter = _parameter_spec(raw_param, method, content_type)
                if not parameter:
                    continue
                for vuln_class in _vuln_classes(endpoint, method, parameter, content_type):
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
    def _baseline_request(item: dict) -> dict:
        """Reconstruct the concrete baseline request for an observed input.

        The specialist replays this exact request to get a control response,
        then changes one value at a time and diffs against it. Values come
        straight from recon's form/fetch templates, so the baseline exercises
        the real code path rather than a model's reconstruction.
        """
        method = str(item.get("method") or "GET").upper()
        action = str(item.get("action_url") or item.get("url") or "")
        content_type = str(item.get("content_type") or "")
        headers_json = item.get("headers_json")
        if not headers_json:
            headers = {"Content-Type": content_type} if content_type else {}
            headers_json = json.dumps(headers, separators=(",", ":"))
        body = str(item.get("body_template") or "")
        url = action
        if method == "GET":
            query = str(item.get("query_template") or "")
            if query and "?" not in action:
                url = f"{action}?{query}"
            body = ""
        return {
            "method": method,
            "url": url,
            "headers_json": headers_json,
            "body": body,
        }

    @staticmethod
    def _key(record: dict) -> tuple:
        return (
            _endpoint(record.get("endpoint")),
            str(record.get("method") or "GET").upper(),
            str(record.get("identity") or "unspecified"),
            _parameter_spec(record.get("parameter"), str(record.get("method") or "GET")),
            _normalize_class(record.get("vulnerability_class")),
        )

    def _resolve_result_key(self, record: dict) -> tuple:
        """Map a probe/finding result onto an existing planned cell when possible.

        A deterministic result rarely reports the endpoint, identity, or
        parameter exactly as the plan enumerated them (e.g. sqlmap reports
        ``unspecified`` where the plan used ``anonymous``, or echoes the full
        URL with its query string). Without reconciliation the result forks a
        new ``planned=False`` row and the planned cell stays ``pending`` — so a
        proven finding never closes its own cell. We attach the result to the
        best matching planned row instead, relaxing only identity (never the
        endpoint, class, method, or a concrete parameter).
        """
        exact = self._key(record)
        if exact in self._records:
            return exact
        endpoint, method, identity, parameter, cls = exact
        generic_identities = {"", "anonymous", "unspecified"}
        best: Optional[tuple] = None
        best_rank: Optional[tuple] = None
        for key, row in self._records.items():
            if not row.get("planned"):
                continue
            if key[4] != cls or key[0] != endpoint or key[1] != method:
                continue
            # Parameter must match, unless one side is endpoint-level scope.
            if not (key[3] == parameter or key[3] == "endpoint" or parameter == "endpoint"):
                continue
            # Relax identity only between generic placeholders (e.g. a sqlmap
            # result reporting "unspecified" closing an "anonymous" plan row).
            # Never let a placeholder claim a named identity's cell, so
            # identity-sensitive classes keep their per-identity gaps visible.
            if key[2] != identity and not (
                key[2] in generic_identities and identity in generic_identities
            ):
                continue
            rank = (
                key[2] != identity,                 # prefer same identity
                key[3] != parameter,                # prefer the concrete parameter
                row.get("state") not in {"pending", "in_progress"},  # prefer untested
            )
            if best_rank is None or rank < best_rank:
                best_rank, best = rank, key
        return best or exact

    def _upsert(self, record: dict, *, planned: bool, key: Optional[tuple] = None) -> dict:
        state = str(record.get("state") or "pending")
        if state not in COVERAGE_STATES:
            raise ValueError(f"invalid coverage state: {state}")
        if key is None:
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
            key = self._resolve_result_key(record)
            row = self._upsert(record, planned=False, key=key)
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
            payload.get("target") or payload.get("inject_url")
            or payload.get("url") or payload.get("endpoint")
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
        # Interleave classes so a large SQLi/XSS surface cannot hide every
        # other pending class from the bounded hunter prompt.
        by_class: Dict[str, List[dict]] = {}
        for row in rows:
            by_class.setdefault(row["vulnerability_class"], []).append(row)
        for group in by_class.values():
            group.sort(key=lambda row: (row["endpoint"], row["parameter"], row["identity"]))
        result: List[dict] = []
        while by_class and len(result) < max(0, limit):
            for vuln_class in sorted(list(by_class)):
                result.append(by_class[vuln_class].pop(0))
                if not by_class[vuln_class]:
                    del by_class[vuln_class]
                if len(result) >= limit:
                    break
        return result

    def lease(
        self,
        *,
        classes: Optional[Iterable[str]] = None,
        limit: int = 20,
        owner: str = "",
    ) -> dict:
        """Hand out a bounded, disjoint set of pending cells as a worklist.

        Breadth before depth: leased cells move to ``in_progress`` so a
        concurrent hunter's lease never returns them, and validated/tested cells
        are never re-handed-out. This stops two specialists from both hammering
        a single already-interesting input while most inputs go untouched.

        Returns ``{"lease": token, "cells": [...]}``. ``release(token)`` reverts
        any cell still ``in_progress`` so a failed handoff keeps its coverage.
        """
        import uuid

        wanted = {_normalize_class(c) for c in classes} if classes is not None else None
        token = owner or f"lease-{uuid.uuid4().hex[:10]}"
        with self._lock:
            candidates = [
                (key, row) for key, row in self._records.items()
                if row.get("planned") and row["state"] == "pending"
                and (wanted is None or row["vulnerability_class"] in wanted)
            ]
            # Interleave classes so a large single-class surface can't crowd out
            # breadth across the rest of the leased worklist.
            by_class: Dict[str, List[tuple]] = {}
            for key, row in candidates:
                by_class.setdefault(row["vulnerability_class"], []).append((key, row))
            for group in by_class.values():
                group.sort(key=lambda kr: (kr[1]["endpoint"], kr[1]["parameter"], kr[1]["identity"]))
            chosen: List[tuple] = []
            while by_class and len(chosen) < max(0, limit):
                for vuln_class in sorted(list(by_class)):
                    chosen.append(by_class[vuln_class].pop(0))
                    if not by_class[vuln_class]:
                        del by_class[vuln_class]
                    if len(chosen) >= limit:
                        break
            now = _now()
            cells = []
            for key, row in chosen:
                row["state"] = "in_progress"
                row["updated_at"] = now
                cell = copy.deepcopy(row)
                baseline = self._baselines.get((row["endpoint"], row["method"]))
                if baseline:
                    cell["baseline"] = dict(baseline)
                cells.append(cell)
            if chosen:
                self._leases.setdefault(token, []).extend(key for key, _ in chosen)
            return {"lease": token, "cells": cells}

    def baseline_for(self, endpoint: str, method: str = "GET") -> Optional[dict]:
        """Return the captured baseline request for an observed input, if any."""
        with self._lock:
            baseline = self._baselines.get((_endpoint(endpoint), str(method or "GET").upper()))
            return dict(baseline) if baseline else None

    def release(self, token: str) -> int:
        """Revert a lease's still-``in_progress`` cells to ``pending``.

        Called when a hunter handoff fails so its assigned inputs are not lost;
        cells that advanced (evidence recorded) are left as-is.
        """
        reverted = 0
        with self._lock:
            keys = self._leases.pop(token, [])
            now = _now()
            for key in keys:
                row = self._records.get(key)
                if row and row["state"] == "in_progress":
                    row["state"] = "pending"
                    row["updated_at"] = now
                    reverted += 1
        return reverted

    def release_stale(self) -> int:
        """Flip any lingering ``in_progress`` cell back to ``pending``.

        Run once at fan-in so the final ledger reports genuinely untested inputs
        as gaps rather than leaving them stuck mid-flight.
        """
        reverted = 0
        with self._lock:
            now = _now()
            for row in self._records.values():
                if row.get("planned") and row["state"] == "in_progress":
                    row["state"] = "pending"
                    row["updated_at"] = now
                    reverted += 1
            self._leases.clear()
        return reverted

    def snapshot(self, limit: Optional[int] = None) -> List[dict]:
        with self._lock:
            rows = [copy.deepcopy(row) for row in self._records.values()]
        rows.sort(key=lambda row: (
            row["endpoint"], row["method"], row["parameter"],
            row["vulnerability_class"], row["identity"],
        ))
        return rows if limit is None else rows[:max(0, limit)]
