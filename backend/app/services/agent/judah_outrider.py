"""Judah Outrider: use an external ARTEX instance as a scout, at arm's length.

ARTEX runs as its own container (AGPL-3.0, not linked into this codebase) and
is driven only through its REST API. Outrider:

1. **Dispatches** an ARTEX task for a Prowl session: the session's approved
   scope hosts, a goal Prowl writes, ARTEX's target gate switched on, and no
   credentials. Nothing else from Prowl is sent.
2. **Imports** the task's findings as *leads* through Prowl's existing external
   candidate intake (:mod:`external_candidates`): each one is wrapped as
   untrusted text, scope-checked against the session, severity-capped, and
   left ``pending``. Prowl's own independent verifier must reproduce it with
   fresh receipts before anything is published. ARTEX's own "verified" flag
   is ignored.

Configuration (environment): ``JUDAH_OUTRIDER_URL`` (e.g.
``http://artex:8787``), and either ``JUDAH_OUTRIDER_TOKEN`` or
``JUDAH_OUTRIDER_USERNAME`` + ``JUDAH_OUTRIDER_PASSWORD``. Run ARTEX on an
isolated network with egress limited to in-scope targets; see
``docs/JUDAH_SUITE.md``.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

TERMINAL_STATUSES = frozenset({"done", "failed", "timeout"})
MAX_IMPORT = 25
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)

# ARTEX vulnerability class -> Prowl coverage class (external_candidates).
_CLASS_MAP = {
    "sqli": "sqli", "sql_injection": "sqli", "sql injection": "sqli",
    "xss": "xss", "reflected_xss": "xss", "dom_xss": "xss", "stored_xss": "stored_xss",
    "ssrf": "ssrf", "ssti": "ssti", "xxe": "xxe", "csrf": "csrf", "cors": "cors",
    "crlf": "crlf", "nosql": "nosql", "nosqli": "nosql", "open_redirect": "open_redirect",
    "path_traversal": "path_traversal", "lfi": "path_traversal", "directory_traversal": "path_traversal",
    "rce": "command_injection", "command_injection": "command_injection", "cmdi": "command_injection",
    "idor": "authz", "bola": "authz", "bac": "authz", "broken_access_control": "authz",
    "authz": "authz", "authorization": "authz", "privilege_escalation": "authz",
    "race_condition": "race_condition", "race": "race_condition",
    "file_upload": "file_upload", "graphql": "graphql", "oauth": "oauth", "jwt": "oauth",
    "business_logic": "business_logic", "logic": "business_logic",
    "prototype_pollution": "prototype_pollution",
}


class OutriderError(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def configured() -> bool:
    return bool(os.environ.get("JUDAH_OUTRIDER_URL", "").strip())


def _base_url() -> str:
    raw = os.environ.get("JUDAH_OUTRIDER_URL", "").strip().rstrip("/")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise OutriderError(503, "JUDAH_OUTRIDER_URL must be an http(s) URL without credentials")
    return raw


class OutriderClient:
    """Minimal client for the ARTEX REST API."""

    def __init__(self, base_url: Optional[str] = None, *, transport: Any = None,
                 token: Optional[str] = None, timeout: float = 30.0) -> None:
        self.base_url = (base_url or _base_url()).rstrip("/")
        self._token = token or os.environ.get("JUDAH_OUTRIDER_TOKEN", "").strip() or None
        kwargs: dict = {"base_url": self.base_url, "timeout": timeout, "trust_env": False}
        if transport is not None:
            kwargs["transport"] = transport
        self._http = httpx.AsyncClient(**kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self._http.aclose()

    async def _auth(self) -> dict:
        if not self._token:
            user = os.environ.get("JUDAH_OUTRIDER_USERNAME", "")
            password = os.environ.get("JUDAH_OUTRIDER_PASSWORD", "")
            if not (user and password):
                raise OutriderError(503, "Outrider credentials are not configured")
            resp = await self._http.post("/api/auth/login", json={"username": user, "password": password})
            if resp.status_code != 200:
                raise OutriderError(502, f"ARTEX login failed ({resp.status_code})")
            self._token = str((resp.json() or {}).get("token") or "")
            if not self._token:
                raise OutriderError(502, "ARTEX login returned no token")
        return {"Authorization": f"Bearer {self._token}"}

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        resp = await self._http.request(method, path, headers=await self._auth(), **kwargs)
        if resp.status_code >= 400:
            raise OutriderError(502, f"ARTEX {method} {path} failed ({resp.status_code})")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise OutriderError(502, f"ARTEX {method} {path} returned non-JSON") from exc

    async def create_task(self, body: dict) -> dict:
        return await self._request("POST", "/api/tasks", json=body) or {}

    async def add_scope(self, task_id: Any, kind: str, value: str, reason: str) -> Any:
        return await self._request("POST", f"/api/tasks/{task_id}/scope",
                                   json={"kind": kind, "value": value, "reason": reason})

    async def task(self, task_id: Any) -> dict:
        return await self._request("GET", f"/api/tasks/{task_id}") or {}

    async def outcome(self, task_id: Any) -> dict:
        return await self._request("GET", f"/api/tasks/{task_id}/outcome") or {}

    async def findings(self, task_id: Any) -> list:
        data = await self._request("GET", "/api/exploration/findings", params={"task": str(task_id)})
        if isinstance(data, dict):
            data = data.get("items") or []
        return [row for row in data or [] if isinstance(row, dict)]


# ---------------------------------------------------------------- dispatch

def scope_entries(hosts: list[str]) -> list[tuple[str, str]]:
    import ipaddress

    out = []
    for host in sorted({(h or "").lower().strip().rstrip(".") for h in hosts if h}):
        try:
            ipaddress.ip_address(host)
            out.append(("ip", host))
            continue
        except ValueError:
            pass
        if host.startswith("*."):
            out.append(("root_domain", host[2:]))
        else:
            out.append(("subdomain", host))
    return out


def task_body(session_id: str, hosts: list[str], *, timeout_seconds: int = 3600) -> dict:
    listed = ", ".join(sorted(hosts)[:20])
    return {
        "name": f"Judah Outrider {session_id[:24]}",
        "description": (f"Authorized assessment requested by Judah Security for: {listed}. "
                        "Stay strictly within these hosts."),
        "goal": ("Find exploitable vulnerabilities on the listed hosts only. Prove impact with "
                 "captured requests and responses. Do not test any other host."),
        "timeout_seconds": int(max(300, min(timeout_seconds, 4 * 3600))),
        "target_gate": True,
        "coverage_enabled": True,
    }


async def dispatch(client: OutriderClient, session_id: str, hosts: list[str], *,
                   timeout_seconds: int = 3600) -> dict:
    if not hosts:
        raise OutriderError(400, "The session has no approved scope to hand to Outrider")
    created = await client.create_task(task_body(session_id, hosts, timeout_seconds=timeout_seconds))
    task_id = created.get("id") or (created.get("task") or {}).get("id")
    if not task_id:
        raise OutriderError(502, "ARTEX did not return a task id")
    for kind, value in scope_entries(hosts):
        await client.add_scope(task_id, kind, value, "Judah Prowl session scope")
    return {"task_id": task_id, "hosts": sorted(hosts), "dispatched_at": time.time()}


# ---------------------------------------------------------------- import

def coverage_class(vulnclass: str, name: str = "") -> str:
    from app.services.agent.external_candidates import coverage_classes

    key = (vulnclass or "").strip().lower().replace("-", "_")
    mapped = _CLASS_MAP.get(key) or _CLASS_MAP.get(key.replace("_", " "))
    if not mapped and key in set(coverage_classes()):
        mapped = key
    if not mapped:
        blob = f"{vulnclass} {name}".lower()
        mapped = next((v for k, v in _CLASS_MAP.items() if k.replace("_", " ") in blob), "business_logic")
    return mapped


def finding_target(row: dict) -> str:
    for asset in row.get("assets") or []:
        label = str((asset or {}).get("label") or "")
        if label.startswith(("http://", "https://")):
            return label
    blob = " ".join(str(row.get(k) or "") for k in ("summary", "evidence"))
    match = _URL_RE.search(blob)
    if match:
        return match.group(0).rstrip(".,;")
    for asset in row.get("assets") or []:
        label = str((asset or {}).get("label") or "")
        if label and "." in label and " " not in label:
            return "https://" + label.strip("/")
    return ""


def to_candidate(row: dict) -> Optional[dict]:
    target = finding_target(row)
    if not target:
        return None
    severity = str(row.get("severity") or "medium").lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "medium"
    title = str(row.get("name") or row.get("vulnclass") or "ARTEX lead").strip()
    return {
        "title": ("ARTEX lead: " + title)[:200],
        "target": target[:2048],
        "vulnerability_class": coverage_class(str(row.get("vulnclass") or ""), title),
        "description": str(row.get("summary") or "")[:2000],
        "severity": severity,
        "evidence_note": (f"ARTEX finding {row.get('finding_id') or row.get('id')}, "
                          f"ARTEX status {row.get('status')!s}; ARTEX verification is not "
                          "accepted as proof.")[:1000],
    }


async def import_findings(client: OutriderClient, organization_id: int, session_id: str,
                          task_id: Any, *, already: Optional[set] = None,
                          submit=None) -> dict:
    """Submit new ARTEX findings as pending Prowl candidates. Returns a summary."""
    if submit is None:
        from app.services.agent.external_candidates import submit_external_candidate as submit
    from app.services.agent.external_candidates import IntakeError

    already = set(already or ())
    rows = await client.findings(task_id)
    summary = {"seen": len(rows), "submitted": [], "skipped": []}
    for row in rows:
        fid = str(row.get("finding_id") or row.get("id") or "")
        if not fid or fid in already:
            continue
        if str(row.get("status") or "").lower() in ("false_positive", "ignored", "duplicate"):
            summary["skipped"].append({"id": fid, "reason": f"ARTEX status {row.get('status')}"})
            already.add(fid)
            continue
        if len(summary["submitted"]) >= MAX_IMPORT:
            summary["skipped"].append({"id": fid, "reason": "import cap reached"})
            continue
        candidate = to_candidate(row)
        if candidate is None:
            summary["skipped"].append({"id": fid, "reason": "no target URL"})
            already.add(fid)
            continue
        try:
            result = submit(organization_id, session_id, **candidate)
        except IntakeError as exc:
            summary["skipped"].append({"id": fid, "reason": exc.detail})
            already.add(fid)
            continue
        already.add(fid)
        result = result or {}
        if not result.get("accepted"):
            summary["skipped"].append({"id": fid, "reason": f"duplicate of {result.get('duplicate_of')}"})
            continue
        stored = result.get("candidate") or {}
        summary["submitted"].append({
            "id": fid, "candidate": stored.get("id") or stored.get("candidate_id"),
            "class": candidate["vulnerability_class"], "queued": bool(result.get("queued")),
        })
    summary["imported_ids"] = sorted(already)
    return summary


# ---------------------------------------------------------------- state

def _state_dir() -> Path:
    base = os.environ.get("AEGIS_DATA_DIR", "").strip() or "/app/data"
    return Path(os.environ.get("JUDAH_OUTRIDER_STATE_DIR", "") or Path(base) / "outrider")


def _state_path(organization_id: int, session_id: str) -> Path:
    import hashlib

    digest = hashlib.sha256(f"{organization_id}:{session_id}".encode()).hexdigest()[:32]
    return _state_dir() / f"{digest}.json"


def load_state(organization_id: int, session_id: str) -> dict:
    path = _state_path(organization_id, session_id)
    try:
        return json.loads(path.read_text()) if path.is_file() else {}
    except (OSError, ValueError):
        return {}


def save_state(organization_id: int, session_id: str, state: dict) -> None:
    path = _state_path(organization_id, session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, default=str))
    tmp.replace(path)


def session_scope_hosts(snapshot: dict) -> list[str]:
    """Hosts this session is approved for, from its saved run snapshot."""
    from app.services.agent.external_candidates import session_seed

    hosts: set[str] = set()
    seed = session_seed(snapshot or {})
    if seed:
        host = urlsplit(seed if "://" in seed else "//" + seed).hostname
        if host:
            hosts.add(host.lower())
    # Only the session's seed host: that is all the intake will accept back.
    return sorted(hosts)


__all__ = [
    "OutriderClient", "OutriderError", "configured", "coverage_class", "dispatch",
    "finding_target", "import_findings", "load_state", "save_state", "scope_entries",
    "session_scope_hosts", "task_body", "to_candidate",
]
