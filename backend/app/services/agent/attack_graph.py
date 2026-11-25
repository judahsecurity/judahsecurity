"""Facts and intents with lineage on the engagement brain (AntiFox-style graph).

* A **fact** is something observed: an origin, an evidence-backed exchange, an
  operator-supplied lead, a callback, a verdict, a parsed scanner result.
* An **intent** is one planned test (class + target + parameter/location +
  identity). It must cite at least one existing parent: a fact, or a candidate
  (finding) id. Intents never hang off other intents only.
* A worker **claims** an open intent, then **completes** it by citing the result
  facts it recorded. Completion without a result fact is refused.

Intents can be backed by a coverage cell, so the scoped probes that lease cells
can work them, including operator-directed tests on parameters Prowl never
observed itself. Facts and intents are planning state: neither is proof.
Everything is stored as plain dicts on ``EngagementBrain.facts`` / ``.intents``.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

FACT_KINDS = frozenset({
    "origin", "observation", "evidence", "operator", "callback", "replay", "verdict", "parser",
})
INTENT_STATUSES = ("open", "claimed", "done", "blocked", "cancelled")
INTENT_LOCATIONS = frozenset({
    "", "query", "body_form", "body_json", "body_xml", "header", "cookie", "path", "fragment",
})
_TERMINAL = frozenset({"done", "blocked", "cancelled"})
# Source of a coverage cell created for an intent (no observed capture behind it).
INTENT_CELL_SOURCE = "attack_graph_intent"
MAX_FACTS = 2000
MAX_INTENTS = 1000
_TEXT = 400


class LineageError(ValueError):
    """An intent or fact cites parents that do not exist (or none at all)."""


def _clean(value: Any, limit: int = _TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _id(prefix: str, *parts: Any) -> str:
    raw = json.dumps([str(p) for p in parts], separators=(",", ":"))
    return f"{prefix}-{hashlib.sha1(raw.encode()).hexdigest()[:12]}"


def _facts(brain: Any) -> List[Dict[str, Any]]:
    if not isinstance(getattr(brain, "facts", None), list):
        brain.facts = []
    return brain.facts


def _intents(brain: Any) -> List[Dict[str, Any]]:
    if not isinstance(getattr(brain, "intents", None), list):
        brain.intents = []
    return brain.intents


def _candidate_ids(brain: Any) -> set:
    return {str(c.get("id")) for c in (getattr(brain, "candidates", None) or [])
            if isinstance(c, dict) and c.get("id")}


def get_fact(brain: Any, fact_id: str) -> Optional[Dict[str, Any]]:
    return next((f for f in _facts(brain) if f.get("id") == fact_id), None)


def get_intent(brain: Any, intent_id: str) -> Optional[Dict[str, Any]]:
    return next((i for i in _intents(brain) if i.get("id") == intent_id), None)


def _check_parents(brain: Any, parents: Iterable[str], *, allow_intents: bool) -> List[str]:
    wanted = [str(p) for p in parents or [] if str(p or "").strip()]
    if not wanted:
        raise LineageError("cite at least one parent fact or finding id")
    facts = {f.get("id") for f in _facts(brain)}
    findings = _candidate_ids(brain)
    intents = {i.get("id") for i in _intents(brain)} if allow_intents else set()
    missing = [p for p in wanted if p not in facts and p not in findings and p not in intents]
    if missing:
        raise LineageError(f"unknown parent id(s): {', '.join(missing[:5])}")
    if not allow_intents and not any(p in facts or p in findings for p in wanted):
        raise LineageError("an intent must cite a fact or finding, not only other intents")
    return list(dict.fromkeys(wanted))


def _trim(rows: List[Dict[str, Any]], limit: int, *, keep_open: bool) -> None:
    if len(rows) <= limit:
        return
    if keep_open:
        closed = [r for r in rows if r.get("status") in _TERMINAL]
        for row in closed[: len(rows) - limit]:
            rows.remove(row)
    del rows[: max(0, len(rows) - limit)]


# ---------------------------------------------------------------- facts

def ensure_origin_fact(brain: Any, target: str) -> Dict[str, Any]:
    """The root fact for an engagement target (the AntiFox origin fact)."""
    parts = urlsplit(target if "://" in str(target) else f"https://{target}")
    origin = f"{parts.scheme}://{parts.netloc}".lower() if parts.netloc else _clean(target)
    fid = _id("fact", "origin", origin)
    existing = get_fact(brain, fid)
    if existing:
        return existing
    row = {"id": fid, "kind": "origin", "summary": f"Engagement target {origin}", "target": origin,
           "parents": [], "evidence_ids": [], "source": "engagement", "data": {},
           "created_at": time.time()}
    _facts(brain).append(row)
    return row


def record_fact(brain: Any, *, kind: str, summary: str, target: str = "",
                evidence_ids: Iterable[str] = (), source: str = "", parents: Iterable[str] = (),
                data: Optional[Dict[str, Any]] = None, key: str = "") -> Dict[str, Any]:
    """Add (or return the existing) fact. Parents may be facts, findings or intents.

    ``origin`` facts use ensure_origin_fact. Other facts need a parent unless the
    brain has no facts yet, in which case the target's origin fact is created
    and used as the parent.
    """
    kind = str(kind or "").strip().lower()
    if kind not in FACT_KINDS or kind == "origin":
        raise ValueError(f"fact kind must be one of {sorted(FACT_KINDS - {'origin'})}")
    summary = _clean(summary)
    if not summary:
        raise ValueError("fact summary is required")
    parents = list(parents or [])
    if not parents:
        root_target = target or getattr(brain, "target", "")
        if not root_target:
            raise LineageError("cite a parent fact, or set the engagement target first")
        parents = [ensure_origin_fact(brain, root_target)["id"]]
    parents = _check_parents(brain, parents, allow_intents=True)
    evidence = [str(e)[:80] for e in evidence_ids or [] if e][:20]
    fid = _id("fact", kind, key or summary, target, *sorted(evidence))
    existing = get_fact(brain, fid)
    if existing:
        existing["parents"] = list(dict.fromkeys([*existing.get("parents", []), *parents]))
        return existing
    row = {"id": fid, "kind": kind, "summary": summary, "target": _clean(target, 2048),
           "parents": parents, "evidence_ids": evidence, "source": _clean(source, 80),
           "data": _bounded_data(data), "created_at": time.time()}
    rows = _facts(brain)
    rows.append(row)
    _trim(rows, MAX_FACTS, keep_open=False)
    return row


def _bounded_data(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {}
    for key, value in list(data.items())[:20]:
        if isinstance(value, (int, float, bool)) or value is None:
            out[str(key)[:60]] = value
        else:
            out[str(key)[:60]] = _clean(value if isinstance(value, str) else json.dumps(value, default=str))
    return out


# ---------------------------------------------------------------- intents

def normalize_test_type(test_type: Any) -> str:
    return _clean(test_type, 64).lower().replace(" ", "_").replace("-", "_")


def intent_id_for(*, test_type: str, target: str, parameter: str = "", location: str = "",
                  method: str = "GET", identity: str = "") -> str:
    """The id add_intent gives this test, so intake can dedup before the brain is loaded."""
    return _id("intent", normalize_test_type(test_type), (_clean(method, 10) or "GET").upper(),
               target, _clean(parameter, 128), _clean(location, 20).lower(), _clean(identity, 40))


def add_intent(brain: Any, *, objective: str, test_type: str, target: str, parents: Iterable[str],
               parameter: str = "", location: str = "", method: str = "GET", identity: str = "",
               created_by: str = "planner", link_coverage: bool = True) -> Dict[str, Any]:
    """Add one planned test. Same test on the same input returns the existing intent."""
    test_type = normalize_test_type(test_type)
    if not test_type:
        raise ValueError("test_type is required")
    location = _clean(location, 20).lower()
    if location not in INTENT_LOCATIONS:
        raise ValueError(f"location must be one of {sorted(INTENT_LOCATIONS - {''})}")
    method = (_clean(method, 10) or "GET").upper()
    parts = urlsplit(str(target or ""))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("intent target must be an absolute http(s) URL")
    parents = _check_parents(brain, parents, allow_intents=False)
    parameter = _clean(parameter, 128)
    identity = _clean(identity, 40)
    iid = intent_id_for(test_type=test_type, target=target, parameter=parameter,
                        location=location, method=method, identity=identity)
    existing = get_intent(brain, iid)
    if existing:
        existing["parents"] = list(dict.fromkeys([*existing.get("parents", []), *parents]))
        return existing
    row = {"id": iid, "objective": _clean(objective) or f"{test_type} on {parameter or target}",
           "test_type": test_type, "method": method, "target": _clean(target, 2048),
           "parameter": parameter, "location": location, "identity": identity,
           "parents": parents, "status": "open", "claimed_by": "", "result_facts": [],
           "created_by": _clean(created_by, 40) or "planner", "coverage_cell_id": "",
           "created_at": time.time(), "updated_at": time.time()}
    if link_coverage:
        row["coverage_cell_id"] = _link_coverage_cell(brain, row, parts)
    rows = _intents(brain)
    rows.append(row)
    _trim(rows, MAX_INTENTS, keep_open=True)
    return row


def _link_coverage_cell(brain: Any, intent: Dict[str, Any], parts) -> str:
    """Back the intent with an exact coverage cell so lease-based probes can work it.

    A new cell is marked ``source=INTENT_CELL_SOURCE`` with the intent id, so
    the scoped probes build its request from the intent (there is no capture).
    When the cell already exists (Prowl observed the same input), it keeps its
    own source and capture and only gains the intent id.
    """
    try:
        from app.services.agent.coverage_cells import record_coverage_cell
    except Exception:  # pragma: no cover - import guard
        return ""
    parameter = intent["parameter"]
    if parameter and intent["location"] and ":" not in parameter:
        parameter = f"{intent['location']}:{parameter}"
    try:
        from app.services.agent.coverage_cells import coverage_cell_id

        cid = coverage_cell_id(
            method=intent["method"], path=parts.path or "/", host=parts.netloc, operation_id="",
            identity=intent["identity"] or "anonymous", tenant="",
            parameter=parameter or "endpoint", test_type=intent["test_type"])
        existing = next((c for c in getattr(brain, "coverage_cells", None) or []
                         if c.get("id") == cid), None)
        if existing is not None:
            # Never reset an observed cell's status, lease or verdict.
            existing["intent_id"] = existing.get("intent_id") or intent["id"]
            return cid
        cell = record_coverage_cell(
            brain, method=intent["method"], path=parts.path or "/", host=parts.netloc,
            status="untested", identity=intent["identity"] or "anonymous", parameter=parameter,
            test_type=intent["test_type"], reason=f"intent {intent['id']} ({intent['created_by']})",
        )
    except Exception:
        return ""
    cell_id = str((cell or {}).get("id") or "")
    live = next((c for c in brain.coverage_cells if c.get("id") == cell_id), None)
    if live is not None:
        live["intent_id"] = intent["id"]
        live["source"] = INTENT_CELL_SOURCE
        live["observation_source"] = f"{intent['created_by']}_intent"[:40]
    return cell_id


def claim_intent(brain: Any, intent_id: str, worker: str) -> Dict[str, Any]:
    intent = get_intent(brain, intent_id)
    if intent is None:
        raise ValueError(f"unknown intent {intent_id}")
    worker = _clean(worker, 60)
    if not worker:
        raise ValueError("worker is required")
    if intent["status"] == "claimed" and intent["claimed_by"] == worker:
        return intent
    if intent["status"] != "open":
        raise ValueError(f"intent {intent_id} is {intent['status']}"
                         + (f" by {intent['claimed_by']}" if intent["claimed_by"] else ""))
    intent.update(status="claimed", claimed_by=worker, updated_at=time.time())
    return intent


def complete_intent(brain: Any, intent_id: str, worker: str, *, result_facts: Iterable[str],
                    status: str = "done", note: str = "") -> Dict[str, Any]:
    """Close a claimed intent, citing the facts the work produced."""
    intent = get_intent(brain, intent_id)
    if intent is None:
        raise ValueError(f"unknown intent {intent_id}")
    if status not in _TERMINAL:
        raise ValueError(f"status must be one of {sorted(_TERMINAL)}")
    if intent["status"] != "claimed" or intent["claimed_by"] != _clean(worker, 60):
        raise ValueError(f"intent {intent_id} is not claimed by {worker}")
    results = [str(f) for f in result_facts or [] if f]
    known = {f.get("id") for f in _facts(brain)}
    missing = [f for f in results if f not in known]
    if missing:
        raise LineageError(f"unknown result fact(s): {', '.join(missing[:5])}")
    if status == "done" and not results:
        raise LineageError("a done intent must cite at least one result fact")
    intent.update(status=status, result_facts=list(dict.fromkeys(results)),
                  note=_clean(note), updated_at=time.time())
    return intent


def open_intents(brain: Any, *, test_type: str = "") -> List[Dict[str, Any]]:
    return [i for i in _intents(brain) if i.get("status") == "open"
            and (not test_type or i.get("test_type") == test_type)]


def lineage(brain: Any, node_id: str, *, depth: int = 12) -> List[Dict[str, str]]:
    """Ancestors of a fact or intent, nearest first."""
    out: List[Dict[str, str]] = []
    seen = {node_id}
    frontier = [node_id]
    while frontier and len(out) < 50 and depth > 0:
        depth -= 1
        nxt = []
        for nid in frontier:
            node = get_fact(brain, nid) or get_intent(brain, nid)
            for parent in (node or {}).get("parents", []):
                if parent in seen:
                    continue
                seen.add(parent)
                p = get_fact(brain, parent) or get_intent(brain, parent)
                label = (p or {}).get("summary") or (p or {}).get("objective") or "finding"
                out.append({"id": parent, "label": _clean(label, 160)})
                nxt.append(parent)
        frontier = nxt
    return out


def overview(brain: Any, *, recent: int = 15) -> Dict[str, Any]:
    """Planner snapshot: counts, open/claimed intents with lineage, recent facts."""
    facts = _facts(brain)
    intents = _intents(brain)
    by_status: Dict[str, int] = {}
    for intent in intents:
        by_status[intent.get("status", "open")] = by_status.get(intent.get("status", "open"), 0) + 1
    active = [i for i in intents if i.get("status") in ("open", "claimed")][:30]
    return {
        "facts": len(facts),
        "intents": by_status,
        "findings": len(_candidate_ids(brain)),
        "active_intents": [{
            "id": i["id"], "status": i["status"], "test_type": i["test_type"],
            "target": i["target"], "parameter": i["parameter"], "location": i["location"],
            "claimed_by": i["claimed_by"], "coverage_cell_id": i["coverage_cell_id"],
            "lineage": [step["id"] for step in lineage(brain, i["id"], depth=3)],
        } for i in active],
        "recent_facts": [{
            "id": f["id"], "kind": f["kind"], "summary": f["summary"],
            "evidence_ids": f.get("evidence_ids", [])[:5],
        } for f in facts[-recent:]],
        "note": "Facts and intents are planning state, never proof.",
    }
