"""Judah Recheck: replay a published finding's own proof later.

When Prowl publishes a finding, the evidence and captures behind it expire with
the session (24 hours by default), and an old capture can never be replayed
because proofs are bound to a fresh verifier run. So the recheck does not
reuse evidence. Instead:

1. **At proof time** the hunter tool remembers the exact recipe it proved:
   proof recipe name, the observed baseline URL, the parameter and identity
   (:func:`remember`).
2. **At publish time** that recipe is stored on the finding as
   ``metadata.recheck_recipe`` if it is safe to store: anonymous identity, a
   supported recipe, and a baseline URL that contains no secrets
   (:func:`publishable`).
3. **At recheck time** the same recipe runs again with a **fresh nonce**,
   scoped to the finding's origin only (:func:`recheck`), and through the
   Judah Gate when it is running.

Outcomes (the finding's original evidence is never changed):

* ``still_reproducible`` — the recipe proved the issue again.
* ``fixed`` — every control request succeeded with a stable baseline and the
  differential the proof depends on is gone.
* ``cannot_confirm`` — anything else: unsupported recipe, authenticated
  identity, unstable or failing baseline, out-of-scope, network error.

Supported recipes: numeric AND Boolean SQLi, string OR Boolean SQLi (and its
JSON-rows variant), string AND Boolean SQLi. Error-, time- and UNION-based
proofs are not replayed, because rerunning a different lane could report
``fixed`` for a bug that is still there.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

RECIPE_VERSION = 1
SUPPORTED_RECIPES = frozenset({
    "numeric_and_boolean_v1",
    "string_or_boolean_v1",
    "string_or_json_rows_v1",
    "string_and_boolean_v1",
})
OUTCOMES = ("still_reproducible", "fixed", "cannot_confirm")
VALIDATION_VERDICT = {
    "still_reproducible": "confirmed",
    "fixed": "false_positive",
    "cannot_confirm": "needs_more_evidence",
}
MAX_HISTORY = 20


def remember(tools_manager: Any, evidence_id: str, result: dict, *, baseline: str,
             parameter: str, identity: str) -> None:
    """Keep a proved recipe on the tools manager for a later publish."""
    if not evidence_id or result.get("proof_confirmed") is not True:
        return
    recipe = str(result.get("proof_recipe") or "")
    if recipe not in SUPPORTED_RECIPES:
        return
    store = getattr(tools_manager, "_recheck_recipes", None)
    if store is None:
        store = {}
        setattr(tools_manager, "_recheck_recipes", store)
    store[evidence_id] = {
        "version": RECIPE_VERSION, "recipe": recipe, "baseline": baseline,
        "parameter": parameter, "identity": identity or "anonymous",
        "target": result.get("target"),
    }


def publishable(recipe: Optional[dict]) -> Optional[dict]:
    """The recipe as it may be stored on a finding, or None if it cannot be."""
    if not isinstance(recipe, dict) or recipe.get("recipe") not in SUPPORTED_RECIPES:
        return None
    if (recipe.get("identity") or "anonymous") != "anonymous":
        return None  # credentials are never persisted, so we could not replay it
    baseline = str(recipe.get("baseline") or "")
    parts = urlsplit(baseline)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    from app.services.agent.content_shield import redact_sensitive

    if redact_sensitive(baseline)[0] != baseline:
        return None  # the observed URL carries something secret-shaped
    return {k: recipe[k] for k in ("version", "recipe", "baseline", "parameter", "identity", "target")}


def recipe_for_finding(remembered: dict, evidence_ids: list) -> Optional[dict]:
    for eid in evidence_ids or []:
        found = publishable((remembered or {}).get(str(eid)))
        if found:
            return found
    return None


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _rows(result: dict) -> list[dict]:
    checks = result.get("checks") or {}
    return [row for row in checks.values() if isinstance(row, dict)]


def _baseline_stable(result: dict) -> bool:
    checks = result.get("checks") or {}
    first, last = checks.get("baseline_first"), checks.get("baseline_last")
    rows = _rows(result)
    return (bool(rows) and isinstance(first, dict) and isinstance(last, dict)
            and all(r.get("status") == 200 and r.get("redirected") is False
                    and r.get("truncated") is False for r in rows)
            and first.get("body_sha256") == last.get("body_sha256"))


def classify(result: dict) -> tuple[str, str]:
    if result.get("proof_confirmed") is True:
        return "still_reproducible", "The original proof recipe confirmed the issue again with a fresh nonce."
    if _baseline_stable(result):
        return "fixed", ("Every control request returned 200 with a stable baseline, and the "
                         "true/false differential the proof relied on is gone.")
    return "cannot_confirm", ("The replay did not get a stable, successful baseline, so the "
                              "result neither confirms nor clears the finding.")


def _run_recipe(recipe: dict) -> dict:
    from app.services.agent.scoped_assessment import sqli_boolean, sqli_string

    baseline, parameter = recipe["baseline"], recipe["parameter"]
    allowed = [_origin(baseline)]
    name = recipe["recipe"]
    if name == "numeric_and_boolean_v1":
        base, true_url, false_url, nonce = sqli_boolean.plan_numeric_boolean_url(
            baseline, parameter=parameter, allowed_origins=allowed)
        return sqli_boolean.probe_numeric_boolean(
            base, true_url, false_url, nonce, parameter=parameter, allowed_origins=allowed,
            storage_state=None, before_request=lambda: None)
    if name in ("string_or_boolean_v1", "string_or_json_rows_v1"):
        base, variants, nonce = sqli_string.plan_string_boolean(
            baseline, parameter=parameter, allowed_origins=allowed)
        return sqli_string.probe_string_boolean(
            base, variants, nonce, parameter=parameter, allowed_origins=allowed,
            storage_state=None, before_request=lambda: None)
    if name == "string_and_boolean_v1":
        base, variants, nonce = sqli_string.plan_string_and_boolean(
            baseline, parameter=parameter, allowed_origins=allowed)
        return sqli_string.probe_string_and_boolean(
            base, variants, nonce, parameter=parameter, allowed_origins=allowed,
            storage_state=None, before_request=lambda: None)
    raise ValueError(f"unsupported recipe {name}")


async def recheck(recipe: Optional[dict], *, finding_id: Any = None,
                  runner=None) -> dict:
    """Replay ``recipe`` and return a recheck record (never raises)."""
    started = time.time()
    record: dict = {"at": started, "finding_id": finding_id,
                    "recipe": (recipe or {}).get("recipe"), "requests_sent": 0}
    safe = publishable(recipe)
    if not safe:
        record.update(outcome="cannot_confirm",
                      reason="No replayable recipe is stored for this finding.")
        return record
    run_id = f"recheck-{finding_id or 'x'}-{uuid.uuid4().hex[:8]}"
    from app.services.agent.action_ledger import active_run_id
    from app.services.agent.judah_gate import ensure_lease_for_run, gate_enabled, gate_address

    host = urlsplit(safe["baseline"]).hostname or ""
    if gate_enabled() and gate_address() is None:
        record.update(outcome="cannot_confirm",
                      reason="Judah Gate is enabled but not running in this process.")
        return record
    token = active_run_id.set(run_id)
    try:
        lease = ensure_lease_for_run(run_id, [host])
        result = await asyncio.to_thread(runner or _run_recipe, safe)
        outcome, reason = classify(result)
        record.update(
            outcome=outcome, reason=reason,
            requests_sent=int(result.get("requests_sent") or len(_rows(result))),
            nonce=result.get("nonce"), proof_recipe=result.get("proof_recipe"),
            checks=result.get("checks"), gated=lease is not None,
        )
    except Exception as exc:
        record.update(outcome="cannot_confirm",
                      reason=f"Replay could not run: {type(exc).__name__}: {str(exc)[:200]}")
    finally:
        active_run_id.reset(token)
        from app.services.agent.judah_gate import registry

        registry.close(run_id)
    record["duration_s"] = round(time.time() - started, 3)
    return record


def as_validation_verdict(record: dict) -> dict:
    """Shape a recheck record like the native validator's verdict dict."""
    outcome = record.get("outcome", "cannot_confirm")
    return {
        "verdict": VALIDATION_VERDICT.get(outcome, "needs_more_evidence"),
        "confidence": "high" if outcome != "cannot_confirm" else "low",
        "is_false_positive": False,
        "still_open": outcome == "still_reproducible",
        "logical_mismatch": False,
        "recommended_severity": None,
        "reasoning": f"Judah Recheck: {outcome.replace('_', ' ')}. {record.get('reason', '')}",
        "evidence": f"recipe={record.get('recipe')} requests={record.get('requests_sent')}",
        "template_logic_issue": None,
        "method": "judah_recheck",
        "recheck_outcome": outcome,
        "recheck": record,
    }


def append_history(metadata: Optional[dict], record: dict) -> dict:
    """New metadata dict with the record appended; original evidence untouched."""
    meta = dict(metadata or {})
    history = list(meta.get("recheck_history") or [])
    history.append({k: v for k, v in record.items() if k != "checks"})
    meta["recheck_history"] = history[-MAX_HISTORY:]
    meta["last_recheck"] = {"outcome": record.get("outcome"), "at": record.get("at")}
    return meta


__all__ = [
    "OUTCOMES", "SUPPORTED_RECIPES", "append_history", "as_validation_verdict", "classify",
    "publishable", "recheck", "recipe_for_finding", "remember",
]
