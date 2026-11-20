"""Re-test one existing finding: is it still there, or fixed?

Validation asks "is this finding real?". A retest assumes it was real and asks
whether the original trigger still works now, with three outcomes:

* ``reproduced`` - this run observed the original behavior again.
* ``fixed`` - the original trigger ran under comparable conditions, failed,
  and a normal control request to the same origin still succeeds.
* ``inconclusive`` - anything short of that: the proof cannot be replayed
  (it needed a signed-in identity or a session-only capture), the target or
  control did not answer normally, or the replay errored. One failed request
  does not prove a fix.

What is replayed depends on how the finding was proven:

* agent findings: the stored typed proof step, re-run with the same
  arguments (bounded SQLi controls, nonce-confirmed browser XSS or client
  behavior), anonymous only;
* template findings: the same Nuclei template;
* port exposure: the same Nmap state check.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

REPRODUCED = "reproduced"
FIXED = "fixed"
INCONCLUSIVE = "inconclusive"

# Proof tools that can be replayed from their stored arguments alone, and the
# result flag that means "the vulnerable behavior was observed".
_REPLAYABLE = {
    "scoped_numeric_sqli": ("proof_confirmed",),
    "scoped_string_sqli": ("proof_confirmed",),
    "scoped_browser_assessment": ("executed", "behavior_observed"),
}
_BROWSER_OPERATIONS = {"check_xss", "check_client"}
_ALLOWED_ARGS = {
    "scoped_numeric_sqli": {"url", "parameter", "identity"},
    "scoped_string_sqli": {"url", "parameter", "identity"},
    "scoped_browser_assessment": {"operation", "url", "identity", "client_test_type"},
}
_CONTROL_BAD_STATUSES = {401, 403, 407, 429}
MAX_REPLAYED_STEPS = 3


def argv_to_kwargs(argv: Any) -> dict[str, Any]:
    """Invert demonstrated_chain.parse_args for dict arguments."""
    if isinstance(argv, dict):
        return dict(argv)
    out: dict[str, Any] = {}
    if not isinstance(argv, list):
        return out
    index = 0
    while index < len(argv):
        token = str(argv[index])
        if token.startswith("--"):
            key = token[2:]
            if index + 1 < len(argv) and not str(argv[index + 1]).startswith("--"):
                out[key] = str(argv[index + 1])
                index += 2
                continue
            out[key] = True
        index += 1
    return out


def replayable_steps(agent_detection: Any, *, asset_host: str) -> tuple[list[dict], list[str]]:
    """Proof steps this service can re-run, and why the others cannot be."""
    chain = (agent_detection or {}).get("chain") if isinstance(agent_detection, dict) else None
    steps: list[dict] = []
    skipped: list[str] = []
    for step in chain or []:
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool") or "")
        if tool not in _REPLAYABLE:
            continue
        kwargs = argv_to_kwargs(step.get("args"))
        if tool == "scoped_browser_assessment" and kwargs.get("operation") not in _BROWSER_OPERATIONS:
            continue
        if kwargs.get("artifact_id") or kwargs.get("capture_id"):
            skipped.append(f"{tool}: proven from a session-only capture")
            continue
        if str(kwargs.get("identity") or "anonymous") != "anonymous":
            skipped.append(f"{tool}: proven as signed-in identity {kwargs.get('identity')!r}")
            continue
        if any("REDACTED" in str(value) for value in kwargs.values()):
            skipped.append(f"{tool}: stored arguments were redacted")
            continue
        url = str(kwargs.get("url") or "")
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        if not url.startswith(("http://", "https://")) or not host:
            skipped.append(f"{tool}: no replayable URL")
            continue
        if asset_host and host != asset_host:
            skipped.append(f"{tool}: URL host {host} is not the finding's asset")
            continue
        clean = {key: value for key, value in kwargs.items() if key in _ALLOWED_ARGS[tool]}
        if (tool, clean) not in [(row["tool"], row["kwargs"]) for row in steps]:
            steps.append({"tool": tool, "kwargs": clean})
    return steps[-MAX_REPLAYED_STEPS:], skipped


_BLOCKING_STATUSES = {401, 403, 406, 407, 429, 503}


def _blocked_checks(data: dict) -> list[int]:
    """Statuses that mean the proof's requests were refused, not answered."""
    checks = data.get("checks")
    if not isinstance(checks, dict):
        return []
    statuses = [row.get("status") for row in checks.values() if isinstance(row, dict)]
    baseline = checks.get("baseline", {}).get("status") if isinstance(checks.get("baseline"), dict) else None
    blocked = sorted({status for status in statuses if status in _BLOCKING_STATUSES})
    if baseline is not None and baseline != 200 and baseline not in blocked:
        blocked.append(baseline)  # the original page itself did not answer normally
    return blocked


def _control(origin: str) -> dict[str, Any]:
    return _control_url(origin.rstrip("/") + "/")


def _control_url(url: str) -> dict[str, Any]:
    from app.services.finding_revalidation_service import _http_probe

    probe = _http_probe(url)
    status = probe.get("status")
    probe["normal"] = bool(
        probe.get("ok") and isinstance(status, int)
        and status < 500 and status not in _CONTROL_BAD_STATUSES
    )
    return probe


def _result(verdict: str, *, reasoning: str, evidence: Any, method: str,
            confidence: str = "medium", **extra: Any) -> dict[str, Any]:
    return {
        "retest_verdict": verdict,
        # The existing validation record keeps its own three verdicts; a
        # retest maps onto it without calling a fixed bug a false positive.
        "verdict": {REPRODUCED: "confirmed", FIXED: "fixed", INCONCLUSIVE: "inconclusive"}[verdict],
        "still_open": {REPRODUCED: True, FIXED: False, INCONCLUSIVE: None}[verdict],
        "confidence": confidence,
        "reasoning": reasoning,
        "evidence": evidence if isinstance(evidence, str) else json.dumps(evidence, default=str)[:5000],
        "method": method,
        "purpose": "retest",
        **extra,
    }


async def _replay_agent_proof(finding: dict, agent_detection: Any) -> dict[str, Any]:
    from app.services.agent.tools import (
        ASMToolsManager,
        current_organization_id,
        current_seed_target,
        current_session_id,
    )

    asset = str(finding.get("asset") or "")
    asset_host = (urlsplit(asset if "://" in asset else f"//{asset}").hostname or "").lower().rstrip(".")
    steps, skipped = replayable_steps(agent_detection, asset_host=asset_host)
    if not steps:
        return _result(
            INCONCLUSIVE, method="agent_proof_replay", confidence="low",
            reasoning=("The stored proof cannot be replayed without the original session"
                       + (f": {'; '.join(skipped[:3])}." if skipped else ".")
                       + " A retest needs an anonymous, URL-addressed proof step."),
            evidence={"skipped": skipped},
        )

    first_url = str(steps[0]["kwargs"]["url"])
    parts = urlsplit(first_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    control = await asyncio.to_thread(_control, origin)

    # Session-scoped manager state (map, captures, evidence) lives under the
    # current session id, so switch to a fresh retest session first.
    tokens = [
        current_organization_id.set(finding.get("organization_id")),
        current_session_id.set(f"retest-{finding.get('id')}-{uuid.uuid4().hex[:12]}"),
        current_seed_target.set(origin),
    ]
    replays: list[dict[str, Any]] = []
    try:
        manager = ASMToolsManager()
        manager._assessment_scope.update({asset_host})
        manager._fallback_target = origin
        # The SQLi proofs only test inputs the session has observed. Re-observe
        # each proof page with one anonymous GET, as a crawl would; a page that no
        # longer answers normally is not a comparable environment.
        observed_pages: list[str] = []
        unobserved: set[str] = set()
        for step in steps:
            if step["tool"] in ("scoped_numeric_sqli", "scoped_string_sqli"):
                url = str(step["kwargs"]["url"])
                page = await asyncio.to_thread(_control_url, url)
                if page["normal"]:
                    observed_pages.append(url)
                else:
                    unobserved.add(url)
        manager._capability_map = {"target": origin, "scope": origin,
                                   "pages_visited": observed_pages}
        for step in steps:
            tool = step["tool"]
            kwargs = dict(step["kwargs"])
            kwargs["identity"] = "anonymous"
            row: dict[str, Any] = {"tool": tool, "url": kwargs.get("url"),
                                   "parameter": kwargs.get("parameter"),
                                   "operation": kwargs.get("operation")}
            if kwargs.get("url") in unobserved:
                row["error"] = "proof page did not answer normally"
                replays.append(row)
                continue
            try:
                if tool == "scoped_browser_assessment":
                    operation = kwargs.pop("operation")
                    url = kwargs.pop("url")
                    raw = await manager.scoped_browser_assessment(operation, url, **kwargs)
                else:
                    raw = await getattr(manager, tool)(**kwargs)
                data = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
            except Exception as exc:  # the replay could not run as recorded
                row["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                replays.append(row)
                continue
            flags = _REPLAYABLE[tool]
            row["observed"] = any(data.get(flag) is True for flag in flags)
            row["inconclusive"] = bool(data.get("inconclusive")) or not any(flag in data for flag in flags)
            blocked = _blocked_checks(data)
            if blocked and not row["observed"]:
                # A WAF or rate limit answering the payloads is not a fix.
                row["inconclusive"] = True
                row["blocked_statuses"] = blocked
            row["evidence_id"] = data.get("evidence_id")
            row["requests_sent"] = data.get("requests_sent")
            replays.append(row)
    finally:
        for var, token in zip(
            (current_organization_id, current_session_id, current_seed_target), tokens
        ):
            var.reset(token)

    evidence = {"replays": replays, "control": {key: control.get(key) for key in
                                                ("url", "status", "normal", "error")},
                "skipped": skipped}
    if any(row.get("observed") for row in replays):
        hit = next(row for row in replays if row.get("observed"))
        return _result(
            REPRODUCED, method="agent_proof_replay", confidence="high", evidence=evidence,
            reasoning=(f"Re-ran the original {hit['tool']} proof"
                       f"{' on ' + str(hit.get('parameter')) if hit.get('parameter') else ''}"
                       f" against {hit.get('url')}; the vulnerable behavior was observed again."),
        )
    clean_negatives = [row for row in replays
                       if not row.get("error") and not row.get("inconclusive")]
    if clean_negatives and len(clean_negatives) == len(replays) and control["normal"] and not skipped:
        return _result(
            FIXED, method="agent_proof_replay", confidence="high", evidence=evidence,
            reasoning=(f"Re-ran {len(replays)} original proof step(s) under the same anonymous "
                       f"conditions; none showed the vulnerable behavior, and a control request "
                       f"to {origin}/ returned {control.get('status')}."),
        )
    reasons = []
    if not control["normal"]:
        reasons.append(f"the control request to {origin}/ did not answer normally "
                       f"({control.get('status') or control.get('error')})")
    if any(row.get("error") for row in replays):
        reasons.append("a proof step could not run as recorded")
    if any(row.get("blocked_statuses") for row in replays):
        reasons.append("the proof requests were refused (HTTP "
                       + ", ".join(str(status) for row in replays
                                   for status in row.get("blocked_statuses") or [])
                       + "), which a WAF or rate limit can cause")
    elif any(row.get("inconclusive") and not row.get("error") for row in replays):
        reasons.append("a proof step's controls were inconclusive")
    if skipped:
        reasons.append("some proof steps need the original session and were not re-run")
    return _result(
        INCONCLUSIVE, method="agent_proof_replay", confidence="low", evidence=evidence,
        reasoning="The original behavior was not observed, but a fix is not proven: "
                  + "; ".join(reasons or ["the replay did not meet the evidence bar"]) + ".",
    )


async def _retest_template(finding: dict) -> Optional[dict[str, Any]]:
    from app.services.finding_revalidation_service import _revalidate_nuclei

    verdict = await _revalidate_nuclei(finding)
    if verdict is None:
        return None
    recheck = verdict.get("nuclei_recheck") or {}
    if verdict.get("verdict") == "confirmed":
        return _result(REPRODUCED, method="nuclei_template_replay", confidence="high",
                       reasoning=verdict.get("reasoning") or "The template still matches.",
                       evidence=recheck)
    target = str(finding.get("target") or finding.get("asset") or "")
    parts = urlsplit(target if "://" in target else f"https://{target}")
    origin = f"{parts.scheme}://{parts.netloc}"
    control = await asyncio.to_thread(_control, origin)
    if verdict.get("verdict") == "false_positive" and recheck.get("ran") and control["normal"]:
        return _result(FIXED, method="nuclei_template_replay", confidence="medium",
                       reasoning=(f"The original template ran against {target} and no longer "
                                  f"matches, and {origin}/ answered {control.get('status')}."),
                       evidence={"recheck": recheck, "control": control})
    return _result(INCONCLUSIVE, method="nuclei_template_replay", confidence="low",
                   reasoning=("The template did not match, but the replay or the control request "
                              "did not complete normally, so a fix is not proven."),
                   evidence={"recheck": recheck, "control": control})


async def _retest_port(finding: dict) -> Optional[dict[str, Any]]:
    from app.services.finding_revalidation_service import revalidate_port_exposure

    verdict = await revalidate_port_exposure(finding)
    if not verdict:
        return None
    state = verdict.get("port_state")
    extra = {key: verdict.get(key) for key in ("port_state", "port_host", "port", "protocol")}
    extra["port_check_method"] = verdict.get("method")
    if state == "open":
        return _result(REPRODUCED, method="nmap_port_verify", confidence="high",
                       reasoning=verdict.get("reasoning") or "The port is still open.",
                       evidence=verdict.get("evidence") or "", **extra)
    if state in ("closed", "filtered"):
        return _result(FIXED, method="nmap_port_verify", confidence="high",
                       reasoning=verdict.get("reasoning") or f"The port is now {state}.",
                       evidence=verdict.get("evidence") or "", **extra)
    return _result(INCONCLUSIVE, method="nmap_port_verify", confidence="low",
                   reasoning=verdict.get("reasoning") or "The port state could not be determined.",
                   evidence=verdict.get("evidence") or "", **extra)


async def retest_finding(finding: dict, metadata: Any = None) -> dict[str, Any]:
    """Re-test one finding. ``finding`` is the validation worker's payload."""
    metadata = metadata if isinstance(metadata, dict) else {}
    detected_by = str(finding.get("detected_by") or "").lower()
    if detected_by == "agent" and isinstance(metadata.get("agent_detection"), dict):
        return await _replay_agent_proof(finding, metadata["agent_detection"])
    if finding.get("template_id") or finding.get("template_yaml"):
        result = await _retest_template(finding)
        if result:
            return result
    if detected_by == "port_scanner" or finding.get("source_kind") == "network_service":
        result = await _retest_port(finding)
        if result:
            return result
    return _result(
        INCONCLUSIVE, method="no_replayable_proof", confidence="low",
        reasoning=("This finding has no proof Prowl can replay (no agent proof step, "
                   "template, or port claim). Use Validate for a detection replay, or "
                   "re-run the assessment."),
        evidence="",
    )


def apply_retest_status(vuln: Any, verdict_data: dict, *, validation_id: Any, now: Any) -> None:
    """Move the finding's status only on a decisive retest.

    ``fixed`` resolves an open finding; ``reproduced`` reopens a resolved one
    (a regression). ``inconclusive`` never changes the status.
    """
    from app.models.vulnerability import VulnerabilityStatus

    verdict = verdict_data.get("retest_verdict")
    previous = vuln.status.value if getattr(vuln, "status", None) is not None else None
    changed_to = None
    if verdict == FIXED and vuln.status in (VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS):
        vuln.status = VulnerabilityStatus.RESOLVED
        vuln.resolved_at = now
        changed_to = VulnerabilityStatus.RESOLVED.value
    elif verdict == REPRODUCED and vuln.status == VulnerabilityStatus.RESOLVED:
        vuln.status = VulnerabilityStatus.OPEN
        vuln.resolved_at = None
        changed_to = VulnerabilityStatus.OPEN.value
    vuln.metadata_ = {
        **(vuln.metadata_ or {}),
        "last_retest": {
            "verdict": verdict,
            "method": verdict_data.get("method"),
            "validation_id": validation_id,
            "at": now.isoformat() if hasattr(now, "isoformat") else str(now),
            "status_before": previous,
            "status_after": changed_to or previous,
        },
    }
