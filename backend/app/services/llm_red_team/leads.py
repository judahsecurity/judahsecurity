"""LLM prompt-injection leads: lead findings, importers and confirmation links.

Scanner output (llm_red_team's LLM grader, garak, promptfoo, PyRIT) is a lead,
never proof. Where no agent session exists (the create_scan worker and the API
route) a hit becomes a Vulnerability row marked ``unverified_lead``. In an agent
session it becomes a verifier candidate. When the scoped verifier later
confirms the same endpoint and the finding is published, the lead rows are
marked ``lead_confirmed`` and linked to the verified finding.

The importers turn each tool's native output into normalized lead dicts::

    {"source", "endpoint", "mode", "ref", "prompt", "response", "detail"}

``mode`` is one of the scoped probe modes (direct, multi_turn, indirect,
system_prompt_leak). Returned text is raw target content; callers sanitize it
before it reaches a model.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable
from urllib.parse import urlsplit

# llm_red_team categories whose hits must be verified before they count.
LEAD_CATEGORIES = {"prompt_injection": "prompt_injection",
                   "system_prompt_leakage": "system_prompt_leak"}
CATEGORY_MODE = {"prompt_injection": "direct", "system_prompt_leakage": "system_prompt_leak"}
LEAD_LEVEL = "unverified_lead"
CONFIRMED_LEAD_LEVEL = "lead_confirmed"
MAX_LEAD_FILE_BYTES = 25 * 1024 * 1024
MAX_LEADS = 200

# garak probe families that test instruction injection or prompt extraction.
GARAK_MODES = (("latentinjection", "indirect"), ("promptinject", "direct"),
               ("sysprompt", "system_prompt_leak"))
# promptfoo red-team plugins and multi-turn strategies.
PROMPTFOO_PLUGIN_MODES = {
    "prompt-extraction": "system_prompt_leak",
    "indirect-prompt-injection": "indirect",
    "hijacking": "direct",
    "system-prompt-override": "direct",
    "ascii-smuggling": "direct",
    "prompt-injection": "direct",
}
PROMPTFOO_MULTI_TURN_STRATEGIES = {"crescendo", "goat", "mischievous-user", "jailbreak:hydra",
                                   "custom", "multi-turn"}


def lead_class_for_mode(mode: str) -> str:
    return "system_prompt_leak" if mode == "system_prompt_leak" else "prompt_injection"


def mark_lead_finding(finding_data: dict, category: str) -> dict:
    """Mark a scanner hit as an unverified lead (no agent session can verify it here)."""
    lead_class = LEAD_CATEGORIES.get(category)
    if not lead_class:
        return finding_data
    finding_data["title"] = "[Unverified lead] " + finding_data["title"]
    finding_data["description"] += (
        "\n\n**Verification**: unverified lead. An LLM grader flagged this reply; it is "
        "not proof. Run an Aegis assessment with this endpoint in "
        "prompt_injection_endpoints so the scoped verifier can reproduce it with "
        "fresh canaries and negative controls.")
    finding_data["tags"] = list(dict.fromkeys(
        [*finding_data.get("tags", []), "unverified-lead", "needs-scoped-verification"]))
    finding_data["verification_level"] = LEAD_LEVEL
    finding_data["detection_confidence"] = "unknown"
    finding_data.setdefault("metadata", {})["lead_class"] = lead_class
    return finding_data


def _same_endpoint(left: str, right: str) -> bool:
    a, b = urlsplit(str(left or "")), urlsplit(str(right or ""))
    return bool(a.netloc) and a.netloc.lower() == b.netloc.lower() and (
        (a.path or "/").rstrip("/") == (b.path or "/").rstrip("/"))


def link_confirmed_leads(db, *, organization_id: Any, endpoint: str, lead_class: str,
                         finding_id: Any) -> int:
    """Mark unverified lead rows for this endpoint as confirmed by a verified finding."""
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability

    rows = (db.query(Vulnerability).join(Asset, Vulnerability.asset_id == Asset.id)
            .filter(Asset.organization_id == organization_id,
                    Vulnerability.verification_level == LEAD_LEVEL).all())
    linked = 0
    for row in rows:
        meta = dict(row.metadata_ or {})
        if meta.get("lead_class") != lead_class or not _same_endpoint(
                meta.get("endpoint_url"), endpoint):
            continue
        meta["confirmed_by_finding_id"] = finding_id
        row.metadata_ = meta
        row.verification_level = CONFIRMED_LEAD_LEVEL
        linked += 1
    if linked:
        db.commit()
    return linked


def red_team_leads(results: Iterable[dict]) -> list[dict]:
    """llm_red_team scan results whose category needs scoped verification."""
    leads = []
    for row in results or []:
        category = row.get("category")
        if row.get("verdict") != "fail" or category not in CATEGORY_MODE:
            continue
        leads.append({"source": "llm_red_team", "endpoint": str(row.get("endpoint") or ""),
                      "mode": CATEGORY_MODE[category], "ref": str(row.get("payload_id") or ""),
                      "prompt": str(row.get("prompt_sent") or ""),
                      "response": str(row.get("response_preview") or ""),
                      "detail": str(row.get("name") or ""),
                      "severity": str(row.get("severity") or "medium")})
    return leads


def _garak_mode(probe: str) -> str:
    name = str(probe or "").lower()
    return next((mode for prefix, mode in GARAK_MODES if name.startswith(prefix)
                 or f".{prefix}" in name or prefix in name.split(".")[0]), "")


def _garak_text(value: Any) -> str:
    if isinstance(value, dict):
        if "turns" in value:
            return "\n".join(_garak_text(turn.get("content")) for turn in value["turns"]
                             if isinstance(turn, dict))
        return str(value.get("text") or "")
    return str(value or "")


def parse_garak(text: str, endpoint: str) -> list[dict]:
    """garak report.jsonl: evaluated attempts with any detector score >= 0.5."""
    leads = []
    for line in str(text or "").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get("entry_type") != "attempt" or row.get("status") != 2:
            continue
        mode = _garak_mode(row.get("probe_classname"))
        scores = [score for values in (row.get("detector_results") or {}).values()
                  for score in (values or []) if isinstance(score, (int, float))]
        if not mode or not scores or max(scores) < 0.5:
            continue
        outputs = [_garak_text(item) for item in row.get("outputs") or []]
        leads.append({"source": "garak", "endpoint": endpoint, "mode": mode,
                      "ref": f"{row.get('probe_classname')}#{row.get('seq')}",
                      "prompt": _garak_text(row.get("prompt")),
                      "response": next((item for item in outputs if item), ""),
                      "detail": ", ".join(sorted(row.get("detector_results") or {}))})
        if len(leads) >= MAX_LEADS:
            break
    return leads


def parse_promptfoo(data: dict, endpoint: str = "") -> list[dict]:
    """promptfoo eval/redteam JSON: a failed assertion means the attack succeeded."""
    results = (data or {}).get("results") or {}
    rows = results.get("results") if isinstance(results, dict) else results
    leads = []
    for row in rows or []:
        # failureReason 1 (ASSERT) is an attack that worked; 2 (ERROR) is a
        # provider failure. Older outputs without it fall back to "no error".
        reason = row.get("failureReason") if isinstance(row, dict) else None
        if (not isinstance(row, dict) or row.get("success") is not False
                or (reason != 1 if reason is not None else bool(row.get("error")))):
            continue
        case = row.get("testCase") or {}
        meta = {**(row.get("metadata") or {}), **(case.get("metadata") or {})}
        mode = str(meta.get("aegis_mode") or "")
        if not mode:
            plugin = str(meta.get("pluginId") or "")
            mode = PROMPTFOO_PLUGIN_MODES.get(plugin, "")
            if mode == "direct" and str(meta.get("strategyId") or "") in PROMPTFOO_MULTI_TURN_STRATEGIES:
                mode = "multi_turn"
        if not mode:
            continue
        provider = row.get("provider") or {}
        provider_id = str(provider.get("id") or "") if isinstance(provider, dict) else str(provider)
        target = provider_id if provider_id.startswith(("http://", "https://")) else endpoint
        response = row.get("response") or {}
        leads.append({"source": "promptfoo", "endpoint": target, "mode": mode,
                      "ref": f"{case.get('description') or row.get('testIdx')}"
                             f"#r{row.get('repeatIndex', 0)}",
                      "prompt": str((row.get("prompt") or {}).get("raw") or ""),
                      "response": str(response.get("output") if isinstance(response, dict) else ""),
                      "detail": str(meta.get("pluginId") or row.get("error") or "")[:200]})
        if len(leads) >= MAX_LEADS:
            break
    return leads


def _score_true(score: dict) -> bool:
    value = score.get("score_value")
    if str(score.get("score_type") or "") == "float_scale":
        try:
            return float(value) >= 0.5
        except (TypeError, ValueError):
            return False
    return str(value).strip().lower() == "true"


def parse_pyrit(data: Any, endpoint: str = "") -> list[dict]:
    """The Aegis PyRIT runner output, or an exported list of PyRIT message pieces."""
    leads = []
    if isinstance(data, dict) and data.get("tool") == "pyrit":
        target = str(data.get("endpoint") or endpoint)
        for row in data.get("results") or []:
            if not isinstance(row, dict) or row.get("success") is not True:
                continue
            turns = [str(turn) for turn in row.get("turns") or []]
            leads.append({"source": "pyrit", "endpoint": target,
                          "mode": str(row.get("mode") or ("multi_turn" if len(turns) > 1 else "direct")),
                          "ref": str(row.get("id") or ""), "prompt": "\n".join(turns),
                          "response": str((row.get("responses") or [""])[-1]),
                          "detail": "SubStringScorer canary match"})
        return leads[:MAX_LEADS]
    conversations: dict[str, list] = {}
    for piece in data if isinstance(data, list) else []:
        if isinstance(piece, dict) and piece.get("conversation_id"):
            conversations.setdefault(str(piece["conversation_id"]), []).append(piece)
    for conversation_id, pieces in conversations.items():
        if not any(_score_true(score) for piece in pieces
                   for score in piece.get("scores") or [] if isinstance(score, dict)):
            continue
        users = [str(p.get("converted_value") or p.get("original_value") or "")
                 for p in pieces if str(p.get("role")) == "user"]
        replies = [str(p.get("converted_value") or p.get("original_value") or "")
                   for p in pieces if str(p.get("role")) == "assistant"]
        leads.append({"source": "pyrit", "endpoint": endpoint,
                      "mode": "multi_turn" if len(users) > 1 else "direct",
                      "ref": conversation_id, "prompt": "\n".join(users),
                      "response": replies[-1] if replies else "", "detail": "PyRIT score"})
        if len(leads) >= MAX_LEADS:
            break
    return leads


def allowed_lead_file(path: str, roots: Iterable[str]) -> str:
    """Resolve a report path inside an allowed root and under the size cap."""
    real = os.path.realpath(str(path or ""))
    allowed = [os.path.realpath(root) for root in roots if root]
    if not any(real == root or real.startswith(root + os.sep) for root in allowed):
        raise ValueError("Report path is outside the allowed report directories")
    if not os.path.isfile(real):
        raise ValueError("Report file not found")
    if os.path.getsize(real) > MAX_LEAD_FILE_BYTES:
        raise ValueError("Report file is too large")
    return real


def parse_lead_file(source: str, path: str, endpoint: str = "") -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    if source == "garak":
        return parse_garak(text, endpoint)
    data = json.loads(text)
    if source == "promptfoo":
        return parse_promptfoo(data, endpoint)
    if source == "pyrit":
        return parse_pyrit(data, endpoint)
    raise ValueError("source must be garak, promptfoo or pyrit")
