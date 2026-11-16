"""Model-led recon: an inventory of what the app is, and ranked attack ideas.

A pentester looks at a site, notes the stack (CMS, versions, frameworks), the
places it stores data (logins, forms, uploads, APIs), and decides what to try.
This module stores that reasoning in the engagement brain:

* the inventory is a ``recon_observations`` row (``kind="recon_inventory"``),
  replaced on each update for the same target;
* each attack idea becomes an open ``Hypothesis`` (``source="recon"``) plus an
  untested coverage cell, so it is tracked by the existing coverage plan and
  completion gates rather than a parallel list.

Ideas are only leads. A finding still needs a class-specific verifier.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit

INVENTORY_FIELDS = (
    "technologies", "cms", "versions", "logins", "forms", "apis",
    "file_uploads", "ai_features", "notes",
)
MAX_ITEMS_PER_FIELD = 40
MAX_IDEAS = 25
MAX_TEXT = 400

# vuln class the model names -> (coverage test_type, specialist lane)
_CLASS_ROUTES: Dict[str, tuple[str, str]] = {
    "sqli": ("sqli", "sqli"),
    "sql_injection": ("sqli", "sqli"),
    "xss": ("xss", "xss"),
    "stored_xss": ("stored_xss", "xss"),
    "ssrf": ("ssrf", "ssrf"),
    "xxe": ("xxe", "injection"),
    "ssti": ("ssti", "injection"),
    "command_injection": ("command_injection", "injection"),
    "path_traversal": ("path_traversal", "injection"),
    "open_redirect": ("open_redirect", "injection"),
    "crlf": ("crlf", "injection"),
    "cors": ("cors", "injection"),
    "nosql": ("nosql", "injection"),
    "graphql": ("graphql", "graphql_api"),
    "authz": ("authz", "api_authz"),
    "idor": ("authz", "api_authz"),
    "authorization": ("authz", "api_authz"),
    "auth": ("auth", "auth_logic"),
    "authentication": ("auth", "auth_logic"),
    "account_enumeration": ("auth", "auth_logic"),
    "csrf": ("csrf", "auth_logic"),
    "business_logic": ("business_logic", "business_logic"),
    "race_condition": ("race_condition", "auth_logic"),
    "file_upload": ("file_upload", "file_upload"),
    "known_cve": ("known_cve", "vuln_triage"),
    "outdated_component": ("known_cve", "vuln_triage"),
    "exposure": ("exposure", "app_mapper"),
    "directory_listing": ("exposure", "app_mapper"),
    "info_disclosure": ("exposure", "app_mapper"),
    "js_secrets": ("js_secret_review", "js_secrets"),
    "llm_prompt_injection": ("llm_ai", "agent_tools"),
    "prompt_injection": ("llm_ai", "agent_tools"),
    "llm_ai": ("llm_ai", "agent_tools"),
    "saml_sso": ("saml_sso", "saml_sso"),
    "oauth": ("oauth", "auth_logic"),
}
_PRIORITIES = ("critical", "high", "medium", "low")


def _clean(value: Any, limit: int = MAX_TEXT) -> str:
    from app.services.agent.content_shield import redact_sensitive

    text = " ".join(str(value or "").split())[:limit]
    return redact_sensitive(text)[0]


def _clean_items(values: Any) -> List[Any]:
    if values in (None, ""):
        return []
    if not isinstance(values, (list, tuple)):
        values = [values]
    out: List[Any] = []
    for item in list(values)[:MAX_ITEMS_PER_FIELD]:
        if isinstance(item, dict):
            out.append({str(k)[:40]: _clean(v, 200) for k, v in list(item.items())[:8]})
        else:
            text = _clean(item, 200)
            if text:
                out.append(text)
    return out


def normalize_inventory(inventory: Any) -> Dict[str, List[Any]]:
    data = inventory if isinstance(inventory, dict) else {}
    return {name: _clean_items(data.get(name)) for name in INVENTORY_FIELDS}


def route_for_class(vuln_class: str) -> tuple[str, str]:
    key = str(vuln_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _CLASS_ROUTES.get(key, (key or "surface_review", "app_mapper"))


def _surface(raw: str, target: str) -> tuple[str, str]:
    """Return (host, path) for an idea's surface, restricted to the target host."""
    base = urlsplit(target if "://" in target else f"https://{target}")
    value = str(raw or "").strip()
    if not value:
        return base.netloc, "/"
    parts = urlsplit(value if "://" in value or value.startswith("/") else "/" + value)
    host = parts.netloc or base.netloc
    if host.lower() != base.netloc.lower():
        raise ValueError(f"Attack idea surface {value!r} is outside the assessment target")
    return host, parts.path or "/"


def record_recon_inventory(
    brain: Any,
    *,
    target: str,
    inventory: Any,
    attack_ideas: Iterable[Any] | None = None,
) -> Dict[str, Any]:
    """Store inventory + ranked ideas on ``brain``; return what was added."""
    from app.services.agent.coverage_cells import _new_cell, migrate_coverage_cells
    from app.services.agent.engagement_brain import Hypothesis, _hyp_id

    target = str(target or getattr(brain, "target", "") or "").strip()
    if not target:
        raise ValueError("target is required")
    normalized = normalize_inventory(inventory)
    now = datetime.now(timezone.utc).isoformat()
    brain.recon_observations = [
        row for row in (brain.recon_observations or [])
        if not (isinstance(row, dict) and row.get("kind") == "recon_inventory"
                and row.get("target") == target)
    ]
    brain.recon_observations.append({
        "kind": "recon_inventory", "target": target, "source": "model",
        "inventory": normalized, "recorded_at": now,
    })

    ideas = [idea for idea in (attack_ideas or []) if isinstance(idea, dict)][:MAX_IDEAS]
    existing_hyp = {h.id for h in brain.hypotheses}
    existing_cells = {row.get("id") for row in brain.coverage_cells if isinstance(row, dict)}
    added: List[Dict[str, Any]] = []
    rejected: List[Dict[str, str]] = []
    for rank, idea in enumerate(ideas, start=1):
        title = _clean(idea.get("title"), 160)
        if not title:
            rejected.append({"rank": str(rank), "reason": "title is required"})
            continue
        try:
            host, path = _surface(str(idea.get("surface") or idea.get("url") or ""), target)
        except ValueError as exc:
            rejected.append({"rank": str(rank), "title": title, "reason": str(exc)})
            continue
        test_type, specialist = route_for_class(str(idea.get("vuln_class") or ""))
        priority = str(idea.get("priority") or "").lower()
        if priority not in _PRIORITIES:
            priority = "high" if rank <= 3 else "medium" if rank <= 8 else "low"
        parameter = _clean(idea.get("parameter"), 80)
        hid = _hyp_id(target, "recon", title, path, parameter)
        if hid not in existing_hyp:
            brain.hypotheses.append(Hypothesis(
                id=hid,
                title=title,
                assumption=_clean(idea.get("rationale") or idea.get("evidence")),
                test=_clean(idea.get("test")) or f"Test {path} for {test_type}",
                pass_criteria=_clean(idea.get("pass_criteria"))
                or "A class-specific verifier reproduces the behavior",
                kill_criteria=_clean(idea.get("kill_criteria"))
                or "Controls show no difference, or the surface does not exist",
                specialist=specialist,
                priority=priority,
                target=target,
                evidence=_clean(idea.get("evidence"), 500),
                source="recon",
                parameter=parameter,
            ))
            existing_hyp.add(hid)
        method = str(idea.get("method") or "GET").upper()[:10]
        cell = _new_cell(
            brain, method=method, path=path, host=host,
            identity=_clean(idea.get("identity"), 60) or "anonymous",
            parameter=parameter, test_type=test_type, hypothesis_id=hid,
            source="recon", reason=f"recon idea rank {rank}",
        )
        cell["priority_rank"] = rank
        if cell["id"] not in existing_cells:
            brain.coverage_cells.append(cell)
            existing_cells.add(cell["id"])
        added.append({"rank": rank, "hypothesis_id": hid, "coverage_cell_id": cell["id"],
                      "title": title, "test_type": test_type, "specialist": specialist,
                      "priority": priority, "surface": f"{method} {path}"})
    migrate_coverage_cells(brain)
    return {
        "target": target,
        "inventory_fields": {k: len(v) for k, v in normalized.items()},
        "attack_ideas": added,
        "rejected": rejected,
        "next": (
            "Work the ideas in rank order. Version-in-range or a suspicious response "
            "is a lead: prove it with the class-specific probe, submit_finding_candidate, "
            "then independent_verify. Update the hypothesis (proven/killed) with evidence."
        ),
    }


def has_recon_inventory(brain_dict: Dict[str, Any] | None, target: str = "") -> bool:
    for row in (brain_dict or {}).get("recon_observations") or []:
        if isinstance(row, dict) and row.get("kind") == "recon_inventory" and (
            not target or row.get("target") == target
        ):
            return True
    return False


RECON_REASONING_GUIDANCE = """Recon reasoning (you lead this step):
Act like a curious pentester. Read what recon captured: page source, headers, JS
analysis, /wp-json/ or other REST indexes, readme/changelog/style.css version lines,
robots.txt, error pages. Then call record_recon_inventory with:
  inventory: technologies, cms, versions (component + version + where you saw it),
    logins, forms, apis, file_uploads, ai_features (chatbots/LLM endpoints), notes.
  attack_ideas (ranked, best first): {title, vuln_class, surface (path on the target),
    parameter?, method?, rationale (what you observed), test, pass_criteria, kill_criteria}.
Reason from the evidence: a login means stored accounts (auth, enumeration, session
handling); a search box or id parameter means SQLi/XSS candidates; an upload means file
upload; an old component version means look up its CVEs (lookup_component_vulns /
web_search, never include the target hostname in a search) and check preconditions.
Ideas become coverage cells. Findings still need a verifier to reproduce them."""
