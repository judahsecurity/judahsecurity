"""Atlassian Jira REST API v3 client for ASM vulnerability ticket creation."""

import base64
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.models.jira_integration import JiraIntegration, JiraTicket
from app.models.vulnerability import Vulnerability
from app.services.remediation_playbook_service import RemediationPlaybookService
from app.services.cwe_service import get_cwe_service
from app.services.campaign_mitigations import campaigns_for_finding

logger = logging.getLogger(__name__)

# Vulnerability statuses that mean "closed" in Jira terms
CLOSING_STATUSES = {"resolved", "accepted", "false_positive", "mitigated"}
REOPENING_STATUSES = {"open", "in_progress"}


# ── Auth helpers ─────────────────────────────────────────────────────────────

def _auth_header(email: str, api_token: str) -> str:
    credentials = f"{email}:{api_token}"
    return "Basic " + base64.b64encode(credentials.encode()).decode()


def _base_url(hostname: str) -> str:
    host = hostname.rstrip("/")
    if not host.startswith("http"):
        host = f"https://{host}"
    return f"{host}/rest/api/3"


def _headers(email: str, api_token: str, content_type: bool = True) -> Dict[str, str]:
    h = {"Authorization": _auth_header(email, api_token), "Accept": "application/json"}
    if content_type:
        h["Content-Type"] = "application/json"
    return h


def _issue_url(hostname: str, key: str) -> str:
    host = hostname.rstrip("/")
    if not host.startswith("http"):
        host = f"https://{host}"
    return f"{host}/browse/{key}"


# ── Connection / metadata ────────────────────────────────────────────────────

async def test_connection(hostname: str, email: str, api_token: str) -> Dict[str, Any]:
    url = f"{_base_url(hostname)}/myself"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=_headers(email, api_token, content_type=False))
        if resp.status_code == 200:
            data = resp.json()
            return {"ok": True, "message": "Connection successful", "display_name": data.get("displayName")}
        elif resp.status_code == 401:
            return {"ok": False, "message": "Authentication failed — check email and API token.", "display_name": None}
        return {"ok": False, "message": f"Jira returned HTTP {resp.status_code}", "display_name": None}
    except httpx.ConnectError:
        return {"ok": False, "message": f"Could not connect to {hostname} — verify the hostname.", "display_name": None}
    except Exception as exc:
        logger.exception("Jira test_connection error")
        return {"ok": False, "message": str(exc), "display_name": None}


async def get_projects(
    hostname: str,
    email: str,
    api_token: str,
    query: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List Jira projects the authenticated user can see.

    Paginates through all pages (Jira caps each page at 100). Optional ``query``
    filters by project name or key server-side so large instances (hundreds of
    projects) can still find e.g. "IT: Vulnerability Management" / ITVM.
    """
    from urllib.parse import quote

    projects: List[Dict[str, Any]] = []
    start_at = 0
    page_size = 100
    # Safety cap — unlikely for a single Jira site, prevents runaway loops
    max_total = 2000

    async with httpx.AsyncClient(timeout=30) as client:
        while start_at < max_total:
            params = f"maxResults={page_size}&startAt={start_at}&orderBy=name"
            if query and query.strip():
                params += f"&query={quote(query.strip())}"
            url = f"{_base_url(hostname)}/project/search?{params}"
            resp = await client.get(url, headers=_headers(email, api_token, content_type=False))
            resp.raise_for_status()
            data = resp.json()
            values = data.get("values", []) or []
            for p in values:
                projects.append({
                    "key": p["key"],
                    "name": p["name"],
                    "project_type": p.get("projectTypeKey"),
                })
            if data.get("isLast", True) or not values:
                break
            start_at += len(values)

    return projects


async def get_issue_types(hostname: str, email: str, api_token: str, project_key: str) -> List[Dict[str, Any]]:
    url = f"{_base_url(hostname)}/project/{project_key}"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=_headers(email, api_token, content_type=False))
    resp.raise_for_status()
    return [
        {"id": it["id"], "name": it["name"], "description": it.get("description", "")}
        for it in resp.json().get("issueTypes", [])
        if not it.get("subtask", False)
    ]


async def get_issue_transitions(hostname: str, email: str, api_token: str, issue_key: str) -> List[Dict[str, Any]]:
    """Return all transitions available from the current state of an issue."""
    url = f"{_base_url(hostname)}/issue/{issue_key}/transitions"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=_headers(email, api_token, content_type=False))
    resp.raise_for_status()
    return [
        {
            "id": t["id"],
            "name": t["name"],
            "to_status": t.get("to", {}).get("name"),
        }
        for t in resp.json().get("transitions", [])
    ]


async def get_issue_detail(hostname: str, email: str, api_token: str, issue_key: str) -> Dict[str, Any]:
    """Fetch current status and assignee from a Jira issue."""
    url = f"{_base_url(hostname)}/issue/{issue_key}?fields=status,assignee,summary"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=_headers(email, api_token, content_type=False))
    resp.raise_for_status()
    fields = resp.json().get("fields", {})
    return {
        "status": fields.get("status", {}).get("name"),
        "assignee": (fields.get("assignee") or {}).get("displayName"),
        "summary": fields.get("summary"),
    }


# ── Transitions & comments ───────────────────────────────────────────────────

async def execute_transition(
    hostname: str,
    email: str,
    api_token: str,
    issue_key: str,
    transition_name: str,
    custom_fields: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Find the named transition from the current state and execute it.
    Returns True if the transition was found and executed, False otherwise.
    """
    transitions = await get_issue_transitions(hostname, email, api_token, issue_key)
    match = next((t for t in transitions if t["name"].lower() == transition_name.lower()), None)
    if not match:
        logger.warning("Jira transition '%s' not available for %s (available: %s)",
                       transition_name, issue_key, [t["name"] for t in transitions])
        return False

    url = f"{_base_url(hostname)}/issue/{issue_key}/transitions"
    body: Dict[str, Any] = {"transition": {"id": match["id"]}}
    if custom_fields:
        body["fields"] = custom_fields

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers=_headers(email, api_token), json=body)

    if resp.status_code in (200, 204):
        return True
    logger.warning("Jira transition %s on %s returned %s: %s",
                   transition_name, issue_key, resp.status_code, resp.text[:200])
    return False


async def add_comment(
    hostname: str,
    email: str,
    api_token: str,
    issue_key: str,
    text: str,
) -> bool:
    """Add a plain-text comment to a Jira issue."""
    url = f"{_base_url(hostname)}/issue/{issue_key}/comment"
    body = {
        "body": {
            "version": 1,
            "type": "doc",
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
        }
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, headers=_headers(email, api_token), json=body)
    return resp.status_code in (200, 201)


# ── Bidirectional status sync ────────────────────────────────────────────────

async def sync_ticket_for_status_change(
    integration: JiraIntegration,
    ticket: JiraTicket,
    old_status: str,
    new_status: str,
    changed_by: str,
) -> Dict[str, Any]:
    """
    Synchronize the Jira ticket state when a vulnerability status changes.

    Closing statuses (resolved, accepted, false_positive, mitigated) → run
    open_to_close_transitions and add a closure comment.

    Reopening statuses (open, in_progress) when previously closed → run
    close_to_open_transitions and add a reopen comment.
    """
    result: Dict[str, Any] = {"ok": True, "message": "", "transitions_executed": [], "comment_added": False}

    is_closing = new_status in CLOSING_STATUSES
    is_reopening = new_status in REOPENING_STATUSES and old_status in CLOSING_STATUSES

    if not is_closing and not is_reopening:
        result["message"] = "No Jira sync needed for this status combination."
        return result

    hostname, email, api_token = integration.hostname, integration.email, integration.api_token
    issue_key = ticket.jira_issue_key

    if is_closing:
        transitions = list(integration.open_to_close_transitions or [])
        custom_fields = integration.close_custom_fields or {}
        reason_map = {
            "resolved": "Remediated",
            "accepted": "Risk Accepted",
            "false_positive": "False Positive",
            "mitigated": "Mitigated",
        }
        reason = reason_map.get(new_status, new_status.replace("_", " ").title())
        comment_text = (
            f"[Judah Security ASM] Vulnerability marked as {reason} by {changed_by}. "
            f"Ticket closed automatically."
        )
    else:
        transitions = list(integration.close_to_open_transitions or [])
        custom_fields = integration.reopen_custom_fields or {}
        comment_text = (
            f"[Judah Security ASM] Vulnerability reopened by {changed_by}. "
            f"New status: {new_status.replace('_', ' ').title()}."
        )

    for transition_name in transitions:
        ok = await execute_transition(
            hostname, email, api_token, issue_key, transition_name,
            custom_fields=custom_fields or None,
        )
        if ok:
            result["transitions_executed"].append(transition_name)

    # Always add a comment to explain the status change
    if comment_text:
        result["comment_added"] = await add_comment(hostname, email, api_token, issue_key, comment_text)

    result["message"] = (
        f"Executed {len(result['transitions_executed'])} transition(s), "
        f"comment {'added' if result['comment_added'] else 'skipped'}."
    )
    return result


# Synchronous wrapper for use from sync FastAPI route handlers via BackgroundTasks
def sync_ticket_for_status_change_sync(
    integration: JiraIntegration,
    ticket: JiraTicket,
    old_status: str,
    new_status: str,
    changed_by: str,
) -> None:
    """Fire-and-forget sync wrapper for background task use."""
    import asyncio
    try:
        asyncio.run(sync_ticket_for_status_change(integration, ticket, old_status, new_status, changed_by))
    except Exception:
        logger.exception("Background Jira sync failed for ticket %s", ticket.jira_issue_key)


# ── ADF builders ─────────────────────────────────────────────────────────────

def _severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity.lower(), "⚪")


def _build_adf_doc(sections: List[Dict]) -> Dict:
    return {"version": 1, "type": "doc", "content": sections}


def _adf_heading(text: str, level: int = 2) -> Dict:
    return {"type": "heading", "attrs": {"level": level}, "content": [{"type": "text", "text": text}]}


def _adf_para(text: str) -> Dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _adf_para_nodes(nodes: List[Dict]) -> Dict:
    return {"type": "paragraph", "content": nodes}


def _adf_strong(text: str) -> Dict:
    return {"type": "text", "text": text, "marks": [{"type": "strong"}]}


def _adf_code_block(text: str, language: str = "text") -> Dict:
    return {"type": "codeBlock", "attrs": {"language": language}, "content": [{"type": "text", "text": text}]}


def _adf_bullet_list(items: List[str]) -> Dict:
    return {
        "type": "bulletList",
        "content": [{"type": "listItem", "content": [_adf_para(item)]} for item in items],
    }


def _adf_ordered_list(items: List[List[Dict]]) -> Dict:
    return {
        "type": "orderedList",
        "content": [{"type": "listItem", "content": blocks} for blocks in items],
    }


def _adf_rule() -> Dict:
    return {"type": "rule"}


def _build_playbook_blocks(playbook: Dict) -> List[Dict]:
    blocks: List[Dict] = []
    blocks.append(_adf_heading("Remediation Playbook", 2))

    meta_lines = [
        f"Summary: {playbook.get('summary', '')}",
        f"Estimated Time: {playbook.get('estimated_time', 'unknown')}",
        f"Effort: {playbook.get('effort', 'unknown').title()}",
        f"Priority: {playbook.get('priority', 'unknown').upper()}",
    ]
    access_list = playbook.get("required_access", [])
    if access_list:
        meta_lines.append(f"Required Access: {', '.join(a.replace('_', ' ').title() for a in access_list)}")
    blocks.append(_adf_bullet_list(meta_lines))

    impact = playbook.get("impact_if_not_fixed", "")
    if impact:
        blocks.append(_adf_para(f"⚠️ Impact if Not Fixed: {impact}"))

    steps = playbook.get("steps", [])
    if steps:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Remediation Steps", 3))
        step_items: List[List[Dict]] = []
        for step in steps:
            label = f"Step {step['order']}: {step['title']}"
            if not step.get("is_required", True):
                label += " (optional)"
            elif step.get("is_alternative", False):
                label += " (alternative)"
            item_blocks: List[Dict] = [
                _adf_para_nodes([_adf_strong(label)]),
                _adf_para(step["description"]),
            ]
            if step.get("command"):
                item_blocks.append(_adf_code_block(step["command"].strip(), "bash"))
            if step.get("code_snippet"):
                item_blocks.append(_adf_code_block(step["code_snippet"].strip()))
            if step.get("notes"):
                item_blocks.append(_adf_para(f"📝 Note: {step['notes']}"))
            step_items.append(item_blocks)
        blocks.append(_adf_ordered_list(step_items))

    verification = playbook.get("verification", [])
    if verification:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Verification Steps", 3))
        verify_items: List[List[Dict]] = []
        for v in verification:
            item_blocks = [
                _adf_para_nodes([_adf_strong(f"Step {v['order']}: {v['description']}")]),
                _adf_para(f"Expected: {v['expected_result']}"),
            ]
            if v.get("command"):
                item_blocks.append(_adf_code_block(v["command"].strip(), "bash"))
            verify_items.append(item_blocks)
        blocks.append(_adf_ordered_list(verify_items))

    common_mistakes = playbook.get("common_mistakes", [])
    if common_mistakes:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Common Mistakes to Avoid", 3))
        blocks.append(_adf_bullet_list(common_mistakes))

    return blocks


def _build_campaign_blocks(campaigns: List[Dict]) -> List[Dict]:
    """Interim mitigations from active exploitation campaigns (feed text, plain only)."""
    blocks: List[Dict] = [_adf_heading("Active Exploitation Campaign: Interim Mitigations", 2)]
    for campaign in campaigns[:3]:
        match = campaign.get("match") or {}
        label = "CVE" if match.get("type") == "cve" else "Exposed product"
        blocks.append(_adf_heading(str(campaign.get("name", ""))[:200], 3))
        blocks.append(_adf_para(
            f"Matched on {label}: {match.get('value', '')}. "
            f"Reported {campaign.get('published', '')}. Source: {campaign.get('url', '')}"
        ))
        if campaign.get("mitigations"):
            blocks.append(_adf_bullet_list([str(m) for m in campaign["mitigations"][:8]]))
        checks = campaign.get("compromise_checks") or []
        if checks:
            blocks.append(_adf_heading("Check for prior compromise", 4))
            blocks.append(_adf_bullet_list([
                f"{c.get('title') or 'Check'}: {c.get('look_for', '')} (logs: {c.get('log_source', 'n/a')})"
                for c in checks[:6]
            ]))
    return blocks


def _build_description(
    vuln: Vulnerability,
    include_description: bool,
    include_evidence: bool,
    include_remediation: bool,
    include_references: bool,
    include_enrichment: bool,
    playbook: Optional[Dict] = None,
    cwe_info: Optional[Dict] = None,
    campaigns: Optional[List[Dict]] = None,
) -> Dict:
    blocks: List[Dict] = []

    asset_value = vuln.asset.value if vuln.asset else "Unknown"
    severity_str = f"{_severity_emoji(vuln.severity.value)} {vuln.severity.value.upper()}"

    blocks.append(_adf_heading("Overview", 2))
    overview_lines = [
        f"Severity: {severity_str}",
        f"Affected Asset: {asset_value}",
        f"Status: {(vuln.status.value if vuln.status else 'open').replace('_', ' ').title()}",
        f"Detected By: {vuln.detected_by or 'unknown'}",
    ]
    if vuln.cve_id:
        overview_lines.append(f"CVE: {vuln.cve_id}")
    if vuln.cwe_id:
        overview_lines.append(f"CWE: {vuln.cwe_id}")
    if vuln.cvss_score is not None:
        overview_lines.append(f"CVSS Score: {vuln.cvss_score:.1f}")
    if vuln.cvss_vector:
        overview_lines.append(f"CVSS Vector: {vuln.cvss_vector}")
    blocks.append(_adf_bullet_list(overview_lines))

    if include_description and vuln.description:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Description", 2))
        blocks.append(_adf_para(vuln.description))

    if include_evidence and vuln.evidence:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Evidence", 2))
        blocks.append(_adf_code_block(vuln.evidence[:2000]))

    if include_evidence and vuln.proof_of_concept:
        blocks.append(_adf_heading("Proof of Concept", 3))
        blocks.append(_adf_code_block(vuln.proof_of_concept[:2000]))

    if include_evidence and vuln.steps_to_reproduce:
        blocks.append(_adf_heading("Steps to Reproduce", 3))
        blocks.append(_adf_para(vuln.steps_to_reproduce))

    if include_remediation and campaigns:
        blocks.append(_adf_rule())
        blocks.extend(_build_campaign_blocks(campaigns))

    if include_remediation:
        if playbook:
            blocks.append(_adf_rule())
            blocks.extend(_build_playbook_blocks(playbook))
        elif vuln.remediation:
            blocks.append(_adf_rule())
            blocks.append(_adf_heading("Remediation", 2))
            blocks.append(_adf_para(vuln.remediation))

        if cwe_info:
            blocks.append(_adf_heading("CWE Guidance", 3))
            cwe_lines = [f"{cwe_info.get('cwe_id', '')}: {cwe_info.get('name', '')}"]
            if cwe_info.get("description"):
                cwe_lines.append(cwe_info["description"][:300])
            mitigations = cwe_info.get("mitigations", [])
            if mitigations:
                cwe_lines.append("Mitigations: " + "; ".join(str(m) for m in mitigations[:3]))
            blocks.append(_adf_bullet_list(cwe_lines))

    if include_enrichment and vuln.metadata_ and isinstance(vuln.metadata_, dict):
        delphi = vuln.metadata_.get("delphi")
        if delphi:
            blocks.append(_adf_rule())
            blocks.append(_adf_heading("Threat Intelligence (Delphi)", 2))
            delphi_lines: List[str] = []
            if delphi.get("kev"):
                kev = delphi["kev"]
                delphi_lines.append("⚠️ CISA Known Exploited Vulnerability (KEV)")
                if kev.get("required_action"):
                    delphi_lines.append(f"Required Action: {kev['required_action']}")
                if kev.get("due_date"):
                    delphi_lines.append(f"CISA Due Date: {kev['due_date']}")
            if delphi.get("epss"):
                epss = delphi["epss"]
                delphi_lines.append(
                    f"EPSS Score: {epss.get('score', 0):.3f} "
                    f"(percentile: {epss.get('percentile', 0) * 100:.1f}%)"
                )
            if delphi.get("priority") and delphi["priority"] != "none":
                delphi_lines.append(f"Delphi Priority: {delphi['priority'].upper()}")
            if delphi_lines:
                blocks.append(_adf_bullet_list(delphi_lines))

        oracle = vuln.metadata_.get("oracle")
        if oracle and oracle.get("opes_category"):
            blocks.append(_adf_heading("Aegis Oracle OPES Analysis", 3))
            oracle_lines = [f"OPES Category: {oracle['opes_category']}"]
            if oracle.get("opes_score") is not None:
                oracle_lines.append(f"OPES Score: {oracle['opes_score']:.1f}")
            if oracle.get("opes_label"):
                oracle_lines.append(f"Label: {oracle['opes_label']}")
            if oracle.get("attack_path_class"):
                oracle_lines.append(f"Attack Path: {oracle['attack_path_class']}")
            if oracle.get("recommendation_text"):
                oracle_lines.append(f"Recommendation: {oracle['recommendation_text'][:300]}")
            blocks.append(_adf_bullet_list(oracle_lines))

    refs = list(vuln.references or [])
    if include_references and refs:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("References", 2))
        blocks.append(_adf_bullet_list(refs[:10]))

    blocks.append(_adf_rule())
    blocks.append(_adf_para("This ticket was created automatically by Judah Security ASM."))

    return _build_adf_doc(blocks)


# ── Ticket creation ──────────────────────────────────────────────────────────

async def create_jira_ticket(
    integration: JiraIntegration,
    vuln: Vulnerability,
    project_key: str,
    issue_type: str = "Bug",
    include_description: bool = True,
    include_evidence: bool = True,
    include_remediation: bool = True,
    include_references: bool = True,
    include_enrichment: bool = True,
    assignee_account_id: Optional[str] = None,
    extra_labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a Jira issue from a vulnerability. Returns key, url, id."""
    playbook_dict: Optional[Dict] = None
    cwe_info: Optional[Dict] = None
    campaigns: List[Dict] = []
    if include_remediation:
        try:
            playbook_obj = RemediationPlaybookService.get_playbook_for_finding(
                title=vuln.title,
                template_id=vuln.template_id,
                port=vuln.metadata_.get("port") if vuln.metadata_ else None,
                tags=vuln.tags or [],
                cwe_id=vuln.cwe_id,
                cve_id=vuln.cve_id,
            )
            if playbook_obj:
                playbook_dict = playbook_obj.to_dict()
        except Exception:
            logger.warning("Could not fetch remediation playbook for vuln %s", vuln.id)

        if vuln.cwe_id:
            try:
                cwe_info = get_cwe_service().get_dict(vuln.cwe_id)
            except Exception:
                logger.warning("Could not fetch CWE info for %s", vuln.cwe_id)

        campaigns = campaigns_for_finding(
            cve_id=vuln.cve_id,
            title=vuln.title,
            template_id=vuln.template_id,
            tags=vuln.tags or [],
        ).get("campaigns") or []

    severity_str = vuln.severity.value if vuln.severity else "unknown"
    title = f"[ASM] [{severity_str.upper()}] {vuln.title or vuln.template_id}"
    if len(title) > 255:
        title = title[:252] + "..."

    labels = [f"asm-{severity_str}", "judah-security"]
    if vuln.cve_id:
        labels.append(vuln.cve_id.replace(" ", "-"))
    if extra_labels:
        labels.extend(extra_labels)

    description_adf = _build_description(
        vuln=vuln,
        include_description=include_description,
        include_evidence=include_evidence,
        include_remediation=include_remediation,
        include_references=include_references,
        include_enrichment=include_enrichment,
        playbook=playbook_dict,
        cwe_info=cwe_info,
        campaigns=campaigns,
    )

    fields: Dict[str, Any] = {
        "project": {"key": project_key},
        "summary": title,
        "issuetype": {"name": issue_type},
        "description": description_adf,
        "labels": labels,
    }
    if assignee_account_id:
        fields["assignee"] = {"accountId": assignee_account_id}

    url = f"{_base_url(integration.hostname)}/issue"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=_headers(integration.email, integration.api_token), json={"fields": fields})

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise ValueError(f"Jira API error {resp.status_code}: {detail}")

    data = resp.json()
    issue_key = data["key"]
    return {"key": issue_key, "url": _issue_url(integration.hostname, issue_key), "id": data.get("id")}


# ── Auto-create (background) ─────────────────────────────────────────────────

def auto_create_ticket_sync(
    integration: JiraIntegration,
    vuln: Vulnerability,
) -> None:
    """Synchronous wrapper — runs async create in a new event loop for BackgroundTasks."""
    import asyncio
    from app.models.jira_integration import JiraTicket as JiraTicketModel

    try:
        result = asyncio.run(
            create_jira_ticket(
                integration=integration,
                vuln=vuln,
                project_key=integration.default_project_key or "",
                issue_type=integration.default_issue_type or "Bug",
            )
        )
        # Persist the ticket record using a fresh DB session
        from app.db.database import SessionLocal
        db = SessionLocal()
        try:
            ticket = JiraTicketModel(
                integration_id=integration.id,
                vulnerability_id=vuln.id,
                jira_issue_key=result["key"],
                jira_issue_url=result["url"],
                jira_project_key=integration.default_project_key or "",
                jira_issue_type=integration.default_issue_type or "Bug",
            )
            db.add(ticket)
            db.commit()
            logger.info("Auto-created Jira ticket %s for vuln %s", result["key"], vuln.id)
        finally:
            db.close()
    except Exception:
        logger.exception("Auto-create Jira ticket failed for vuln %s", vuln.id)
