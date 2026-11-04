"""Azure DevOps Boards (Work Item Tracking) client and sync logic.

Auth:
  * Personal Access Token  → HTTP Basic with an empty username.
  * Entra ID service principal → OAuth2 client-credentials token for the
    Azure DevOps resource (499b84ac-1321-427f-aa17-267ca6975798), cached in
    process until shortly before expiry.

All Azure DevOps calls go through ``AzureDevOpsClient.request`` which retries
429 / 503 responses with ``Retry-After`` / exponential backoff.
"""

from __future__ import annotations

import asyncio
import base64
import html
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.models.azure_devops_integration import (
    AUTH_METHOD_ENTRA,
    AUTH_METHOD_PAT,
    DEFAULT_REMOTE_CLOSED_STATES,
    AzureDevOpsIntegration,
    AzureDevOpsTemplate,
    AzureDevOpsWorkItem,
)
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

API_VERSION = "7.1"
COMMENTS_API_VERSION = "7.1-preview.4"
AZURE_DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
ENTRA_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

# Vulnerability statuses that mean "closed" / "reopened" from the ASM side.
CLOSING_STATUSES = {"resolved", "accepted", "false_positive", "mitigated"}
REOPENING_STATUSES = {"open", "in_progress"}

SEVERITY_MAP = {
    "critical": "1 - Critical",
    "high": "2 - High",
    "medium": "3 - Medium",
    "low": "4 - Low",
    "info": "4 - Low",
}

SEVERITY_FIELD = "Microsoft.VSTS.Common.Severity"
REPRO_STEPS_FIELD = "Microsoft.VSTS.TCM.ReproSteps"

MAX_RETRIES = 4
_ORG_URL_RE = re.compile(r"^https://dev\.azure\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/?$")

# Tests may inject an httpx.MockTransport here.
_transport: Optional[httpx.AsyncBaseTransport] = None

# (tenant_id, client_id) -> (access_token, expires_at_epoch)
_token_cache: Dict[Tuple[str, str], Tuple[str, float]] = {}


class AzureDevOpsError(Exception):
    """Raised for Azure DevOps API / auth failures with a user-facing message."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


# ── Pure helpers ─────────────────────────────────────────────────────────────

def normalize_organization_url(url: str) -> str:
    """Validate and normalize ``https://dev.azure.com/<org>``. Raises ValueError."""
    raw = (url or "").strip()
    if "visualstudio.com" in raw.lower():
        raise ValueError(
            "Legacy visualstudio.com URLs are not supported. "
            "Use https://dev.azure.com/<organization>."
        )
    if raw.startswith("dev.azure.com/"):
        raw = "https://" + raw
    m = _ORG_URL_RE.match(raw)
    if not m:
        raise ValueError(
            "Invalid Azure DevOps URL. Expected https://dev.azure.com/<organization>."
        )
    return f"https://dev.azure.com/{m.group(1)}"


def map_severity(severity: Optional[str]) -> str:
    return SEVERITY_MAP.get((severity or "info").lower(), "4 - Low")


def is_closed_state(state: Optional[str], closed_states: Optional[Iterable[str]] = None) -> bool:
    if not state:
        return False
    states = closed_states or DEFAULT_REMOTE_CLOSED_STATES
    return state.strip().lower() in {s.strip().lower() for s in states if s}


def _vuln_severity(vuln: Vulnerability) -> str:
    sev = vuln.severity
    return (sev.value if hasattr(sev, "value") else str(sev or "info")).lower()


def _vuln_status(vuln: Vulnerability) -> str:
    st = vuln.status
    return (st.value if hasattr(st, "value") else str(st or "open")).lower()


def finding_url(vuln_id: int) -> Optional[str]:
    base = (settings.PUBLIC_APP_URL or "").rstrip("/")
    return f"{base}/findings?id={vuln_id}" if base else None


def _pre(text: str, limit: int = 4000) -> str:
    return f"<pre>{html.escape(text[:limit])}</pre>"


def _para(text: str) -> str:
    return "<p>" + html.escape(text).replace("\n", "<br/>") + "</p>"


def build_description_html(vuln: Vulnerability) -> str:
    """Rich HTML body: link back, severity, impacted assets, definition, evidence, proof."""
    parts: List[str] = []
    severity = _vuln_severity(vuln)

    link = finding_url(vuln.id)
    if link:
        parts.append(
            f'<p><a href="{html.escape(link, quote=True)}">View this finding in Judah Security ASM</a></p>'
        )
    parts.append(
        f"<p><b>Severity:</b> {html.escape(severity.upper())} ({html.escape(map_severity(severity))})</p>"
    )
    meta: List[str] = []
    if vuln.cve_id:
        meta.append(f"<b>CVE:</b> {html.escape(vuln.cve_id)}")
    if vuln.cwe_id:
        meta.append(f"<b>CWE:</b> {html.escape(vuln.cwe_id)}")
    if vuln.cvss_score is not None:
        meta.append(f"<b>CVSS:</b> {vuln.cvss_score:.1f}")
    if vuln.detected_by:
        meta.append(f"<b>Detected by:</b> {html.escape(vuln.detected_by)}")
    if meta:
        parts.append("<p>" + " &nbsp;|&nbsp; ".join(meta) + "</p>")

    asset = vuln.asset
    parts.append("<h3>Impacted Assets</h3>")
    parts.append("<table border=\"1\" cellpadding=\"4\"><tr><th>Group</th><th>Identifier</th></tr>")
    if asset is not None:
        at = asset.asset_type
        group = asset.root_domain or (at.value if hasattr(at, "value") else str(at or ""))
        parts.append(
            f"<tr><td>{html.escape(group or '-')}</td><td>{html.escape(asset.value or '-')}</td></tr>"
        )
    else:
        parts.append("<tr><td>-</td><td>Unknown</td></tr>")
    parts.append("</table>")

    if vuln.description:
        parts.append("<h3>Definition</h3>")
        parts.append(_para(vuln.description))
    if vuln.impact:
        parts.append("<h3>Impact</h3>")
        parts.append(_para(vuln.impact))
    if vuln.evidence:
        parts.append("<h3>Evidence</h3>")
        parts.append(_pre(vuln.evidence))
    if vuln.proof_of_concept or vuln.steps_to_reproduce:
        parts.append("<h3>Proof</h3>")
        if vuln.proof_of_concept:
            parts.append(_pre(vuln.proof_of_concept))
        if vuln.steps_to_reproduce:
            parts.append(_para(vuln.steps_to_reproduce))
    if vuln.remediation:
        parts.append("<h3>Remediation</h3>")
        parts.append(_para(vuln.remediation))
    refs = [r for r in (vuln.references or []) if r][:10]
    if refs:
        parts.append("<h3>References</h3><ul>")
        for r in refs:
            esc = html.escape(str(r), quote=True)
            parts.append(f'<li><a href="{esc}">{esc}</a></li>' if str(r).startswith("http") else f"<li>{esc}</li>")
        parts.append("</ul>")
    parts.append("<p><i>Created by Judah Security ASM.</i></p>")
    return "".join(parts)


def build_title(vuln: Vulnerability) -> str:
    title = vuln.title or vuln.template_id or f"Finding {vuln.id}"
    # System.Title max length is 255
    return title if len(title) <= 255 else title[:252] + "..."


def build_tags(vuln: Vulnerability, extra: Optional[Iterable[str]] = None) -> str:
    tags = ["judah-security", f"asm-{_vuln_severity(vuln)}"]
    if vuln.cve_id:
        tags.append(vuln.cve_id.replace(" ", "-"))
    for t in extra or []:
        t = (t or "").strip()
        if t and t not in tags:
            tags.append(t)
    return "; ".join(t.replace(";", ",") for t in tags)


def _mention_html(identity: Optional[Dict[str, Any]]) -> str:
    if not identity or not identity.get("id"):
        return ""
    name = html.escape(identity.get("displayName") or "assignee")
    return f'<a href="#" data-vss-mention="version:2.0,{html.escape(identity["id"], quote=True)}">@{name}</a> '


# ── Client ───────────────────────────────────────────────────────────────────

class AzureDevOpsClient:
    def __init__(
        self,
        organization_url: str,
        auth_method: str = AUTH_METHOD_PAT,
        pat: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        self.base = normalize_organization_url(organization_url)
        self.auth_method = auth_method
        self.pat = pat
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    @classmethod
    def from_integration(cls, integration: AzureDevOpsIntegration) -> "AzureDevOpsClient":
        return cls(
            organization_url=integration.organization_url,
            auth_method=integration.auth_method,
            pat=integration.get_pat() if integration.auth_method == AUTH_METHOD_PAT else None,
            tenant_id=integration.tenant_id,
            client_id=integration.client_id,
            client_secret=(
                integration.get_client_secret() if integration.auth_method == AUTH_METHOD_ENTRA else None
            ),
        )

    # ── auth ────────────────────────────────────────────────────────────────
    async def _entra_token(self) -> str:
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise AzureDevOpsError("Azure DevOps token not available: tenant ID, client ID and client secret are required.")
        key = (self.tenant_id, self.client_id)
        cached = _token_cache.get(key)
        if cached and cached[1] - 120 > time.time():
            return cached[0]
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{AZURE_DEVOPS_RESOURCE}/.default",
        }
        async with httpx.AsyncClient(timeout=20, transport=_transport) as client:
            resp = await client.post(ENTRA_TOKEN_URL.format(tenant=quote(self.tenant_id, safe="")), data=data)
        if resp.status_code != 200:
            detail = ""
            try:
                detail = resp.json().get("error_description", "") or ""
            except Exception:
                detail = resp.text[:300]
            raise AzureDevOpsError(
                "Azure DevOps token not available from Entra ID — verify tenant ID, client ID, "
                f"client secret and the Azure DevOps API permission. {detail.splitlines()[0] if detail else ''}".strip(),
                status_code=resp.status_code,
            )
        body = resp.json()
        token = body["access_token"]
        _token_cache[key] = (token, time.time() + int(body.get("expires_in", 3600)))
        return token

    async def _auth_header(self) -> str:
        if self.auth_method == AUTH_METHOD_ENTRA:
            return "Bearer " + await self._entra_token()
        if not self.pat:
            raise AzureDevOpsError("Azure DevOps token not available: no Personal Access Token configured.")
        return "Basic " + base64.b64encode(f":{self.pat}".encode()).decode()

    # ── transport ───────────────────────────────────────────────────────────
    def url(self, path: str, project: Optional[str] = None) -> str:
        prefix = self.base + (f"/{quote(project, safe='')}" if project else "")
        return f"{prefix}/{path.lstrip('/')}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        project: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Any = None,
        content_type: str = "application/json",
        api_version: str = API_VERSION,
    ) -> httpx.Response:
        headers = {
            "Authorization": await self._auth_header(),
            "Accept": "application/json",
        }
        if json is not None:
            headers["Content-Type"] = content_type
        q = {"api-version": api_version, **(params or {})}
        url = self.url(path, project)

        resp: Optional[httpx.Response] = None
        async with httpx.AsyncClient(timeout=30, transport=_transport) as client:
            for attempt in range(MAX_RETRIES + 1):
                resp = await client.request(method, url, params=q, json=json, headers=headers)
                if resp.status_code not in (429, 503) or attempt == MAX_RETRIES:
                    break
                retry_after = resp.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2 ** (attempt + 1)
                except ValueError:
                    delay = 2 ** (attempt + 1)
                delay = min(delay, 60)
                logger.warning("Azure DevOps %s %s → %s; retrying in %.0fs", method, path, resp.status_code, delay)
                await asyncio.sleep(delay)
        assert resp is not None

        if resp.status_code in (401, 203):
            # 203 = sign-in page returned for an invalid/expired PAT
            raise AzureDevOpsError(
                "Azure DevOps authentication failed — the token may be expired or lack access.",
                status_code=401,
            )
        if resp.status_code >= 400:
            raise AzureDevOpsError(_error_message(resp), status_code=resp.status_code)
        return resp

    # ── metadata ────────────────────────────────────────────────────────────
    async def list_projects(self) -> List[Dict[str, Any]]:
        projects: List[Dict[str, Any]] = []
        token: Optional[str] = None
        for _ in range(50):  # safety cap: 50 * 100 projects
            params: Dict[str, Any] = {"$top": 100, "stateFilter": "wellFormed"}
            if token:
                params["continuationToken"] = token
            resp = await self.request("GET", "_apis/projects", params=params)
            for p in resp.json().get("value", []) or []:
                projects.append({"id": p.get("id"), "name": p.get("name"), "description": p.get("description")})
            token = resp.headers.get("x-ms-continuationtoken")
            if not token:
                break
        projects.sort(key=lambda p: (p["name"] or "").lower())
        return projects

    async def list_work_item_types(self, project: str) -> List[Dict[str, Any]]:
        resp = await self.request("GET", "_apis/wit/workitemtypes", project=project)
        types = []
        for t in resp.json().get("value", []) or []:
            if t.get("isDisabled"):
                continue
            types.append({
                "name": t.get("name"),
                "reference_name": t.get("referenceName"),
                "description": t.get("description"),
            })
        types.sort(key=lambda t: (t["name"] or "").lower())
        return types

    async def test_connection(self) -> Dict[str, Any]:
        try:
            projects = await self.list_projects()
        except AzureDevOpsError as exc:
            return {"ok": False, "message": str(exc), "project_count": None}
        except httpx.HTTPError as exc:
            return {"ok": False, "message": f"Could not reach {self.base}: {exc}", "project_count": None}
        if not projects:
            return {
                "ok": True,
                "message": (
                    "Connected, but no projects found. In Azure DevOps open Organization Settings > Users, "
                    "click the service principal or PAT user, choose Manage access and add it to each "
                    "target project as Project Contributors."
                ),
                "project_count": 0,
            }
        return {"ok": True, "message": f"Connected — {len(projects)} project(s) visible.", "project_count": len(projects)}

    # ── work items ──────────────────────────────────────────────────────────
    async def create_work_item(
        self,
        project: str,
        work_item_type: str,
        vuln: Vulnerability,
        area_path: Optional[str] = None,
        iteration_path: Optional[str] = None,
        extra_tags: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        description = build_description_html(vuln)
        ops: List[Dict[str, Any]] = [
            {"op": "add", "path": "/fields/System.Title", "value": build_title(vuln)},
            {"op": "add", "path": "/fields/System.Description", "value": description},
            {"op": "add", "path": "/fields/System.Tags", "value": build_tags(vuln, extra_tags)},
            {"op": "add", "path": f"/fields/{SEVERITY_FIELD}", "value": map_severity(_vuln_severity(vuln))},
        ]
        if work_item_type.strip().lower() == "bug":
            # Bugs in Agile/CMMI show Repro Steps rather than Description on the form.
            ops.append({"op": "add", "path": f"/fields/{REPRO_STEPS_FIELD}", "value": description})
        if area_path:
            ops.append({"op": "add", "path": "/fields/System.AreaPath", "value": area_path})
        if iteration_path:
            ops.append({"op": "add", "path": "/fields/System.IterationPath", "value": iteration_path})

        path = f"_apis/wit/workitems/${quote(work_item_type, safe='')}"
        try:
            resp = await self.request("POST", path, project=project, json=ops,
                                      content_type="application/json-patch+json")
        except AzureDevOpsError as exc:
            # Not every work item type has Severity / Repro Steps (e.g. Task, Issue
            # in Basic). Retry without the optional fields rather than failing.
            msg = str(exc)
            optional = (SEVERITY_FIELD, REPRO_STEPS_FIELD)
            if exc.status_code == 400 and any(f in msg for f in optional):
                ops = [o for o in ops if not any(o["path"].endswith(f) for f in optional)]
                resp = await self.request("POST", path, project=project, json=ops,
                                          content_type="application/json-patch+json")
            else:
                raise
        return _work_item_summary(resp.json(), self.base)

    async def get_work_item(self, work_item_id: int) -> Dict[str, Any]:
        resp = await self.request("GET", f"_apis/wit/workitems/{int(work_item_id)}")
        return _work_item_summary(resp.json(), self.base)

    async def get_work_items(self, ids: List[int]) -> Dict[int, Dict[str, Any]]:
        """Batch fetch (200 per call). Missing / deleted ids are omitted."""
        out: Dict[int, Dict[str, Any]] = {}
        fields = ["System.Id", "System.State", "System.AssignedTo", "System.TeamProject", "System.WorkItemType"]
        for i in range(0, len(ids), 200):
            chunk = [int(x) for x in ids[i:i + 200]]
            resp = await self.request(
                "POST", "_apis/wit/workitemsbatch",
                json={"ids": chunk, "fields": fields, "errorPolicy": "omit"},
            )
            for wi in resp.json().get("value", []) or []:
                if wi:
                    s = _work_item_summary(wi, self.base)
                    out[s["id"]] = s
        return out

    async def set_state(self, work_item_id: int, state: str) -> None:
        await self.request(
            "PATCH", f"_apis/wit/workitems/{int(work_item_id)}",
            json=[{"op": "add", "path": "/fields/System.State", "value": state}],
            content_type="application/json-patch+json",
        )

    async def add_comment(self, project: str, work_item_id: int, html_text: str) -> None:
        await self.request(
            "POST", f"_apis/wit/workItems/{int(work_item_id)}/comments",
            project=project, json={"text": html_text}, api_version=COMMENTS_API_VERSION,
        )


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        msg = body.get("message") or body.get("value", {}).get("Message") or str(body)
    except Exception:
        msg = resp.text[:300]
    if resp.status_code == 404:
        return f"Azure DevOps resource not found (404): {msg}"
    if resp.status_code == 403:
        return f"Azure DevOps permission denied (403): {msg}"
    return f"Azure DevOps API error {resp.status_code}: {msg}"


def _work_item_summary(data: Dict[str, Any], base: str) -> Dict[str, Any]:
    fields = data.get("fields", {}) or {}
    wid = int(data.get("id") or fields.get("System.Id"))
    assigned = fields.get("System.AssignedTo")
    if isinstance(assigned, str):
        assigned_identity: Optional[Dict[str, Any]] = {"displayName": assigned}
    else:
        assigned_identity = assigned or None
    project = fields.get("System.TeamProject")
    html_url = ((data.get("_links") or {}).get("html") or {}).get("href")
    if not html_url:
        html_url = f"{base}/{quote(project, safe='')}/_workitems/edit/{wid}" if project else f"{base}/_workitems/edit/{wid}"
    return {
        "id": wid,
        "url": html_url,
        "state": fields.get("System.State"),
        "assigned_to": (assigned_identity or {}).get("displayName"),
        "assigned_identity": assigned_identity,
        "project": project,
        "work_item_type": fields.get("System.WorkItemType"),
    }


# ── Higher-level operations (DB-aware) ───────────────────────────────────────

async def create_for_vulnerability(
    db,
    integration: AzureDevOpsIntegration,
    vuln: Vulnerability,
    project: str,
    work_item_type: str,
    template: Optional[AzureDevOpsTemplate] = None,
) -> AzureDevOpsWorkItem:
    client = AzureDevOpsClient.from_integration(integration)
    result = await client.create_work_item(
        project=project,
        work_item_type=work_item_type,
        vuln=vuln,
        area_path=template.area_path if template else None,
        iteration_path=template.iteration_path if template else None,
        extra_tags=(template.extra_tags or []) if template else None,
    )
    link = AzureDevOpsWorkItem(
        integration_id=integration.id,
        template_id=template.id if template else None,
        vulnerability_id=vuln.id,
        work_item_id=result["id"],
        work_item_url=result["url"],
        project=result.get("project") or project,
        work_item_type=result.get("work_item_type") or work_item_type,
        state=result.get("state"),
        assigned_to=result.get("assigned_to"),
        last_synced_at=datetime.utcnow(),
        last_notified_severity=_vuln_severity(vuln),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def matching_auto_templates(integration: AzureDevOpsIntegration, severity: str) -> List[AzureDevOpsTemplate]:
    from app.models.azure_devops_integration import severity_meets_threshold

    return [
        t for t in (integration.templates or [])
        if t.is_active and t.auto_create_enabled
        and severity_meets_threshold(severity, t.auto_create_min_severity or "high")
    ]


async def refresh_links(
    db,
    integration: AzureDevOpsIntegration,
    links: List[AzureDevOpsWorkItem],
    apply_remote_close: bool = True,
) -> Dict[str, int]:
    """Pull state/assignee for links; close ASM findings whose work item is closed."""
    if not links:
        return {"refreshed": 0, "closed_in_asm": 0}
    client = AzureDevOpsClient.from_integration(integration)
    remote = await client.get_work_items([l.work_item_id for l in links])
    closed_states = integration.remote_closed_states or DEFAULT_REMOTE_CLOSED_STATES
    refreshed = closed = 0
    now = datetime.utcnow()
    for link in links:
        info = remote.get(link.work_item_id)
        if not info:
            continue
        link.state = info.get("state")
        link.assigned_to = info.get("assigned_to")
        link.last_synced_at = now
        refreshed += 1
        if apply_remote_close and integration.sync_enabled and is_closed_state(link.state, closed_states):
            vuln = link.vulnerability
            if vuln is not None and _vuln_status(vuln) in REOPENING_STATUSES:
                _apply_remote_close(vuln, integration, link)
                closed += 1
    db.commit()
    return {"refreshed": refreshed, "closed_in_asm": closed}


def _apply_remote_close(vuln: Vulnerability, integration: AzureDevOpsIntegration, link: AzureDevOpsWorkItem) -> None:
    from app.models.vulnerability import VulnerabilityStatus

    target = (integration.accept_close_as or "resolved").lower()
    try:
        vuln.status = VulnerabilityStatus(target)
    except ValueError:
        vuln.status = VulnerabilityStatus.RESOLVED
        target = "resolved"
    if target == "resolved" and not vuln.resolved_at:
        vuln.resolved_at = datetime.utcnow()
    logger.info(
        "Azure DevOps work item #%s is %s — vuln %s set to %s",
        link.work_item_id, link.state, vuln.id, target,
    )


async def pull_integration(db, integration: AzureDevOpsIntegration) -> Dict[str, Any]:
    links = (
        db.query(AzureDevOpsWorkItem)
        .filter(
            AzureDevOpsWorkItem.integration_id == integration.id,
            AzureDevOpsWorkItem.disconnected_at.is_(None),
        )
        .all()
    )
    try:
        result = await refresh_links(db, integration, links, apply_remote_close=True)
        integration.last_error = None
        ok = True
        message = (
            f"Refreshed {result['refreshed']} work item(s); "
            f"{result['closed_in_asm']} finding(s) closed from Azure DevOps."
        )
    except Exception as exc:
        result = {"refreshed": 0, "closed_in_asm": 0}
        integration.last_error = str(exc)[:1000]
        ok = False
        message = f"Pull failed: {exc}"
        logger.exception("Azure DevOps pull failed for integration %s", integration.id)
    integration.last_pull_at = datetime.utcnow()
    db.commit()
    return {"ok": ok, "message": message, "errors": 0 if ok else 1, **result}


async def notify_status_change(
    integration: AzureDevOpsIntegration,
    link: AzureDevOpsWorkItem,
    old_status: str,
    new_status: str,
    changed_by: str,
) -> None:
    is_closing = new_status in CLOSING_STATUSES and old_status not in CLOSING_STATUSES
    is_reopening = new_status in REOPENING_STATUSES and old_status in CLOSING_STATUSES
    if not (is_closing or is_reopening):
        return
    client = AzureDevOpsClient.from_integration(integration)
    label = new_status.replace("_", " ").title()
    if is_closing:
        text = f"[Judah Security ASM] Finding marked as <b>{html.escape(label)}</b> by {html.escape(changed_by)}."
        target_state = integration.close_state
    else:
        text = f"[Judah Security ASM] Finding reopened by {html.escape(changed_by)}. New status: <b>{html.escape(label)}</b>."
        target_state = integration.reopen_state
    if link.project:
        await client.add_comment(link.project, link.work_item_id, text)
    if target_state:
        try:
            await client.set_state(link.work_item_id, target_state)
        except AzureDevOpsError as exc:
            logger.warning("Could not set work item #%s to state %r: %s", link.work_item_id, target_state, exc)


async def notify_severity_change(
    integration: AzureDevOpsIntegration,
    link: AzureDevOpsWorkItem,
    old_severity: str,
    new_severity: str,
) -> None:
    client = AzureDevOpsClient.from_integration(integration)
    info = await client.get_work_item(link.work_item_id)
    mention = _mention_html(info.get("assigned_identity"))
    text = (
        f"{mention}[Judah Security ASM] Severity of this finding changed from "
        f"<b>{html.escape(old_severity.upper())}</b> to <b>{html.escape(new_severity.upper())}</b> "
        f"({html.escape(map_severity(new_severity))})."
    )
    await client.add_comment(link.project or info.get("project") or "", link.work_item_id, text)


# ── Background-task entry points (own DB session, ids only) ──────────────────

def _load(db, integration_id: int):
    return db.query(AzureDevOpsIntegration).filter(AzureDevOpsIntegration.id == integration_id).first()


def auto_create_background(integration_id: int, vulnerability_id: int) -> None:
    """Create work items for every matching auto-create template."""
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        integration = _load(db, integration_id)
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not integration or not integration.is_active or not vuln:
            return
        for template in matching_auto_templates(integration, _vuln_severity(vuln)):
            exists = (
                db.query(AzureDevOpsWorkItem)
                .filter(
                    AzureDevOpsWorkItem.integration_id == integration.id,
                    AzureDevOpsWorkItem.vulnerability_id == vuln.id,
                    AzureDevOpsWorkItem.project == template.project,
                    AzureDevOpsWorkItem.disconnected_at.is_(None),
                )
                .first()
            )
            if exists:
                continue
            try:
                link = asyncio.run(create_for_vulnerability(
                    db, integration, vuln, template.project, template.work_item_type, template
                ))
                logger.info("Auto-created Azure DevOps work item #%s for vuln %s (template %s)",
                            link.work_item_id, vuln.id, template.name)
            except Exception as exc:
                db.rollback()
                integration.last_error = f"Auto-create failed for finding {vuln.id}: {exc}"[:1000]
                db.commit()
                logger.exception("Azure DevOps auto-create failed for vuln %s", vuln.id)
    finally:
        db.close()


def status_change_background(vulnerability_id: int, old_status: str, new_status: str, changed_by: str) -> None:
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        for integration, link in _active_links_for_vuln(db, vulnerability_id):
            try:
                asyncio.run(notify_status_change(integration, link, old_status, new_status, changed_by))
            except Exception:
                logger.exception("Azure DevOps status sync failed for work item #%s", link.work_item_id)
    finally:
        db.close()


def severity_change_background(vulnerability_id: int, old_severity: str, new_severity: str) -> None:
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        for integration, link in _active_links_for_vuln(db, vulnerability_id):
            if not integration.notify_severity_change or link.last_notified_severity == new_severity:
                continue
            try:
                asyncio.run(notify_severity_change(integration, link, old_severity, new_severity))
                link.last_notified_severity = new_severity
                db.commit()
            except Exception:
                db.rollback()
                logger.exception("Azure DevOps severity comment failed for work item #%s", link.work_item_id)
    finally:
        db.close()


def _active_links_for_vuln(db, vulnerability_id: int):
    rows = (
        db.query(AzureDevOpsWorkItem, AzureDevOpsIntegration)
        .join(AzureDevOpsIntegration, AzureDevOpsWorkItem.integration_id == AzureDevOpsIntegration.id)
        .filter(
            AzureDevOpsWorkItem.vulnerability_id == vulnerability_id,
            AzureDevOpsWorkItem.disconnected_at.is_(None),
            AzureDevOpsIntegration.is_active.is_(True),
        )
        .all()
    )
    return [(integ, link) for link, integ in rows]


async def pull_all_integrations() -> None:
    """Periodic job: pull every active integration with sync enabled."""
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        integrations = (
            db.query(AzureDevOpsIntegration)
            .filter(AzureDevOpsIntegration.is_active.is_(True), AzureDevOpsIntegration.sync_enabled.is_(True))
            .all()
        )
        for integration in integrations:
            await pull_integration(db, integration)
    finally:
        db.close()
