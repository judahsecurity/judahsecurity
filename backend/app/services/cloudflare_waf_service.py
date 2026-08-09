"""Cloudflare WAF integration service.

Creates and maintains a single custom WAF skip rule per Cloudflare zone so
Judah Security scanner traffic is not blocked by WAF / bot / rate-limit
protections. Modeled after Praetorian Guard's Cloudflare WAF integration:

    https://docs.praetorian.com/articles/1488526-cloudflare-waf

Scanner traffic is identified by a combination of:
  1. Source IP (platform ASM_SCANNER_EGRESS_IPS and/or per-connection override)
  2. A per-connection custom HTTP header secret
  3. A dedicated user-agent (ASM_SCANNER_USER_AGENT)

API reference:
    Base URL : https://api.cloudflare.com/client/v4
    Auth     : Authorization: Bearer <api_token>
    Zones    : GET /zones
    Entrypoint: GET /zones/{id}/rulesets/phases/http_request_firewall_custom/entrypoint
    Rules    : POST/PUT /zones/{id}/rulesets/{ruleset_id}/rules[/{rule_id}]

Required token permissions (Praetorian docs):
    Account Rulesets — Read
    Zone WAF — Edit
    Zone Settings — Read
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cloudflare_integration import CloudflareWafIntegration

logger = logging.getLogger(__name__)

MANAGED_MARKER = "(Managed By Judah)"
RULE_DESCRIPTION = f"Whitelist Judah Security scanner traffic {MANAGED_MARKER}"
CUSTOM_PHASE = "http_request_firewall_custom"
DEFAULT_HEADER_NAME = "X-Judah-Scan-Token"
DEFAULT_USER_AGENT = "JudahSecurity-ASM-Scanner/1.0"
SYNC_TIMEOUT_SECONDS = 60.0

# Skip the same family of protections Praetorian documents for matching traffic.
SKIP_PHASES = [
    "http_ratelimit",
    "http_request_firewall_managed",
    "http_request_sbfm",
]
SKIP_PRODUCTS = [
    "zoneLockdown",
    "uaBlock",
    "bic",
    "hot",
    "securityLevel",
    "rateLimit",
    "waf",
]


def _platform_scanner_ips() -> List[str]:
    raw = getattr(settings, "ASM_SCANNER_EGRESS_IPS", "") or ""
    return [p.strip() for p in str(raw).split(",") if p.strip()]


def scanner_user_agent() -> str:
    ua = (getattr(settings, "ASM_SCANNER_USER_AGENT", None) or DEFAULT_USER_AGENT).strip()
    return ua or DEFAULT_USER_AGENT


def effective_scanner_ips(integration: CloudflareWafIntegration) -> List[str]:
    override = integration.scanner_ips or []
    if isinstance(override, list) and any(str(x).strip() for x in override):
        return [str(x).strip() for x in override if str(x).strip()]
    return _platform_scanner_ips()


def generate_scan_header_secret() -> str:
    return secrets.token_urlsafe(32)


def build_scan_identity(integration: CloudflareWafIntegration) -> Dict[str, Any]:
    """Return the scanner identity tuple used in WAF expressions and scan clients."""
    return {
        "header_name": integration.scan_header_name or DEFAULT_HEADER_NAME,
        "header_value": integration.get_scan_header_secret() or "",
        "user_agent": scanner_user_agent(),
        "ips": effective_scanner_ips(integration),
    }


def _cf_escape(value: str) -> str:
    """Escape a string for use inside a double-quoted Cloudflare expression literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_whitelist_expression(
    *,
    ips: List[str],
    header_name: str,
    header_value: str,
    user_agent: str,
) -> str:
    """Build a multi-layered match expression for scanner traffic.

    All configured layers are ANDed. At least the header secret is always
    required; IP and UA layers are included when available.
    """
    parts: List[str] = []

    if ips:
        ip_list = " ".join(ips)
        parts.append(f"(ip.src in {{{ip_list}}})")

    hdr = header_name.strip().lower()
    parts.append(
        f'(any(http.request.headers["{_cf_escape(hdr)}"][*] '
        f'eq "{_cf_escape(header_value)}"))'
    )

    if user_agent:
        parts.append(f'(http.user_agent eq "{_cf_escape(user_agent)}")')

    return " and ".join(parts)


def build_skip_rule_payload(expression: str) -> Dict[str, Any]:
    return {
        "action": "skip",
        "action_parameters": {
            "phases": SKIP_PHASES,
            "products": SKIP_PRODUCTS,
        },
        "expression": expression,
        "description": RULE_DESCRIPTION,
        "enabled": True,
    }


class CloudflareClient:
    """Thin async client for the Cloudflare Rulesets / Zones API."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token: str, *, timeout: float = SYNC_TIMEOUT_SECONDS):
        if not (api_token or "").strip():
            raise ValueError("missing Cloudflare API token")
        self.api_token = api_token.strip()
        self.timeout = timeout
        self._headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
    ) -> Tuple[Optional[Any], Optional[str], Optional[int]]:
        url = f"{self.BASE_URL}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers) as client:
                resp = await client.request(method, url, params=params, json=json_body)
                if resp.status_code in (401, 403):
                    return None, (
                        f"Unauthorized (HTTP {resp.status_code}). "
                        "Check the API token and required permissions "
                        "(Account Rulesets:Read, Zone WAF:Edit, Zone Settings:Read)."
                    ), resp.status_code
                if resp.status_code == 404:
                    return None, "not_found", 404
                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    return None, f"Invalid JSON response from {path}", resp.status_code

                if not payload.get("success", False):
                    errors = payload.get("errors") or []
                    msg = "; ".join(
                        e.get("message", str(e)) for e in errors if isinstance(e, dict)
                    ) or f"Cloudflare API error on {path} (HTTP {resp.status_code})"
                    return None, msg, resp.status_code

                return payload.get("result"), None, resp.status_code
        except httpx.TimeoutException:
            return None, f"Request to {path} timed out after {self.timeout}s", None
        except Exception as exc:  # noqa: BLE001
            logger.error("Cloudflare %s %s error: %s", method, path, exc)
            return None, str(exc), None

    async def verify_token(self) -> Tuple[bool, str]:
        result, err, _ = await self._request("GET", "/user/tokens/verify")
        if err and err != "not_found":
            # Some account-owned tokens cannot hit /user/tokens/verify; fall through.
            zones, zerr = await self.list_zones()
            if zerr:
                return False, err
            return True, f"Token accepted ({len(zones)} zone(s) visible)."
        if err:
            return False, err
        status = (result or {}).get("status") if isinstance(result, dict) else None
        if status and status != "active":
            return False, f"Token status is '{status}', expected 'active'."
        return True, "Token is active."

    async def list_zones(self) -> Tuple[List[Dict], Optional[str]]:
        zones: List[Dict] = []
        page = 1
        while page <= 50:
            result, err, _ = await self._request(
                "GET",
                "/zones",
                params={"page": page, "per_page": 50},
            )
            if err:
                return [], err if err != "not_found" else "No zones found or token lacks Zone read."
            batch = result if isinstance(result, list) else []
            zones.extend(batch)
            if len(batch) < 50:
                break
            page += 1
        return zones, None

    async def get_custom_ruleset_entrypoint(
        self, zone_id: str
    ) -> Tuple[Optional[Dict], Optional[str]]:
        result, err, status = await self._request(
            "GET",
            f"/zones/{zone_id}/rulesets/phases/{CUSTOM_PHASE}/entrypoint",
        )
        if status == 404 or err == "not_found":
            return None, None
        if err:
            return None, err
        return result if isinstance(result, dict) else None, None

    async def create_custom_ruleset(
        self, zone_id: str, rule: Dict[str, Any]
    ) -> Tuple[Optional[Dict], Optional[str]]:
        body = {
            "name": "Zone custom ruleset (Judah Security)",
            "description": "Managed entry point for Judah Security scanner whitelist rules",
            "kind": "zone",
            "phase": CUSTOM_PHASE,
            "rules": [rule],
        }
        result, err, _ = await self._request(
            "POST",
            f"/zones/{zone_id}/rulesets",
            json_body=body,
        )
        if err:
            return None, err
        return result if isinstance(result, dict) else None, None

    async def create_rule(
        self, zone_id: str, ruleset_id: str, rule: Dict[str, Any]
    ) -> Tuple[Optional[Dict], Optional[str]]:
        # Place at the top so skip applies before later block rules.
        body = {**rule, "position": {"index": 1}}
        result, err, _ = await self._request(
            "POST",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
            json_body=body,
        )
        if err:
            return None, err
        return result if isinstance(result, dict) else None, None

    async def update_rule(
        self,
        zone_id: str,
        ruleset_id: str,
        rule_id: str,
        rule: Dict[str, Any],
    ) -> Tuple[Optional[Dict], Optional[str]]:
        result, err, _ = await self._request(
            "PUT",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            json_body=rule,
        )
        if err:
            return None, err
        return result if isinstance(result, dict) else None, None


def _find_managed_rule(ruleset: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for rule in ruleset.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        desc = rule.get("description") or ""
        if MANAGED_MARKER in desc or RULE_DESCRIPTION in desc:
            return rule
    return None


def _rule_is_current(existing: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    if (existing.get("expression") or "") != desired["expression"]:
        return False
    if (existing.get("action") or "") != desired["action"]:
        return False
    if not existing.get("enabled", True):
        return False
    # Compare skip parameters loosely — Cloudflare may normalize order.
    existing_params = existing.get("action_parameters") or {}
    desired_params = desired.get("action_parameters") or {}
    if set(existing_params.get("phases") or []) != set(desired_params.get("phases") or []):
        return False
    if set(existing_params.get("products") or []) != set(desired_params.get("products") or []):
        return False
    return True


async def test_connection(api_token: str) -> Dict[str, Any]:
    """Validate a Cloudflare API token by listing zones."""
    try:
        client = CloudflareClient(api_token)
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "zones_found": None}

    ok, msg = await client.verify_token()
    if not ok:
        return {"ok": False, "message": msg, "zones_found": None}

    zones, err = await client.list_zones()
    if err:
        return {"ok": False, "message": err, "zones_found": None}
    return {
        "ok": True,
        "message": f"Connected — {len(zones)} zone(s) visible.",
        "zones_found": len(zones),
    }


async def ensure_zone_whitelist_rule(
    client: CloudflareClient,
    zone: Dict[str, Any],
    rule_payload: Dict[str, Any],
) -> str:
    """Create or update the managed skip rule for one zone.

    Returns one of: created | updated | skipped | failed:<msg>
    """
    zone_id = zone.get("id")
    zone_name = zone.get("name") or zone_id
    if not zone_id:
        return "failed:missing zone id"

    ruleset, err = await client.get_custom_ruleset_entrypoint(zone_id)
    if err:
        return f"failed:{err}"

    if ruleset is None:
        created, cerr = await client.create_custom_ruleset(zone_id, rule_payload)
        if cerr:
            logger.warning("Cloudflare create ruleset failed for %s: %s", zone_name, cerr)
            return f"failed:{cerr}"
        return "created" if created else "failed:empty create response"

    ruleset_id = ruleset.get("id")
    if not ruleset_id:
        return "failed:ruleset missing id"

    existing = _find_managed_rule(ruleset)
    if existing and _rule_is_current(existing, rule_payload):
        return "skipped"

    if existing and existing.get("id"):
        updated, uerr = await client.update_rule(
            zone_id, ruleset_id, existing["id"], rule_payload
        )
        if uerr:
            logger.warning("Cloudflare update rule failed for %s: %s", zone_name, uerr)
            return f"failed:{uerr}"
        return "updated" if updated is not None else "failed:empty update response"

    created_rule, crerr = await client.create_rule(zone_id, ruleset_id, rule_payload)
    if crerr:
        logger.warning("Cloudflare create rule failed for %s: %s", zone_name, crerr)
        return f"failed:{crerr}"
    return "created" if created_rule is not None else "failed:empty create response"


async def sync_integration(db: Session, integration: CloudflareWafIntegration) -> Dict[str, Any]:
    """Ensure the managed whitelist rule exists (and is current) on each selected zone."""
    stats = {
        "ok": False,
        "message": "",
        "zones_seen": 0,
        "rules_created": 0,
        "rules_updated": 0,
        "rules_skipped": 0,
        "rules_failed": 0,
    }

    token = integration.get_api_token()
    if not token:
        stats["message"] = "No API token stored for this connection."
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = stats["message"]
        integration.last_sync_stats = stats
        db.commit()
        return stats

    identity = build_scan_identity(integration)
    if not identity["header_value"]:
        stats["message"] = "Missing scan header secret — reconnect the integration."
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = stats["message"]
        integration.last_sync_stats = stats
        db.commit()
        return stats

    if not identity["ips"]:
        stats["message"] = (
            "No scanner egress IPs configured. Set ASM_SCANNER_EGRESS_IPS on the "
            "platform or provide scanner_ips on this connection before syncing."
        )
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = stats["message"]
        integration.last_sync_stats = stats
        db.commit()
        return stats

    expression = build_whitelist_expression(
        ips=identity["ips"],
        header_name=identity["header_name"],
        header_value=identity["header_value"],
        user_agent=identity["user_agent"],
    )
    rule_payload = build_skip_rule_payload(expression)

    client = CloudflareClient(token)
    zones, err = await client.list_zones()
    if err:
        stats["message"] = err
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = err
        integration.last_sync_stats = stats
        db.commit()
        return stats

    filter_names = {
        (z or "").strip().lower().rstrip(".")
        for z in (integration.zones or [])
        if (z or "").strip()
    }
    if filter_names:
        zones = [
            z for z in zones
            if (z.get("name") or "").strip().lower().rstrip(".") in filter_names
        ]

    stats["zones_seen"] = len(zones)
    failures: List[str] = []

    for zone in zones:
        outcome = await ensure_zone_whitelist_rule(client, zone, rule_payload)
        if outcome == "created":
            stats["rules_created"] += 1
        elif outcome == "updated":
            stats["rules_updated"] += 1
        elif outcome == "skipped":
            stats["rules_skipped"] += 1
        else:
            stats["rules_failed"] += 1
            zone_name = zone.get("name") or zone.get("id") or "?"
            failures.append(f"{zone_name}: {outcome.removeprefix('failed:')}")

    if filter_names and stats["zones_seen"] == 0:
        stats["message"] = (
            "No matching zones found for the configured zone filter. "
            "Check zone names and token access."
        )
        ok = False
    elif stats["rules_failed"] and (
        stats["rules_created"] + stats["rules_updated"] + stats["rules_skipped"] == 0
    ):
        stats["message"] = f"All zone updates failed. {failures[0] if failures else ''}".strip()
        ok = False
    elif stats["rules_failed"]:
        stats["message"] = (
            f"Synced with errors — created {stats['rules_created']}, "
            f"updated {stats['rules_updated']}, skipped {stats['rules_skipped']}, "
            f"failed {stats['rules_failed']}."
        )
        ok = True  # partial success still useful
    else:
        stats["message"] = (
            f"Whitelist synchronized across {stats['zones_seen']} zone(s) — "
            f"{stats['rules_created']} created, {stats['rules_updated']} updated, "
            f"{stats['rules_skipped']} unchanged."
        )
        ok = True

    stats["ok"] = ok
    integration.last_sync_at = datetime.utcnow()
    integration.last_sync_ok = ok
    integration.last_error = None if ok and not failures else (
        "; ".join(failures[:5]) if failures else stats["message"]
    )
    integration.last_sync_stats = {
        "zones_seen": stats["zones_seen"],
        "rules_created": stats["rules_created"],
        "rules_updated": stats["rules_updated"],
        "rules_skipped": stats["rules_skipped"],
        "rules_failed": stats["rules_failed"],
    }
    db.commit()
    return stats


def enrichment_for_response(integration: CloudflareWafIntegration) -> Dict[str, Any]:
    """Extra response fields that aren't plain ORM columns."""
    return {
        "scanner_user_agent": scanner_user_agent(),
        "effective_scanner_ips": effective_scanner_ips(integration),
    }


def get_org_scan_bypass_headers(
    db: Session, organization_id: int
) -> Dict[str, str]:
    """Return HTTP headers scanners should send for Cloudflare WAF bypass.

    Picks the newest active Cloudflare WAF connection for the org. Returns an
    empty dict when none is configured. Intended for scan workers / httpx /
    nuclei header injection.
    """
    integration = (
        db.query(CloudflareWafIntegration)
        .filter(
            CloudflareWafIntegration.organization_id == organization_id,
            CloudflareWafIntegration.is_active == True,  # noqa: E712
        )
        .order_by(CloudflareWafIntegration.created_at.desc())
        .first()
    )
    if not integration:
        return {}
    identity = build_scan_identity(integration)
    headers: Dict[str, str] = {}
    if identity["header_name"] and identity["header_value"]:
        headers[identity["header_name"]] = identity["header_value"]
    if identity["user_agent"]:
        headers["User-Agent"] = identity["user_agent"]
    return headers
