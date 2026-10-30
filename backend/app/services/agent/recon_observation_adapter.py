"""Turn bounded, in-scope recon signals into deduplicated hypothesis leads."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from app.services.agent.engagement_brain import EngagementBrain, Hypothesis
from app.services.takeover_scanner_service import _match_fingerprint


def _host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def _allowed(host: str, scope_hosts: Iterable[str]) -> bool:
    return any(
        host == item or (item.startswith("*.") and host.endswith(item[1:]) and host != item[2:])
        for raw in scope_hosts
        if (item := str(raw).lower().rstrip("."))
    )


def _id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def observation_event(
    kind: str, target: str, value: str, *, source: str,
    scope_hosts: Iterable[str], evidence_ref: str = "", observed_at: str = "",
) -> dict[str, Any]:
    """Small, redacted event contract shared by recon and takeover outputs."""
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path if kind in {"js_api_endpoint", "api_endpoint", "js_file"} else ""
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    address = f"[{host}]" if ":" in host else host
    safe_target = f"{parsed.scheme}://{address}{port}{path}" if host and parsed.scheme in {"http", "https"} else ""
    value = str(value or "")[:256]
    canonical_kind = "api_endpoint" if kind in {"js_api_endpoint", "api_endpoint"} else kind
    key = _id(canonical_kind, safe_target, "" if kind == "live_host" else value.lower())
    return {
        "id": key, "dedupe_key": key, "kind": kind,
        "target": safe_target, "host": host, "value": value,
        "source": str(source)[:80],
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
        "evidence_ref": str(evidence_ref or f"observation:{key}")[:96],
        "scope": {"allowed_hosts": sorted({str(h).lower().rstrip(".") for h in scope_hosts})[:100]},
    }


def ingest_event(brain: EngagementBrain, event: dict[str, Any]) -> bool:
    """Persist an in-scope observation and create one ready specialist card."""
    kind = str(event.get("kind") or "")
    host = _host(str(event.get("target") or ""))
    scope = (event.get("scope") or {}).get("allowed_hosts") or []
    if not host or not _allowed(host, scope):
        return False
    key = str(event.get("dedupe_key") or "")
    if not key or any(row.get("dedupe_key", row.get("id")) == key for row in brain.recon_observations):
        return False
    brain.recon_observations.append(dict(event))
    brain.recon_observations = brain.recon_observations[-200:]
    if kind == "dns_cname":
        provider = _match_fingerprint([str(event.get("value") or "")])
        if not provider:
            return True
        specialist, title = "takeover", f"Check {provider.provider} CNAME ownership on {host}"
        assumption = "A provider CNAME may point to an unclaimed resource"
        test = "Verify the DNS chain and provider response; check whether the resource is unclaimed"
        passed = "Independent provider-specific evidence confirms an unclaimed resource"
        killed = "Resource is claimed, DNS no longer points to provider, or fingerprint is absent"
        priority = "high"
    elif kind in {"js_api_endpoint", "api_endpoint"}:
        specialist, title = "api_authz", f"Review observed API path {urlsplit(event['target']).path}"
        assumption = "A discovered API path may expose an access boundary"
        test = "Observe a baseline response, then compare only authorized test identities"
        passed = "A class-specific independent check demonstrates an access control failure"
        killed = "The path is unavailable or the tested identities have consistent access"
        priority = "medium"
    elif kind == "js_file":
        specialist, title = "spa_client", f"Review observed script {urlsplit(event['target']).path}"
        assumption = "An observed script may reveal client-side routes or API calls"
        test = "Inspect the script and confirm any discovered route against the authorized host"
        passed = "A live first-party route or security-relevant client behavior is independently observed"
        killed = "Script is unavailable or contains no actionable first-party route"
        priority = "low"
    elif kind == "live_host":
        specialist, title = "web_recon", f"Map live host {host}"
        assumption = "A live in-scope host has an application surface to map"
        test = "Check first-party endpoints and technology without expanding scope"
        passed = "A live application surface is mapped"
        killed = "Host is unavailable or outside the approved scope"
        priority = "low"
    elif kind == "technology":
        specialist, title = "vuln_triage", f"Review observed technology {event.get('value')} on {host}"
        assumption = "A detected technology may warrant a version-specific check"
        test = "Confirm technology and version before any applicability claim"
        passed = "Technology is independently confirmed and a relevant check is identified"
        killed = "Technology fingerprint is false or no relevant check applies"
        priority = "low"
    else:
        return True
    hid = _id("observation", key, specialist)
    if not any(h.id == hid for h in brain.hypotheses):
        brain.hypotheses.append(Hypothesis(
            id=hid, title=title, assumption=assumption, test=test,
            pass_criteria=passed, kill_criteria=killed, specialist=specialist,
            status="open", priority=priority, target=event["target"],
            evidence=f"{event['evidence_ref']}: {kind} {event.get('value', '')}", source="recon",
            observation_id=key,
        ))
    return True


def _dns_rows(output: str) -> list[dict[str, Any]]:
    if len(output) > 200_000:
        output = output[:200_000]
    rows: list[dict[str, Any]] = []
    for line in output.splitlines()[:400]:
        try:
            parsed = json.loads(line)
        except (ValueError, TypeError):
            continue
        candidates = parsed if isinstance(parsed, list) else parsed.get("results", [parsed]) if isinstance(parsed, dict) else []
        for row in candidates:
            if isinstance(row, dict):
                rows.append(row)
            if len(rows) >= 200:
                return rows
    return rows


def ingest_dnsx_cnames(
    brain: EngagementBrain, output: str, *, scope_hosts: Iterable[str],
    evidence_ref: str = "",
) -> int:
    """Only recognized provider CNAMEs on explicitly scoped hosts become leads."""
    added = 0
    for row in _dns_rows(output):
        host = _host(str(row.get("host") or row.get("input") or ""))
        if not host or not _allowed(host, scope_hosts):
            continue
        raw = row.get("cname") or row.get("cname_chain") or []
        names = raw if isinstance(raw, list) else [raw]
        names = [_host(str(name)) for name in names[:8] if isinstance(name, str)]
        names = [name for name in names if name and len(name) <= 253]
        if not names:
            continue
        cname = next((name for name in names if _match_fingerprint([name])), "")
        if not cname:
            continue
        event = observation_event(
            "dns_cname", f"https://{host}", cname, source="execute_dnsx",
            scope_hosts=scope_hosts, evidence_ref=evidence_ref,
        )
        added += int(ingest_event(brain, event))
    return added


def ingest_js_api_paths(
    brain: EngagementBrain, cmap: dict[str, Any], *, scope_hosts: Iterable[str],
    evidence_ref: str = "",
) -> int:
    """Queue first-party API paths found in scripts for focused specialist review."""
    target = str(cmap.get("target") or brain.target or "")
    origin = urlsplit(target if "://" in target else f"https://{target}")
    host = (origin.hostname or "").lower().rstrip(".")
    if not host or not _allowed(host, scope_hosts):
        return 0
    added = 0
    for raw in (cmap.get("js_endpoints") or [])[:80]:
        if not isinstance(raw, str) or len(raw) > 512:
            continue
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme not in {"http", "https"} or _host(raw) != host:
                continue
        path = parsed.path
        if not path.startswith("/") or path.startswith("//") or len(path) > 256:
            continue
        if not any(token in path.lower() for token in ("/api", "/graphql", "/gql", "/v1/", "/v2/")):
            continue
        event = observation_event(
            "js_api_endpoint", f"{origin.scheme}://{host}{path}", path,
            source="capability_map", scope_hosts=scope_hosts,
            evidence_ref=evidence_ref,
        )
        added += int(ingest_event(brain, event))
        if added >= 20:
            break
    return added


def ingest_httpx_observations(
    brain: EngagementBrain, output: str, *, scope_hosts: Iterable[str],
    evidence_ref: str = "",
) -> int:
    """Record scoped live-host and technology signals from JSONL HTTPX output."""
    added = 0
    for row in _dns_rows(output):
        raw_target = str(row.get("url") or row.get("input") or "")
        host = _host(raw_target)
        if not host or not _allowed(host, scope_hosts):
            continue
        status = row.get("status_code") or row.get("status-code")
        if not isinstance(status, int) or status < 100 or status > 599:
            continue
        target = f"https://{host}"
        added += int(ingest_event(brain, observation_event(
            "live_host", target, str(status), source="execute_httpx",
            scope_hosts=scope_hosts, evidence_ref=evidence_ref,
        )))
        techs = row.get("tech") or row.get("technologies") or []
        if not isinstance(techs, list):
            continue
        for tech in techs[:8]:
            if isinstance(tech, str) and 0 < len(tech) <= 80:
                added += int(ingest_event(brain, observation_event(
                    "technology", target, tech, source="execute_httpx",
                    scope_hosts=scope_hosts, evidence_ref=evidence_ref,
                )))
        if added >= 40:
            break
    return added


def ingest_capability_observations(
    brain: EngagementBrain, cmap: dict[str, Any], *, scope_hosts: Iterable[str],
    evidence_ref: str = "",
) -> int:
    """Map JS-only paths, captured API paths, and scripts to focused lanes."""
    added = ingest_js_api_paths(
        brain, cmap, scope_hosts=scope_hosts, evidence_ref=evidence_ref,
    )
    target = str(cmap.get("target") or brain.target or "")
    origin = urlsplit(target if "://" in target else f"https://{target}")
    host = (origin.hostname or "").lower().rstrip(".")
    if not host or not _allowed(host, scope_hosts):
        return added
    for row in (cmap.get("api_endpoints") or [])[:80]:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path") or "").split("?", 1)[0]
        row_host = str(row.get("host") or "")
        if row_host and _host(row_host) != host:
            continue
        if path.startswith("/") and not path.startswith("//") and len(path) <= 256:
            event = observation_event(
                "api_endpoint", f"{origin.scheme}://{host}{path}", path,
                source="capability_map", scope_hosts=scope_hosts,
                evidence_ref=evidence_ref,
            )
            added += int(ingest_event(brain, event))
    for raw in (cmap.get("js_files") or [])[:40]:
        if not isinstance(raw, str) or len(raw) > 512:
            continue
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme not in {"http", "https"} or _host(raw) != host:
                continue
        path = parsed.path
        if not path.startswith("/") or path.startswith("//") or not path.lower().endswith((".js", ".mjs")):
            continue
        event = observation_event(
            "js_file", f"{origin.scheme}://{host}{path}", path,
            source="capability_map", scope_hosts=scope_hosts,
            evidence_ref=evidence_ref,
        )
        added += int(ingest_event(brain, event))
    return added


def ingest_takeover_findings(
    brain: EngagementBrain, findings: Iterable[Any], *, scope_hosts: Iterable[str],
    evidence_ref: str = "",
) -> int:
    """Adapt existing takeover scanner results into the same lead contract."""
    return sum(ingest_event(brain, event) for event in takeover_finding_events(
        findings, scope_hosts=scope_hosts, evidence_ref=evidence_ref,
    ))


def takeover_finding_events(
    findings: Iterable[Any], *, scope_hosts: Iterable[str], evidence_ref: str = "",
) -> list[dict[str, Any]]:
    """Serialize scanner observations without upgrading a lead to a finding."""
    events = []
    for finding in list(findings)[:100]:
        host = _host(str(getattr(finding, "hostname", "") or ""))
        chain = getattr(finding, "cname_chain", None) or []
        cname = next((str(name) for name in chain if _match_fingerprint([str(name)])), "")
        if not host or not cname:
            continue
        event = observation_event(
            "dns_cname", f"https://{host}", _host(cname),
            source="takeover_scanner", scope_hosts=scope_hosts,
            evidence_ref=evidence_ref,
        )
        if _allowed(host, scope_hosts) and event["dedupe_key"] not in {
            item["dedupe_key"] for item in events
        }:
            events.append(event)
    return events
