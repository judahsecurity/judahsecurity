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


def _record(brain: EngagementBrain, kind: str, host: str, value: str, source: str) -> bool:
    key = _id(kind, host, value)
    if any(row.get("id") == key for row in brain.recon_observations):
        return False
    brain.recon_observations.append({
        "id": key, "kind": kind, "host": host, "value": value,
        "source": source, "observed_at": datetime.now(timezone.utc).isoformat(),
    })
    brain.recon_observations = brain.recon_observations[-200:]
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
) -> int:
    """Only recognized provider CNAMEs on explicitly scoped hosts become leads."""
    known = {h.id for h in brain.hypotheses}
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
        provider = _match_fingerprint(names)
        if not provider:
            continue
        cname = names[-1]
        _record(brain, "dns_cname", host, cname, "execute_dnsx")
        hid = _id("takeover", host, provider.provider.lower())
        if hid in known:
            continue
        brain.hypotheses.append(Hypothesis(
            id=hid, title=f"Check {provider.provider} CNAME ownership on {host}",
            assumption="A provider CNAME may point to an unclaimed resource",
            test="Verify the DNS chain and provider response; check whether the resource is unclaimed",
            pass_criteria="Independent provider-specific evidence confirms an unclaimed resource",
            kill_criteria="Resource is claimed, DNS no longer points to provider, or fingerprint is absent",
            specialist="takeover", status="open", priority="high",
            target=f"https://{host}", evidence=f"CNAME {host} -> {cname}", source="recon",
        ))
        known.add(hid)
        added += 1
    return added


def ingest_js_api_paths(
    brain: EngagementBrain, cmap: dict[str, Any], *, scope_hosts: Iterable[str],
) -> int:
    """Queue first-party API paths found in scripts for focused specialist review."""
    target = str(cmap.get("target") or brain.target or "")
    origin = urlsplit(target if "://" in target else f"https://{target}")
    host = (origin.hostname or "").lower().rstrip(".")
    if not host or not _allowed(host, scope_hosts):
        return 0
    known = {h.id for h in brain.hypotheses}
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
        _record(brain, "js_api_endpoint", host, path, "capability_map")
        hid = _id("js_api", host, path)
        if hid in known:
            continue
        brain.hypotheses.append(Hypothesis(
            id=hid, title=f"Review observed API path {path}",
            assumption="A script-discovered API path may expose an access boundary",
            test="Observe a baseline response, then compare only authorized test identities",
            pass_criteria="A class-specific independent check demonstrates an access control failure",
            kill_criteria="The path is unavailable or the tested identities have consistent access",
            specialist="api_authz", status="open", priority="medium",
            target=f"{origin.scheme}://{origin.netloc}{path}",
            evidence=f"First-party script referenced {path}", source="recon",
        ))
        known.add(hid)
        added += 1
        if added >= 20:
            break
    return added
