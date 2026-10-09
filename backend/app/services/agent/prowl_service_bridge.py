"""Aegis-owned session bridge to the scoped assessment execution service.

The model selects an allowlisted operation. It never receives the service's
admin, hunter, verifier, or finding-ingestion credentials.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

import httpx

from app.core.config import settings
from app.models.asset import Asset, AssetType
from app.models.scoped_assessment_run import ScopedAssessmentRun

_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_OPERATIONS = {
    "browser_map": ("POST", "browser/map"),
    "browser_crawl": ("POST", "browser/crawl"),
    "browser_inspect_js": ("POST", "browser/inspect-js"),
    "http_get": ("POST", "http/get"),
    "http_compare": ("POST", "http/compare"),
    "browser_check_xss": ("POST", "browser/check-xss"),
    "http_query_probe": ("POST", "http/query-probe"),
    "http_body_probe": ("POST", "http/body-probe"),
    "http_sqli_boolean": ("POST", "http/sqli-boolean"),
    "http_authz_owner_only": ("POST", "http/authz-owner-only"),
    "submit_candidate": ("POST", "candidates"),
    "memory_recall": ("POST", "memory/recall"),
    "threat_model_get": ("GET", "threat-model"),
    "threat_model_set": ("POST", "threat-model"),
    "coverage_create": ("POST", "coverage"),
    "coverage_update": ("POST", "coverage"),
    "complete_assessment": ("POST", "complete-assessment"),
    "coverage": ("GET", "coverage"),
    "assessment_summary": ("GET", "assessment-summary"),
}
OBSERVE_OPERATIONS = frozenset({
    "browser_map", "browser_crawl", "browser_inspect_js", "http_get", "http_compare",
})
PROBE_OPERATIONS = frozenset({
    "browser_check_xss", "http_query_probe", "http_body_probe",
    "http_sqli_boolean", "http_authz_owner_only",
})


def capability_map_from_observation(observation: dict) -> dict | None:
    """Translate a service browser observation into the existing Aegis map."""
    if observation.get("signal") not in {
        "browser_map", "browser_crawl", "browser_inspect_js",
    }:
        return None
    result = observation.get("result")
    if not isinstance(result, dict):
        return None
    scope = result.get("final_origin")
    if not isinstance(scope, str) or not scope:
        return None
    origin_parts = urlsplit(scope)
    if origin_parts.scheme not in ("http", "https") or not origin_parts.hostname:
        return None

    def in_origin_path(value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 512:
            return ""
        if value.startswith(("http://", "https://")):
            parts = urlsplit(value)
            if (parts.scheme, parts.netloc) != (origin_parts.scheme, origin_parts.netloc):
                return ""
            value = parts.path or "/"
        if not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value:
            return ""
        return value
    from app.services.agent.capability_map import CapabilityMap, finalize_capability_map

    pages = []
    if isinstance(result.get("pages"), list):
        pages = [row["url"] for row in result["pages"][:80]
                 if isinstance(row, dict) and isinstance(row.get("url"), str)
                 and isinstance(row.get("status"), int) and 200 <= row["status"] < 400]
    elif isinstance(result.get("status"), int) and 200 <= result["status"] < 400:
        pages = [scope + str(result.get("final_path") or "/")]

    raw_forms = list(result.get("forms") or [])
    for page in (result.get("pages") or [])[:80]:
        if isinstance(page, dict):
            raw_forms.extend(page.get("forms") or [])
    forms = [
        {"method": row.get("method"), "action": row.get("action"),
         "inputs": [field["name"] for field in (row.get("fields") or [])[:40]
                    if isinstance(field, dict) and isinstance(field.get("name"), str)],
         "fields": [
             {"name": field["name"], "control_type": field.get("control_type", "")}
             for field in (row.get("fields") or [])[:40]
             if isinstance(field, dict) and isinstance(field.get("name"), str)
         ]}
        for row in raw_forms[:60] if isinstance(row, dict)
    ]
    api_endpoints = []
    for row in [*(result.get("requests") or [])[:200], *(result.get("traffic") or [])[:40]]:
        if not isinstance(row, dict) or row.get("resource_type") not in ("xhr", "fetch"):
            continue
        path = in_origin_path(row.get("path"))
        if path:
            api_endpoints.append({
                "host": origin_parts.netloc, "method": row.get("method", "GET"),
                "path": path, "query_keys": row.get("query_keys") or
                [field.get("name") for field in (row.get("query_fields") or []) if isinstance(field, dict)],
                "identity": result.get("identity", "anonymous"),
                "source": "browser_traffic" if row.get("artifact_id") else "browser_request",
                "artifact_id": row.get("artifact_id", ""),
                "status": row.get("status"), "content_type": row.get("content_type", ""),
            })
    inventory = result.get("surface_inventory") or {}
    if not isinstance(inventory, dict):
        inventory = {}
    js_endpoints = []
    for row in (inventory.get("endpoints") or [])[:100]:
        if not isinstance(row, dict) or "javascript_static" not in (row.get("sources") or []):
            continue
        path = in_origin_path(row.get("path"))
        if path:
            js_endpoints.append(scope + path)
            for method in (row.get("methods") or ["GET"])[:8]:
                if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    api_endpoints.append({"host": origin_parts.netloc, "method": method,
                                          "path": path, "source": "javascript_static"})
    js_files = []
    for row in [*(result.get("requests") or [])[:200], *(result.get("scripts") or [])[:20]]:
        if not isinstance(row, dict):
            continue
        if row.get("resource_type") != "script" and row.get("kind") != "external":
            continue
        path = in_origin_path(row.get("path"))
        if path:
            js_files.append(scope + path)
    js_files = list(dict.fromkeys(js_files))[:160]
    js_sources = [
        {"url": scope + path, "artifact_id": row.get("artifact_id", ""),
         "sha256": row.get("sha256", ""), "bytes": row.get("bytes", 0),
         "sink_leads": row["analysis"].get("sink_leads", []) if isinstance(row.get("analysis"), dict) else [],
         "source_leads": row["analysis"].get("source_leads", []) if isinstance(row.get("analysis"), dict) else []}
        for row in (result.get("scripts") or [])[:20]
        if isinstance(row, dict) and row.get("kind") == "external"
        and (path := in_origin_path(row.get("path")))
    ]
    parameters = []
    link_inputs = list(result.get("link_query_inputs") or [])
    for page in (result.get("pages") or [])[:80]:
        if isinstance(page, dict):
            link_inputs.extend(page.get("link_query_inputs") or [])
    for row in link_inputs[:300]:
        if not isinstance(row, dict):
            continue
        path = in_origin_path(row.get("path"))
        if not path:
            continue
        for name in (row.get("query_keys") or [])[:20]:
            if isinstance(name, str):
                parameters.append({"method": "GET", "path": path, "name": name,
                                   "location": "query", "source": "browser_link"})
    for row in (result.get("requests") or [])[:100]:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        for name in (row.get("query_keys") or [])[:20]:
            parameters.append({
                "method": row.get("method", "GET"), "path": row["path"],
                "name": name, "location": "query", "source": "browser_request",
                "identity": result.get("identity", "anonymous"),
            })
    for row in (result.get("traffic") or [])[:40]:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        common = {"method": row.get("method", "GET"), "path": row["path"],
                  "source": "browser_traffic", "identity": result.get("identity", "anonymous"),
                  "artifact_id": row.get("artifact_id", "")}
        request_type = str(row.get("request_content_type") or "").lower()
        if str(common["method"]).upper() in {"POST", "PUT", "PATCH"} and any(
            mime in request_type for mime in ("application/xml", "text/xml", "+xml")
        ):
            parameters.append(common | {"name": "document", "location": "body_xml"})
        for field in (row.get("query_fields") or [])[:20]:
            if isinstance(field, dict):
                parameters.append(common | {"name": field.get("name"),
                                            "value_type": field.get("value_type", ""),
                                            "location": "query"})
        for field in (row.get("body_fields") or [])[:40]:
            if isinstance(field, dict):
                parameters.append(common | {"name": field.get("path"),
                                            "value_type": field.get("value_type", ""),
                                            "location": "body_json" if field.get("location") == "json" else "body_form"})
    for script in (result.get("scripts") or [])[:20]:
        if not isinstance(script, dict) or not isinstance(script.get("analysis"), dict):
            continue
        for lead in (script["analysis"].get("query_leads") or [])[:40]:
            if not isinstance(lead, dict):
                continue
            path = in_origin_path(lead.get("path"))
            method = lead.get("method")
            if not path or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            for name in (lead.get("names") or [])[:20]:
                parameters.append({"method": method, "path": path, "name": name,
                                   "location": "query", "source": "javascript_static"})
    cmap = CapabilityMap(
        target=str(result.get("target_template") or scope), scope=scope,
        pages_visited=pages, forms=forms, api_endpoints=api_endpoints,
        js_endpoints=list(dict.fromkeys(js_endpoints)), js_files=js_files,
        js_sources=js_sources,
        parameter_inventory=parameters[:4000],
        notes=["Source: scoped browser observation"],
    )
    return finalize_capability_map(cmap).to_dict()


def _service_url() -> str:
    value = settings.PROWL_ASSESSMENT_URL.rstrip("/")
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or
            parts.username or parts.password or parts.path or parts.query or parts.fragment):
        raise ValueError("PROWL_ASSESSMENT_URL must be an HTTP(S) service origin")
    return value


def exact_asset_origin(asset: Asset, requested_origin: str) -> str:
    """Do not let an agent or caller expand a service run beyond one stored asset."""
    if not asset.in_scope or asset.asset_type not in {
        AssetType.URL, AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS,
    }:
        raise ValueError("Asset is not an in-scope web target")
    parts = urlsplit(requested_origin)
    if (parts.scheme not in ("http", "https") or not parts.hostname or
            parts.username or parts.password or parts.path or parts.query or parts.fragment or
            requested_origin != f"{parts.scheme}://{parts.netloc}"):
        raise ValueError("Origin must be an exact HTTP(S) origin without credentials or path")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Origin has an invalid port") from exc
    if ":" in parts.hostname:
        raise ValueError("IPv6 origins are not supported by the scoped executor")
    default_port = 443 if parts.scheme == "https" else 80
    canonical = f"{parts.scheme}://{parts.hostname.lower()}"
    if port and port != default_port:
        canonical += f":{port}"
    value = asset.value.strip()
    if asset.asset_type == AssetType.URL:
        stored = urlsplit(value)
        # The executor scopes by origin. A path-scoped URL asset does not
        # authorize the rest of that origin.
        if stored.path not in ("", "/") or stored.query or stored.fragment:
            raise ValueError("A URL asset with a path cannot authorize an origin-wide run")
        if (stored.scheme, stored.hostname, stored.port or default_port) != (
            parts.scheme, parts.hostname, port or default_port,
        ):
            raise ValueError("Origin does not match the in-scope URL asset")
    elif parts.hostname.lower().rstrip(".") != value.lower().rstrip("."):
        raise ValueError("Origin host does not match the in-scope asset")
    return canonical


async def _request(method: str, path: str, token: str, body: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(
        base_url=_service_url(), timeout=90.0, follow_redirects=False, trust_env=False,
    ) as client:
        response = await client.request(method, path, headers=headers, json=body if method == "POST" else None)
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("Assessment service returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Assessment service returned a non-object response")
    if response.is_error:
        raise ValueError(f"Assessment service rejected the operation ({response.status_code}): "
                         f"{str(payload.get('error') or 'unknown error')[:300]}")
    return payload


async def provision_run(
    db, *, organization_id: int, user_id: int, session_id: str, asset: Asset,
    origin: str, identities: dict | None = None,
    body_replay_paths: list[str] | None = None,
    authz_expectations: list[dict] | None = None,
) -> ScopedAssessmentRun:
    if not settings.PROWL_ADMIN_TOKEN:
        raise ValueError("Scoped assessment service is not configured")
    allowed_origin = exact_asset_origin(asset, origin)
    existing = db.query(ScopedAssessmentRun).filter_by(
        organization_id=organization_id, session_id=session_id,
    ).first()
    if existing:
        raise ValueError("This agent session already has a scoped assessment run")
    response = await _request("POST", "/v1/runs", settings.PROWL_ADMIN_TOKEN, {
        "organization_id": organization_id,
        "asset_id": asset.id,
        "allowed_origins": [allowed_origin],
        "identities": identities or {},
        "body_replay_paths": body_replay_paths or [],
        "authz_expectations": authz_expectations or [],
    })
    run_id = response.get("run_id")
    if (not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id) or
            response.get("organization_id") != organization_id or
            response.get("asset_id") != asset.id or
            response.get("allowed_origins") != [allowed_origin] or
            not isinstance(response.get("hunter_token"), str) or
            not isinstance(response.get("verifier_token"), str)):
        raise ValueError("Assessment service returned an invalid run binding")
    binding = ScopedAssessmentRun(
        organization_id=organization_id, user_id=user_id, session_id=session_id,
        asset_id=asset.id, service_run_id=run_id, allowed_origin=allowed_origin,
    )
    binding.set_tokens(response["hunter_token"], response["verifier_token"])
    db.add(binding)
    db.commit()
    db.refresh(binding)
    return binding


async def hunter_operation(db, *, organization_id: int, user_id: int, session_id: str,
                           operation: str, body: dict | None = None) -> dict:
    if operation not in _OPERATIONS:
        raise ValueError("Unknown scoped assessment operation")
    binding = db.query(ScopedAssessmentRun).filter_by(
        organization_id=organization_id, user_id=user_id, session_id=session_id,
    ).first()
    if binding is None:
        raise ValueError("No scoped assessment is bound to this agent session")
    if body is not None and (not isinstance(body, dict) or len(json.dumps(body)) > 60_000):
        raise ValueError("Assessment arguments must be a bounded JSON object")
    method, suffix = _OPERATIONS[operation]
    if operation == "coverage_update":
        coverage_id = (body or {}).get("coverage_id")
        if not isinstance(coverage_id, str) or not _RUN_ID.fullmatch(coverage_id):
            raise ValueError("Invalid coverage ID")
        suffix += f"/{coverage_id}"
        body = {key: value for key, value in body.items() if key != "coverage_id"}
    return await _request(method, f"/v1/runs/{binding.service_run_id}/{suffix}",
                          binding.hunter_token(), body or {})


async def verify_candidate_with_fresh_proof(
    db, *, organization_id: int, user_id: int, session_id: str,
    candidate_id: str, recipe: str, identity: str = "anonymous",
    page_url: str = "", parameter: str = "",
) -> dict:
    """Server-side replay with a distinct service capability and fresh evidence.

    The verifier uses a distinct capability and a new service action. The
    service itself decides whether the new proof matches the hunter's proof.
    """
    if not _RUN_ID.fullmatch(candidate_id):
        raise ValueError("Invalid candidate ID")
    if recipe not in ("browser_xss", "public_directory_index", "numeric_sqli", "owner_only_authz"):
        raise ValueError("Unknown automated verification recipe")
    if not isinstance(identity, str) or not identity or len(identity) > 80:
        raise ValueError("Invalid verifier identity")
    if recipe in ("numeric_sqli", "owner_only_authz"):
        if not isinstance(page_url, str) or not page_url or len(page_url) > 2048:
            raise ValueError("Verifier browser page URL is required for this recipe")
        if recipe == "numeric_sqli" and (not isinstance(parameter, str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", parameter)):
            raise ValueError("Numeric SQLi verification requires the observed query parameter")
    binding = db.query(ScopedAssessmentRun).filter_by(
        organization_id=organization_id, user_id=user_id, session_id=session_id,
    ).first()
    if binding is None:
        raise ValueError("No scoped assessment is bound to this agent session")
    base = f"/v1/runs/{binding.service_run_id}"
    verifier_token = binding.verifier_token()
    candidate = await _request("GET", f"{base}/candidates/{candidate_id}", verifier_token)
    target = candidate.get("target")
    if (candidate.get("run_id") != binding.service_run_id or
            candidate.get("candidate_id") != candidate_id or
            candidate.get("status") != "pending" or not isinstance(target, str)):
        raise ValueError("Candidate is not pending in the bound assessment run")
    if page_url:
        page_parts = urlsplit(page_url)
        if (page_parts.scheme not in ("http", "https") or page_parts.username or
                page_parts.password or page_parts.netloc != urlsplit(binding.allowed_origin).netloc or
                page_parts.scheme != urlsplit(binding.allowed_origin).scheme):
            raise ValueError("Verifier page must be within the bound origin")
    if recipe == "browser_xss":
        observation = await _request("POST", f"{base}/browser/check-xss", verifier_token,
                                     {"url_template": target, "identity": identity})
        confirmed = (observation.get("result") or {}).get("executed") is True
    elif recipe == "public_directory_index":
        observation = await _request("POST", f"{base}/http/get", verifier_token,
                                     {"url": target, "identity": "anonymous"})
        result = observation.get("result") or {}
        confirmed = (result.get("directory_index") is True and result.get("status") == 200
                     and result.get("truncated") is False)
    else:
        # A fresh browser run must produce the verifier's own private XHR/fetch
        # capture. Hunter artifact IDs are deliberately unusable by this actor.
        browser = await _request("POST", f"{base}/browser/inspect-js", verifier_token, {
            "url": page_url, "identity": identity, "max_pages": 1, "max_actions": 3,
        })
        if browser.get("run_id") != binding.service_run_id or browser.get("actor") != "verifier":
            raise ValueError("Verifier browser capture is not bound to this run")
        target_parts = urlsplit(target)
        query_keys = {key for key, _ in parse_qsl(target_parts.query, keep_blank_values=True)}
        traffic = (browser.get("result") or {}).get("traffic") or []
        matches = [
            row for row in traffic if isinstance(row, dict)
            and row.get("method") == "GET"
            and row.get("path") == (target_parts.path or "/")
            and set(row.get("query_keys") or []) == query_keys
            and (recipe != "numeric_sqli" or any(
                field.get("name") == parameter and field.get("value_type") == "positive_integer"
                for field in (row.get("query_fields") or []) if isinstance(field, dict)
            ))
            and isinstance(row.get("artifact_id"), str)
        ]
        if len(matches) != 1:
            raise ValueError("Fresh browser capture did not identify one matching GET request")
        capture_id = matches[0]["artifact_id"]
        if recipe == "numeric_sqli":
            observation = await _request("POST", f"{base}/http/sqli-boolean", verifier_token, {
                "artifact_id": capture_id, "parameter": parameter, "identity": identity,
            })
            result = observation.get("result") or {}
            confirmed = (result.get("proof_confirmed") is True and result.get("target") == target
                         and result.get("parameter") == parameter
                         and result.get("captured_artifact_id") == capture_id)
        else:
            observation = await _request("POST", f"{base}/http/authz-owner-only", verifier_token, {
                "artifact_id": capture_id, "owner_identity": identity,
            })
            result = observation.get("result") or {}
            confirmed = (result.get("proof_confirmed") is True and result.get("target") == target
                         and result.get("owner_identity") == identity
                         and result.get("captured_artifact_id") == capture_id)
    evidence_ids = observation.get("artifact_ids") or []
    if (observation.get("run_id") != binding.service_run_id or
            observation.get("actor") != "verifier" or not evidence_ids):
        raise ValueError("Verifier did not receive a fresh service observation")
    verdict = "confirmed" if confirmed else "inconclusive"
    verification = await _request("POST", f"{base}/candidates/{candidate_id}/verify",
                                  verifier_token, {
                                      "verifier_id": "aegis-deterministic-verifier",
                                      "verdict": verdict,
                                      "evidence_ids": [evidence_ids[0]],
                                      "reason": ("Fresh service proof reproduced the claim"
                                                 if confirmed else "Fresh service proof did not confirm the claim"),
                                  })
    publication = None
    publication_error = None
    if verdict == "confirmed":
        try:
            publication = await _request("POST", f"{base}/candidates/{candidate_id}/publish",
                                         verifier_token, {})
        except (ValueError, httpx.RequestError) as exc:
            publication_error = str(exc)[:300]
    return {"candidate_id": candidate_id, "verdict": verdict,
            "verification_id": verification.get("verification_id"),
            "verifier_artifact_id": evidence_ids[0], "publication": publication,
            "publication_error": publication_error}


async def publish_confirmed_candidate(db, *, organization_id: int, user_id: int,
                                      session_id: str, candidate_id: str) -> dict:
    if not isinstance(candidate_id, str) or not _RUN_ID.fullmatch(candidate_id):
        raise ValueError("Invalid candidate ID")
    binding = db.query(ScopedAssessmentRun).filter_by(
        organization_id=organization_id, user_id=user_id, session_id=session_id,
    ).first()
    if binding is None:
        raise ValueError("No scoped assessment is bound to this agent session")
    return await _request(
        "POST", f"/v1/runs/{binding.service_run_id}/candidates/{candidate_id}/publish",
        binding.hunter_token(), {},
    )
