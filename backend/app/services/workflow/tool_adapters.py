"""Adapters that run catalog tools and write normalized artifacts."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability
from app.services.workflow.artifacts import (
    node_dir,
    register_artifact,
    write_json,
    write_text_list,
    value_from_artifact_ref,
)
from app.services.workflow.tool_catalog import get_tool

logger = logging.getLogger(__name__)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        p = Path(value)
        if p.is_file():
            return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        return [value.strip()] if value.strip() else []
    return [str(value)]


def _targets_from_inputs(inputs: Dict[str, Any], keys: List[str]) -> List[str]:
    for k in keys:
        if k in inputs and inputs[k] is not None:
            vals = _as_list(value_from_artifact_ref(inputs[k]))
            if vals:
                return vals
    return []


async def run_tool_node(
    db: Session,
    worker: Any,
    *,
    run_id: int,
    organization_id: int,
    node_id: str,
    tool_id: str,
    params: Dict[str, Any],
    resolved_inputs: Dict[str, Any],
) -> Tuple[Dict[str, Any], str]:
    """
    Execute a tool via the scanner worker handlers (ephemeral Scan),
    then harvest normalized output artifacts.
    Returns (outputs_dict, logs).
    """
    tool = get_tool(tool_id)
    if not tool:
        raise ValueError(f"Unknown tool: {tool_id}")

    ndir = node_dir(organization_id, run_id, node_id)
    job_type = tool["job_type"]
    logs: List[str] = []

    targets = _targets_from_inputs(resolved_inputs, ["urls", "hosts", "domains", "domain"])
    if "domain" in resolved_inputs and not targets:
        domain_val = value_from_artifact_ref(resolved_inputs["domain"])
        if isinstance(domain_val, list):
            targets = [str(x) for x in domain_val]
        elif domain_val:
            targets = [str(domain_val)]

    scan_type_map = {
        "DISCOVERY": ScanType.DISCOVERY,
        "PORT_SCAN": ScanType.PORT_SCAN,
        "HTTP_PROBE": ScanType.HTTP_PROBE,
        "KATANA": ScanType.KATANA,
        "WAYBACKURLS": ScanType.WAYBACKURLS,
        "PARAMSPIDER": ScanType.PARAMSPIDER,
        "NUCLEI_SCAN": ScanType.VULNERABILITY,
        "SCREENSHOT": ScanType.SCREENSHOT,
        "TECHNOLOGY_SCAN": ScanType.TECHNOLOGY,
    }
    scan_type = scan_type_map.get(job_type, ScanType.DISCOVERY)

    config = dict(params or {})
    config["workflow_run_id"] = run_id
    config["workflow_node_id"] = node_id

    scan = Scan(
        name=f"workflow-{run_id}-{node_id}",
        scan_type=scan_type,
        organization_id=organization_id,
        targets=targets,
        config=config,
        status=ScanStatus.PENDING,
        started_by="workflow",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logs.append(f"Created ephemeral scan {scan.id} for tool {tool_id}")

    job_data = {
        "job_type": job_type,
        "scan_id": scan.id,
        "organization_id": organization_id,
        "targets": targets,
        "config": config,
        "domain": targets[0] if targets else None,
        "scanner": config.get("scanner", "naabu"),
        "ports": config.get("ports"),
        "severity": config.get("severity"),
        "tags": config.get("tags"),
    }

    handler = {
        "DISCOVERY": worker.handle_discovery,
        "PORT_SCAN": worker.handle_port_scan,
        "HTTP_PROBE": worker.handle_http_probe,
        "KATANA": worker.handle_katana_scan,
        "WAYBACKURLS": worker.handle_waybackurls_scan,
        "PARAMSPIDER": worker.handle_paramspider_scan,
        "NUCLEI_SCAN": worker.handle_nuclei_scan,
        "SCREENSHOT": worker.handle_screenshot_scan,
        "TECHNOLOGY_SCAN": worker.handle_technology_scan,
    }.get(job_type)

    if not handler:
        raise ValueError(f"No worker handler for job_type {job_type}")

    await handler(job_data)
    db.expire_all()
    scan = db.query(Scan).filter(Scan.id == scan.id).first()
    if scan and scan.status == ScanStatus.FAILED:
        raise RuntimeError(scan.error_message or f"Tool {tool_id} failed")

    outputs = await _harvest_outputs(
        db,
        tool_id=tool_id,
        organization_id=organization_id,
        run_id=run_id,
        node_id=node_id,
        ndir=ndir,
        targets=targets,
        scan=scan,
    )
    logs.append(f"Tool {tool_id} completed; outputs={list(outputs.keys())}")
    return outputs, "\n".join(logs)


async def _harvest_outputs(
    db: Session,
    *,
    tool_id: str,
    organization_id: int,
    run_id: int,
    node_id: str,
    ndir: Path,
    targets: List[str],
    scan: Optional[Scan],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out_dir = ndir / "out"

    if tool_id in ("subfinder_discovery", "port_scan", "http_probe"):
        q = db.query(Asset).filter(Asset.organization_id == organization_id)
        if tool_id == "http_probe":
            q = q.filter(Asset.is_live.is_(True))
        assets = q.order_by(Asset.updated_at.desc()).limit(5000).all()
        # Prefer assets matching target roots when possible
        hosts = []
        urls = []
        for a in assets:
            val = a.value
            if not val:
                continue
            if targets:
                if not any(val == t or val.endswith("." + t) or t in val for t in targets):
                    # still include recently-updated org assets for discovery fan-out
                    if tool_id != "subfinder_discovery":
                        continue
            hosts.append(val)
            if getattr(a, "live_url", None):
                urls.append(a.live_url)
            elif getattr(a, "is_live", False):
                urls.append(f"https://{val}")

        if tool_id == "subfinder_discovery" and not hosts and targets:
            hosts = list(targets)

        hosts_path = write_text_list(out_dir / "hosts.txt", hosts)
        art = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="hosts", path=hosts_path)
        out["hosts"] = {"path": str(hosts_path), "artifact_id": art.id, "count": len(hosts)}

        if tool_id == "http_probe":
            urls_path = write_text_list(out_dir / "urls.txt", urls or [f"https://{h}" for h in hosts])
            art_u = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="urls", path=urls_path)
            out["urls"] = {"path": str(urls_path), "artifact_id": art_u.id, "count": len(urls)}

        if tool_id == "subfinder_discovery":
            summary = {"hosts": len(hosts), "scan_results": (scan.results if scan else None)}
            jp = write_json(out_dir / "assets.json", summary)
            art_j = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="assets_json", path=jp, content_type="application/json")
            out["assets_json"] = {"path": str(jp), "artifact_id": art_j.id}

        if tool_id == "port_scan":
            ports_payload = (scan.results if scan else {}) or {}
            jp = write_json(out_dir / "ports.json", ports_payload)
            art_p = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="ports", path=jp, content_type="application/json")
            out["ports"] = {"path": str(jp), "artifact_id": art_p.id}

    elif tool_id in ("katana", "waybackurls", "paramspider"):
        # Prefer scan.results URLs; fallback to live asset URLs
        urls: List[str] = []
        results = (scan.results if scan else None) or {}
        for key in ("urls", "endpoints", "results"):
            val = results.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        urls.append(item)
                    elif isinstance(item, dict) and item.get("url"):
                        urls.append(item["url"])
        if not urls:
            assets = (
                db.query(Asset)
                .filter(Asset.organization_id == organization_id, Asset.is_live.is_(True))
                .limit(2000)
                .all()
            )
            for a in assets:
                if a.live_url:
                    urls.append(a.live_url)
                eps = a.endpoints or []
                if isinstance(eps, list):
                    for ep in eps:
                        if isinstance(ep, str):
                            urls.append(ep)
                        elif isinstance(ep, dict) and ep.get("url"):
                            urls.append(ep["url"])
        urls = list(dict.fromkeys(urls))
        urls_path = write_text_list(out_dir / "urls.txt", urls)
        art = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="urls", path=urls_path)
        out["urls"] = {"path": str(urls_path), "artifact_id": art.id, "count": len(urls)}
        jp = write_json(out_dir / "endpoints.json", results)
        art_j = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="endpoints", path=jp, content_type="application/json")
        out["endpoints"] = {"path": str(jp), "artifact_id": art_j.id}
        if tool_id == "paramspider":
            out["params"] = out["endpoints"]

    elif tool_id == "nuclei":
        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id)
            .all()
            if scan
            else []
        )
        findings = []
        for v in vulns:
            asset_val = None
            if getattr(v, "asset", None) is not None:
                asset_val = v.asset.value
            findings.append(
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value if v.severity else None,
                    "asset_id": v.asset_id,
                    "asset": asset_val,
                    "template_id": v.template_id,
                    "matched_at": getattr(v, "affected_component", None),
                }
            )
        jp = write_json(out_dir / "findings.json", findings)
        art = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="findings", path=jp, content_type="application/json")
        out["findings"] = {"path": str(jp), "artifact_id": art.id, "count": len(findings)}

    else:
        payload = (scan.results if scan else {}) or {}
        jp = write_json(out_dir / "results.json", payload)
        art = register_artifact(db, run_id=run_id, organization_id=organization_id, node_id=node_id, port="results", path=jp, content_type="application/json")
        out["results"] = {"path": str(jp), "artifact_id": art.id}
        if tool_id == "technology":
            out["tech"] = out["results"]

    db.commit()
    return out
