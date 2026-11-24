#!/usr/bin/env python3
"""Publish /chain results to the ASM platform as structured exploit chains.

Reads <run-dir>/chains.json and <run-dir>/findings.json and sends each
``demonstrated`` chain through ASMBridge.confirm_chain: one step per link (the
link's finding title, endpoint, class and evidence) plus a final step for the
end-to-end proof. The platform anchors each step to its asset, shows the chain
as an attack path and weights it by exploitability.

Only ``demonstrated`` chains are sent: chain severity needs end-to-end proof
(see /chain). ``--include-unproven`` also sends ``links_confirmed_not_demonstrated``
chains, at the highest severity of their confirmed links, with the missing
step recorded as not demonstrated.

    python3 .claude/skills/_lib/publish_chains.py <run-dir> [--dry-run] [--include-unproven]

Needs ASM_API_URL and ASM_API_KEY unless --dry-run. Every finding from the run
shares one session ID (the chain's Prowl session, else the run directory), so
the platform groups them into one campaign.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}")


def _findings_by_id(run_dir: Path) -> Dict[str, Dict[str, Any]]:
    path = run_dir / "findings.json"
    if not path.exists():
        return {}
    data = _load(path)
    rows = data.get("findings", []) if isinstance(data, dict) else data
    return {str(r.get("id")): r for r in rows if isinstance(r, dict) and r.get("id") is not None}


def _where(finding: Dict[str, Any]) -> str:
    return str(finding.get("endpoint") or finding.get("url") or finding.get("location")
               or finding.get("target") or "")


def _host(value: str) -> str:
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0].lower()


def chain_to_steps(chain: Dict[str, Any], findings: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for link in chain.get("links") or []:
        if not link.get("link_confirmed", link.get("verdict") == "confirmed"):
            continue
        finding = findings.get(str(link.get("finding_id")), {})
        title = str(finding.get("title") or link.get("finding_id") or "link")
        role = str(link.get("role") or "").strip()
        steps.append({
            "summary": f"{'Link ' + role + ': ' if role else ''}{title}",
            "asset": _where(finding),
            "finding_ref": title,
            "vuln_type": str(finding.get("vuln_class") or finding.get("class") or ""),
            "request_raw": str(finding.get("request") or finding.get("request_raw") or ""),
            "response_snippet": str(finding.get("evidence") or finding.get("response") or "")[:4000],
            "outcome": str(finding.get("impact") or "")[:280],
            "tool": "prowl" if chain.get("prowl_session") else "vanguard",
        })
    if chain.get("status") == "demonstrated" and chain.get("evidence"):
        last_asset = next((s["asset"] for s in reversed(steps) if s["asset"]), "")
        steps.append({
            "summary": f"End-to-end: {chain.get('name') or 'chain'} demonstrated",
            "asset": last_asset,
            "response_snippet": str(chain["evidence"])[:4000],
            "outcome": str(chain.get("severity") or "")[:280],
            "tool": "prowl" if chain.get("prowl_session") else "vanguard",
        })
    return steps


def chain_severity(chain: Dict[str, Any], findings: Dict[str, Dict[str, Any]]) -> str:
    if chain.get("status") == "demonstrated" and chain.get("severity"):
        return str(chain["severity"]).lower()
    best = "low"
    for link in chain.get("links") or []:
        sev = str(findings.get(str(link.get("finding_id")), {}).get("severity") or "").lower()
        if _SEVERITY.get(sev, -1) > _SEVERITY[best]:
            best = sev
    return best


def publish(run_dir: Path, *, dry_run: bool = False, include_unproven: bool = False,
            bridge: Optional[Any] = None) -> List[Dict[str, Any]]:
    chains = _load(run_dir / "chains.json")
    if isinstance(chains, dict):
        chains = chains.get("chains") or []
    findings = _findings_by_id(run_dir)
    wanted = {"demonstrated"} | ({"links_confirmed_not_demonstrated"} if include_unproven else set())

    if bridge is None:
        sys.path.insert(0, str(ROOT))
        from asm_bridge import ASMBridge
        bridge = ASMBridge(auto_flush=False)
        if dry_run:
            bridge.api_url = ""  # ASMBridge falls back to ASM_API_URL for ""; force no send

    sent: List[Dict[str, Any]] = []
    for chain in chains:
        if not isinstance(chain, dict) or chain.get("status") not in wanted:
            continue
        steps = chain_to_steps(chain, findings)
        if len(steps) < 2:
            print(f"skip {chain.get('chain_id')}: fewer than 2 confirmed steps", file=sys.stderr)
            continue
        os.environ["ASM_SESSION_ID"] = str(chain.get("prowl_session") or f"vanguard:{run_dir.name}")
        host = next((_host(s["asset"]) for s in steps if s["asset"]), "") or "unknown"
        not_demonstrated = "" if chain.get("status") == "demonstrated" else str(
            chain.get("next_step") or "End-to-end impact not demonstrated")
        result = bridge.confirm_chain(
            host=host,
            title=str(chain.get("name") or chain.get("chain_id") or "Exploit chain"),
            steps=steps,
            severity=chain_severity(chain, findings),
            impact=str(chain.get("evidence") or chain.get("name") or ""),
            not_demonstrated=not_demonstrated,
        )
        sent.append({"chain_id": chain.get("chain_id"), "host": host, **result})
    bridge.flush()
    return sent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="print, do not send")
    parser.add_argument("--include-unproven", action="store_true",
                        help="also send links_confirmed_not_demonstrated chains")
    args = parser.parse_args()
    if not args.dry_run and not (os.environ.get("ASM_API_URL") and os.environ.get("ASM_API_KEY")):
        print("ASM_API_URL and ASM_API_KEY are required (or pass --dry-run)", file=sys.stderr)
        return 2
    sent = publish(args.run_dir, dry_run=args.dry_run, include_unproven=args.include_unproven)
    print(json.dumps([{k: s[k] for k in ("chain_id", "host", "title", "severity")}
                      | {"steps": len(s["chain"])} for s in sent], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
