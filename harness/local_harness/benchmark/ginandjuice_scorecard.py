"""Score a Prowl (or any scanner's) run against Gin & Juice Shop's expected issues.

Turns "it should find more" into a number. Each expected issue in
``ground_truth/GINANDJUICE.json`` lands in exactly one bucket:

- ``verified``    a matching candidate the independent verifier confirmed
- ``unverified``  found (pending, inconclusive, or reported by a tool with no
                  verifier) but not confirmed
- ``refuted``     found, and every match was refuted by the verifier
- ``missed``      nothing matched

Matching is by vulnerability class first, then by a title regex; the endpoint
hint only breaks ties, because the ground truth's locations are best guesses.
Candidates that match nothing expected are listed too: a confirmed one is a
possible real issue the ground truth lacks, a refuted one is a false positive
the verifier caught.

For a Prowl export, each miss gets a likely cause from the run record (no
coverage for that class, browser/OAST/POST tooling never ran, budget end).

Inputs:
- Prowl: ``scripts/export_agent_run.py`` output (schema ``prowl-run-export/1``).
- Anything else (AntiFox, Burp, ZAP): a JSON list of findings, or
  ``{"findings": [...]}``, each with ``title`` and optionally ``severity``,
  ``url``/``target``/``endpoint``, ``vulnerability_class`` and ``verified``.

Usage::

    cd harness
    python -m local_harness.benchmark.ginandjuice_scorecard prowl_run.json
    python -m local_harness.benchmark.ginandjuice_scorecard prowl_run.json --compare antifox.json
    python -m local_harness.benchmark.ginandjuice_scorecard prowl_run.json --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GROUND_TRUTH = Path(__file__).resolve().parent / "ground_truth" / "GINANDJUICE.json"
BUCKETS = ("verified", "unverified", "refuted", "missed")
# Coverage test types and tools that show Prowl attempted a class.
CLASS_TEST_TYPES = {
    "sql_injection": {"sqli", "sql_injection"},
    "xss": {"xss", "reflected_xss", "stored_xss", "dom_xss"},
    "xxe": {"xxe", "xml", "xml_entity"},
    "client_template_injection": {"client_template_injection", "csti", "xss"},
    "client_prototype_pollution": {"client_prototype_pollution", "prototype_pollution"},
    "dom_open_redirect": {"dom_open_redirect", "open_redirect"},
    "open_redirect": {"open_redirect", "dom_open_redirect"},
    "ssrf": {"ssrf", "oob"},
    "known_cve": {"js_dependency_review", "known_cve"},
}
NEED_TOOLS = {
    "browser": {"execute_browser", "scoped_browser_assessment", "execute_deep_crawl"},
    "oast": {"run_oob_callback_workflow", "execute_interactsh"},
    "post_xml": {"scoped_xml_entity_assigned"},
}


def load_ground_truth(path: Path = GROUND_TRUTH) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _status_of(row: Dict[str, Any], source: str) -> str:
    if source == "prowl":
        status = str(row.get("status") or "pending").lower()
        return status if status in ("confirmed", "refuted", "inconclusive", "pending") else "pending"
    verified = row.get("verified")
    if verified is True or str(row.get("status") or "").lower() in ("confirmed", "verified"):
        return "confirmed"
    if str(row.get("status") or "").lower() in ("refuted", "false_positive", "rejected"):
        return "refuted"
    return "reported"


def load_run(path: Path) -> Dict[str, Any]:
    """Normalize a Prowl export or a generic findings list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("schema", "").startswith("prowl-run-export/"):
        rows, source = data.get("candidates") or [], "prowl"
    else:
        rows = data.get("findings") if isinstance(data, dict) else data
        rows, source, data = rows or [], "generic", {}
    findings = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        findings.append({
            "id": str(row.get("id") or f"f{index + 1}"),
            "title": str(row.get("title") or row.get("name") or row.get("type") or ""),
            "class": str(row.get("vulnerability_class") or "").strip().lower(),
            "target": str(row.get("target") or row.get("url") or row.get("endpoint") or ""),
            "severity": str(row.get("severity") or "").lower(),
            "status": _status_of(row, source),
        })
    return {"source": source, "label": Path(path).stem, "findings": findings, "export": data}


def _matches(expected: Dict[str, Any], finding: Dict[str, Any]) -> int:
    """0 = no match; higher is a better match (endpoint agreement breaks ties)."""
    score = 0
    if finding["class"] and finding["class"] in (expected.get("classes") or []):
        score = 2
    elif expected.get("keywords") and re.search(expected["keywords"], finding["title"], re.I):
        score = 1
    if score and expected.get("endpoint_hint") and expected["endpoint_hint"] in finding["target"]:
        score += 1
    return score


def score_run(run: Dict[str, Any], truth: Dict[str, Any]) -> Dict[str, Any]:
    expected = truth["expected_findings"]
    claimed: Dict[str, str] = {}
    # Each finding goes to its best-matching expected issue.
    for finding in run["findings"]:
        best: Tuple[int, Optional[str]] = (0, None)
        for item in expected:
            score = _matches(item, finding)
            if score > best[0]:
                best = (score, item["id"])
        if best[1]:
            claimed[finding["id"]] = best[1]
    rows = []
    for item in expected:
        matched = [f for f in run["findings"] if claimed.get(f["id"]) == item["id"]]
        statuses = {f["status"] for f in matched}
        if "confirmed" in statuses:
            bucket = "verified"
        elif statuses & {"pending", "inconclusive", "reported"}:
            bucket = "unverified"
        elif statuses == {"refuted"}:
            bucket = "refuted"
        else:
            bucket = "missed"
        row = {"id": item["id"], "title": item["title"], "tier": item.get("tier", "core"),
               "bucket": bucket, "matches": [f"{f['id']}:{f['status']}" for f in matched][:6]}
        if bucket in ("missed", "refuted", "unverified") and run["source"] == "prowl":
            row["likely_cause"] = _likely_cause(item, run["export"], bucket)
        rows.append(row)
    extras = [f for f in run["findings"] if f["id"] not in claimed]
    core = [r for r in rows if r["tier"] == "core"]
    counts = {b: sum(1 for r in core if r["bucket"] == b) for b in BUCKETS}
    return {
        "label": run["label"], "source": run["source"], "rows": rows,
        "core_total": len(core), "core": counts,
        "core_detected": counts["verified"] + counts["unverified"],
        "hygiene_detected": sum(1 for r in rows if r["tier"] == "hygiene" and r["bucket"] != "missed"),
        "extras": {
            "confirmed": [f["title"] for f in extras if f["status"] == "confirmed"],
            "refuted": [f["title"] for f in extras if f["status"] == "refuted"],
            "other": [f["title"] for f in extras if f["status"] not in ("confirmed", "refuted")],
        },
        "run": (run["export"] or {}).get("run") or {},
    }


def _likely_cause(item: Dict[str, Any], export: Dict[str, Any], bucket: str) -> str:
    if bucket == "refuted":
        return "found, but the verifier refuted every match; read its verdict"
    if bucket == "unverified":
        return "found but not confirmed: verification still pending or inconclusive"
    tools = set(((export.get("tools") or {}).get("runs") or {}).keys())
    tested = set((export.get("coverage") or {}).get("tested_test_types") or [])
    planned = set(((export.get("coverage") or {}).get("by_test_type") or {}).keys())
    reasons = []
    test_types = set()
    for cls in item.get("classes") or []:
        test_types |= CLASS_TEST_TYPES.get(cls, {cls})
    if test_types and not (test_types & planned):
        reasons.append("no coverage cell was planned for this class")
    elif test_types and not (test_types & tested):
        reasons.append("planned but never tested")
    for need in item.get("needs") or []:
        if not (NEED_TOOLS.get(need, set()) & tools):
            reasons.append(f"needs {need}, and no {need} tool ran")
    run_reason = str((export.get("run") or {}).get("reason") or "").lower()
    if any(word in run_reason for word in ("budget", "ceiling", "deadline", "timeout")):
        reasons.append(f"run ended early ({run_reason[:60]})")
    return "; ".join(reasons) or "tested, but nothing was submitted"


def format_scorecard(card: Dict[str, Any]) -> str:
    c = card["core"]
    lines = [f"Gin & Juice Shop scorecard: {card['label']} ({card['source']})",
             f"Core issues: {card['core_detected']}/{card['core_total']} detected "
             f"({c['verified']} verified, {c['unverified']} unverified), "
             f"{c['refuted']} refuted, {c['missed']} missed. "
             f"Hygiene: {card['hygiene_detected']} found."]
    run = card.get("run") or {}
    if run:
        duration = run.get("duration_s")
        lines.append(f"Run: {run.get('status')} {f'in {duration / 60:.0f} min' if duration else ''}"
                     f"{' - ' + str(run.get('reason'))[:80] if run.get('reason') else ''}")
    for row in card["rows"]:
        cause = f"  <- {row['likely_cause']}" if row.get("likely_cause") else ""
        lines.append(f"  [{row['bucket']:<10}] {row['id']:<26} {row['title']}{cause}")
    extras = card["extras"]
    if extras["confirmed"]:
        lines.append("Confirmed but not in the ground truth (review; may be real): "
                     + "; ".join(extras["confirmed"][:8]))
    if extras["refuted"]:
        lines.append(f"False positives the verifier caught: {len(extras['refuted'])}")
    if extras["other"]:
        lines.append(f"Other unmatched findings: {len(extras['other'])}")
    return "\n".join(lines)


def format_comparison(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    lines = [f"{'issue':<26} {a['label'][:18]:<18} {b['label'][:18]:<18}"]
    for row_a, row_b in zip(a["rows"], b["rows"]):
        marker = "" if row_a["bucket"] == row_b["bucket"] else "  *"
        lines.append(f"{row_a['id']:<26} {row_a['bucket']:<18} {row_b['bucket']:<18}{marker}")
    lines.append(f"{'core detected':<26} {a['core_detected']}/{a['core_total']:<16} "
                 f"{b['core_detected']}/{b['core_total']}")
    lines.append(f"{'core verified':<26} {a['core']['verified']:<18} {b['core']['verified']:<18}")
    lines.append(f"{'false positives caught':<26} {len(a['extras']['refuted']):<18} "
                 f"{len(b['extras']['refuted']):<18}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Score a run against Gin & Juice Shop.")
    parser.add_argument("run", type=Path)
    parser.add_argument("--compare", type=Path, help="second run to score side by side")
    parser.add_argument("--ground-truth", type=Path, default=GROUND_TRUTH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    truth = load_ground_truth(args.ground_truth)
    card = score_run(load_run(args.run), truth)
    other = score_run(load_run(args.compare), truth) if args.compare else None
    if args.json:
        json.dump({"run": card, "compare": other}, sys.stdout, indent=1)
        sys.stdout.write("\n")
        return 0
    print(format_scorecard(card))
    if other:
        print()
        print(format_scorecard(other))
        print()
        print(format_comparison(card, other))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
