#!/usr/bin/env python3
"""Generate data/vuln_classes.json from Prowl's canonical proof policy.

Prowl (backend/app/services/agent) owns the vulnerability class list:

- ``proof_policy.PROOFS_BY_CLASS``: class -> proof kinds that can confirm it.
  A class with no proof kinds is never confirmable (stays a lead).
- ``vulnerability_catalog``: coverage classes the input inventory creates work
  for (``sqli``, ``authz``, ...). They map onto proof classes below.

Vanguard reads the generated JSON so /pentest, /triage, /chain and
prowl_client.py use the same names and the same medium+ gate as Prowl.

    python3 scripts/sync_vuln_classes.py            # write data/vuln_classes.json
    python3 scripts/sync_vuln_classes.py --check    # exit 1 on drift
    python3 scripts/sync_vuln_classes.py --backend ../backend

When the backend checkout is not importable, the existing JSON is kept.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vuln_classes.json"
DEFAULT_BACKEND = ROOT.parent / "backend"

# Classes being added to PROOFS_BY_CLASS upstream. Merged only when the
# backend does not have them yet, and listed under "pending_upstream" so the
# sync test shows the gap until the backend edit lands.
EXPECTED_UPSTREAM = {
    "ssti": ["scoped_ssti_eval"],
    "command_injection": ["scoped_cmdi_eval"],
    "path_traversal": ["scoped_traversal_read"],
    "csrf": ["scoped_csrf_state_change"],
}

# Classes that are never confirmable and carry a hard severity cap.
SEVERITY_CAPS = {"known_cve": "low"}

# vulnerability_catalog coverage class -> PROOFS_BY_CLASS class.
# None: Prowl has no validator yet, so the class can only produce leads.
COVERAGE_TO_PROOF = {
    "sqli": "sql_injection",
    "xss": "xss",
    "stored_xss": "xss",
    "crlf": "crlf",
    "nosql": "nosql",
    "ssti": "ssti",
    "ssrf": "ssrf",
    "open_redirect": "open_redirect",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "authz": "authorization",
    "xxe": "xxe",
    "prototype_pollution": None,
    "csrf": "csrf",
    "race_condition": "race_condition",
    "cors": "cors",
    "graphql": None,
    "file_upload": None,
    "oauth": None,
    "saml_sso": None,
    "llm_ai": None,
    "business_logic": None,
    "dom_open_redirect": "dom_open_redirect",
    "dom_link_manipulation": None,
    "dom_data_manipulation": None,
    "request_url_override": None,
    "client_template_injection": "client_template_injection",
    "client_prototype_pollution": "client_prototype_pollution",
    "js_dependency_review": "known_cve",
    "auth": None,
}

# Names Vanguard hunters, findings.json and asm_bridge already use.
VANGUARD_ALIASES = {
    "sqli": "sql_injection", "sql": "sql_injection", "blind_sqli": "sql_injection",
    "xss": "xss", "reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss", "dom-xss": "xss",
    "idor": "authorization", "bola": "authorization", "bfla": "authorization",
    "authz": "authorization", "access_control": "authorization",
    "broken_access_control": "authorization", "privilege_escalation": "authorization",
    "mass_assignment": "authorization", "auth_bypass": "authorization",
    "lfi": "path_traversal", "directory_traversal": "path_traversal",
    "rce": "command_injection", "cmdi": "command_injection", "os_command_injection": "command_injection",
    "ssti": "ssti", "template_injection": "ssti",
    "ssrf": "ssrf", "xxe": "xxe", "crlf": "crlf", "header_injection": "crlf",
    "open_redirect": "open_redirect", "redirect": "open_redirect",
    "cors": "cors", "csrf": "csrf", "race": "race_condition", "race_condition": "race_condition",
    "info_disclosure": "exposure", "information_disclosure": "exposure",
    "directory_listing": "exposure", "secret_exposure": "exposure", "exposure": "exposure",
    "cve": "known_cve", "known_cve": "known_cve", "outdated_component": "known_cve",
    "user_enumeration": "account_enumeration", "account_enumeration": "account_enumeration",
}


def _load_backend(backend: Path):
    if not (backend / "app" / "services" / "agent" / "proof_policy.py").is_file():
        return None, None
    sys.path.insert(0, str(backend))
    try:
        policy = importlib.import_module("app.services.agent.proof_policy")
    except Exception as exc:  # backend deps missing: keep the committed JSON
        print(f"backend not importable: {exc}", file=sys.stderr)
        return None, None
    catalog_path = backend / "app" / "services" / "agent" / "vulnerability_catalog.py"
    return policy.PROOFS_BY_CLASS, coverage_classes_from_source(catalog_path.read_text())


def coverage_classes_from_source(source: str) -> list[str]:
    """String literals the catalog adds, returns, or routes (no import needed)."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add" and node.args
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            found.add(node.args[0].value)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            found.update(e.value for e in node.value.elts
                         if isinstance(e, ast.Constant) and isinstance(e.value, str))
        elif isinstance(node, ast.FunctionDef) and node.name == "specialist_for_class":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Set):
                    found.update(e.value for e in sub.elts
                                 if isinstance(e, ast.Constant) and isinstance(e.value, str))
                elif (isinstance(sub, ast.Compare) and isinstance(sub.comparators[0], ast.Constant)
                      and isinstance(sub.comparators[0].value, str)):
                    found.add(sub.comparators[0].value)
    return sorted(found)


def build(proofs: dict, coverage: list[str]) -> dict:
    pending = {}
    merged = {name: sorted(kinds) for name, kinds in proofs.items()}
    for name, kinds in EXPECTED_UPSTREAM.items():
        if not merged.get(name):
            merged[name] = sorted(kinds)
            pending[name] = sorted(kinds)
    unknown = sorted(set(coverage) - set(COVERAGE_TO_PROOF))
    if unknown:
        raise SystemExit(f"map new coverage classes in COVERAGE_TO_PROOF: {unknown}")
    classes = {}
    for name in sorted(merged):
        kinds = merged[name]
        classes[name] = {
            "proof_kinds": kinds,
            "confirmable": bool(kinds) and name not in SEVERITY_CAPS,
            "severity_cap": SEVERITY_CAPS.get(name),
            "coverage_classes": sorted(c for c in coverage if COVERAGE_TO_PROOF.get(c) == name),
        }
    bad_alias = sorted(a for a, c in VANGUARD_ALIASES.items() if c not in classes)
    if bad_alias:
        raise SystemExit(f"aliases point at unknown classes: {bad_alias}")
    return {
        "source": "backend/app/services/agent/proof_policy.py:PROOFS_BY_CLASS + vulnerability_catalog.py",
        "generated_by": "scripts/sync_vuln_classes.py",
        "rules": {
            "medium_plus_requires_proof_kind": True,
            "unproven_severity_cap": "low",
            "note": "A class with no proof kind cannot be confirmed; report it as a lead at low/info.",
        },
        "pending_upstream": pending,
        "classes": classes,
        "coverage_to_class": {c: COVERAGE_TO_PROOF[c] for c in sorted(coverage)},
        "vanguard_aliases": dict(sorted(VANGUARD_ALIASES.items())),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", type=Path, default=DEFAULT_BACKEND)
    p.add_argument("--check", action="store_true", help="exit 1 if the JSON differs")
    args = p.parse_args()
    proofs, coverage = _load_backend(args.backend.resolve())
    if proofs is None:
        print(f"backend not found at {args.backend}; {OUT.name} unchanged", file=sys.stderr)
        return 0 if OUT.is_file() else 1
    text = json.dumps(build(proofs, coverage), indent=2) + "\n"
    if args.check:
        current = OUT.read_text() if OUT.is_file() else ""
        if current != text:
            print(f"{OUT} is out of date; run scripts/sync_vuln_classes.py", file=sys.stderr)
            return 1
        print("vuln_classes.json in sync")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
