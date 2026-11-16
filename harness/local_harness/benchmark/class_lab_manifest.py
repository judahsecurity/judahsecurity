"""Write the positive/negative product-agent lab manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


CASES = {
    "sqli": ("sqli", "/search", "sqli"),
    "sqli_encoded": ("sqli", "/catalog", "sqli"),
    "sqli_post_blind": ("sqli", "/api/filter", "sqli"),
    "xss": ("xss", "/search", "xss"),
    "xss_dom": ("xss", "/blog", "xss"),
    "xss_post_xhr": ("xss", "/api/render", "xss"),
    "ssrf": ("ssrf", "/api/fetch", "ssrf"),
    "idor": ("idor", "/api/objects/1", "api_authz"),
    "graphql_authz": ("idor", "/graphql", "graphql_api"),
    "unsafe_file_upload": ("file_upload", "/api/uploads/{id}", "file_upload"),
    "csrf": ("csrf", "/profile", "auth_logic"),
    "ssti": ("ssti", "/greeting", "server_injection"),
    "command_injection": ("rce", "/tools/ping", "server_injection"),
    "path_traversal": ("lfi", "/download", "server_injection"),
    "jwt": ("auth", "/api/documents/{id}", "auth_logic"),
}

ACCEPTED_CATEGORIES = {
    "graphql_authz": ["authz"],
    "unsafe_file_upload": ["xss"],
    # A forged-token read of A's document may be titled as broken access control.
    "jwt": ["authz", "idor"],
}

# Classes Prowl cannot yet confirm through a deterministic validator. They are
# still run and scored, but the report marks them so a 0 verified recall reads
# as a tracked gap rather than a regression.
KNOWN_GAPS = {
    "jwt": ("Prowl's scoped_jwt_probe needs a registered identity whose session carries "
            "the JWT (Authorization: Bearer); the lab identity uses a cookie session, so "
            "expected verified recall stays 0 until the lab registers a bearer identity."),
}


def build_manifest(target: str) -> dict:
    cases = []
    for bug_class, (category, endpoint, specialist) in CASES.items():
        for polarity in ("positive", "negative"):
            name = f"{bug_class}-{polarity}"
            cases.append({
                "id": name, "bug_class": bug_class, "polarity": polarity,
                "run_dir": f"runs/{name}", "target": target, "scope": target,
                "specialist": specialist,
                "expected_findings": [{
                    "id": name, "category": category, "endpoint": endpoint,
                    "description": f"Lab {bug_class} impact at {endpoint}",
                    "accepted_categories": ACCEPTED_CATEGORIES.get(bug_class, []),
                }] if polarity == "positive" else [],
                **({"known_gap": KNOWN_GAPS[bug_class]} if bug_class in KNOWN_GAPS else {}),
            })
    return {"cases": cases}


def build_identities(target: str) -> list[dict]:
    return [
        {
            "name": name, "target": target,
            "headers": {"X-Lab-Identity": name},
            "cookies": {"lab_session": name},
            "role": "owner" if name == "A" else "peer",
            "check": {"url": target + "/whoami", "field": "principal_id", "expected": name},
        }
        for name in ("A", "B")
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:8765")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    target = args.target.rstrip("/")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(build_manifest(target), indent=2) + "\n")
    identities = args.out.with_name("class_lab_identities.json")
    identities.write_text(json.dumps(build_identities(target), indent=2) + "\n")
    print(args.out)
    print(identities)


if __name__ == "__main__":
    main()
