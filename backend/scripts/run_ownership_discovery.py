#!/usr/bin/env python3
"""
Run owned-domain discovery (with recursive expansion + ownership scoring)
against a deployed Judah Security API and print a tiered summary.

Works for any organization. Example (Rockwell demo):

    ASM_PASSWORD=... python scripts/run_ownership_discovery.py \
        --base-url https://asm.example.com --username analyst@example.com \
        --org-id 3 --domain rockwellautomation.com \
        --org-name "Rockwell Automation, Inc." --org-name "Rockwell Automation" \
        --org-name "Allen-Bradley Company, LLC"

Legal names are passed on the request (used for the certificate-organization
search and registrant-company reverse WHOIS); saved service configs are not
modified. Use --dry-run to see the request without spending any credits.
"""

import argparse
import json
import os
import sys

import httpx


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True, help="API origin, e.g. https://asm.example.com")
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=os.environ.get("ASM_PASSWORD"), help="or set ASM_PASSWORD")
    p.add_argument("--org-id", type=int, required=True)
    p.add_argument("--domain", required=True, help="Primary domain, e.g. rockwellautomation.com")
    p.add_argument("--org-name", action="append", default=[], help="Legal/registrant org name (repeatable)")
    p.add_argument("--email", action="append", default=[], help="Registrant email to reverse (repeatable)")
    p.add_argument("--no-paid", action="store_true", help="Free sources only (no WHOIS/reverse credits)")
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--max-domains", type=int, default=25)
    p.add_argument("--max-paid-pivots", type=int, default=10)
    p.add_argument("--rescore-existing", action="store_true",
                   help="Also write ownership score/tier onto domains that already exist")
    p.add_argument("--no-create-assets", action="store_true", help="Report only; do not create assets")
    p.add_argument("--no-enrichment", action="store_true", help="Skip tech scan / screenshots / probes")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--out", help="Write the full JSON response here")
    args = p.parse_args()

    body = {
        "organization_id": args.org_id,
        "domain": args.domain.strip().lower(),
        "include_paid_sources": not args.no_paid,
        "organization_names": args.org_name or None,
        "registration_emails": args.email or None,
        "create_assets": not args.no_create_assets,
        "skip_existing": not args.rescore_existing,
        "expand_ownership": True,
        "expansion_max_depth": args.max_depth,
        "expansion_max_domains": args.max_domains,
        "expansion_include_paid": not args.no_paid,
        "expansion_max_paid_pivots": args.max_paid_pivots,
    }
    if args.no_enrichment:
        body.update(run_technology_scan=False, run_screenshots=False, run_http_probe=False,
                    run_dns_resolution=False, run_geo_enrichment=False)

    if args.dry_run:
        print(json.dumps(body, indent=2))
        return 0
    if not args.password:
        print("Password required (--password or ASM_PASSWORD)", file=sys.stderr)
        return 2

    api = args.base_url.rstrip("/") + "/api/v1"
    with httpx.Client(timeout=httpx.Timeout(900.0, connect=30.0)) as client:
        login = client.post(f"{api}/auth/login", data={"username": args.username, "password": args.password})
        if login.status_code != 200:
            print(f"Login failed: HTTP {login.status_code} {login.text[:300]}", file=sys.stderr)
            return 1
        token = login.json().get("access_token")
        print(f"Running discovery for {body['domain']} (org {args.org_id}); this can take several minutes...")
        resp = client.post(f"{api}/external-discovery/run", json=body,
                           headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        print(f"Discovery failed: HTTP {resp.status_code} {resp.text[:500]}", file=sys.stderr)
        return 1
    data = resp.json()
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(data, fh, indent=2)

    print(f"\nSources ({data.get('total_elapsed_time', 0):.0f}s total):")
    for s in data.get("source_results", []):
        status = "ok " if s.get("success") else "ERR"
        err = f"  - {s['error'][:120]}" if s.get("error") else ""
        print(f"  [{status}] {s['source']:<28} domains={s.get('domains_found', 0):<5}"
              f" subdomains={s.get('subdomains_found', 0)}{err}")

    exp = data.get("expansion") or {}
    if exp:
        print(f"\nExpansion: pivoted from {len(exp.get('domains_pivoted', []))} domains in "
              f"{len(exp.get('rounds', []))} round(s); {len(exp.get('new_domains', []))} new domains; "
              f"{exp.get('paid_pivots_used', 0)} paid pivots; "
              f"{len(exp.get('corroborated', []))} review domains corroborated")

    ownership = data.get("ownership", {})
    print(f"\nOwnership: {data.get('ownership_counts')}")
    for tier in ("confirmed", "likely", "review"):
        rows = sorted(((d, o) for d, o in ownership.items() if o["tier"] == tier), key=lambda r: -r[1]["score"])
        if not rows:
            continue
        print(f"\n== {tier.upper()} ({len(rows)}) ==")
        for d, o in rows:
            print(f"  {o['score']:>3}%  {d:<45} {', '.join(o['signals'])}")
    print(f"\nAssets created: {data.get('assets_created', 0)}, skipped (existing): {data.get('assets_skipped', 0)}")
    print("Review-tier domains were created out of scope and tagged ownership:review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
