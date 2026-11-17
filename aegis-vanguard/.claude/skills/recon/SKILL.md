---
name: recon
description: >-
  Scoped reconnaissance for an authorized target: subdomains (only when the
  scope file has a wildcard), live hosts, crawl, JavaScript endpoints and a
  parameter inventory. Writes results/<target>/<ts>/recon.json. Enforces the
  scope file on every host. Can hand mapping to a Prowl run or use local
  tools. Use before /pentest or when asked to map, enumerate, or crawl.
argument-hint: "<target> --scope-file <file> [--prowl] [--fresh]"
allowed-tools:
  - Read
  - Write
  - Grep
  - Glob
  - AskUserQuestion
  - Bash(python3 .claude/skills/_lib/run_dir.py:*)
  - Bash(python3 .claude/skills/_lib/scope.py:*)
  - Bash(python3 prowl_client.py:*)
  - Bash(subfinder:*)
  - Bash(dnsx:*)
  - Bash(httpx:*)
  - Bash(katana:*)
  - Bash(curl:*)
---

# /recon

Map, do not attack. No payloads, no fuzzing of values, no brute force.

**Invoke:** `/recon <target> --scope-file <file> [--prowl] [--fresh]`

`<target>` is a hostname, URL, or wildcard root the operator named. No bundled
target. Recon sends live traffic: confirm authorization (AskUserQuestion) first.

## Scope (hard rule)

The scope file is required. Format and helpers: `.claude/skills/_lib/scope.py`.

```bash
python3 .claude/skills/_lib/scope.py check <scope-file> <target>
python3 .claude/skills/_lib/scope.py wildcards <scope-file>
```

- Check every host before any request. Out of scope → skip and record it
  under `out_of_scope` in recon.json. Never widen scope yourself.
- Pipe every discovered host list through
  `python3 .claude/skills/_lib/scope.py filter <scope-file>` before probing.
- Third-party hosts (CDN, analytics, auth providers) found in JS are listed as
  references only, never probed unless the scope file names them.

## Run directory

```bash
python3 .claude/skills/_lib/run_dir.py mint <target-host> [--fresh]
```

## Steps

1. **Subdomains — only if `wildcards` printed a root.** Enumerate for those
   roots only (passive sources), then resolve and filter:
   `subfinder -d <root> -silent | python3 .claude/skills/_lib/scope.py filter <scope-file>`
   then `dnsx -silent`. Exact-host scope → skip this step entirely.
2. **Live hosts.** `httpx -silent -status-code -title -tech-detect` on the
   filtered list. Record status, title, tech, final URL; drop redirects that
   leave scope.
3. **Crawl.** `katana -u <url> -d 3 -jc -silent` (or curl GETs when missing),
   same-origin only, rate-limited. Note forms (method, action, field names),
   links with query keys, upload endpoints, auth/OAuth/SSO paths.
4. **JS endpoints.** For first-party scripts: extract API paths, GraphQL
   operations, base URLs, source-map references. Record paths and names only —
   never copy secret values; note "possible secret in <file>" for `/pentest`.
5. **Parameter inventory.** One row per (method, host, path, name, location:
   query|body_form|body_json|header|cookie|path), with source and the coverage
   classes from `data/vuln_classes.json` that apply (e.g. `id` → `authz`,
   `url`/`callback` → `ssrf`, `redirect`/`next` → `open_redirect`). Values are
   never stored.

### Prowl mode (`--prowl`, or when local tools are missing)

Prowl's scoped browser maps SPAs, XHR/fetch traffic and JS better than curl:

```bash
python3 prowl_client.py start --target <origin> --scope-file <scope-file> \
    --playbook quick_recon --run-dir <run-dir>
python3 prowl_client.py poll --session <id> --wait --run-dir <run-dir>
```

Platform CLI wrappers are also available, scope-checked by the client:
`python3 prowl_client.py tool --scope-file <f> --name execute_httpx --args "-u <host> -silent"`
(allowed: subfinder, dnsx, httpx, katana, waybackurls). Merge Prowl's
`input_testing` / coverage into the inventory; mark the source `prowl`.

## Write

`recon.json`:

```json
{ "target": "", "scope_file": "", "generated_at": "",
  "subdomain_enum": "skipped_exact_scope|done",
  "hosts": [{ "host": "", "url": "", "status": 0, "title": "", "tech": [] }],
  "endpoints": [{ "method": "", "url": "", "source": "crawl|js|prowl|wayback" }],
  "js_files": [{ "url": "", "endpoints": [], "notes": [] }],
  "parameters": [{ "method": "", "host": "", "path": "", "name": "",
                   "location": "", "source": "", "coverage_classes": [] }],
  "out_of_scope": [], "references": [], "prowl_session": null }
```

Also `RECON.md`: short summary, top surfaces ranked by attacker value, gaps
(auth not mapped, tools missing).

Stop. Next: `/threat-model bootstrap <url>` or `/pentest <url> --scope-file <file>`.
