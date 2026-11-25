# Aegis Claude Code skills

Run this like Glasswing: open the harness folder in Claude Code, invoke slash
skills, point them at **your** checkout or URL. No bundled canary.

```bash
cd aegis-vanguard
claude
# then:
/aegis
/threat-model bootstrap /path/to/their/app
/code-scan /path/to/their/app
/triage results/<app-basename>/<timestamp>/
```

Live (authorized URL). Write a scope file first (format in
`.claude/skills/_lib/scope.py`: exact hosts, `*.root` wildcards, `!exclusions`):

```
export AEGIS_API_URL=http://localhost:8000      # platform; /api/v1 optional
export AEGIS_API_TOKEN=<user JWT access token>  # from POST /api/v1/auth/login
/recon   https://app.example.com --scope-file scope.txt
/pentest https://app.example.com --scope-file scope.txt
/triage  results/app.example.com/<timestamp>/ --reprobe --scope-file scope.txt
/chain   results/app.example.com/<timestamp>/
```

`/pentest` hands execution to **Prowl** (the platform agent) through
`prowl_client.py`: Prowl owns the scoped browser, OOB callbacks, deterministic
proof probes, the independent verifier and the publication gate. curl in the
session is for leads only. `--local` hunts without Prowl (medium+ stays
`improve`). `--cli` runs `python3 run_pentest.py --target …` instead.

## Cycle

```
/aegis → /recon (live, scoped) → /threat-model
       → /code-scan  (checkout, static; Claude is the scanner)
       → /pentest    (live URL; Prowl executes)
       → /triage     (gate + root-cause dedup + Prowl re-probe)
       → /chain      (chain-required table; end-to-end proof only)
```

## Shared class list and gate

`data/vuln_classes.json` is generated from Prowl's
`backend/app/services/agent/proof_policy.py:PROOFS_BY_CLASS` and
`vulnerability_catalog.py` coverage classes:

```bash
python3 scripts/sync_vuln_classes.py          # regenerate
python3 scripts/sync_vuln_classes.py --check  # CI drift check
```

`tests/test_vuln_classes_sync.py` asserts the JSON matches the backend when the
backend is importable (skips otherwise). Rule shared with Prowl: medium or
above only with a proof kind for the class; classes without proof kinds and
`known_cve` cap at low. Gate details: `.claude/skills/triage/gate.md`
(validation discipline adapted from elementalsouls/Claude-BugHunter, CC BY 4.0).

## prowl_client.py endpoints

| Command | Endpoint (under `/api/v1`) | Auth |
|---------|----------------------------|------|
| `status` | `GET /agent/status` | none |
| `asset --host` | `GET /assets/?search=&in_scope=true` | JWT |
| `start` | `POST /agent/query` (`mode=agent`, `target`, `playbook_id`, `assessment_policy`) | JWT |
| `start --executor` | `POST /agent/scoped-assessments` (legacy scoped executor) | JWT |
| `poll` | `GET /agent/conversations/{sid}`, `GET /agent/conversations/{sid}/ledger` | JWT |
| `findings` | `GET /vulnerabilities/?asset_id=&detected_by=agent_family` | JWT |
| `verify` (live session) | `POST /agent/sessions/{sid}/candidates`, then `POST /agent/query` (resume `sid`) when idle (201), or `POST /agent/sessions/{sid}/steer` when the run is active (202 `queued`; `mode=intake_queued`) | JWT |
| `verify` (fallback) | `POST /agent/query` with `playbook_id=finding_validation` + redacted packet | JWT |
| `candidates` | `GET /agent/sessions/{sid}/candidates` | JWT |
| `probe` | `POST /agent/sessions/{sid}/intents` (one operator-directed test; scope-checked locally first) | JWT |
| `intents` | `GET /agent/sessions/{sid}/intents` | JWT |
| `verdict` | candidate status from `candidates` when intake was used; else ledger receipts | JWT |
| `stop` | `POST /agent/sessions/{sid}/stop` | JWT |
| `identities` / `start --identity-file` | logs each identity in locally (`agent/identity_sessions.py`), then `POST /agent/sessions/{sid}/identities` with cookies + auth headers only | JWT |
| `har` | `POST /agent/sessions/{sid}/har` (DevTools HAR of a logged-in session) | JWT |
| `capture-token` | `POST /agent/sessions/{sid}/capture-token` (for the capture extension) | JWT |
| `tool` | `POST /mcp/call` (subfinder, dnsx, httpx, katana, waybackurls; scope-checked) | JWT |
| `classes` | local `data/vuln_classes.json` | — |
| `classes --remote` | `GET /agent/proof-classes` | JWT |

### Candidate intake (closed gap)

`POST /agent/sessions/{sid}/candidates` (JWT; owner user + org of that
conversation, agent-mode sessions only) takes
`{title, target, vulnerability_class, description, claimed_request (<=2000),
severity, parameter?, evidence_note?}`:

- `target` must be inside the session's scope (the session's saved seed,
  checked with `assessment_scope.assert_url_in_scope`); `vulnerability_class`
  must be a `PROOFS_BY_CLASS` key (resolve aliases client side).
- The candidate is appended as **pending** through `submit_candidate` with
  `specialist=vanguard_external`, no `evidence_ids` and empty `evidence`.
  Text is length-capped, control characters stripped, and wrapped in
  `[OPERATOR-SUPPLIED CANDIDATE CLAIM ...]` markers because the verifier LLM
  sees it. Severity is capped at `low` for `known_cve` and classes with no
  proof kind.
- An existing candidate with the same id or root cause is reported as
  `duplicate_of` and left untouched: external text cannot reopen or rewrite a
  session verdict. At most 25 external candidates per session (429).
- Persistence: the brain lives in LangGraph state during a run and in the run
  snapshot (`run_snapshot.py`, `~/.aegis/sessions` or the DB for `sched-`
  sessions) between runs; every resume restores it from that snapshot. Idle
  intake writes the snapshot (**201**). While a run is active the same
  validation runs, then the wrapped payload goes into the session's
  durable candidate inbox (`run_control`: written through to
  `~/.aegis/sessions/{org}_{sid}.inbox.jsonl` before the response, with an
  in-memory cache) and the route returns **202** `{accepted, queued: true, next_step}`. The
  orchestrator drains the inbox where it drains steers (start of each think
  turn), submits each item through the same `submit_candidate` path into the
  live brain, and records an `external_candidate_intake` trace step plus a
  `candidates_ingested` status event; a root-cause duplicate found at drain
  time is reported as `duplicate_of` and not modified. The 25 cap counts
  queued items, including ones left on disk by an earlier process. **409** only
  when the session has no snapshot/target. Delivery is at-least-once: an item
  is removed from the inbox only after the run snapshot holding it is saved; a
  re-delivered item merges as a duplicate (never inserted twice). A backend
  restart before the drain keeps the item; the next think turn of the resumed
  run (same `session_id`) drains it. A run ending without a drain also keeps it.
  Two inbox stores sit behind the same `run_control` API, chosen by
  `AEGIS_CANDIDATE_INBOX_BACKEND`: `file` (the flock-locked JSON-lines file,
  safe on one host), `db` (one `agent_candidate_inbox` row per item, safe
  across hosts; use it for multi-host deployments), or unset/`auto` (default:
  `db` for `sched-` sessions, whose snapshot is already in the DB, `file`
  otherwise). The DB store redacts the same claim fields at rest, counts rows
  for the 25 cap, claims rows with a token (`FOR UPDATE SKIP LOCKED` on
  Postgres) so two workers never merge the same row, deletes only claimed rows
  on settle, and re-delivers a claim older than
  `AEGIS_CANDIDATE_INBOX_CLAIM_STALE_SECONDS` (default 600). The table is
  created by `python -m scripts.apply_agent_ledger_migration` (and by
  `create_all` at API start).
- Nothing is confirmed by intake. Resuming an idle session (`POST /agent/query`,
  same `session_id`), or the live run after the inbox drains, lets Prowl verify it: the tester loop forces
  `independent_verify` for pending `sql_injection`/`xss`; for other classes the
  resume note (or, for a running session, a steer) names the candidate id. Deterministic replays need a hunter
  receipt from that session; without one the class is re-hunted or the LLM
  verifier attempts it, and `inconclusive` is expected.

`GET /agent/sessions/{sid}/candidates` lists id, title, class, severity,
status, verifier_summary, root_cause, duplicate_titles (no evidence bodies,
nonces or requests) from the last snapshot, plus undrained inbox items with
status `queued`, plus `run_in_progress`. `verdict` maps `queued` to `pending`.

`GET /agent/proof-classes` returns `PROOFS_BY_CLASS` (sorted kinds), coverage
classes with their proof class and lane, `severity_caps` and
`non_confirmable`. `data/vuln_classes.json` stays as the offline copy.

### Operator-directed probing (closed gap)

`probe --session S --target URL --test-type T --scope-file F [--parameter P
--location L --method M --identity I --note TXT --baseline-value V |
--body-sample BODY]` plans one test on any
in-scope URL and input, including inputs Prowl never observed. The client
checks the scope file, the class (coverage class or alias: `cmdi`, `lfi`,
`redirect`, `template_injection`, ...) and the location locally; it also
accepts `probes.py` specs (`header:X-Debug`, `cookie:theme`, `json:a.b`,
`form:file`). The backend re-validates: exact URL on the session's seed origin
(no credentials, fragment or credential-bearing query), coverage class,
location in `query | body_form | body_json | body_xml | header | cookie | path
| fragment`, method `GET | POST | PUT | PATCH | DELETE`. It stores an `operator`
fact plus an intent (`created_by=operator`) backed by a coverage cell. Idle
session: 201, written to the snapshot. Running session: 202 `queued`, merged at
the next think turn. Same intent twice: 200 with `duplicate_of`. At most 50
operator intents per session (429). The note is wrapped as untrusted text and
never directs the probe.

Prowl's leased scoped probes then build the request from the intent:

| Class | Locations | Methods |
|-------|-----------|---------|
| ssti, command_injection, path_traversal | query, header, cookie, body_form, body_json, body_xml, path | GET, POST, PUT, PATCH, DELETE |
| crlf, open_redirect | query, header, cookie, body_form, body_json, body_xml, path | GET, POST, PUT, PATCH, DELETE |
| sqli (string Boolean OR/AND, error, UNION, time; numeric Boolean) | query, header, cookie, body_form, body_json, body_xml, path | GET, POST, PUT, PATCH, DELETE |
| nosql (operator differential) | query, body_form, body_json (operators), cookie (`j:` JSON), header (JSON baseline only), body_xml (operator elements), path (string `$where`/`$regex` recipes) | GET, POST, PUT, PATCH, DELETE (path: GET/POST) |
| xss (browser nonce execution) | query, fragment | GET |

Body locations need a non-GET method. `body_xml` takes an element name or a
path (`xml:order.note` becomes `/order/note`); the value is XML-escaped into
one text node, no DOCTYPE. `path` names one segment by 0-based index
(`path:2`) or its exact literal (`path:alice`); only that segment changes.
`fragment` is client-side only (the server never receives it), so only xss
tests it (`fragment:q` makes `#q=<payload>`, `fragment:*` makes `#<payload>`).

**Baselines.** `--baseline-value` is the input's ordinary value (1-512
printable characters; it must match the value the `--target` already carries
for a query field or path literal). `--body-sample` takes a JSON or form body
and sends only the named field's value as the baseline. Prowl's own
`add_intent` can instead cite `source_capture_id`, the browser exchange the
test comes from (same method, path and identity), and the probe takes the
baseline value and request from that capture. Numeric Boolean SQLi runs only
when the baseline is a positive integer; UNION (NULL-padded column discovery,
hex-encoded marker reflected only by query execution) only when an ordinary
string baseline's fresh response reflects result data; both first fetch a fresh
baseline with that exact value. NoSQL on a header needs the header's JSON
object/array value with exactly one string field (`{"user":"alice"}`); the
intake refuses it otherwise. Cookies are probed as Express cookie-parser JSON
cookies (`j:{"$ne":"<nonce>"}` and `j:{"$eq":...}` against the literal), XML as
`<field><$ne>nonce</$ne></field>` against `<field>nonce</field>` (strict XML
parsers reject `$`, so they never confirm), path segments only with string
recipes (`' || 'a'=='a` / `' && 'a'=='b`, the double-quote pair, and
`<lit>|.*` / `(?:<lit>)`). Every NoSQL location uses the same interleaved
differential: stable always-true variant that differs from the literal
control, same-meaning variant equal to the control. Missing baselines leave
recipes skipped (`numeric_skipped`, `union_skipped`) or the cell open, never
`tested_clean`. The independent verifier replays the hunter's recipe through
the same builder and baseline source with fresh nonces.

Method approval comes from the start `--policy-file`: GET is free; POST needs
the path in `body_replay_paths`.

**Write probes only ever touch records Prowl created and verified as its
own.** PUT/PATCH/DELETE never modify a company's existing data, even when the
intent names a real record. The policy names, at most four times, how Prowl
may make a dummy record:

```json
{"test_record_endpoints": [{
  "create_path": "/api/notes",
  "create_body": {"title": "__PROWL_NONCE__"},
  "content_type": "json",
  "record_path": "/api/notes/{id}",
  "id_source": "location",
  "write_methods": ["PUT", "PATCH", "DELETE"],
  "cleanup": "delete",
  "cleanup_delete_approved": true
}]}
```

Paths are exact (no query, fragment, `%` or dot segments); `record_path` has
exactly one `{id}` and nowhere else; `create_body` (JSON object, or a form
string for `content_type: form`) must contain `__PROWL_NONCE__`; `id_source`
is `location` (the create response's same-origin Location matching
`record_path`) or `json:<dotted.field>`; ids must be 1-64 of `[A-Za-z0-9_-]`.
`cleanup: delete` needs `cleanup_delete_approved: true`: that cleanup DELETE is
the only DELETE Prowl sends besides a DELETE probe on its own record.

For each PUT/PATCH/DELETE probe Prowl: matches the intent path to a
`record_path` with the method in `write_methods` (a concrete id such as
`/api/notes/42` is never used; the request is retargeted); POSTs `create_path`
with a fresh nonce (same identity, exact origin, no redirects); GETs the new
record and requires the nonce; sends the probe only to that record URL
(header/cookie/query/body inputs; `path` inputs are refused for writes); then,
for `cleanup: delete` or a DELETE probe, DELETEs it and GETs again to confirm
404/410/nonce gone (`cleaned`). A create without a usable id, a record whose
nonce cannot be read back (never deleted: it may not be Prowl's), a failed
cleanup or `cleanup: none` leaves the record `cleanup_pending`. A DELETE probe
uses a fresh record per request. The independent verifier creates its own
fresh record. Creates and cleanups spend the POST budget. `prowl_client.py
intents` and the run summary list `test_records`; every `cleanup_pending`
record is reported for you to remove. Intake refuses (422) a write intent with
no matching endpoint; without one at run time the probe returns
`operator_approval_required` and the cell stays open; a record that is not
provably Prowl's returns `test_record_aborted` and nothing is probed. Host, Cookie,
Authorization, framing, X-Forwarded-Host and credential-like headers, and
credential-like or HttpOnly identity cookies, are never mutated. Anything else
(xss on header/cookie/body/path, sqli/server classes on fragment, nosql on
header/cookie/xml/path, a path segment the URL lacks) stays open/inconclusive
with `unsupported_shape` and the intent is `blocked`; it is never
`tested_clean`. A probe signal is still a lead until Prowl's independent
verifier replays it with the same request builder. `intents --session S` shows
status, result facts and the backing cell's status.

### Test identities (closed gap)

`identities` (or `start --identity-file`) reads a Vanguard identity file
(`agent/identities.py` format), logs each identity in on this machine with the
Vanguard login engine, and hands Prowl only the resulting session: exact
origin, cookies and auth headers. Passwords never leave this machine. The
backend stores the material encrypted in the operator-capture inbox, checks it
against the engagement scope when the run drains it at its next think turn, and
registers a named identity the model can use but never see. Identities whose
login is rejected are not sent; `ready_unverified` ones (no success marker) need
`--allow-unverified`. Prowl does not refresh CSRF tokens or re-login on expiry;
re-run `identities` for a new session.

### Remaining API gaps (documented, not invented)

1. **`POST /prowl/findings` is not usable by Vanguard.** It requires the
   `PROWL_INGEST_KEY` service key and paired hunter/verifier observations with
   run/candidate/verification IDs produced by the scoped executor. Vanguard
   must not fabricate those. Use candidate intake instead.
2. **Candidate inbox is single-host unless the DB store is on.** Intake into a
   running session is queued (202) and survives restarts. With the default
   `file` store (non-`sched-` sessions) backends on several hosts do not share
   it; set `AEGIS_CANDIDATE_INBOX_BACKEND=db` there. A crashed claimer's items
   wait out the stale-claim window before re-delivery.
   Without a live session `verify` uses the `finding_validation` playbook; with
   `playbook_id` the backend keeps only the text after `Operator note:`
   (<=4000 chars), so that packet is trimmed and redacted.
3. **Findings are not linked to a session in the list API**
   (`VulnerabilityResponse` has no session id); per-run results come from the
   ledger receipts and `candidates`, per-asset results from `/vulnerabilities`.
4. **JWT only.** `/agent/*` uses user access tokens (expire); ingest API keys
   (`tfasm_…`) are not accepted. `/agent/status` and `/agent/playbooks` are
   unauthenticated.
5. **No per-probe REST, by design.** Browser, OOB and scoped proof probes run
   only inside a Prowl session, where coverage leases, scope, operator write
   approvals and budget apply. Exposing them over REST would bypass all four.
   Reach them with `start` (or an existing session) + candidate intake +
   resume. `/mcp/call` exposes CLI recon wrappers, not proofs.
6. `POST /ingest/findings` (API key) bypasses the gate; do not use it for
   medium+ Vanguard findings.

## Requirements

- Claude Code CLI, launched from `aegis-vanguard/`
- Local path: a checkout the operator names. Nothing else for `/threat-model`.
- Live path: authorization, a scope file, `curl` on `$PATH`; `AEGIS_API_URL` +
  `AEGIS_API_TOKEN` for Prowl. `ANTHROPIC_API_KEY` if using `--cli`.
  Optional local recon tools: subfinder, dnsx, httpx, katana.

## Run directories

Outputs go to `aegis-vanguard/results/<target>/<timestamp>/` (gitignored).
Repeat runs resume the latest dir unless `--fresh`.

## Size rule

`SKILL.md` stays under 150 lines. Methodology lives in sibling files
(`schema.md`, `researchers.md`, `gate.md`), `_lib/*.py`, or Python
(`run_pentest.py`, `prowl_client.py`).
Do not grow skills by pasting platform playbooks.

## Platform agent (optional)

In-product Joshua is a different harness:

```bash
cd ../backend
python -m app.cli run --target https://app.example.com --playbook tester_process
```
