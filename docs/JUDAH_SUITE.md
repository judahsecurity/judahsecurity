# Judah suite for Prowl

Five Judah-built capabilities around the Prowl agent. All are our own code, in
`backend/app/services/agent/`. ARTEX is used only as a separate service over
its REST API (Judah Outrider); none of its code is in this repository.

| Name | Module | What it does |
|---|---|---|
| Judah Gate | `judah_gate.py`, `judah_gate_ca.py` | One local egress proxy for target traffic: per-run lease, scope check, per-host pacing, 429/503 backoff, hard request cap |
| Judah Hold | `judah_hold.py` | Pausing for CAPTCHA / OTP / MFA / emailed links / credentials without leaking them or being phished |
| Judah Whisper | `judah_whisper.py` | Read-only questions about a running or finished session |
| Judah Recheck | `judah_recheck.py` | Replays a published finding's stored proof recipe later |
| Judah Outrider | `judah_outrider.py` | Sends a session's scope to an external ARTEX instance and imports its findings as pending leads |

## Judah Gate

Enable with `JUDAH_GATE_ENABLED=1` on the API, schedule worker and scanner
worker. Each of those processes starts its own Gate.

| Setting | Default | Meaning |
|---|---|---|
| `JUDAH_GATE_BIND` | `127.0.0.1:8899` | Listen address (keep it on loopback) |
| `JUDAH_GATE_PROFILE` | `balanced` | `quiet` 1 rps / 1 in flight, `balanced` 5 rps / 4, `aggressive` 20 rps / 10, per host per run |
| `JUDAH_GATE_MAX_REQUESTS` | `5000` | Hard cap per run (0 = none) |
| `JUDAH_GATE_CA_DIR` | `$AEGIS_DATA_DIR/judah-gate` | Private CA and leaf key (mode 0600) |

How a run uses it:
- The orchestrator opens a lease for the run on its approved scope hosts. The
  lease token goes in the proxy credentials, so the Gate is not an open proxy.
- What goes through it: Python assessment HTTP (`assessment_proxy`), the
  scoped Chromium browser, and these CLI tools: nuclei, httpx, katana, ffuf,
  feroxbuster, sqlmap, dalfox, wpscan and curl. Proxy flags are added in the
  MCP chokepoint. A tool call that brings its own proxy flag is refused.
- HTTPS is terminated with the Judah Gate CA, so limits count requests, not
  connections. Chromium trusts only the Gate's leaf key
  (`--ignore-certificate-errors-spki-list`); other certificate errors still fail.
  The Gate verifies TLS to the target, and chains through Caido when
  `AEGIS_ASSESSMENT_PROXY_URL` is set.
- A host outside the lease returns `403` (`X-Judah-Gate: scope`). A spent
  budget returns `429` (`request-budget`) and ends the run with "Request budget
  reached". If the Gate is enabled but not running, the run stops before
  sending any request.

Not covered: raw TCP tools (nmap, naabu, masscan), WebSocket upgrades, HTTP/2,
and any tool not listed above. The lease token is visible in CLI arguments and
the MCP audit log for the life of the run.

## Judah Hold

Applies to every `ask_user` question:
- **Kind.** Each question is classified as `captcha`, `otp`, `mfa`,
  `email_link`, `credential` or `question` (`pending_question.hold.kind`).
- **Host check.** A question for a secret that names a host outside the run's
  scope, and not named by the operator, is refused before it reaches the
  analyst. A question of any other kind that does this is shown with a warning.
- **Secrets kept out.** For `captcha`, `otp`, `mfa` and `credential`, the
  answer goes into an in-process vault for 20 minutes. The model sees
  `{{judah_hold:<id>}}`, which is swapped for the real value only when a tool
  runs. The conversation log stores `[operator secret withheld]`, and tool
  output is scrubbed of the value.
- **Expiry.** Holds expire after 15 minutes; a late answer is discarded.

Limits: the vault is per process, so the answer must reach the process that
resumes the run (true for the `/agent/answer` route and the WebSocket). The raw
answer sits in the graph checkpoint for the one step before it is processed.

## Judah Whisper

`POST /agent/sessions/{session_id}/whisper` with `{"question": "..."}`.
- Answers from the checkpointed state, or the saved run snapshot, of a
  conversation you own.
- Makes one model call (the org's `report` model) with no tools. The snapshot
  is sealed and redacted.
- Does not steer, pause or charge the run purse.

## Judah Recheck

Uses the existing **Validate finding** action
(`POST /vulnerabilities/{id}/validate`).
- **At proof time,** the numeric and string Boolean SQLi probes remember the
  exact recipe they proved.
- **At publish time,** `create_finding` stores it as `metadata.recheck_recipe`
  when it is anonymous, a supported recipe, and its URL holds nothing
  secret-shaped.
- **At validate time,** the worker replays the recipe with a fresh nonce,
  scoped to the finding's origin and through the Gate when enabled.

| Outcome | Meaning | Validation verdict |
|---|---|---|
| `still_reproducible` | Proof confirmed again | `confirmed` |
| `fixed` | Stable baseline, differential gone | `false_positive` (as nuclei replays already do) |
| `cannot_confirm` | Anything else | `needs_more_evidence` |

The finding's status and original evidence are not changed. Results are added
to `metadata.recheck_history`.

Supported recipes: `numeric_and_boolean_v1`, `string_or_boolean_v1`,
`string_or_json_rows_v1`, `string_and_boolean_v1`.
- Not replayed: error-, time- and UNION-based proofs, browser-replayed proofs,
  and authenticated identities (credentials are never stored).
- Findings without a recipe keep the existing endpoint revalidation.

## Judah Outrider (ARTEX)

| Setting | Meaning |
|---|---|
| `JUDAH_OUTRIDER_URL` | ARTEX base URL, e.g. `http://artex:8787` |
| `JUDAH_OUTRIDER_TOKEN`, or `JUDAH_OUTRIDER_USERNAME` + `JUDAH_OUTRIDER_PASSWORD` | ARTEX API login |
| `JUDAH_OUTRIDER_STATE_DIR` | Where task links are kept (default `$AEGIS_DATA_DIR/outrider`) |

- **`POST /agent/sessions/{id}/outrider`** creates one ARTEX task with the
  session's seed host as scope, a Judah-written goal, and `target_gate: true`.
  No credentials are sent.
- **`POST /agent/sessions/{id}/outrider/import`** pulls the task's findings
  into the session through the external-candidate intake. They are untrusted
  text, scope-checked, severity-capped, at most 25, and left pending until
  Prowl's own verifier reproduces them. ARTEX's own verification is never
  accepted as proof.

Running ARTEX safely (from the trust review):
- Build it from a pinned commit you have reviewed, including its
  `github.com/BaaRai/Norma` dependency.
- Run it on its own network. Allow egress only to in-scope targets and your
  model endpoint, and no route to the platform's network.
- Its agent shell runs as root next to its own JWT and secret keys, so store
  nothing there you would mind losing. Use one instance per engagement, or
  wipe it afterwards.
- Disable or replace its default DuckDuckGo search, which can leak target
  names.
- Keep ARTEX unmodified, or publish your changes: the AGPL network clause
  applies to a modified copy offered over a network.
