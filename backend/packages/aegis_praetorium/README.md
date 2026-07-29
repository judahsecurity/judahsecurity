# aegis-praetorium

Aegis Vanguard's deterministic guard layer, shared between the platform agent
(`backend/app/services/agent/`) and the Aegis Vanguard agent (`aegis-vanguard/`).

> The Praetorium was the headquarters where Roman magistrates — the praetors,
> lictors, censors, and augurs — held court. This package houses the three
> "magistrate" components that govern every tool invocation in Aegis Vanguard.

## Components

- **Censor** (`censor.py`) — per-tool input validator. Rejects malformed or
  dangerous arguments before they reach Lictor or subprocess. Per-tool schemas
  (URL, hostname, json, integer, cli string) with shared validators for shell
  metacharacters, length bombs, command substitution, and required-flag /
  allowed-subcommand checks.
- **Lictor** (`lictor.py`) — pre/post tool-execution enforcer (Praetorian's
  "PreToolUse / PostToolUse / Stop" lifecycle equivalent). Default pre-hooks:
  `block_ssrf_targets`, `block_destructive_flags`, `inject_safe_defaults`,
  `enforce_scope` (uses the pluggable `ScopeResolver`), `rate_limit`. Default
  post-hooks: `audit_log`, `clip_output`.
- **Augur** (`augur.py`) — per-tool output interpreter. Filters raw scanner
  output into compact, high-signal text and emits structured `NextStep`
  recommendations the agent should chain into (e.g. nuclei detects WordPress
  on info severity → recommend `wpscan`; nuclei discovers `/admin` → recommend
  `ffuf` with the AdminPanels wordlist; nuclei discovers `/.git` → recommend
  `curl /.git/config`).

## Configuration

Two ways to configure:

```python
# Programmatic (preferred for the platform — pulls from app.core.config.settings)
from aegis_praetorium import PraetoriumConfig, set_config
set_config(PraetoriumConfig(
    lictor_enabled=True,
    censor_enabled=True,
    augur_enabled=True,
    enforce_scope=True,
    rate_capacity=30,
    rate_per_minute=30,
    tool_output_max_chars=20000,
))

# Env vars (preferred for Aegis Vanguard)
# AEGIS_LICTOR_ENABLED=true AEGIS_CENSOR_ENABLED=true AEGIS_AUGUR_ENABLED=true
# AEGIS_ENFORCE_SCOPE=false AEGIS_RATE_CAPACITY=30 AEGIS_RATE_PER_MINUTE=30
# AEGIS_TOOL_OUTPUT_MAX_CHARS=20000 AEGIS_AUGUR_VERBOSE=false
```

## Scope resolution (pluggable)

```python
from aegis_praetorium import HostListResolver, set_scope_resolver

# Aegis Vanguard: cli flag --scope example.com
set_scope_resolver(HostListResolver(["example.com"]))

# Platform: SQLAlchemy-backed lookup
from aegis_praetorium import ScopeResolver
class DbScopeResolver(ScopeResolver):
    def is_in_scope(self, hostname, *, org_id=None):
        # query Asset table for org_id, return True/False
        ...
set_scope_resolver(DbScopeResolver())
```

## Typical wiring

```python
from aegis_praetorium import get_lictor, get_censor, get_augur, HookContext

# Censor (before subprocess)
verdict = get_censor().validate("execute_nuclei", {"args": "-u https://x.com -jsonl"})
if not verdict.ok:
    return {"error": verdict.error}

# Lictor pre
ctx = HookContext(tool_name="execute_nuclei", args="-u https://x.com -jsonl",
                  parsed_args=["-u", "https://x.com", "-jsonl"],
                  command=["nuclei", "-u", "https://x.com", "-jsonl"],
                  org_id=42, user_id=1)
res = get_lictor().run_pre(ctx)
if not res.allowed:
    return {"error": res.reason}

# ... run subprocess ...

# Augur (after subprocess)
reading = get_augur().interpret("nuclei", raw_output, max_chars=20000)
if reading:
    return {"output": reading.to_text(), "augur": {
        "next_steps": [ns.to_dict() for ns in reading.next_steps],
        "kept": reading.kept, "dropped": reading.dropped,
    }}
```

## Tests

```bash
cd backend/packages/aegis_praetorium
python3 -m pytest
```

(See `tests/` for end-to-end smoke coverage of all three components against
synthetic nuclei JSONL, naabu/nmap text output, and various adversarial inputs.)
