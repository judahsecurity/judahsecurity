# Assessment secret detection

Judah Security Full assessments treat public JavaScript secret discovery as a
required coverage lane. The pipeline inventories bundles with Katana, extracts
paths and parameters with jsluice, and then applies complementary detectors:

- curated provider and generic credential patterns;
- Gitleaks filesystem scanning (`--no-git --redact`);
- structural detection for HMAC, encryption, MQTT, and RFID credentials that
  are reconstructed at runtime and do not exist as one string literal;
- exposed source maps, hidden API routes, dependency-confusion candidates, and
  DOM execution sinks.

`scan.results.assessment_coverage.javascript_security` records completed,
degraded, partial, or skipped status plus tool errors and finding counts. A
missing optional binary is visible as degraded coverage rather than a silent
pass.

Authorized repository history is covered by the separate **Repository Secrets
(TruffleHog)** scan. The UI accepts Git URLs and GitHub owner/repository slugs;
the API also supports explicitly configured GitLab, filesystem, and object-store
sources. Private-source credentials are never inferred from a web target.

## Secret handling

Raw credential material is used only transiently during detection and optional
validation. Scan summaries and vulnerability evidence store a SHA-256
fingerprint, length, source URL, detector, and redaction marker. They do not
store the raw value or reconstructable property-name fragments.

Live provider validation is disabled by default. Set `verify_secrets=true` only
when the rules of engagement authorize read-only validation calls. Rotate a
confirmed browser-shipped credential; do not turn the assessment platform into
a credential vault.

## Agent Intruder workflow

The agent exposes two complementary tools:

1. `plan_intruder_mutations` creates a dry-run queue from captured API traffic.
   It covers object authorization, boundary inputs, parser canaries, and
   URL-fetch/redirect fields. Each entry changes one field.
2. `run_intruder_batch` executes at most 12 baseline/mutant comparisons at a
   bounded rate. It is operator-confirmation gated, enforces assessment scope on
   every request, and excludes state-changing methods unless explicitly enabled.

Response differences are leads, not confirmed findings. Analysts must validate
that another user's data, an authorization boundary, or a security-relevant
parser behavior was actually demonstrated.
