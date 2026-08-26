# Independent verify gate

Score what is in the run directory. Status 200 is never enough.

## confirmed

All of:

- Concrete request/response or file:line with the failing check
- Impact beyond "might be bad" (data, authz boundary, RCE class, secret)
- Aligns with a threat row when a threat model exists, or is a clear
  instantiation of a structural shape
- Not a duplicate of another confirmed row (same endpoint + same bug class)

Default/weak login alone is **not** confirmed. Need a privileged action after.

## improve

Real signal, missing proof. Examples: Nuclei template match with no follow-up;
SAST hit without reachability; IDOR guessed but no cross-identity body diff.

Say the single next probe. Do not invent that probe's result.

## refuted

Any of:

- Unreachable / dead code / docs-only
- Mitigated one layer up (WAF is not a kill; app-layer check is)
- Theoretical CWE with no instantiation
- Duplicate of a confirmed finding — keep one, refute the copy
- Out of scope per threat-model deprioritized / open questions

## Hygiene

Redact tokens, cookies, PII in TRIAGE.md. Keep endpoint, status, field names.
