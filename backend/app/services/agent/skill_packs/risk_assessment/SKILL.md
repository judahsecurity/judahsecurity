---
name: risk_assessment
description: Marcus RA — confirm/downgrade/upgrade severity from the demonstrated packet. No live retest.
---

# Risk assessment (Marcus)

Solomon judges whether it is a finding. Deborah re-derives the proof. **Marcus scores the published packet.**

After `create_finding` on medium+, call `assess_finding_risk`. Do not complete the engagement while RA is pending.

## Rules

1. Score **demonstrated evidence only**. Failed probes belong in `not_demonstrated`, not the chain.
2. **Do not live-retest.** Do not `execute_curl` / `execute_browser` against the host.
3. **Do not invent** writes, IMDS, RCE, or customer PII. Residual risk of those paths is `why_not_higher`, not Critical.
4. **Critical** requires demonstrated write, RCE, or cloud credential theft. Non-blind SSRF with IMDS/localhost blocked is **High**.
5. Open self-registration is the internet exposure (PR:N). It is a control failure, not a second finding.
6. Every remediation step needs `done_when` close criteria. Ticket closes only if `retest_criteria` all pass.

## Required JSON (pass as `assessment`)

```
verdict: confirm | downgrade | upgrade | keep_open
confirmed_severity, why_this_severity, why_not_higher, why_not_lower
cvss_score, cvss_vector (CVSS:3.1/…), cvss_basis=demonstrated
demonstrated: [{asset, result}, …]   ≥2 for medium+
not_demonstrated: [{target, outcome}, …]
control_failures: [{control, failure}, …]
business_risk, sla (now|this_week|follow_up)
remediation_sequence: [{when, action, done_when}, …]
retest_criteria: [string, …]   ≥3
ticket_title, ra_note, cwes
```

## Gold bar (Appsmith action SSRF)

Confirm **High**. Internet signup + REST action execute = non-blind SSRF from the AKS pod. `appsmith-0` hostname bypassed the IP allowlist (health + tenants). IMDS and localhost blocked → not Critical. Disable signup now; block pod DNS / RFC1918 / cluster names; lock datasource test to admins; NetworkPolicy egress.

If the tool returns `RA IMPROVE`, fix the named gaps and retry once.
