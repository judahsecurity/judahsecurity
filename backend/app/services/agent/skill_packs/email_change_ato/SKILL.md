---
name: email_change_ato
description: Planner scenario for an email-change endpoint that skips authentication (djoser reset_email style).
triggers: (?i)reset_email|reset_email_confirm|change_email|update_email|/email/change|/users/set_email
---

Validation bar: Unauth email-change IMPROVE until set_password 401 vs reset_email 204 is proven; one canary; do not complete ATO on a real mailbox.

Paired proof:
Email-change ATO: compare_requests(use_auth_session=false,
  baseline={"method":"POST","url":"https://app/api/auth/users/set_password/"},
  mutant={"method":"POST","url":"https://app/api/auth/users/reset_email/",
  "json":{"email":"aegis-ato-canary@example.invalid"}})
