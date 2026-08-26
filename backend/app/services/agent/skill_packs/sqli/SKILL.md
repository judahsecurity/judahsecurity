---
name: sqli
description: SQLi/SSTI/command injection on mapped non-reflect params and login/auth fields. Canary then sqlmap on hits only.
---

# SQLi / SSTI / cmd

Skip pure search/reflect params (those belong to XSS).

1. **Login/auth first** even when there are no query-string params. POST username/password or JSON `/login` `/signin` `/api/auth/login`: `compare_requests` baseline vs one mutation (error, then boolean pair, then timing pair). Timing that scales with SLEEP is SUBMIT with the table. Session from a canary is Critical. Not Appsmith `/user/login` email.
2. Error / boolean / time canaries on other ranked params.
3. `execute_sqlmap --batch` only on anomalous hits. No `--os-shell`.
4. `execute_commix` only on command-looking fields.
5. WAF/403: one `compare_requests` or `run_custom_probe` rewrite from the defense body, then prove or kill. Do not kill after a single scanner miss.
6. PASS needs a differential (body/time/error), not a template match.
