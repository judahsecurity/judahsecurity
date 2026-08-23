---
name: sqli
description: SQLi/SSTI/command injection on mapped non-reflect params. Canary then sqlmap on hits only.
---

# SQLi / SSTI / cmd (mapped params)

Skip pure search/reflect params (those belong to XSS).

1. Error / boolean / time canaries on ranked params.
2. `execute_sqlmap --batch` only on anomalous hits. No `--os-shell`.
3. `execute_commix` only on command-looking fields.
4. PASS needs a differential (body/time/error), not a template match.
