---
name: ssrf
description: SSRF via webhook/proxy/import/preview/datasource URL-fetch fields. OOB plus in-scope canary.
---

# SSRF / URL-fetch

Fields: `url`, `uri`, `webhook`, `callback`, `proxy`, `import`, `preview`, `datasource`, `requestUrl`, `execute`.

1. `execute_interactsh` register → plant `payload_url` → poll.
2. `compare_requests` benign URL vs in-scope canary.
3. Never `169.254.169.254` / localhost if Lictor blocks.
4. OOB DNS without an internal HTTP body is incomplete.
