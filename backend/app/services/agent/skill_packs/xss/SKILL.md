---
name: xss
description: Hunt XSS on search/reflect params the page actually showed. Canary first, browser confirm. Not a generic injection dump.
---

# XSS (what the page showed)

Only attack inputs a human would type into: `q`, `search`, `name`, `message`, `comment`, `redirect`, `next`, `return`.

1. Canary in the observed param.
2. Map the HTML context (attribute / text / script / URL).
3. Confirm in browser for DOM sinks. CSP block is not a kill.
4. Stored: comments, profiles, filenames — only if those forms exist.

Status 200 is not XSS. Nuclei xss tags are leftover coverage, not this hunt.
