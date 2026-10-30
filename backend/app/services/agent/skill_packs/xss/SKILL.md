---
name: xss
description: Test observed inputs for reflected, DOM, and stored XSS with context-aware browser proof.
---

# XSS on observed inputs

Work the exact leased input and its observed rendering page. Prioritize search and
reflect parameters (`q`, `search`, `name`, `message`, `comment`, `redirect`, `next`),
but do not exclude another observed input because its name is unfamiliar or it is
encoded. An input may have both an XSS and a SQLi coverage cell; test each class
independently.

1. Verify the route and preserve the observed request shape. Use a unique canary
   in one field to locate the source; an archived parameter is only a lead until
   its route responds.
2. Trace the canary through decoding and rendering. Classify HTML text,
   attribute, script, URL, or client-side DOM context before choosing a probe.
3. Use the assigned scoped browser probe and its `xss_trace` feedback. Select an
   allowlisted technique and variant for the observed context; record each
   attempt's evidence ID. A reflection or HTTP 200 alone does not prove XSS.
4. Confirm execution with a fresh browser nonce, then submit a candidate with
   the exact coverage cell and receipt for independent replay. A CSP block on
   one payload leaves other applicable contexts untested.
5. Test stored XSS only through an observed form with an approved reversible
   write, separate readback, and cleanup. Do not POST to an unobserved form.

`mutate_list(kind='xss')`, `mutate_captured_request`, XSStrike, and Dalfox can
help investigate leads. Their output is not a substitute for browser proof.
