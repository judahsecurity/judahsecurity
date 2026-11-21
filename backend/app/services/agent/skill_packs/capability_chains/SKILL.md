---
name: capability_chains
description: Treat proven results as capabilities and combine low-impact ones into a demonstrated chain.
---

# Capability chains

Record what each proven result lets you *do*, not just its name:
read_file, source_config, secret, credential, read_data, other_object,
victim_browser, cross_origin_read, redirect, server_fetch, forge_identity,
admin_surface, user_list, write_field, template_eval, host_poison.

When no single result has impact, ask which combination does:

| Have | Plus | Gives |
|---|---|---|
| read_file / source_config | admin_surface | credentials or bypass for the admin login |
| secret | a reachable API | direct API access beyond the public client |
| credential | admin_surface | privileged management features |
| read_data (SQLi) | admin_surface | account tokens/keys usable at login |
| victim_browser (XSS/CSRF) | admin_surface | privileged action as an admin |
| cross_origin_read | other_object / read_data | cross-origin data theft |
| redirect | OAuth/SSO or credential flow | code/token sent off-site |
| server_fetch (SSRF) | internal host from a leak | non-public internal response |
| forge_identity | admin_surface | admin functions |
| other_object | write_field | role/owner change on another account |
| user_list | host_poison | reset links to an attacker host |

Work backwards when stuck: pick the impact, name the missing primitive, and
look for the cheapest proven result or feature that supplies it. Product
features (export, webhooks, plugin/template editors, import) are primitives too.

Rules:

1. A chain is a hypothesis until every step has its own execution receipt.
   Call `suggest_capability_chains` to queue chain cards from proven results;
   prove or kill them with `update_hypothesis`.
2. File the chain through `create_finding` with `demonstrated_chain` listing
   each step's tool call and observed response. Severity follows the
   demonstrated end impact, not the strongest-sounding step.
3. Stay non-destructive: test identities you own, read-only actions, canary
   writes with read-back and revert. Do not crack hashes, log in as real
   users, or run commands beyond a harmless marker.
4. Record a step that fails as a killed hypothesis so it is not retried.
