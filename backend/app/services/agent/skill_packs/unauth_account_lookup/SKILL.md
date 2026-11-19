---
name: unauth_account_lookup
description: Planner scenario for an account lookup API that answers without authentication (/api/auth/account/?email=).
triggers: (?i)/(?:api/)?auth/account\b
---

Unauth /api/auth/account/?email= is SUBMIT Critical if OpenAPI marks it security: {} with is_staff/role OR unauth lookup is 200/404/500 while /api/auth/profile/ is 401 — a down database or 404 existence oracle is not a kill; one canary email, do not spray; do not claim a 200 UserAccount body unless stdout has it.

Validation bar: Unauth /api/auth/account/ lookup IMPROVE until security: {} + is_staff/role is quoted or sibling 401 vs lookup 200/404/500 is proven; a down database or 404 existence oracle is not a kill; one canary email, do not spray; do not claim a 200 role body unless stdout has it. File Critical.
