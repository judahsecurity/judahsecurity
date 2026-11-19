---
name: unauth_settings_write
description: Planner scenario for a settings write endpoint missing [Authorize] (ASP.NET SaveSettings style).
triggers: (?i)/api/[^/?#\s]*settings[^/?#\s]*/(?:save|write|update)|/(?:save|write|update)settings\b
---

Unauth POST /api/Settings/SaveSettings 200 Content-Length: 0 while a sibling write (TaskAdmin/UpdateTask) is 401 is SUBMIT High (missing [Authorize]); GET GetSettings 500 is not a kill; one canary key (aegis-verify-*), do not replace production settings.

Validation bar: Unauth Settings/SaveSettings write IMPROVE until sibling write 401 vs SaveSettings 200 void is proven; GET GetSettings 500 is not a kill; one canary key, do not replace production settings.

Paired proof:
Unauth settings write: compare_requests(use_auth_session=false,
  baseline={"method":"POST","url":"https://app/api/TaskAdmin/UpdateTask"},
  mutant={"method":"POST","url":"https://app/api/Settings/SaveSettings",
  "json":{"settings":[{"key":"aegis-verify-key","value":"aegis-verify-ok"}]}})

Finding bar: Unauth SaveSettings 200 void vs sibling write 401 is High — GET 500 is not a kill; one canary key, do not replace production settings.
