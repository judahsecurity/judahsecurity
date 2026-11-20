# Prowl DevTools Sender

A Chrome/Edge DevTools panel that sends a request you captured in the
Network panel to a Prowl agent session as a **pending lead**.

Prowl does not trust it: the request goes to
`POST /api/v1/agent/sessions/{session_id}/candidates` (the same intake Aegis
Vanguard uses). The target must be inside the session's scope. The session's
own independent verifier has to reproduce the issue with fresh requests before
anything is filed.

Burp users: Prowl already attaches Burp (or Caido) as tools through their MCP
servers (`mcp_connect` in the agent), so there is no separate Burp plugin.

## Install (unpacked)

1. Open `chrome://extensions` (or `edge://extensions`), turn on Developer mode.
2. Load unpacked → choose this folder.
3. Open DevTools on the app you are testing → **Prowl** tab.
4. Settings → API base (for example `https://prowl.example.com/api/v1`),
   username/email and password → Sign in. Chrome asks for permission to
   reach that host.

## Use

1. Browse the target with DevTools open; requests appear in the list.
2. Pick a request, choose the agent session and vulnerability class, add a
   title, severity and optional parameter/notes.
3. Check the request preview, then **Send to Prowl as a lead**.
   - 201: added to an idle session; resume it so the verifier re-tests it.
   - 202: queued into the running session.
   - 409/422: no assessment state for that session, or the target is out of scope.

## Privacy

- `Cookie`, `Authorization`, `X-API-Key`, CSRF and similar header values are
  replaced with `[redacted]` unless you tick the box to include them.
- The request text is capped at 2000 characters (the API limit).
- The access token is kept in `chrome.storage.session` (memory, cleared when
  the browser closes). The password is not stored.
- API base must be `https` (plain `http` only for localhost).

## Tests

```bash
node --test tests/lib.test.js
```
