# Judah Capture (Chrome extension)

Hands Prowl a logged-in session that the agent cannot create on its own:
captchas, email or SMS codes, 2FA, SSO, device approval. An analyst logs in by
hand; the extension streams that tab's traffic to the running assessment as a
named test identity (for example `user_a`).

## What it captures

It uses the Chrome debugger protocol (`chrome.debugger`, Network domain), which
is the only extension API that sees:

- the request headers actually sent, including `HttpOnly` cookies;
- `Set-Cookie` on login redirects;
- response bodies (text only; images, fonts and media are skipped).

While capture is on, Chrome shows a "Judah Capture started debugging this
browser" bar. That is expected. Capture is per tab and stops when you press
Stop, close the tab, or dismiss the bar.

## Install

1. `chrome://extensions` → enable Developer mode → **Load unpacked** → select
   this `capture-extension/` folder.
2. In Judah, open the assessment on the agent page → **Capture a logged-in
   session** → set the identity name → **Get extension token**.
3. In the extension popup: paste the API base URL shown there
   (`https://<your-judah-host>/api/v1`) and the token, optionally restrict to
   the target's hosts, then **Start capture on this tab**.
4. Log in and use the app as that user. Press **Stop** when done.

Repeat with a second account (`user_b`) in another browser profile so Prowl can
test cross-user access.

## What happens server-side

- The token is HMAC-signed, bound to one assessment and one identity, and
  expires after four hours. The extension keeps it in memory/session storage
  only, never in `chrome.storage.local`.
- Batches are stored encrypted until the running assessment drains them.
- On drain, Prowl keeps only in-scope exchanges, registers the identity's
  cookies and auth headers (`Authorization`, `X-CSRF-Token`, …) in the identity
  registry, records each exchange as redacted `http_exchange` evidence, and maps
  the requests into operations specialists can mutate. The model sees the
  identity name, never the secrets.

No extension? Export a HAR from Chrome DevTools (Network tab → ⋯ → Save all as
HAR) and use **Upload HAR** on the same panel. Same pipeline, but no session
refresh.
