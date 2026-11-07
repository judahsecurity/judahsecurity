# Prowl traffic capture (browser extension)

Records **your own** browsing of an in-scope target into Judah Security, so
traffic behind a login, 2FA or a captcha becomes searchable evidence next to
the requests Prowl sends itself.

You log in by hand; the extension records the tab through the Chrome DevTools
protocol and uploads batches to `POST /api/v1/traffic/ingest`. Recorded
exchanges appear on the **Traffic** page and can be attached to a finding from
its *Recorded traffic* panel.

## What is and is not recorded

* Document, XHR/fetch, EventSource and WebSocket-upgrade requests from the one
  tab you start capture on. Images, fonts, media and stylesheets are skipped.
* `Cookie`, `Set-Cookie`, `Authorization`, CSRF and API-key headers are
  replaced with `[redacted]` **in the browser**, before upload. The server
  redacts again with the evidence-store rules and caps each body at 256 KiB.
* The server stores an exchange only when its host is an **in-scope asset** of
  the API key's organization *and* passes the Rules of Engagement check.
  Everything else is reported back as out of scope and dropped.
* Captured traffic is a **discovery hint** for Prowl (`search_traffic`). It
  never grants the agent replay authority: Prowl re-issues a request itself
  before it can count as proof.

## Install (Chrome / Edge)

1. Create an API key with the `ingest:traffic` scope (admin):

   ```bash
   curl -X POST https://<platform>/api/v1/ingest/api-keys \
     -H "Authorization: Bearer <admin JWT>" -H "Content-Type: application/json" \
     -d '{"name": "browser-capture-<you>", "agent_type": "custom", "scopes": ["ingest:traffic"]}'
   ```

2. Open `chrome://extensions`, enable **Developer mode**, choose **Load
   unpacked** and select this `browser-extension/` directory.
3. Open the extension popup → **Settings**: enter the platform URL and the
   key, optionally a host allowlist, and **Save** (Chrome asks for permission
   to reach the platform).

## Use

1. Open the target in a tab and press **Start capture on this tab**. Chrome
   shows a "started debugging this browser" banner while recording.
2. Log in and use the application normally.
3. Press **Stop capture** (or close the tab, or cancel the banner). Remaining
   batches are flushed on stop.

The popup shows captured / stored / out-of-scope counts and the last upload
error. A `401`/`403` stops the capture: check the key and its scope.

## Tests

```bash
node --test browser-extension/capture.test.mjs
```

`background.js` exposes `globalThis.__prowlCapture` (start/stop/flush) so an
automated browser test can drive a capture without the popup.
