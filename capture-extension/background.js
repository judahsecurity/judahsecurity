// Judah Capture: records one tab's network traffic through the Chrome
// debugger protocol (full request headers incl. cookies, and response bodies,
// which webRequest cannot read) and streams it to a Prowl assessment.

const FLUSH_MS = 2000;
const BATCH_MAX = 25;
const BODY_MAX = 256 * 1024;
const SKIP_TYPES = new Set(["Image", "Media", "Font", "Stylesheet", "Manifest", "Ping"]);

// tabId -> { config, pending: Map<requestId, entry>, queue: [], sent, failed, lastError }
const captures = new Map();

function hostAllowed(url, hosts) {
  if (!hosts.length) return true;
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
  return hosts.some((h) => host === h || host.endsWith("." + h));
}

function parkEarly(cap, requestId, kind, headers) {
  if (cap.early.size > 500) cap.early.clear();
  const row = cap.early.get(requestId) || {};
  row[kind] = headers;
  cap.early.set(requestId, row);
}

// Raw response headers (incl. Set-Cookie) arrive in a separate ExtraInfo event.
function finalize(entry) {
  if (entry.raw_response_headers) {
    entry.response_headers = { ...(entry.response_headers || {}), ...entry.raw_response_headers };
    delete entry.raw_response_headers;
  }
  return entry;
}

function headerObject(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) out[k] = String(v);
  return out;
}

function track(tabId, config) {
  const cap = {
    config, pending: new Map(), early: new Map(), hops: new Map(), finished: new Map(), queue: [], sent: 0, failed: 0, lastError: "",
    timer: setInterval(() => flush(tabId), FLUSH_MS),
  };
  captures.set(tabId, cap);
  return cap;
}

// The service worker can be suspended while the debugger stays attached.
// Rebuild in-memory state from session storage (memory-only, cleared when the
// browser closes) on the next event instead of silently dropping traffic.
async function ensure(tabId) {
  if (captures.has(tabId)) return captures.get(tabId);
  const key = `capture:${tabId}`;
  const stored = (await chrome.storage.session.get(key))[key];
  return stored && stored.config ? track(tabId, stored.config) : null;
}

async function flush(tabId) {
  const cap = captures.get(tabId);
  if (!cap || !cap.queue.length) return;
  const batch = cap.queue.splice(0, BATCH_MAX).map(({ raw_seen, raw_response_headers, ...row }) => row);
  try {
    const resp = await fetch(`${cap.config.server.replace(/\/+$/, "")}/agent/capture`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${cap.config.token}` },
      body: JSON.stringify({ entries: batch }),
      credentials: "omit",
    });
    if (!resp.ok) {
      cap.failed += batch.length;
      cap.lastError = `Server returned ${resp.status}`;
      if (resp.status === 401) await stop(tabId, "Capture token rejected or expired");
    } else {
      cap.sent += batch.length;
      cap.lastError = "";
    }
  } catch (err) {
    cap.failed += batch.length;
    cap.lastError = `Upload failed: ${err.message}`;
  }
  if (cap.queue.length) setTimeout(() => flush(tabId), 200);
}

async function start(tabId, config) {
  if (captures.has(tabId)) return;
  await chrome.debugger.attach({ tabId }, "1.3");
  await chrome.debugger.sendCommand({ tabId }, "Network.enable", {
    maxPostDataSize: BODY_MAX,
  });
  track(tabId, config);
  await chrome.storage.session.set({ [`capture:${tabId}`]: { config } });
}

async function stop(tabId, reason = "") {
  const cap = await ensure(tabId);
  if (!cap) return;
  await flush(tabId);
  clearInterval(cap.timer);
  captures.delete(tabId);
  await chrome.storage.session.remove(`capture:${tabId}`);
  try { await chrome.debugger.detach({ tabId }); } catch { /* already detached */ }
  if (reason) await chrome.storage.session.set({ lastStopReason: reason });
}

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  const cap = await ensure(source.tabId);
  if (!cap) return;
  const { pending } = cap;
  if (method === "Network.requestWillBeSent") {
    // A redirect reuses the requestId: close the previous hop (e.g. the login
    // POST whose 302 sets the session cookie) before tracking the next one.
    const prior = pending.get(params.requestId);
    if (prior && params.redirectResponse) {
      prior.status = params.redirectResponse.status;
      prior.response_headers = headerObject(params.redirectResponse.headers);
      prior.mime_type = params.redirectResponse.mimeType || "";
      prior.response_headers = {
        ...prior.response_headers, ...(prior.raw_response_headers || {}),
      };
      delete prior.raw_response_headers;
      pending.delete(params.requestId);
      cap.queue.push(prior);
      // Its raw headers (Set-Cookie) may still arrive; they carry the 3xx status.
      cap.hops.set(params.requestId, prior);
      if (cap.hops.size > 200) cap.hops.delete(cap.hops.keys().next().value);
    }
    const req = params.request;
    if (!/^https?:/.test(req.url) || SKIP_TYPES.has(params.type)) return;
    if (!hostAllowed(req.url, cap.config.hosts)) { cap.early.delete(params.requestId); return; }
    const early = cap.early.get(params.requestId) || {};
    cap.early.delete(params.requestId);
    pending.set(params.requestId, {
      method: req.method,
      url: req.url,
      request_headers: { ...headerObject(req.headers), ...(early.request || {}) },
      request_body: (req.postData || "").slice(0, BODY_MAX),
      raw_response_headers: early.response,
      captured_at: new Date().toISOString(),
    });
  } else if (method === "Network.requestWillBeSentExtraInfo") {
    // The headers actually sent on the wire, including Cookie. Chrome may emit
    // this before requestWillBeSent, so park it until the request appears.
    const headers = headerObject(params.headers);
    const entry = pending.get(params.requestId) || cap.finished.get(params.requestId);
    if (entry) entry.request_headers = { ...entry.request_headers, ...headers };
    else parkEarly(cap, params.requestId, "request", headers);
  } else if (method === "Network.responseReceivedExtraInfo") {
    const entry = pending.get(params.requestId);
    const headers = headerObject(params.headers);
    const hop = cap.hops.get(params.requestId);
    const code = params.statusCode || 0;
    if (hop && code >= 300 && code < 400 && hop.status === code && !hop.raw_seen) {
      // Late raw headers for a redirect hop already queued (not yet flushed).
      hop.response_headers = { ...hop.response_headers, ...headers };
      hop.raw_seen = true;
    } else if (entry) entry.raw_response_headers = headers;
    else if (cap.finished.has(params.requestId)) {
      const done = cap.finished.get(params.requestId);
      done.response_headers = { ...(done.response_headers || {}), ...headers };
    }
    else parkEarly(cap, params.requestId, "response", headers);
  } else if (method === "Network.responseReceived") {
    const entry = pending.get(params.requestId);
    if (!entry) return;
    entry.status = params.response.status;
    entry.response_headers = headerObject(params.response.headers);
    entry.mime_type = params.response.mimeType || "";
  } else if (method === "Network.loadingFinished") {
    const entry = pending.get(params.requestId);
    if (!entry) return;
    pending.delete(params.requestId);
    // Wire headers can arrive after loadingFinished (and while the body is
    // fetched below); keep the entry addressable until it is flushed.
    cap.finished.set(params.requestId, entry);
    if (cap.finished.size > 200) cap.finished.delete(cap.finished.keys().next().value);
    try {
      const body = await chrome.debugger.sendCommand(
        { tabId: source.tabId }, "Network.getResponseBody", { requestId: params.requestId },
      );
      if (!body.base64Encoded) entry.response_body = (body.body || "").slice(0, BODY_MAX);
    } catch { /* body evicted or not available */ }
    cap.queue.push(finalize(entry));
    if (cap.queue.length >= BATCH_MAX) flush(source.tabId);
  } else if (method === "Network.loadingFailed") {
    pending.delete(params.requestId);
    cap.early.delete(params.requestId);
  }
});

chrome.debugger.onDetach.addListener((source, reason) => {
  stop(source.tabId, `Debugger detached: ${reason}`);
});

chrome.tabs.onRemoved.addListener((tabId) => stop(tabId));

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "start") {
      await start(msg.tabId, msg.config);
      sendResponse({ ok: true });
    } else if (msg.type === "stop") {
      await stop(msg.tabId);
      sendResponse({ ok: true });
    } else if (msg.type === "status") {
      const cap = await ensure(msg.tabId);
      const { lastStopReason = "" } = await chrome.storage.session.get("lastStopReason");
      sendResponse(cap ? {
        active: true, identity: cap.config.identity, sent: cap.sent, failed: cap.failed,
        queued: cap.queue.length, lastError: cap.lastError,
      } : { active: false, lastStopReason });
    }
  })().catch((err) => sendResponse({ ok: false, error: err.message }));
  return true;
});
