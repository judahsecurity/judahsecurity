// Records the operator's own browsing of one tab via the DevTools protocol and
// uploads it to POST {platform}/api/v1/traffic/ingest in batches.

import { MAX_BATCH, RECORDED_TYPES, hostAllowed, newCaptureId, toEntry } from './capture.js';

const FLUSH_MS = 3000;
const PROTOCOL = '1.3';

// One capture at a time; state survives popup close but not browser restart.
let capture = null; // { tabId, captureId, settings, pending: Map, queue: [], stats }
let flushTimer = null;

async function loadSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return settings || { baseUrl: '', apiKey: '', allowlist: [] };
}

async function setStatus(extra = {}) {
  const status = capture
    ? { active: true, tabId: capture.tabId, captureId: capture.captureId, ...capture.stats, ...extra }
    : { active: false, ...extra };
  await chrome.storage.session.set({ status });
  chrome.action.setBadgeText({ text: capture ? 'REC' : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#b91c1c' });
  return status;
}

async function flush() {
  if (!capture || !capture.queue.length) return;
  const { settings, captureId } = capture;
  while (capture && capture.queue.length) {
    const entries = capture.queue.splice(0, MAX_BATCH);
    try {
      const res = await fetch(`${settings.baseUrl}/api/v1/traffic/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${settings.apiKey}` },
        body: JSON.stringify({ capture_id: captureId, entries }),
      });
      if (!res.ok) {
        capture.stats.lastError = `Upload failed: HTTP ${res.status}`;
        if (res.status === 401 || res.status === 403) {
          await stop(`Upload rejected (HTTP ${res.status}). Check the API key and its ingest:traffic scope.`);
          return;
        }
        capture.queue.unshift(...entries); // retry next tick
        break;
      }
      const body = await res.json();
      capture.stats.uploaded += body.accepted || 0;
      capture.stats.rejected += (body.rejected || []).length;
      capture.stats.lastError = (body.rejected || [])[0]?.reason || '';
    } catch (err) {
      capture.stats.lastError = `Upload failed: ${err.message}`;
      capture.queue.unshift(...entries);
      break;
    }
  }
  await setStatus();
}

async function onEvent(source, method, params) {
  if (!capture || source.tabId !== capture.tabId) return;
  const { pending } = capture;
  if (method === 'Network.requestWillBeSent') {
    if (!RECORDED_TYPES.has(params.type || 'Other')) return;
    if (!hostAllowed(params.request.url, capture.settings.allowlist)) return;
    if (!/^https?:/.test(params.request.url)) return;
    // Register synchronously: responseReceived can arrive before any await resolves.
    pending.set(params.requestId, {
      request: params.request,
      pageUrl: params.documentURL || null,
      startedAt: params.timestamp,
    });
  } else if (method === 'Network.responseReceived') {
    const item = pending.get(params.requestId);
    if (item) item.response = params.response;
  } else if (method === 'Network.loadingFinished' || method === 'Network.loadingFailed') {
    const item = pending.get(params.requestId);
    if (!item) return;
    pending.delete(params.requestId);
    item.finishedAt = params.timestamp;
    let body = null;
    if (method === 'Network.loadingFinished') {
      try {
        const res = await chrome.debugger.sendCommand({ tabId: capture.tabId }, 'Network.getResponseBody',
          { requestId: params.requestId });
        body = res.base64Encoded ? null : res.body;
      } catch {
        body = null; // evicted or unavailable
      }
      if (item.request.hasPostData && item.request.postData == null) {
        try {
          const post = await chrome.debugger.sendCommand({ tabId: capture.tabId }, 'Network.getRequestPostData',
            { requestId: params.requestId });
          item.request.postData = post.postData;
        } catch { /* ignore */ }
      }
    }
    if (!capture) return;
    capture.queue.push(toEntry(item, body));
    capture.stats.captured += 1;
    if (capture.queue.length >= MAX_BATCH) flush();
  }
}

async function start(tabId) {
  if (capture) throw new Error('A capture is already running.');
  const settings = await loadSettings();
  if (!settings.baseUrl || !settings.apiKey) throw new Error('Set the platform URL and API key first.');
  await chrome.debugger.attach({ tabId }, PROTOCOL);
  await chrome.debugger.sendCommand({ tabId }, 'Network.enable', { maxPostDataSize: 256 * 1024 });
  capture = {
    tabId, settings, captureId: newCaptureId(), pending: new Map(), queue: [],
    stats: { captured: 0, uploaded: 0, rejected: 0, lastError: '' },
  };
  flushTimer = setInterval(flush, FLUSH_MS);
  return setStatus();
}

async function stop(reason = '') {
  if (!capture) return setStatus({ lastError: reason });
  const { tabId } = capture;
  clearInterval(flushTimer);
  flushTimer = null;
  await flush();
  const stats = capture ? { ...capture.stats } : {};
  capture = null;
  await chrome.debugger.detach({ tabId }).catch(() => {});
  return setStatus({ ...stats, lastError: reason || stats.lastError || '' });
}

chrome.debugger.onEvent.addListener((source, method, params) => { onEvent(source, method, params); });
chrome.debugger.onDetach.addListener((source, reason) => {
  if (capture && source.tabId === capture.tabId) {
    stop(reason === 'canceled_by_user' ? 'Capture stopped from the browser banner.' : '');
  }
});
chrome.tabs.onRemoved.addListener((tabId) => { if (capture && capture.tabId === tabId) stop('Tab closed.'); });

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === 'start') sendResponse({ ok: true, status: await start(message.tabId) });
      else if (message.type === 'stop') sendResponse({ ok: true, status: await stop() });
      else if (message.type === 'status') sendResponse({ ok: true, status: await setStatus() });
      else sendResponse({ ok: false, error: 'unknown message' });
    } catch (err) {
      sendResponse({ ok: false, error: err.message });
    }
  })();
  return true; // async response
});

// Test hook for the Playwright end-to-end check (not used by the popup).
globalThis.__prowlCapture = { start, stop, flush };
