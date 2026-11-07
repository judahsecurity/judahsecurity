// Pure helpers shared by the service worker and the Node tests.

export const MAX_BODY_CHARS = 256 * 1024;
export const MAX_BATCH = 50;

// Chrome DevTools resource types worth recording. Images, fonts, media and
// stylesheets add noise and bytes without exposing application inputs.
export const RECORDED_TYPES = new Set(['Document', 'XHR', 'Fetch', 'Other', 'EventSource', 'WebSocket']);

// Never leave the browser, even though the server redacts again.
const SECRET_HEADER = /^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;

export function stripSecretHeaders(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) {
    out[name] = SECRET_HEADER.test(name) ? '[redacted]' : String(value ?? '');
  }
  return out;
}

export function isBinaryMime(mime) {
  const m = String(mime || '').toLowerCase();
  return m.startsWith('image/') || m.startsWith('font/') || m.startsWith('audio/') || m.startsWith('video/')
    || m === 'application/octet-stream' || m === 'application/pdf' || m === 'application/zip';
}

export function hostAllowed(url, allowlist) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  const rules = (allowlist || []).map((r) => r.trim().toLowerCase()).filter(Boolean);
  if (!rules.length) return true; // server-side scope check still applies
  return rules.some((rule) => {
    const bare = rule.startsWith('*.') ? rule.slice(2) : rule;
    return host === bare || host.endsWith(`.${bare}`);
  });
}

export function truncate(text) {
  if (text == null) return null;
  const s = String(text);
  return s.length > MAX_BODY_CHARS ? s.slice(0, MAX_BODY_CHARS) : s;
}

/** Build one ingest entry from accumulated DevTools Network events. */
export function toEntry(pending, responseBody) {
  const { request, response, pageUrl, startedAt, finishedAt } = pending;
  const mime = response?.mimeType || '';
  return {
    method: request.method,
    url: request.url,
    status: response?.status ?? null,
    request_headers: stripSecretHeaders(request.headers),
    request_body: truncate(request.postData ?? null),
    response_headers: stripSecretHeaders(response?.headers),
    response_body: isBinaryMime(mime) ? null : truncate(responseBody),
    elapsed_ms: startedAt && finishedAt ? Math.max(0, Math.round((finishedAt - startedAt) * 1000)) : null,
    page_url: pageUrl || null,
  };
}

export function newCaptureId() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `cap-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export function normalizeBaseUrl(value) {
  const url = new URL(String(value || '').trim());
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
    throw new Error('Use an https:// platform URL (http is allowed only for localhost).');
  }
  return url.origin;
}
