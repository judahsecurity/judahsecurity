// node --test browser-extension/capture.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MAX_BODY_CHARS, hostAllowed, isBinaryMime, newCaptureId, normalizeBaseUrl, stripSecretHeaders, toEntry,
} from './capture.js';

test('secret headers never leave the browser', () => {
  const out = stripSecretHeaders({ Cookie: 'sid=1', authorization: 'Bearer x', 'X-CSRF-Token': 't', Accept: '*/*' });
  assert.deepEqual(out, { Cookie: '[redacted]', authorization: '[redacted]', 'X-CSRF-Token': '[redacted]', Accept: '*/*' });
});

test('host allowlist matches exact hosts and subdomains only', () => {
  assert.equal(hostAllowed('https://app.example.com/x', ['example.com']), true);
  assert.equal(hostAllowed('https://example.com/', ['*.example.com']), true);
  assert.equal(hostAllowed('https://evil-example.com/', ['example.com']), false);
  assert.equal(hostAllowed('https://anything.test/', []), true);
  assert.equal(hostAllowed('not a url', ['example.com']), false);
});

test('entries drop binary bodies and truncate large ones', () => {
  const pending = {
    request: { method: 'POST', url: 'https://app.example.com/api', headers: { Cookie: 'a=b' }, postData: '{"q":1}' },
    response: { status: 200, headers: { 'content-type': 'application/json' }, mimeType: 'application/json' },
    pageUrl: 'https://app.example.com/', startedAt: 1.0, finishedAt: 1.25,
  };
  const entry = toEntry(pending, 'x'.repeat(MAX_BODY_CHARS + 5));
  assert.equal(entry.response_body.length, MAX_BODY_CHARS);
  assert.equal(entry.elapsed_ms, 250);
  assert.equal(entry.request_headers.Cookie, '[redacted]');
  assert.equal(entry.request_body, '{"q":1}');
  assert.equal(isBinaryMime('image/png'), true);
  const img = toEntry({ ...pending, response: { ...pending.response, mimeType: 'image/png' } }, 'PNG');
  assert.equal(img.response_body, null);
});

test('capture ids satisfy the server pattern', () => {
  assert.match(newCaptureId(), /^cap-[0-9a-f]{24}$/);
});

test('platform URL must be https except on localhost', () => {
  assert.equal(normalizeBaseUrl('https://asm.example.com/dashboard'), 'https://asm.example.com');
  assert.equal(normalizeBaseUrl('http://localhost:8000'), 'http://localhost:8000');
  assert.throws(() => normalizeBaseUrl('http://asm.example.com'));
});
