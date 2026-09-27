const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const Module = require('node:module');

// Exercise pure TypeScript helpers without adding a separate frontend test framework.
const filename = path.resolve(__dirname, '../src/components/findings/finding-record.ts');
const compiled = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
const loaded = new Module(filename, module);
loaded._compile(compiled, filename);
const { webUrl, captureUrl, findingType } = loaded.exports;

test('raw service output and unsafe URLs are not treated as web evidence', () => {
  for (const input of ['192.0.2.1:3306', 'Matched at: https://example.test/', 'javascript:alert(1)', 'https://user:pass@example.test/', 'https://example.test/#fragment']) {
    assert.equal(webUrl(input), null);
  }
  assert.equal(webUrl('https://example.test:8443/login'), 'https://example.test:8443/login');
});

test('capture uses the exact finding endpoint and cannot silently select another host', () => {
  const base = { id: 1, title: 'Test', host: 'example.test', severity: 'high' };
  assert.equal(captureUrl({ ...base, matched_at: 'https://example.test:8443/admin' }, 'https://example.test/'), 'https://example.test:8443/admin');
  assert.equal(captureUrl({ ...base, matched_at: 'https://unrelated.test/' }), null);
  assert.equal(captureUrl({ ...base, host: '192.0.2.1' }), null);
});

test('unclassified findings remain Other rather than being assigned a speculative type', () => {
  assert.equal(findingType({ tags: ['manual'] }), 'Other finding');
  assert.equal(findingType({ cve_id: 'CVE-2026-0001', tags: ['tls'] }), 'CVE vulnerability');
  assert.equal(findingType({ tags: ['tls'] }), 'TLS / certificate');
});
