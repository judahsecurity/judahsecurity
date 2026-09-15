import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const nextConfig = require('./next.config.js');

test('slash-terminated FastAPI collection routes use explicit rewrites', async () => {
  const rewrites = await nextConfig.rewrites();
  const bySource = new Map(rewrites.map((rewrite) => [rewrite.source, rewrite.destination]));
  const apiOrigin = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  assert.equal(bySource.get('/api/v1/assets'), `${apiOrigin}/api/v1/assets/`);
  assert.equal(bySource.get('/api/v1/netblocks'), `${apiOrigin}/api/v1/netblocks/`);
});
