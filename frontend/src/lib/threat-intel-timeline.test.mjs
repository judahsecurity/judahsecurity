import assert from 'node:assert/strict';
import test from 'node:test';

import { isSafeTimelineReference, timelineEventLabel, timelineEventTone } from './threat-intel-timeline.mjs';

test('deadlines are visually and textually distinct', () => {
  const event = { deadline: true, category: 'deadline', title: 'CISA remediation deadline' };
  assert.equal(timelineEventTone(event), 'deadline');
  assert.equal(timelineEventLabel(event), 'Deadline · CISA remediation deadline');
});

test('Nuclei lifecycle and first detection receive separate tones', () => {
  assert.equal(timelineEventTone({ category: 'detection_enabled' }), 'detection');
  assert.equal(timelineEventTone({ category: 'asset_detected' }), 'detected');
});

test('only web and application references render as links', () => {
  assert.equal(isSafeTimelineReference('https://nvd.nist.gov/vuln/detail/CVE-2024-1'), true);
  assert.equal(isSafeTimelineReference('/nuclei-templates/7'), true);
  assert.equal(isSafeTimelineReference('/srv/nuclei/private.yaml'), false);
  assert.equal(isSafeTimelineReference('file:///srv/nuclei/private.yaml'), false);
});
