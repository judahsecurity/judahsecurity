export function timelineEventTone(event) {
  if (event?.deadline) return 'deadline';
  if (event?.category === 'asset_detected') return 'detected';
  if (String(event?.category || '').startsWith('detection_')) return 'detection';
  if (event?.category === 'exploitation') return 'exploitation';
  return 'neutral';
}

export function timelineEventLabel(event) {
  return event?.deadline ? `Deadline · ${event.title}` : event?.title || 'Intel update';
}

export function isSafeTimelineReference(value) {
  if (typeof value !== 'string') return false;
  if (/^https?:\/\//i.test(value)) return true;
  return /^\/(nuclei-templates|threat-intel)(\/|\?|$)/.test(value);
}
