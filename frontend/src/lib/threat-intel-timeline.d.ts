export function timelineEventTone(event: { deadline?: boolean; category?: string }): 'deadline' | 'detected' | 'detection' | 'exploitation' | 'neutral';
export function timelineEventLabel(event: { deadline?: boolean; title?: string }): string;
export function isSafeTimelineReference(value: unknown): boolean;
