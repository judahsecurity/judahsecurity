import { cn } from '@/lib/utils';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** One colour per severity, shared by chips, bars and legends. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
};

export function normalizeSeverity(value?: string | null): Severity {
  const v = (value || '').toLowerCase();
  return (['critical', 'high', 'medium', 'low', 'info'] as Severity[]).includes(v as Severity)
    ? (v as Severity)
    : 'info';
}

/** Compact round severity marker: a coloured ring with the initial (C/H/M/L/I). */
export function SeverityChip({
  severity,
  className,
}: {
  severity?: string | null;
  className?: string;
}) {
  const s = normalizeSeverity(severity);
  const color = SEVERITY_COLOR[s];
  return (
    <span
      title={s}
      aria-label={`${s} severity`}
      className={cn(
        'inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold uppercase leading-none',
        className
      )}
      style={{ borderColor: color, color, background: `${color}14` }}
    >
      {s[0]}
    </span>
  );
}
