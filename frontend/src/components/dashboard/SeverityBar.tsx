import Link from 'next/link';
import { SEVERITY_COLOR, type Severity } from '@/components/ui/severity-chip';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/**
 * Thin proportional bar with counts underneath — a faster read than a pie.
 * Segment widths are proportional; every non-zero segment keeps a sliver.
 */
export function SeverityBar({
  counts,
  hrefFor,
}: {
  counts: Partial<Record<Severity, number>>;
  hrefFor?: (s: Severity) => string;
}) {
  const total = ORDER.reduce((sum, s) => sum + (counts[s] || 0), 0);
  return (
    <div>
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-muted">
        {total > 0
          ? ORDER.map((s) =>
              counts[s] ? (
                <div
                  key={s}
                  style={{
                    width: `${Math.max(2, ((counts[s] || 0) / total) * 100)}%`,
                    background: SEVERITY_COLOR[s],
                  }}
                />
              ) : null
            )
          : null}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {ORDER.map((s) => {
          const label = (
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_COLOR[s] }} />
              <span className="tabular-nums text-foreground">{(counts[s] || 0).toLocaleString()}</span>
              <span className="capitalize">{s}</span>
            </span>
          );
          return hrefFor ? (
            <Link key={s} href={hrefFor(s)} className="hover:text-foreground">
              {label}
            </Link>
          ) : (
            <span key={s}>{label}</span>
          );
        })}
      </div>
    </div>
  );
}
