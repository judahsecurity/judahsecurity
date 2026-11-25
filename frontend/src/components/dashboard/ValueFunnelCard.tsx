'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, ChevronRight, Loader2, ShieldCheck } from 'lucide-react';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

export interface ValueFunnel {
  open_critical_high: number;
  likely_exploitable: number;
  not_scored: number;
  prioritized: number;
  agent_tested: number;
  proven: number;
  proven_outside_priority: number;
  proven_finding_ids: number[];
}

interface Stage {
  key: keyof ValueFunnel;
  label: string;
  hint: string;
}

const STAGES: Stage[] = [
  { key: 'open_critical_high', label: 'Open Critical/High', hint: 'Every open Critical or High finding from scanners and the agent' },
  { key: 'likely_exploitable', label: 'Likely exploitable', hint: 'Delphi exploit likelihood (KEV, EPSS, exploit maturity). Findings Delphi cannot score are kept, not dropped' },
  { key: 'prioritized', label: 'Prioritized', hint: 'OPES asset priority: Critical, plus High when known-exploited or OPES ≥ 7' },
  { key: 'agent_tested', label: 'Tested by agent', hint: 'Prioritized findings the agent attempted to exploit or validate' },
  { key: 'proven', label: 'Proven exploitable', hint: 'Reproduced by the independent verifier against the live target, or confirmed by an analyst' },
];

/** Log-scaled height so 2 stays visible next to 5,000. */
function barHeight(value: number, max: number): number {
  if (value <= 0) return 3;
  const t = Math.log10(value + 1) / Math.log10(max + 1);
  return Math.max(10, Math.round(t * 120));
}

function fmt(n: number): string {
  return n.toLocaleString();
}

function pct(part: number, whole: number): string {
  if (!whole) return '0%';
  const p = (part / whole) * 100;
  if (p > 0 && p < 0.1) return '<0.1%';
  if (p < 100 && p > 99.9) return '99.9%';
  // Near the ends, rounding to a whole number misleads ("99%" for 99.2%).
  if (p >= 99 || p < 10) return `${p.toFixed(1)}%`;
  return `${Math.round(p)}%`;
}

export function ValueFunnelView({ funnel, className }: { funnel: ValueFunnel; className?: string }) {
  const max = Math.max(1, funnel.open_critical_high);
  const deprioritized = funnel.open_critical_high - funnel.prioritized;
  const provenHref =
    funnel.proven === 1 && funnel.proven_finding_ids[0]
      ? `/findings?id=${funnel.proven_finding_ids[0]}`
      : '/attacks';

  return (
    <div className={cn('flex flex-col', className)}>
      <div className="mb-5 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <p className="text-2xl font-semibold tabular-nums">{fmt(funnel.open_critical_high)}</p>
        <p className="text-sm text-muted-foreground">open Critical/High</p>
        <ArrowRight className="h-4 w-4 self-center text-muted-foreground" />
        <p className="text-2xl font-semibold tabular-nums text-red-400">{fmt(funnel.proven)}</p>
        <p className="text-sm text-muted-foreground">proven exploitable</p>
        <span className="basis-full text-xs text-muted-foreground">
          {pct(deprioritized, funnel.open_critical_high)} deprioritized
          {funnel.not_scored ? ` · ${fmt(funnel.not_scored)} without a CVE score kept for review` : ''}
        </span>
      </div>

      <div className="grid grid-cols-5 items-end gap-2">
        {STAGES.map((s, i) => {
          const value = funnel[s.key] as number;
          const last = i === STAGES.length - 1;
          const prev = i > 0 ? (funnel[STAGES[i - 1].key] as number) : null;
          const dropped = prev !== null ? prev - value : 0;
          const bar = (
            <div
              className={cn(
                'w-full rounded-md transition-colors',
                last ? 'bg-red-500/80' : 'bg-primary'
              )}
              style={{
                height: barHeight(value, max),
                opacity: last ? 1 : 0.9 - i * 0.15,
              }}
            />
          );
          return (
            <div key={s.key} className="flex min-w-0 flex-col" title={s.hint}>
              <div className="mb-2">
                <span className={cn('block text-xl font-semibold tabular-nums', last && value ? 'text-red-400' : 'text-foreground')}>
                  {fmt(value)}
                </span>
                <span className="block h-4 truncate text-[11px] tabular-nums text-muted-foreground">
                  {i > 0 && dropped > 0 ? `−${fmt(dropped)} from previous` : ''}
                </span>
              </div>
              <div className="flex h-[120px] items-end">
                {last && value ? (
                  <Link href={provenHref} className="w-full" aria-label="View proven findings">
                    {bar}
                  </Link>
                ) : (
                  bar
                )}
              </div>
              <p className="mt-2 flex items-center gap-1 truncate text-xs text-muted-foreground">
                {last ? <ShieldCheck className="h-3 w-3 shrink-0 text-red-400" /> : null}
                {s.label}
                {i < STAGES.length - 1 ? <ChevronRight className="ml-auto h-3 w-3 shrink-0 opacity-40" /> : null}
              </p>
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          Delphi exploit likelihood → OPES asset priority → agent proof. Bars are log-scaled so small counts stay visible.
          {funnel.proven_outside_priority
            ? ` ${fmt(funnel.proven_outside_priority)} more proven finding${funnel.proven_outside_priority === 1 ? ' was' : 's were'} scored below priority.`
            : ''}
        </span>
        {funnel.proven ? (
          <Link href={provenHref} className="flex items-center gap-1 text-primary hover:underline">
            View proven <ArrowRight className="h-3 w-3" />
          </Link>
        ) : null}
      </div>
    </div>
  );
}

/** Self-loading dashboard card. */
export function ValueFunnelCard({ className }: { className?: string }) {
  const [funnel, setFunnel] = useState<ValueFunnel | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .getPrioritizationFunnel()
      .then((d) => live && setFunnel(d?.value_funnel ?? null))
      .catch(() => live && setError('Could not load the prioritization funnel'));
    return () => {
      live = false;
    };
  }, []);

  return (
    <section className={cn('rounded-lg border border-border bg-card p-5', className)}>
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">From alerts to proof</h2>
          <p className="text-xs text-muted-foreground">What Judah filtered, and what it proved</p>
        </div>
        <Link href="/findings" className="shrink-0 text-xs text-muted-foreground hover:text-foreground">
          All findings
        </Link>
      </div>
      {error ? (
        <p className="py-10 text-center text-sm text-muted-foreground">{error}</p>
      ) : !funnel ? (
        <div className="flex h-[220px] items-center justify-center text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
        </div>
      ) : funnel.open_critical_high === 0 ? (
        <p className="py-10 text-center text-sm text-muted-foreground">No open Critical or High findings.</p>
      ) : (
        <ValueFunnelView funnel={funnel} />
      )}
    </section>
  );
}
