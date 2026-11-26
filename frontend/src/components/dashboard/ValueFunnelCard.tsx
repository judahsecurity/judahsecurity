'use client';

import { useEffect, useId, useMemo, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Loader2 } from 'lucide-react';
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

interface Stage {
  key: 'open_critical_high' | 'likely_exploitable' | 'prioritized' | 'agent_tested' | 'proven';
  label: string;
  hint: string;
}

const STAGES: Stage[] = [
  { key: 'open_critical_high', label: 'Open Critical & High', hint: 'Every open Critical or High finding from scanners and the agent' },
  { key: 'likely_exploitable', label: 'Likely exploitable', hint: 'Delphi exploit likelihood: KEV, EPSS, exploit maturity. Findings without a CVE score are kept for review, not dropped' },
  { key: 'prioritized', label: 'Prioritized', hint: 'OPES asset priority: Critical, plus High when known-exploited or OPES ≥ 7' },
  { key: 'agent_tested', label: 'Tested by agent', hint: 'Prioritized findings the agent attempted to exploit or validate' },
  { key: 'proven', label: 'Proven exploitable', hint: 'Reproduced by the independent verifier against the live target, or confirmed by an analyst' },
];

/**
 * One tapering band, flat across each stage and easing between stages.
 * Thickness is log-scaled so 2 stays visible next to 5,000.
 */
export function funnelPath(values: number[], width: number, height: number): string {
  const max = Math.max(1, values[0] || 1);
  const minT = 6;
  const maxT = height * 0.86;
  const thick = values.map((v) =>
    v <= 0 ? 2 : minT + (maxT - minT) * (Math.log(v + 1) / Math.log(max + 1))
  );
  const col = width / values.length;
  const mid = height / 2;
  const top: string[] = [];
  const bottom: string[] = [];
  values.forEach((_, i) => {
    const x0 = i * col;
    const plateauStart = x0 + (i === 0 ? 0 : col * 0.3);
    const plateauEnd = x0 + col * 0.55;
    const t = thick[i] / 2;
    if (i === 0) {
      top.push(`M0,${mid - t}`);
    } else {
      // Ease from the previous plateau's end down to this plateau's start.
      const prevT = thick[i - 1] / 2;
      const px = (i - 1) * col + col * 0.55;
      const c = (plateauStart - px) / 2;
      top.push(`C${px + c},${mid - prevT} ${plateauStart - c},${mid - t} ${plateauStart},${mid - t}`);
    }
    top.push(`L${i === values.length - 1 ? width : plateauEnd},${mid - t}`);
  });
  // Walk back along the bottom edge, mirrored.
  for (let i = values.length - 1; i >= 0; i--) {
    const x0 = i * col;
    const plateauStart = x0 + (i === 0 ? 0 : col * 0.3);
    const plateauEnd = i === values.length - 1 ? width : x0 + col * 0.55;
    const t = thick[i] / 2;
    if (i === values.length - 1) bottom.push(`L${plateauEnd},${mid + t}`);
    bottom.push(`L${plateauStart},${mid + t}`);
    if (i > 0) {
      const prevT = thick[i - 1] / 2;
      const px = (i - 1) * col + col * 0.55;
      const c = (plateauStart - px) / 2;
      bottom.push(`C${plateauStart - c},${mid + t} ${px + c},${mid + prevT} ${px},${mid + prevT}`);
    }
  }
  return `${top.join(' ')} ${bottom.join(' ')} Z`;
}

export function ValueFunnelView({ funnel, className }: { funnel: ValueFunnel; className?: string }) {
  const gradientId = useId().replace(/:/g, '');
  const values = STAGES.map((s) => funnel[s.key]);
  const path = useMemo(() => funnelPath(values, 1000, 170), [values.join(',')]); // eslint-disable-line react-hooks/exhaustive-deps
  const deprioritized = funnel.open_critical_high - funnel.prioritized;
  const notTested = Math.max(0, funnel.prioritized - funnel.agent_tested);
  const provenHref =
    funnel.proven === 1 && funnel.proven_finding_ids[0] ? `/findings?id=${funnel.proven_finding_ids[0]}` : '/attacks';

  const notes: Record<Stage['key'], React.ReactNode> = {
    open_critical_high: null,
    likely_exploitable: funnel.not_scored ? `${fmt(funnel.not_scored)} without a CVE score, kept` : null,
    prioritized: null,
    agent_tested: notTested ? (
      <Link href="/agent" className="text-amber-400 hover:underline">
        {fmt(notTested)} prioritized not yet tested — validate →
      </Link>
    ) : null,
    proven: funnel.proven_outside_priority
      ? `+${fmt(funnel.proven_outside_priority)} proven below priority`
      : null,
  };

  return (
    <div className={cn('flex flex-col', className)}>
      <p className="mb-4 text-sm text-muted-foreground">
        <span className="font-semibold text-foreground">{pct(deprioritized, funnel.open_critical_high)}</span> of open
        Critical & High deprioritized, down to{' '}
        <span className="font-semibold text-red-400">{fmt(funnel.proven)} proven exploitable</span>
      </p>

      <div className="relative">
        {/* Stage columns: number and label on top, dashed dividers like a ledger */}
        <div className="grid grid-cols-5">
          {STAGES.map((s, i) => {
            const value = funnel[s.key];
            const prev = i > 0 ? funnel[STAGES[i - 1].key] : null;
            const last = i === STAGES.length - 1;
            const number = (
              <span className={cn('block text-2xl font-semibold tabular-nums', last ? 'text-red-400' : 'text-foreground')}>
                {fmt(value)}
              </span>
            );
            return (
              <div
                key={s.key}
                title={s.hint}
                className={cn('min-w-0 px-3 pb-2', i > 0 && 'border-l border-dashed border-border')}
              >
                {last && value ? <Link href={provenHref} className="hover:underline">{number}</Link> : number}
                <span className="block truncate text-xs text-muted-foreground">{s.label}</span>
                <span className="mt-0.5 block h-4 truncate text-[11px] tabular-nums text-muted-foreground/70">
                  {prev !== null && prev - value > 0 ? `−${fmt(prev - value)}` : ''}
                </span>
              </div>
            );
          })}
        </div>

        {/* The funnel shape spans all columns underneath */}
        <div className="grid grid-cols-5">
          {STAGES.map((s, i) => (
            <div key={s.key} className={cn('h-[170px]', i > 0 && 'border-l border-dashed border-border')} />
          ))}
        </div>
        <svg
          viewBox="0 0 1000 170"
          preserveAspectRatio="none"
          className="pointer-events-none absolute bottom-[34px] left-0 h-[170px] w-full"
          role="img"
          aria-label={`${fmt(funnel.open_critical_high)} open Critical and High findings narrowed to ${fmt(funnel.proven)} proven exploitable`}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" x2="1" y1="0" y2="0">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.05} />
              <stop offset="18%" stopColor="#3b82f6" stopOpacity={0.35} />
              <stop offset="62%" stopColor="#6366f1" stopOpacity={0.45} />
              <stop offset="100%" stopColor="#ef4444" stopOpacity={0.85} />
            </linearGradient>
          </defs>
          <path d={path} fill={`url(#${gradientId})`} />
        </svg>

        {/* Per-stage notes under the shape */}
        <div className="grid min-h-[34px] grid-cols-5">
          {STAGES.map((s, i) => (
            <div
              key={s.key}
              className={cn('px-3 pt-1 text-[11px] leading-snug text-muted-foreground', i > 0 && 'border-l border-dashed border-border')}
            >
              {notes[s.key]}
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>Delphi exploit likelihood → OPES asset priority → agent proof. Band thickness is log-scaled.</span>
        {funnel.proven ? (
          <Link href={provenHref} className="flex items-center gap-1 text-primary hover:underline">
            View proven <ArrowRight className="h-3 w-3" />
          </Link>
        ) : null}
      </div>
    </div>
  );
}

export interface FunnelSummary {
  input_critical: number;
  input_high: number;
  output_critical: number;
  output_high: number;
  input_total: number;
}

/**
 * Scanner Critical & High re-scored by Judah: one source fanning out into
 * Critical / High / Deprioritized. Ribbon widths are log-scaled.
 */
export function SeverityRemapView({ summary }: { summary: FunnelSummary }) {
  const total = Math.max(0, summary.input_total);
  const outs = [
    { key: 'C', label: 'Critical', value: summary.output_critical, color: '#ef4444' },
    { key: 'H', label: 'High', value: summary.output_high, color: '#f97316' },
    {
      key: '–',
      label: 'Deprioritized',
      value: Math.max(0, total - summary.output_critical - summary.output_high),
      color: '#64748b',
    },
  ];
  const W = 300;
  const H = 210;
  const srcY = 6;
  const dstY = 168;
  const w = (v: number) => (v <= 0 ? 0 : 6 + 46 * (Math.log(v + 1) / Math.log(Math.max(2, total) + 1)));
  const widths = outs.map((o) => w(o.value));
  const srcW = widths.reduce((a, b) => a + b, 0);
  let srcX = (W - srcW) / 2;
  const slots = [W * 0.18, W * 0.5, W * 0.82];
  return (
    <div className="flex flex-col">
      <div className="mx-auto mb-1 rounded-md border border-border bg-background/60 px-4 py-2 text-center">
        <p className="text-2xl font-semibold tabular-nums">{fmt(total)}</p>
        <p className="text-xs text-muted-foreground">Scanner Critical & High</p>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Scanner severity re-scored by Judah">
        <rect x={(W - srcW) / 2} y={0} width={srcW} height={srcY} rx={2} fill="#f87171" opacity={0.6} />
        {outs.map((o, i) => {
          const ww = widths[i];
          if (!ww) return null;
          const x0 = srcX;
          srcX += ww;
          const x1 = slots[i] - ww / 2;
          const midY = (srcY + dstY) / 2;
          const d = `M${x0},${srcY} C${x0},${midY} ${x1},${midY} ${x1},${dstY} L${x1 + ww},${dstY} C${x1 + ww},${midY} ${x0 + ww},${midY} ${x0 + ww},${srcY} Z`;
          return (
            <g key={o.key}>
              <path d={d} fill={o.color} fillOpacity={o.key === '–' ? 0.22 : 0.4}>
                <title>{`${o.label}: ${fmt(o.value)}`}</title>
              </path>
              <rect x={x1} y={dstY} width={ww} height={5} rx={2} fill={o.color} />
            </g>
          );
        })}
        {outs.map((o, i) => (
          <text key={`t-${o.key}`} x={slots[i]} y={H - 8} textAnchor="middle" fontSize={13} fontWeight={600} fill={o.key === '–' ? '#94a3b8' : o.color}>
            {fmt(o.value)}
            <tspan dx={5} fontSize={10} fontWeight={400} fill="#94a3b8">{o.label}</tspan>
          </text>
        ))}
      </svg>
    </div>
  );
}

/** Funnel (2/3) beside the severity re-scoring (1/3), from one request. */
export function ValueFunnelSection({ className }: { className?: string }) {
  const [data, setData] = useState<{ value_funnel?: ValueFunnel; summary?: FunnelSummary } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .getPrioritizationFunnel()
      .then((d) => live && setData(d ?? {}))
      .catch(() => live && setError('Could not load the prioritization funnel'));
    return () => {
      live = false;
    };
  }, []);

  const funnel = data?.value_funnel;
  const summary = data?.summary;
  const reduction =
    summary && summary.input_total
      ? pct(summary.input_total - summary.output_critical - summary.output_high, summary.input_total)
      : null;

  return (
    <div className={cn('grid gap-6 lg:grid-cols-3', className)}>
      <section className="rounded-lg border border-border bg-card p-5 lg:col-span-2">
        <div className="mb-2 flex items-baseline justify-between gap-3">
          <h2 className="text-base font-semibold">From alerts to proof</h2>
          <Link href="/findings" className="shrink-0 text-xs text-muted-foreground hover:text-foreground">
            All findings
          </Link>
        </div>
        {error ? (
          <p className="py-10 text-center text-sm text-muted-foreground">{error}</p>
        ) : !funnel ? (
          <div className="flex h-[280px] items-center justify-center text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
          </div>
        ) : funnel.open_critical_high === 0 ? (
          <p className="py-10 text-center text-sm text-muted-foreground">No open Critical or High findings.</p>
        ) : (
          <ValueFunnelView funnel={funnel} />
        )}
      </section>
      <section className="rounded-lg border border-border bg-card p-5">
        <h2 className="text-base font-semibold">Scanner severity → Judah priority</h2>
        <p className="mb-3 text-xs text-muted-foreground">
          {reduction ? `${reduction} reduction of scanner Critical & High` : 'Delphi likelihood and OPES asset priority'}
        </p>
        {summary && summary.input_total ? (
          <SeverityRemapView summary={summary} />
        ) : (
          <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
            {error ? '—' : <Loader2 className="h-5 w-5 animate-spin" />}
          </div>
        )}
      </section>
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
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold">From alerts to proof</h2>
        <Link href="/findings" className="shrink-0 text-xs text-muted-foreground hover:text-foreground">
          All findings
        </Link>
      </div>
      {error ? (
        <p className="py-10 text-center text-sm text-muted-foreground">{error}</p>
      ) : !funnel ? (
        <div className="flex h-[280px] items-center justify-center text-muted-foreground">
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
