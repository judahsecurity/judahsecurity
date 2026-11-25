'use client';

import { useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { SeverityChip } from '@/components/ui/severity-chip';
import { cn } from '@/lib/utils';
import type { AttackPath, PriorityTier } from './types';

export const TIER_META: Record<PriorityTier, { label: string; color: string; hint: string }> = {
  fix_now: { label: 'Fix now', color: '#ef4444', hint: 'Proven or known-exploited, and reaches something that matters' },
  high: { label: 'High', color: '#f97316', hint: 'Serious, but missing proof, exposure or impact' },
  monitor: { label: 'Monitor', color: '#64748b', hint: 'Low impact, unproven or already resolved' },
};

const TIERS: PriorityTier[] = ['fix_now', 'high', 'monitor'];

export function tierOf(p: AttackPath): PriorityTier {
  return p.priority?.tier || 'monitor';
}

export function TierBadge({ path, className }: { path: AttackPath; className?: string }) {
  const meta = TIER_META[tierOf(path)];
  return (
    <span
      title={meta.hint}
      className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs', className)}
      style={{ borderColor: `${meta.color}66`, color: meta.color, background: `${meta.color}14` }}
    >
      {meta.label}
      {path.priority ? <span className="tabular-nums opacity-70">{path.priority.score}</span> : null}
    </span>
  );
}

/** Ranked list of attack paths, grouped by priority tier, with the reasons inline. */
export function PriorityPathList({
  paths,
  selectedId,
  onSelect,
}: {
  paths: AttackPath[];
  selectedId?: string;
  onSelect: (id: string) => void;
}) {
  const [filter, setFilter] = useState<PriorityTier | 'all'>('all');
  const counts = useMemo(
    () => Object.fromEntries(TIERS.map((t) => [t, paths.filter((p) => tierOf(p) === t).length])) as Record<PriorityTier, number>,
    [paths]
  );
  const shown = filter === 'all' ? paths : paths.filter((p) => tierOf(p) === filter);

  return (
    <div className="flex min-h-0 flex-col">
      <div className="mb-2 flex flex-wrap gap-1">
        {(['all', ...TIERS] as const).map((t) => {
          const active = filter === t;
          const meta = t === 'all' ? null : TIER_META[t];
          return (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={cn(
                'flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors',
                active ? 'border-primary/50 bg-primary/10 text-foreground' : 'border-border text-muted-foreground hover:text-foreground'
              )}
            >
              {meta ? <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} /> : null}
              {meta ? meta.label : 'All'}
              <span className="tabular-nums opacity-70">{t === 'all' ? paths.length : counts[t]}</span>
            </button>
          );
        })}
      </div>
      <ul className="-mx-1 min-h-0 flex-1 space-y-0.5 overflow-y-auto px-1">
        {shown.map((p) => {
          const meta = TIER_META[tierOf(p)];
          const selected = p.id === selectedId;
          return (
            <li key={p.id}>
              <button
                onClick={() => onSelect(p.id)}
                className={cn(
                  'relative w-full rounded-md py-2 pl-3 pr-2 text-left transition-colors',
                  selected ? 'bg-primary/10' : 'hover:bg-muted/50'
                )}
              >
                <span className="absolute inset-y-2 left-0 w-[3px] rounded-full" style={{ background: meta.color }} />
                <div className="flex items-start gap-2">
                  <SeverityChip severity={p.severity} className="mt-0.5" />
                  <span className={cn('line-clamp-2 flex-1 text-sm leading-snug', selected && 'text-foreground')}>{p.title}</span>
                  {p.verified ? <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" aria-label="Exploit verified" /> : null}
                  <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{p.priority?.score ?? ''}</span>
                </div>
                {p.priority?.reasons?.length ? (
                  <p className="mt-1 truncate pl-7 text-[11px] text-muted-foreground">
                    {p.priority.reasons.slice(0, 3).join(' · ')}
                  </p>
                ) : null}
              </button>
            </li>
          );
        })}
        {shown.length === 0 ? <li className="py-6 text-center text-xs text-muted-foreground">No paths in this tier.</li> : null}
      </ul>
    </div>
  );
}
