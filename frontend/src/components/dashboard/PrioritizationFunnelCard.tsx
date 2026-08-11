'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Filter, Loader2, Target } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { cn, formatNumber } from '@/lib/utils';

interface FunnelSummary {
  input_critical: number;
  input_high: number;
  output_critical: number;
  output_high: number;
  input_total: number;
  output_total: number;
  reduction_pct: number;
}

interface FunnelColumn {
  name: string;
  critical: number;
  high: number;
  filtered: number;
}

interface FunnelResponse {
  stages?: string[];
  columns?: FunnelColumn[];
  summary: FunnelSummary;
}

const SEGMENT_META = [
  { key: 'critical' as const, label: 'Critical', bar: 'bg-red-500', text: 'text-red-400', glow: 'shadow-[0_0_12px_rgba(239,68,68,0.35)]' },
  { key: 'high' as const, label: 'High', bar: 'bg-orange-500', text: 'text-orange-400', glow: 'shadow-[0_0_12px_rgba(249,115,22,0.3)]' },
  { key: 'filtered' as const, label: 'Filtered out', bar: 'bg-slate-600/80', text: 'text-slate-400', glow: '' },
];

function StageColumn({
  column,
  maxTotal,
}: {
  column: FunnelColumn;
  maxTotal: number;
}) {
  const total = column.critical + column.high + column.filtered;
  // Keep Critical → High → Filtered vertical order; scale column height by volume
  const columnHeight = Math.max(72, Math.round((total / Math.max(maxTotal, 1)) * 220));

  return (
    <div className="flex flex-col min-w-0 flex-1">
      <p className="text-[11px] font-medium tracking-wide uppercase text-muted-foreground text-center mb-2">
        {column.name}
      </p>
      <div
        className="relative flex flex-col gap-1 rounded-md bg-[#0b0f17] border border-border/40 p-1.5"
        style={{ height: columnHeight }}
      >
        {SEGMENT_META.map((seg) => {
          const count = column[seg.key];
          if (seg.key === 'filtered' && count <= 0 && column.name === 'Scanner') {
            return null;
          }
          const flexGrow = Math.max(count, count > 0 ? 1 : 0.15);
          return (
            <div
              key={seg.key}
              className={cn(
                'relative min-h-[4px] rounded-sm flex items-center px-2 overflow-hidden',
                seg.bar,
                count > 0 && seg.glow
              )}
              style={{ flexGrow, flexBasis: 0, opacity: count > 0 ? 1 : 0.25 }}
              title={`${seg.label}: ${count}`}
            >
              {count > 0 && (
                <span className="text-[11px] font-semibold text-white/95 tabular-nums drop-shadow">
                  {formatNumber(count)}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <div className="mt-2 space-y-0.5 text-[10px] text-muted-foreground">
        <p>
          <span className="text-red-400">Crit</span> {formatNumber(column.critical)}
        </p>
        <p>
          <span className="text-orange-400">High</span> {formatNumber(column.high)}
        </p>
        {column.filtered > 0 && (
          <p>
            <span className="text-slate-400">Filtered</span> {formatNumber(column.filtered)}
          </p>
        )}
      </div>
    </div>
  );
}

export function PrioritizationFunnelCard() {
  const [funnel, setFunnel] = useState<FunnelResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getPrioritizationFunnel();
        if (!cancelled) setFunnel(data);
      } catch (err: unknown) {
        if (!cancelled) {
          const message =
            err && typeof err === 'object' && 'message' in err
              ? String((err as { message?: string }).message)
              : 'Failed to load prioritization funnel';
          setError(message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const columns = useMemo(() => {
    if (funnel?.columns?.length) return funnel.columns;
    return [];
  }, [funnel]);

  const summary = funnel?.summary;
  const inputTotal = summary?.input_total ?? 0;
  const outputTotal = summary?.output_total ?? 0;
  const reductionPct = summary?.reduction_pct ?? 0;
  const maxTotal = Math.max(...columns.map((c) => c.critical + c.high + c.filtered), 1);
  const hasData = inputTotal > 0 && columns.length > 0;

  return (
    <Card className="border-orange-500/20 overflow-hidden">
      <CardHeader className="flex flex-row items-start justify-between gap-4 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-lg flex items-center gap-2">
            <Target className="h-5 w-5 text-orange-400" />
            Prioritization Value
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            Live open Critical/High reduced by Delphi likelihood and OPES asset priority
          </p>
        </div>
        <Link href="/findings">
          <Button variant="ghost" size="sm" className="shrink-0">
            View priorities <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </Link>
      </CardHeader>

      <CardContent className="space-y-4">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground text-sm">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading prioritization funnel…
          </div>
        ) : error ? (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-8 text-center text-sm text-muted-foreground">
            Could not load live funnel data. Pull latest and rebuild backend + frontend.
          </div>
        ) : !hasData ? (
          <div className="rounded-md border border-border/50 bg-muted/20 px-4 py-8 text-center text-sm text-muted-foreground">
            No open Critical/High findings to prioritize yet.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-md bg-muted/40 px-3 py-2">
                <p className="text-[11px] text-muted-foreground">Scanner Critical/High</p>
                <p className="text-xl font-semibold tabular-nums">{formatNumber(inputTotal)}</p>
              </div>
              <div className="rounded-md bg-muted/40 px-3 py-2">
                <p className="text-[11px] text-muted-foreground">Prioritized</p>
                <p className="text-xl font-semibold tabular-nums text-orange-400">
                  {formatNumber(outputTotal)}
                </p>
              </div>
              <div className="rounded-md bg-muted/40 px-3 py-2">
                <p className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <Filter className="h-3 w-3" /> Noise reduced
                </p>
                <p className="text-xl font-semibold tabular-nums text-emerald-400">
                  {reductionPct}%
                </p>
              </div>
              <div className="rounded-md bg-muted/40 px-3 py-2">
                <p className="text-[11px] text-muted-foreground">Final mix</p>
                <p className="text-sm font-medium mt-1">
                  <span className="text-red-400">{summary?.output_critical ?? 0} Critical</span>
                  <span className="text-muted-foreground"> · </span>
                  <span className="text-orange-400">{summary?.output_high ?? 0} High</span>
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {columns.map((column) => (
                <StageColumn key={column.name} column={column} maxTotal={maxTotal} />
              ))}
            </div>

            <p className="text-xs text-muted-foreground">
              Each column is ordered Critical → High → Filtered out. Filtered out means demoted by
              Delphi or OPES (reachability, exploit evidence, confidence, asset criticality). Final
              Priority keeps OPES Critical plus High when KEV-listed or OPES ≥ 7.0.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
