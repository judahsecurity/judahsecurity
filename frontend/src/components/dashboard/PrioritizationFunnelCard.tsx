'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { Layer, Rectangle, ResponsiveContainer, Sankey, Tooltip } from 'recharts';
import { ArrowRight, Filter, Loader2, Target } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';

type NodeKind = 'critical' | 'high' | 'filtered';

interface FunnelNode {
  name: string;
  kind: NodeKind;
  stage: number;
  count?: number;
}

interface FunnelLink {
  source: number;
  target: number;
  value: number;
  kind: NodeKind;
}

interface FunnelSummary {
  input_critical: number;
  input_high: number;
  output_critical: number;
  output_high: number;
  input_total: number;
  output_total: number;
  reduction_pct: number;
}

interface FunnelResponse {
  stages: string[];
  nodes: FunnelNode[];
  links: FunnelLink[];
  summary: FunnelSummary;
}

const COLORS: Record<NodeKind, string> = {
  critical: '#ef4444',
  high: '#f97316',
  filtered: '#3f4555',
};

const LINK_COLORS: Record<NodeKind, string> = {
  critical: 'rgba(239, 68, 68, 0.45)',
  high: 'rgba(249, 115, 22, 0.4)',
  filtered: 'rgba(63, 69, 85, 0.55)',
};

const DEFAULT_STAGES = ['Scanner', 'Delphi', 'OPES', 'Priority'];

/** Recharts injects layout props when cloning this element — keep them optional for build. */
function SankeyNode(props: {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  payload?: FunnelNode & { value?: number };
  containerWidth?: number;
}) {
  const x = props.x ?? 0;
  const y = props.y ?? 0;
  const width = props.width ?? 0;
  const height = props.height ?? 0;
  const payload = props.payload ?? { name: '', kind: 'filtered' as NodeKind, stage: 0 };
  const { containerWidth } = props;
  const kind = (payload.kind ?? 'filtered') as NodeKind;
  const fill = COLORS[kind];
  const isRight = typeof containerWidth === 'number' && x + width > containerWidth / 2;
  const label = payload.count != null ? String(payload.count) : payload.name;
  const showName = kind === 'filtered' && height > 28;

  return (
    <Layer>
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        fill={fill}
        fillOpacity={kind === 'filtered' ? 0.85 : 1}
        radius={[2, 2, 2, 2] as unknown as number}
        style={
          kind !== 'filtered'
            ? { filter: `drop-shadow(0 0 6px ${fill}88)` }
            : undefined
        }
      />
      {height > 14 && (
        <text
          x={isRight ? x - 8 : x + width + 8}
          y={y + height / 2}
          textAnchor={isRight ? 'end' : 'start'}
          dominantBaseline="middle"
          className="fill-foreground"
          style={{ fontSize: 12, fontWeight: 600 }}
        >
          {label}
        </text>
      )}
      {showName && (
        <text
          x={isRight ? x - 8 : x + width + 8}
          y={y + height / 2 + 14}
          textAnchor={isRight ? 'end' : 'start'}
          dominantBaseline="middle"
          className="fill-muted-foreground"
          style={{ fontSize: 10 }}
        >
          Filtered out
        </text>
      )}
    </Layer>
  );
}

function SankeyLink(props: {
  sourceX?: number;
  targetX?: number;
  sourceY?: number;
  targetY?: number;
  sourceControlX?: number;
  targetControlX?: number;
  linkWidth?: number;
  payload?: FunnelLink;
}) {
  const sourceX = props.sourceX ?? 0;
  const targetX = props.targetX ?? 0;
  const sourceY = props.sourceY ?? 0;
  const targetY = props.targetY ?? 0;
  const sourceControlX = props.sourceControlX ?? sourceX;
  const targetControlX = props.targetControlX ?? targetX;
  const linkWidth = props.linkWidth ?? 1;
  const payload = props.payload;
  const [hover, setHover] = useState(false);
  const kind = (payload?.kind ?? 'filtered') as NodeKind;
  const d = `
    M${sourceX},${sourceY}
    C${sourceControlX},${sourceY} ${targetControlX},${targetY} ${targetX},${targetY}
  `;

  return (
    <path
      d={d}
      fill="none"
      stroke={LINK_COLORS[kind]}
      strokeWidth={linkWidth}
      strokeOpacity={hover ? 0.9 : 0.7}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    />
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

  const chartData = useMemo(() => {
    if (!funnel?.nodes?.length) return { nodes: [] as FunnelNode[], links: [] as FunnelLink[] };
    // Drop zero-value links so Recharts doesn't draw empty ribbons
    const links = (funnel.links || []).filter((l) => (l.value || 0) > 0);
    return { nodes: funnel.nodes as FunnelNode[], links: links as FunnelLink[] };
  }, [funnel]);

  const summary = funnel?.summary;
  const stages = funnel?.stages?.length ? funnel.stages : DEFAULT_STAGES;
  const inputTotal = summary?.input_total ?? 0;
  const outputTotal = summary?.output_total ?? 0;
  const reductionPct = summary?.reduction_pct ?? 0;
  const hasData = inputTotal > 0 && chartData.links.length > 0;

  return (
    <Card className="border-orange-500/20 overflow-hidden">
      <CardHeader className="flex flex-row items-start justify-between gap-4 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-lg flex items-center gap-2">
            <Target className="h-5 w-5 text-orange-400" />
            Prioritization Value
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            Live open Critical/High → Delphi likelihood → OPES asset priority
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
            Could not load live funnel data. Rebuild/restart the backend if this endpoint is new.
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

            <div className="grid grid-cols-4 gap-2 px-1 text-[11px] text-muted-foreground">
              {stages.map((stage) => (
                <div key={stage} className="text-center font-medium tracking-wide uppercase">
                  {stage}
                </div>
              ))}
            </div>

            <div className="h-[280px] w-full rounded-md bg-[#0b0f17] border border-border/40">
              <ResponsiveContainer width="100%" height="100%">
                <Sankey
                  data={chartData}
                  nodeWidth={14}
                  nodePadding={28}
                  linkCurvature={0.55}
                  iterations={0}
                  margin={{ top: 16, right: 72, bottom: 16, left: 56 }}
                  node={(nodeProps: object) => <SankeyNode {...(nodeProps as object)} />}
                  link={(linkProps: object) => <SankeyLink {...(linkProps as object)} />}
                  sort={false}
                >
                  <Tooltip
                    content={({ payload }) => {
                      if (!payload?.length) return null;
                      const item = payload[0]?.payload as
                        | (FunnelNode & { value?: number })
                        | FunnelLink
                        | undefined;
                      if (!item) return null;
                      const value =
                        'value' in item && typeof item.value === 'number'
                          ? item.value
                          : 'count' in item
                            ? item.count
                            : undefined;
                      const label =
                        'name' in item && item.name
                          ? item.name
                          : 'kind' in item
                            ? String(item.kind)
                            : 'Flow';
                      return (
                        <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
                          <p className="font-medium capitalize">{label}</p>
                          {value != null && (
                            <p className="text-muted-foreground">{formatNumber(value)} findings</p>
                          )}
                        </div>
                      );
                    }}
                  />
                </Sankey>
              </ResponsiveContainer>
            </div>

            <p className="text-xs text-muted-foreground">
              Filtered out = demoted by Delphi likelihood or OPES (reachability, exploit evidence,
              detection confidence, asset criticality). Final Priority keeps OPES Critical plus
              High when KEV-listed or OPES ≥ 7.0.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
