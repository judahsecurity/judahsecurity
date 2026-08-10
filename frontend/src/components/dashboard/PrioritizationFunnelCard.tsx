'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Layer, Rectangle, ResponsiveContainer, Sankey, Tooltip } from 'recharts';
import { ArrowRight, Filter, Target } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { formatNumber } from '@/lib/utils';

/** Demo numbers matching the reference Sankey — replace with API data later. */
export const DEMO_FUNNEL = {
  stages: ['Scanner', 'Delphi', 'OPES', 'Priority'] as const,
  input: { critical: 291, high: 573 },
  output: { critical: 6, high: 11 },
};

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

function buildDemoData(): { nodes: FunnelNode[]; links: FunnelLink[] } {
  // Column layout mirrors the reference: Critical/High thin out; filtered absorbs the rest.
  const nodes: FunnelNode[] = [
    { name: 'Critical', kind: 'critical', stage: 0, count: 291 },
    { name: 'High', kind: 'high', stage: 0, count: 573 },
    { name: 'Critical', kind: 'critical', stage: 1, count: 136 },
    { name: 'High', kind: 'high', stage: 1, count: 375 },
    { name: 'Filtered out', kind: 'filtered', stage: 1 },
    { name: 'Critical', kind: 'critical', stage: 2, count: 9 },
    { name: 'High', kind: 'high', stage: 2, count: 26 },
    { name: 'Filtered out', kind: 'filtered', stage: 2 },
    { name: 'Critical', kind: 'critical', stage: 3, count: 6 },
    { name: 'High', kind: 'high', stage: 3, count: 11 },
    { name: 'Filtered out', kind: 'filtered', stage: 3 },
  ];

  const links: FunnelLink[] = [
    // Scanner → Delphi
    { source: 0, target: 2, value: 136, kind: 'critical' },
    { source: 0, target: 4, value: 155, kind: 'filtered' },
    { source: 1, target: 3, value: 375, kind: 'high' },
    { source: 1, target: 4, value: 198, kind: 'filtered' },
    // Delphi → OPES
    { source: 2, target: 5, value: 9, kind: 'critical' },
    { source: 2, target: 7, value: 127, kind: 'filtered' },
    { source: 3, target: 6, value: 26, kind: 'high' },
    { source: 3, target: 7, value: 349, kind: 'filtered' },
    // OPES → Priority
    { source: 5, target: 8, value: 6, kind: 'critical' },
    { source: 5, target: 10, value: 3, kind: 'filtered' },
    { source: 6, target: 9, value: 11, kind: 'high' },
    { source: 6, target: 10, value: 15, kind: 'filtered' },
  ];

  return { nodes, links };
}

function SankeyNode({
  x,
  y,
  width,
  height,
  payload,
  containerWidth,
}: {
  x: number;
  y: number;
  width: number;
  height: number;
  payload: FunnelNode & { value?: number };
  containerWidth?: number;
}) {
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

function SankeyLink({
  sourceX,
  targetX,
  sourceY,
  targetY,
  sourceControlX,
  targetControlX,
  linkWidth,
  payload,
}: {
  sourceX: number;
  targetX: number;
  sourceY: number;
  targetY: number;
  sourceControlX: number;
  targetControlX: number;
  linkWidth: number;
  payload: FunnelLink;
}) {
  const [hover, setHover] = useState(false);
  const kind = (payload.kind ?? 'filtered') as NodeKind;
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

interface PrioritizationFunnelCardProps {
  /** When true, shows demo data + example badge. Swap for live API later. */
  demo?: boolean;
}

export function PrioritizationFunnelCard({ demo = true }: PrioritizationFunnelCardProps) {
  const data = useMemo(() => buildDemoData(), []);
  const inputTotal = DEMO_FUNNEL.input.critical + DEMO_FUNNEL.input.high;
  const outputTotal = DEMO_FUNNEL.output.critical + DEMO_FUNNEL.output.high;
  const reductionPct = Math.round((1 - outputTotal / inputTotal) * 100);

  return (
    <Card className="border-orange-500/20 overflow-hidden">
      <CardHeader className="flex flex-row items-start justify-between gap-4 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-lg flex items-center gap-2">
            <Target className="h-5 w-5 text-orange-400" />
            Prioritization Value
            {demo && (
              <Badge
                variant="outline"
                className="text-[10px] font-normal bg-amber-500/10 text-amber-300 border-amber-500/30"
              >
                Example data
              </Badge>
            )}
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            Scanner Critical/High → Delphi likelihood → OPES asset priority
          </p>
        </div>
        <Link href="/findings">
          <Button variant="ghost" size="sm" className="shrink-0">
            View priorities <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </Link>
      </CardHeader>

      <CardContent className="space-y-4">
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
            <p className="text-xl font-semibold tabular-nums text-emerald-400">{reductionPct}%</p>
          </div>
          <div className="rounded-md bg-muted/40 px-3 py-2">
            <p className="text-[11px] text-muted-foreground">Final mix</p>
            <p className="text-sm font-medium mt-1">
              <span className="text-red-400">{DEMO_FUNNEL.output.critical} Critical</span>
              <span className="text-muted-foreground"> · </span>
              <span className="text-orange-400">{DEMO_FUNNEL.output.high} High</span>
            </p>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-2 px-1 text-[11px] text-muted-foreground">
          {DEMO_FUNNEL.stages.map((stage) => (
            <div key={stage} className="text-center font-medium tracking-wide uppercase">
              {stage}
            </div>
          ))}
        </div>

        <div className="h-[280px] w-full rounded-md bg-[#0b0f17] border border-border/40">
          <ResponsiveContainer width="100%" height="100%">
            <Sankey
              data={data}
              nodeWidth={14}
              nodePadding={28}
              linkCurvature={0.55}
              margin={{ top: 16, right: 72, bottom: 16, left: 56 }}
              node={<SankeyNode />}
              link={<SankeyLink />}
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
          Filtered out = demoted by reachability, exploit evidence, detection confidence, or asset
          criticality — severity unchanged, priority lowered.
        </p>
      </CardContent>
    </Card>
  );
}
