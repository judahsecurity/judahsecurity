'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Filter, Loader2, Target } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';

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

interface FunnelNode {
  name: string;
  kind: 'critical' | 'high' | 'filtered';
  stage: number;
  count?: number;
}

interface FunnelLink {
  source: number;
  target: number;
  value: number;
  kind: 'critical' | 'high' | 'filtered';
}

interface FunnelResponse {
  stages?: string[];
  columns?: FunnelColumn[];
  nodes?: FunnelNode[];
  links?: FunnelLink[];
  summary: FunnelSummary;
}

const KIND_ORDER: Array<'critical' | 'high' | 'filtered'> = ['critical', 'high', 'filtered'];

const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  filtered: '#3f4555',
} as const;

const LINK_COLORS = {
  critical: 'rgba(239, 68, 68, 0.42)',
  high: 'rgba(249, 115, 22, 0.38)',
  filtered: 'rgba(71, 85, 105, 0.45)',
} as const;

interface LaidOutNode {
  index: number;
  kind: 'critical' | 'high' | 'filtered';
  stage: number;
  count: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface LaidOutLink {
  kind: 'critical' | 'high' | 'filtered';
  value: number;
  path: string;
  width: number;
}

function layoutSankey(
  nodes: FunnelNode[],
  links: FunnelLink[],
  width: number,
  height: number
): { laidNodes: LaidOutNode[]; laidLinks: LaidOutLink[]; stageXs: number[] } {
  const padTop = 12;
  const padBottom = 12;
  const padLeft = 28;
  const padRight = 72;
  const nodeWidth = 14;
  const gap = 3;
  const usableH = height - padTop - padBottom;
  const stageCount = 4;
  const innerW = width - padLeft - padRight - nodeWidth;
  const stageGap = stageCount > 1 ? innerW / (stageCount - 1) : 0;
  const stageXs = Array.from({ length: stageCount }, (_, i) => padLeft + i * stageGap);

  const values = nodes.map((n, i) => {
    const inSum = links.filter((l) => l.target === i).reduce((s, l) => s + l.value, 0);
    const outSum = links.filter((l) => l.source === i).reduce((s, l) => s + l.value, 0);
    return Math.max(n.count ?? 0, inSum, outSum);
  });

  const stageTotals = Array.from({ length: stageCount }, (_, stage) =>
    nodes.reduce((sum, n, i) => (n.stage === stage ? sum + values[i] : sum), 0)
  );
  const globalMax = Math.max(...stageTotals, 1);

  const byIndex = new Map<number, LaidOutNode>();
  const positioned: LaidOutNode[] = [];

  for (let stage = 0; stage < stageCount; stage++) {
    const ordered = KIND_ORDER.map((kind) => {
      const index = nodes.findIndex((n) => n.stage === stage && n.kind === kind);
      if (index < 0) return null;
      return { index, kind, value: values[index] };
    }).filter(Boolean) as Array<{ index: number; kind: 'critical' | 'high' | 'filtered'; value: number }>;

    const stageTotal = stageTotals[stage] || 0;
    const columnPixelH = Math.max(48, (stageTotal / globalMax) * usableH);
    const scale = stageTotal > 0 ? columnPixelH / stageTotal : 0;
    // Top-align: Critical → High → Filtered out (bottom)
    let y = padTop;

    for (const item of ordered) {
      if (item.value <= 0) {
        const hasLinks = links.some((l) => l.source === item.index || l.target === item.index);
        if (!hasLinks) continue;
      }
      const h = item.value > 0 ? Math.max(3, item.value * scale) : 0;
      if (h <= 0) continue;
      const node: LaidOutNode = {
        index: item.index,
        kind: item.kind,
        stage,
        count: nodes[item.index].count ?? item.value,
        x: stageXs[stage],
        y,
        width: nodeWidth,
        height: h,
      };
      byIndex.set(item.index, node);
      positioned.push(node);
      y += h + gap;
    }
  }

  const sourceOffsets = new Map<number, number>();
  const targetOffsets = new Map<number, number>();
  const kindRank = { critical: 0, high: 1, filtered: 2 };
  const activeLinks = links
    .filter((l) => l.value > 0 && byIndex.has(l.source) && byIndex.has(l.target))
    .sort((a, b) => {
      if (a.source !== b.source) return a.source - b.source;
      return kindRank[a.kind] - kindRank[b.kind];
    });

  const laidLinks: LaidOutLink[] = [];
  for (const link of activeLinks) {
    const src = byIndex.get(link.source)!;
    const tgt = byIndex.get(link.target)!;
    const srcScale = src.height / Math.max(values[link.source], 1);
    const tgtScale = tgt.height / Math.max(values[link.target], 1);
    const sw = Math.max(2, link.value * srcScale);
    const tw = Math.max(2, link.value * tgtScale);

    const sy0 = src.y + (sourceOffsets.get(link.source) ?? 0);
    const ty0 = tgt.y + (targetOffsets.get(link.target) ?? 0);
    sourceOffsets.set(link.source, (sourceOffsets.get(link.source) ?? 0) + sw);
    targetOffsets.set(link.target, (targetOffsets.get(link.target) ?? 0) + tw);

    const x0 = src.x + src.width;
    const x1 = tgt.x;
    const y0a = sy0;
    const y0b = sy0 + sw;
    const y1a = ty0;
    const y1b = ty0 + tw;
    const cx = (x0 + x1) / 2;

    laidLinks.push({
      kind: link.kind,
      value: link.value,
      width: (sw + tw) / 2,
      path: [
        `M${x0},${y0a}`,
        `C${cx},${y0a} ${cx},${y1a} ${x1},${y1a}`,
        `L${x1},${y1b}`,
        `C${cx},${y1b} ${cx},${y0b} ${x0},${y0b}`,
        'Z',
      ].join(' '),
    });
  }

  return { laidNodes: positioned, laidLinks, stageXs };
}

function PrioritizationSankey({
  nodes,
  links,
  stages,
  columns,
}: {
  nodes: FunnelNode[];
  links: FunnelLink[];
  stages: string[];
  columns: FunnelColumn[];
}) {
  const width = 720;
  const height = 280;
  const { laidNodes, laidLinks, stageXs } = useMemo(
    () => layoutSankey(nodes, links, width, height),
    [nodes, links]
  );

  const inputTotal = (columns[0]?.critical ?? 0) + (columns[0]?.high ?? 0);

  return (
    <div className="w-full overflow-x-auto rounded-md bg-[#0b0f17] border border-border/40">
      <div className="grid grid-cols-4 gap-2 px-3 pt-3 text-[11px] text-muted-foreground">
        {stages.map((stage, i) => {
          const col = columns[i];
          const kept = (col?.critical ?? 0) + (col?.high ?? 0);
          const reduction =
            i === 0 || inputTotal <= 0
              ? null
              : Math.round((1 - kept / inputTotal) * 100);
          return (
            <div key={stage} className="text-center">
              <p className="font-medium tracking-wide uppercase">{stage}</p>
              {reduction != null && (
                <p className="text-emerald-400/90 tabular-nums mt-0.5">−{reduction}%</p>
              )}
            </div>
          );
        })}
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[280px]" role="img">
        <title>Prioritization Sankey</title>
        {laidLinks.map((link, i) => (
          <path
            key={`l-${i}`}
            d={link.path}
            fill={LINK_COLORS[link.kind]}
            stroke="none"
          >
            <title>{`${link.kind}: ${link.value}`}</title>
          </path>
        ))}
        {laidNodes.map((node) => {
          const isRight = node.stage >= 2;
          const label =
            node.kind === 'filtered'
              ? node.count > 0
                ? formatNumber(node.count)
                : ''
              : formatNumber(node.count);
          return (
            <g key={`n-${node.index}`}>
              <rect
                x={node.x}
                y={node.y}
                width={node.width}
                height={node.height}
                rx={2}
                fill={COLORS[node.kind]}
                opacity={node.kind === 'filtered' ? 0.9 : 1}
                style={
                  node.kind !== 'filtered'
                    ? { filter: `drop-shadow(0 0 6px ${COLORS[node.kind]}88)` }
                    : undefined
                }
              />
              {node.height > 10 && label && (
                <text
                  x={isRight ? node.x - 6 : node.x + node.width + 6}
                  y={node.y + node.height / 2}
                  textAnchor={isRight ? 'end' : 'start'}
                  dominantBaseline="middle"
                  fill="#e2e8f0"
                  fontSize={11}
                  fontWeight={600}
                >
                  {label}
                </text>
              )}
              {node.kind === 'filtered' && node.height > 28 && (
                <text
                  x={isRight ? node.x - 6 : node.x + node.width + 6}
                  y={node.y + node.height / 2 + 12}
                  textAnchor={isRight ? 'end' : 'start'}
                  dominantBaseline="middle"
                  fill="#94a3b8"
                  fontSize={9}
                >
                  Filtered out
                </text>
              )}
            </g>
          );
        })}
        {/* invisible stage anchors for layout stability */}
        {stageXs.map((x, i) => (
          <circle key={`a-${i}`} cx={x} cy={0} r={0} />
        ))}
      </svg>
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

  const summary = funnel?.summary;
  const columns = funnel?.columns ?? [];
  const nodes = funnel?.nodes ?? [];
  const links = (funnel?.links ?? []).filter((l) => (l.value || 0) > 0);
  const stages = funnel?.stages?.length
    ? funnel.stages
    : ['Scanner', 'Delphi', 'OPES', 'Priority'];
  const inputTotal = summary?.input_total ?? 0;
  const outputTotal = summary?.output_total ?? 0;
  const reductionPct = summary?.reduction_pct ?? 0;
  const hasData = inputTotal > 0 && nodes.length > 0 && links.length > 0;

  return (
    <Card className="border-orange-500/20 overflow-hidden">
      <CardHeader className="flex flex-row items-start justify-between gap-4 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-lg flex items-center gap-2">
            <Target className="h-5 w-5 text-orange-400" />
            Prioritization Value
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

            <PrioritizationSankey
              nodes={nodes}
              links={links}
              stages={stages}
              columns={columns}
            />

            <p className="text-xs text-muted-foreground">
              Ribbons show how scanner Critical/High are demoted into Filtered out by Delphi and
              OPES. Critical and High stay on top; Filtered out stays at the bottom. Final Priority
              keeps OPES Critical plus High when KEV-listed or OPES ≥ 7.0.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
