'use client';

import { useEffect, useMemo, useState } from 'react';
import Dagre from '@dagrejs/dagre';
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ChevronDown, ChevronUp, GitBranch } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { TRUST_COLORS } from './TrustBoundaryMap';

type LineageKind = 'goal' | 'intent' | 'fact' | 'finding';
type LineageRel = 'spawns' | 'derived_from' | 'yields' | 'proves';

interface LineageNode {
  key: string;
  kind: LineageKind;
  label: string;
  status?: string;
  host?: string;
  asset_id?: number;
  specialist?: string;
  source?: string;
  fact_kind?: string;
  reason?: string;
  blocked_reason?: string;
  evidence?: string;
}

interface Lineage {
  session_id: string;
  node_counts: Partial<Record<LineageKind, number>>;
  nodes: LineageNode[];
  edges: { source: string; rel: LineageRel; target: string }[];
  truncated?: boolean;
}

const KIND_COLOR: Record<LineageKind, string> = {
  goal: TRUST_COLORS.blue,
  intent: TRUST_COLORS.purple,
  fact: TRUST_COLORS.gray,
  finding: TRUST_COLORS.red,
};

const REL_COLOR: Record<LineageRel, string> = {
  spawns: TRUST_COLORS.purple,
  derived_from: TRUST_COLORS.gray,
  yields: TRUST_COLORS.green,
  proves: TRUST_COLORS.red,
};

const DONE = new Set(['proven', 'killed', 'tested_clean', 'finding', 'skipped', 'verified', 'reported']);
const SIZE = { width: 230, height: 64 };

function LineageNodeView({ data }: NodeProps) {
  const d = data as unknown as LineageNode;
  const color = KIND_COLOR[d.kind] || TRUST_COLORS.gray;
  const muted = d.status === 'killed';
  return (
    <div
      className={cn('h-full w-full rounded-md border-2 bg-card/90 px-2.5 py-1.5 text-left', muted && 'opacity-50')}
      style={{ borderColor: color }}
      title={[d.label, d.reason, d.blocked_reason, d.evidence, d.host].filter(Boolean).join('\n')}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div className="flex items-center gap-1.5 text-[9px] uppercase tracking-wider" style={{ color }}>
        <span>{d.kind === 'fact' && d.fact_kind ? d.fact_kind.replace('_', ' ') : d.kind}</span>
        {d.status ? <span className="text-muted-foreground">· {d.status}</span> : null}
        {d.specialist ? <span className="truncate text-muted-foreground">· {d.specialist}</span> : null}
      </div>
      <p className="line-clamp-2 text-[11px] leading-snug text-foreground">{d.label}</p>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}

const nodeTypes = { lineage: LineageNodeView };

function layout(lineage: Lineage, hideDone: boolean): { nodes: Node[]; edges: Edge[] } {
  const keep = new Set(
    lineage.nodes
      .filter((n) => !hideDone || n.kind !== 'intent' || !DONE.has(n.status || '') || n.status === 'proven')
      .map((n) => n.key)
  );
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', nodesep: 18, ranksep: 70, marginx: 24, marginy: 24 });
  const nodes = lineage.nodes.filter((n) => keep.has(n.key));
  nodes.forEach((n) => g.setNode(n.key, { ...SIZE }));
  // derived_from points intent -> fact; draw it fact -> intent so the graph reads left to right.
  const edges = lineage.edges
    .filter((e) => keep.has(e.source) && keep.has(e.target))
    .map((e) => (e.rel === 'derived_from' ? { ...e, source: e.target, target: e.source } : e));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  Dagre.layout(g);
  return {
    nodes: nodes.map((n) => {
      const pos = g.node(n.key);
      return {
        id: n.key,
        type: 'lineage',
        data: n as unknown as Record<string, unknown>,
        position: { x: (pos?.x || 0) - SIZE.width / 2, y: (pos?.y || 0) - SIZE.height / 2 },
        style: { ...SIZE },
      };
    }),
    edges: edges.map((e, i) => ({
      id: `${e.source}-${e.rel}-${e.target}-${i}`,
      source: e.source,
      target: e.target,
      label: e.rel.replace('_', ' '),
      labelStyle: { fontSize: 9, fill: REL_COLOR[e.rel] },
      labelBgStyle: { fill: 'transparent' },
      style: { stroke: REL_COLOR[e.rel], strokeWidth: e.rel === 'proves' ? 2 : 1.2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: REL_COLOR[e.rel] },
    })),
  };
}

export function ExplorationLineagePanel({
  sessionId,
  refreshKey,
}: {
  sessionId: string;
  /** Any value that changes when the session advances (e.g. the chain data). */
  refreshKey?: unknown;
}) {
  const [lineage, setLineage] = useState<Lineage | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [hideDone, setHideDone] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .getAgentSessionExploration(sessionId)
      .then((d: Lineage) => live && setLineage(d))
      .catch(() => live && setLineage(null));
    return () => {
      live = false;
    };
  }, [sessionId, refreshKey]);

  const graph = useMemo(() => (lineage ? layout(lineage, hideDone) : null), [lineage, hideDone]);
  if (!lineage || lineage.nodes.length <= 1) return null;
  const counts = lineage.node_counts || {};

  return (
    <Card>
      <CardHeader className="py-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <GitBranch className="h-4 w-4 text-primary" />
            Exploration lineage
            <span className="flex gap-1 font-normal">
              {(['intent', 'fact', 'finding'] as LineageKind[]).map((k) =>
                counts[k] ? (
                  <Badge key={k} variant="outline" className="text-[10px]" style={{ borderColor: KIND_COLOR[k] }}>
                    {counts[k]} {k}s
                  </Badge>
                ) : null
              )}
            </span>
          </CardTitle>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setHideDone(!hideDone)}>
              {hideDone ? 'Show finished' : 'Open work only'}
            </Button>
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setCollapsed(!collapsed)}>
              {collapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
            </Button>
          </div>
        </div>
        {!collapsed ? (
          <p className="text-[11px] text-muted-foreground">
            Goal → intents (hypotheses, follow-ups) → facts they were derived from or yielded → findings they proved.
            {lineage.truncated ? ' Large session: showing the first 1,500 nodes.' : ''}
          </p>
        ) : null}
      </CardHeader>
      {!collapsed && graph ? (
        <CardContent className="h-[460px] p-0">
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.1}
            proOptions={{ hideAttribution: true }}
            nodesDraggable={false}
          >
            <Background gap={24} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </CardContent>
      ) : null}
    </Card>
  );
}
