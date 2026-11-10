'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ChevronDown, ChevronRight, GitBranch, Loader2, RefreshCw, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { api, type ExplorationGraph, type ExplorationNode, type ExplorationNodeType } from '@/lib/api';
import { cn } from '@/lib/utils';

const COLUMNS: ExplorationNodeType[] = ['asset', 'observation', 'hypothesis', 'candidate', 'finding'];
const COLUMN_TITLE: Record<ExplorationNodeType, string> = {
  asset: 'Assets', observation: 'Observations', hypothesis: 'Hypotheses', candidate: 'Candidates', finding: 'Findings',
};
const COL_WIDTH = 260;
const ROW_HEIGHT = 64;

const BUCKET_STYLE: Record<string, string> = {
  proven: 'border-red-500/70 bg-red-500/10',
  killed: 'border-muted-foreground/40 bg-muted/40 text-muted-foreground line-through',
  blocked: 'border-amber-500/70 bg-amber-500/10',
  running: 'border-sky-500/70 bg-sky-500/10',
  open: 'border-border bg-card',
};

function nodeClass(n: ExplorationNode) {
  if (n.type === 'hypothesis') return BUCKET_STYLE[n.bucket] || BUCKET_STYLE.open;
  if (n.type === 'candidate') return n.verified ? 'border-red-500/70 bg-red-500/10' : 'border-dashed border-amber-500/60 bg-card';
  if (n.type === 'finding') return 'border-red-600 bg-red-600/20';
  if (n.type === 'asset') return n.primary ? 'border-primary bg-primary/10' : 'border-primary/40 bg-card';
  return 'border-border bg-muted/30';
}

function subtitle(n: ExplorationNode) {
  if (n.type === 'hypothesis') return [n.specialist, n.status, n.attempts ? `${n.attempts} tries` : ''].filter(Boolean).join(' · ');
  if (n.type === 'observation') return [n.kind, n.source].filter(Boolean).join(' · ');
  if (n.type === 'candidate') return n.verified ? 'verified' : 'lead — not verified';
  if (n.type === 'finding') return [n.severity, n.status].filter(Boolean).join(' · ');
  if (n.type === 'asset' && n.coverage) {
    const c = n.coverage;
    return `${c.hypotheses} tested · ${c.proven} proven · ${c.killed} killed · ${c.open + c.running + c.blocked} open`;
  }
  return '';
}

function Label({ n }: { n: ExplorationNode }) {
  return (
    <div className={cn('w-[220px] rounded-md border px-2 py-1 text-left', nodeClass(n))}>
      <p className="truncate text-xs font-medium" title={n.label}>{n.label || n.id}</p>
      <p className="truncate text-[10px] text-muted-foreground">{subtitle(n)}</p>
    </div>
  );
}

function layout(graph: ExplorationGraph, showAnchors: boolean, focus: Set<string> | null) {
  const rows: Record<string, number> = {};
  const order = { proven: 0, running: 1, blocked: 2, open: 3, killed: 4 } as Record<string, number>;
  const sorted = [...graph.nodes].sort((a, b) =>
    a.type === 'hypothesis' && b.type === 'hypothesis' ? (order[a.bucket] ?? 9) - (order[b.bucket] ?? 9) : 0);
  const nodes: Node[] = sorted.map((n) => {
    const col = COLUMNS.indexOf(n.type);
    const row = (rows[n.type] = (rows[n.type] ?? -1) + 1);
    const dimmed = focus !== null && !focus.has(n.id);
    return {
      id: n.id,
      position: { x: col * COL_WIDTH, y: (row + 1) * ROW_HEIGHT },
      data: { label: <Label n={n} /> },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      draggable: true,
      connectable: false,
      style: { padding: 0, border: 'none', background: 'transparent', width: 220, opacity: dimmed ? 0.2 : 1 },
    };
  });
  const present = new Set(graph.nodes.map((n) => n.type));
  for (const type of COLUMNS) {
    if (!present.has(type)) continue;
    nodes.push({
      id: `column:${type}`,
      position: { x: COLUMNS.indexOf(type) * COL_WIDTH, y: 0 },
      data: { label: <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{COLUMN_TITLE[type]}</p> },
      draggable: false,
      selectable: false,
      connectable: false,
      style: { padding: 0, border: 'none', background: 'transparent', width: 220, pointerEvents: 'none' },
    });
  }
  const edges: Edge[] = graph.edges
    .filter((e) => showAnchors || e.kind !== 'anchored')
    .map((e, i) => {
      const dimmed = focus !== null && !(focus.has(e.source) && focus.has(e.target));
      return {
        id: `${e.kind}-${i}`,
        source: e.source,
        target: e.target,
        label: e.kind === 'anchored' ? undefined : e.kind.replace('_', ' '),
        labelStyle: { fontSize: 9, fill: 'hsl(var(--muted-foreground))' },
        labelBgStyle: { fill: 'hsl(var(--card))' },
        markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12 },
        animated: e.kind === 'proves',
        style: {
          strokeDasharray: e.kind === 'anchored' ? '3 3' : undefined,
          opacity: dimmed ? 0.1 : 0.8,
        },
      };
    });
  return { nodes, edges };
}

/** Everything connected to ``start`` (both directions), so an asset shows what tested it. */
function neighborhood(graph: ExplorationGraph, start: string): Set<string> {
  const adjacent: Record<string, string[]> = {};
  for (const e of graph.edges) {
    (adjacent[e.source] ||= []).push(e.target);
    (adjacent[e.target] ||= []).push(e.source);
  }
  const seen = new Set([start]);
  const queue = [start];
  while (queue.length) {
    const id = queue.shift()!;
    for (const next of adjacent[id] || []) {
      // Do not walk through other assets: keep the focus on this one.
      if (!seen.has(next) && !(next.startsWith('asset:') && next !== start)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}

function Details({ node, onClose }: { node: ExplorationNode; onClose: () => void }) {
  const fields = Object.entries(node).filter(([k, v]) =>
    !['id', 'type', 'label', 'coverage', 'bucket'].includes(k) && v !== '' && v !== null && v !== undefined && v !== 0);
  return (
    <div className="space-y-2 rounded-md border border-border p-3 text-xs">
      <div className="flex items-start justify-between gap-2">
        <div>
          <Badge variant="outline" className="mb-1 text-[10px]">{node.type}</Badge>
          <p className="text-sm font-medium break-words">{node.label}</p>
        </div>
        <Button size="icon" variant="ghost" className="h-6 w-6" aria-label="Close details" onClick={onClose}><X className="h-3 w-3" /></Button>
      </div>
      {node.coverage && (
        <p className="text-muted-foreground">
          {node.coverage.observations} observations · {node.coverage.hypotheses} hypotheses ({node.coverage.proven} proven,{' '}
          {node.coverage.killed} killed, {node.coverage.blocked} blocked, {node.coverage.open + node.coverage.running} open) ·{' '}
          {node.coverage.candidates} candidates · {node.coverage.findings} findings
        </p>
      )}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
        {fields.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{k.replace(/_/g, ' ')}</dt>
            <dd className="break-all">{String(v)}</dd>
          </div>
        ))}
      </dl>
      {node.type === 'finding' && node.finding_id && (
        <p className="text-muted-foreground">Finding #{node.finding_id} on the Findings page</p>
      )}
      {node.type === 'asset' && node.asset_id && (
        <Link className="text-primary underline" href={`/assets/${node.asset_id}`}>Open asset</Link>
      )}
    </div>
  );
}

export function ExplorationGraphPanel({ sessionId, live }: { sessionId: string; live?: boolean }) {
  const [open, setOpen] = useState(false);
  const [graph, setGraph] = useState<ExplorationGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showAnchors, setShowAnchors] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setGraph(await api.getExplorationGraph(sessionId));
      setError('');
    } catch {
      setError('The exploration graph is unavailable for this run.');
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { setGraph(null); setSelected(null); }, [sessionId]);
  useEffect(() => { if (open) load(); }, [open, load]);
  useEffect(() => {
    if (!open || !live) return;
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, [open, live, load]);

  const byId = useMemo(() => Object.fromEntries((graph?.nodes || []).map((n) => [n.id, n])), [graph]);
  const focus = useMemo(() => (graph && selected ? neighborhood(graph, selected) : null), [graph, selected]);
  const flow = useMemo(() => (graph ? layout(graph, showAnchors, focus) : { nodes: [], edges: [] }), [graph, showAnchors, focus]);
  const counts = graph?.counts || {};

  return (
    <Card>
      <CardHeader className="py-3">
        <button type="button" className="flex w-full items-center justify-between gap-2 text-left" onClick={() => setOpen((o) => !o)}>
          <CardTitle className="flex items-center gap-2 text-sm">
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <GitBranch className="h-4 w-4" />Exploration graph
          </CardTitle>
          {graph && (
            <span className="text-xs text-muted-foreground">
              {COLUMNS.map((c) => `${counts[c] || 0} ${COLUMN_TITLE[c].toLowerCase()}`).join(' · ')}
            </span>
          )}
        </button>
      </CardHeader>
      {open && (
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span>What this run observed, hypothesised, tried and proved. Click an asset to see what tested it.</span>
            <label className="ml-auto flex items-center gap-2">
              <Switch checked={showAnchors} onCheckedChange={setShowAnchors} />Asset anchors
            </label>
            <Button size="sm" variant="ghost" onClick={load} disabled={loading} aria-label="Refresh graph">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </div>
          {error && <p className="text-xs text-amber-500">{error}</p>}
          {graph && graph.nodes.length === 0 && (
            <p className="text-xs text-muted-foreground">Nothing recorded yet. The graph fills in once the run saves its engagement state.</p>
          )}
          {graph && graph.nodes.length > 0 && (
            <div className="grid gap-3 lg:grid-cols-[1fr_300px]">
              <div className="h-[520px] rounded-md border border-border">
                <ReactFlow
                  nodes={flow.nodes}
                  edges={flow.edges}
                  fitView
                  minZoom={0.1}
                  nodesConnectable={false}
                  colorMode="system"
                  onNodeClick={(_, node) => { if (!node.id.startsWith('column:')) setSelected((s) => (s === node.id ? null : node.id)); }}
                  onPaneClick={() => setSelected(null)}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="hsl(var(--border))" />
                  <Controls className="!bg-card !border-border !shadow-none" showInteractive={false} />
                </ReactFlow>
              </div>
              <div className="space-y-2">
                {selected && byId[selected] ? (
                  <Details node={byId[selected]} onClose={() => setSelected(null)} />
                ) : (
                  <ul className="space-y-1 text-xs text-muted-foreground">
                    <li><span className="font-medium text-foreground">Red</span>: proven hypothesis, verified candidate, finding</li>
                    <li><span className="font-medium text-foreground">Amber</span>: blocked, or a lead not yet verified</li>
                    <li><span className="font-medium text-foreground">Blue</span>: running · <span className="line-through">struck</span>: killed</li>
                    <li>Edges: spawns, depends on, derived from, yields, proves, chains to</li>
                  </ul>
                )}
                {graph.truncated && <p className="text-xs text-amber-500">Large run: only the first 800 nodes are shown.</p>}
                {graph.saved_at && (
                  <p className="text-[11px] text-muted-foreground">State saved {new Date(graph.saved_at * 1000).toLocaleString()}</p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}
