'use client';

import { useMemo, useState } from 'react';
import { Controls, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Maximize2, Route, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { AGENT_NODE_SIZE, agentPathNodeTypes } from './AgentPathNodes';
import { layoutAttackGraph } from './layout';
import {
  KIND_META,
  STATUS_STYLE,
  type AgentAttackGraphData,
  type AgentGraphKind,
  type AgentGraphNode,
  type AgentGraphStatus,
} from './agentGraph';

function toFlow(graph: AgentAttackGraphData): { nodes: Node[]; edges: Edge[] } {
  const rawNodes: Node[] = graph.nodes.map((n) => ({
    id: n.id,
    type: 'agent',
    position: { x: 0, y: 0 },
    data: { ...n },
  }));
  const edges: Edge[] = graph.edges.map((e) => {
    const s = STATUS_STYLE[e.status] || STATUS_STYLE.inferred;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'default',
      style: {
        stroke: s.edge,
        strokeWidth: e.status === 'proven' ? 1.75 : 1.25,
        strokeDasharray: s.dash,
        opacity: s.opacity,
      },
    };
  });
  const nodes = layoutAttackGraph(rawNodes, edges, {
    sizeOf: () => AGENT_NODE_SIZE,
    nodesep: 28,
    ranksep: 40,
    align: null,
  });
  return { nodes, edges };
}

function Legend({ graph }: { graph: AgentAttackGraphData }) {
  const kinds = Array.from(new Set(graph.nodes.map((n) => n.kind))).filter(
    (k) => k !== 'action'
  ) as AgentGraphKind[];
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
      {kinds.map((k) => (
        <span key={k} className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ background: KIND_META[k].color }} />
          {KIND_META[k].label}
        </span>
      ))}
      <span className="mx-1 h-3 w-px bg-border" />
      {(Object.keys(STATUS_STYLE) as AgentGraphStatus[]).map((s) => (
        <span key={s} className="flex items-center gap-1" title={STATUS_STYLE[s].hint}>
          <svg width="16" height="6" aria-hidden>
            <line
              x1="0"
              y1="3"
              x2="16"
              y2="3"
              stroke={STATUS_STYLE[s].edge}
              strokeWidth={1.75}
              strokeDasharray={STATUS_STYLE[s].dash}
              opacity={STATUS_STYLE[s].opacity}
            />
          </svg>
          {STATUS_STYLE[s].label}
        </span>
      ))}
    </div>
  );
}

function Inspector({ node, onClose }: { node: AgentGraphNode; onClose: () => void }) {
  const kind = KIND_META[node.kind];
  const status = STATUS_STYLE[node.status];
  const ev = node.evidence;
  return (
    <div className="absolute bottom-2 right-2 top-2 z-10 flex w-[280px] flex-col overflow-hidden rounded-lg border border-border bg-card/95 shadow-xl backdrop-blur">
      <div className="flex items-start justify-between gap-2 border-b border-border px-3 py-2">
        <div className="min-w-0">
          <p className="text-[10px] uppercase tracking-wide" style={{ color: kind.color }}>
            {kind.label} · {status.label}
          </p>
          <p className="mt-0.5 break-words text-xs font-medium text-foreground">
            {node.description || node.title}
          </p>
        </div>
        <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0" onClick={onClose}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
      <div className="flex-1 space-y-2.5 overflow-y-auto px-3 py-2 text-[11px]">
        <p className="text-muted-foreground">{status.hint}.</p>
        {node.host ? <Field label="Host" value={node.host} mono /> : null}
        {node.severity ? <Field label="Severity" value={node.severity} /> : null}
        {ev ? (
          <>
            <Field label="Step" value={`#${ev.iteration} · ${ev.phase || 'unknown phase'}`} />
            {ev.tool ? <Field label="Tool" value={ev.tool} mono /> : null}
            {ev.thought ? <Field label="Agent reasoning" value={ev.thought} /> : null}
            {ev.args ? <Field label="Request" value={ev.args} mono block /> : null}
            {ev.output ? <Field label="Result" value={ev.output} mono block /> : null}
          </>
        ) : null}
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  block,
}: {
  label: string;
  value: string;
  mono?: boolean;
  block?: boolean;
}) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p
        className={cn(
          'mt-0.5 break-words text-foreground',
          mono && 'font-mono text-[10.5px]',
          block && 'max-h-40 overflow-y-auto whitespace-pre-wrap rounded border border-border bg-muted/40 px-2 py-1'
        )}
      >
        {value}
      </p>
    </div>
  );
}

function Canvas({ graph, className }: { graph: AgentAttackGraphData; className?: string }) {
  const flow = useMemo(() => toFlow(graph), [graph]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = graph.nodes.find((n) => n.id === selectedId) || null;

  return (
    <div className={cn('relative h-full w-full bg-card', className)}>
      <ReactFlow
        nodes={flow.nodes.map((n) => ({ ...n, selected: n.id === selectedId }))}
        edges={flow.edges}
        nodeTypes={agentPathNodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2}
        maxZoom={1.75}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        nodesDraggable={false}
        onNodeClick={(_, n) => setSelectedId(n.id === selectedId ? null : n.id)}
        onPaneClick={() => setSelectedId(null)}
        panOnScroll
      >
        <Controls
          showInteractive={false}
          position="bottom-left"
          className="!m-2 !overflow-hidden !rounded-md !border !border-border !bg-card !shadow-none [&>button]:!border-border [&>button]:!bg-transparent [&>button]:!fill-foreground"
        />
      </ReactFlow>
      {selected ? <Inspector node={selected} onClose={() => setSelectedId(null)} /> : null}
    </div>
  );
}

export function AgentAttackGraph({
  graph,
  className,
}: {
  graph: AgentAttackGraphData | null | undefined;
  className?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const meta = graph?.meta || {};

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className={cn('flex flex-1 items-center justify-center p-6 text-center', className)}>
        <div>
          <Route className="mx-auto mb-2 h-8 w-8 text-muted-foreground opacity-40" />
          <p className="text-xs text-muted-foreground">No attack path yet</p>
          <p className="mt-1 text-[10px] text-muted-foreground/70">
            The path appears when the agent confirms a vulnerability or captures access.
            {meta.failed_attempts ? ` ${meta.failed_attempts} failed attempts so far.` : ''}
          </p>
        </div>
      </div>
    );
  }

  const summary = [
    `${meta.hosts ?? 0} host${meta.hosts === 1 ? '' : 's'}`,
    `${meta.actions ?? 0} actions`,
    `${meta.capabilities ?? 0} captured`,
    `${meta.proven ?? 0} proven`,
  ].join(' · ');

  return (
    <div className={cn('flex min-h-0 flex-1 flex-col', className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
        <span className="font-mono text-[10px] text-muted-foreground">{summary}</span>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6"
          title="Expand"
          onClick={() => setExpanded(true)}
        >
          <Maximize2 className="h-3 w-3" />
        </Button>
      </div>
      <div className="min-h-[360px] flex-1">
        <Canvas graph={graph} />
      </div>
      <div className="border-t border-border px-3 py-1.5">
        <Legend graph={graph} />
      </div>

      <Dialog open={expanded} onOpenChange={setExpanded}>
        <DialogContent className="flex h-[85vh] max-w-[92vw] flex-col gap-3 p-5">
          <DialogTitle className="flex items-center gap-2 text-base">
            <Route className="h-4 w-4 text-primary" />
            Attack path
            <span className="ml-2 font-mono text-[11px] font-normal text-muted-foreground">{summary}</span>
          </DialogTitle>
          {meta.objective ? (
            <p className="-mt-1 line-clamp-2 text-xs text-muted-foreground">{meta.objective}</p>
          ) : null}
          <div className="min-h-0 flex-1 overflow-hidden rounded-md border border-border">
            {expanded ? <Canvas graph={graph} /> : null}
          </div>
          <Legend graph={graph} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
