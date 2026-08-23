'use client';

import { useMemo } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toPng } from 'html-to-image';
import { attackNodeTypes } from './AttackNodes';
import { layoutAttackGraph } from './layout';
import { AttackStatusLegend } from './AttackPathNarrative';
import { STATUS_META, type AttackPath } from './types';

function toFlow(path: AttackPath): { nodes: Node[]; edges: Edge[] } {
  const rawNodes: Node[] = path.nodes.map((n) => ({
    id: n.id,
    type: n.kind,
    position: { x: 0, y: 0 },
    data: { ...n },
    draggable: true,
  }));
  const rawEdges: Edge[] = path.edges.map((e) => {
    const src = path.nodes.find((n) => n.id === e.source);
    const color = STATUS_META[src?.status || 'tested']?.border || '#ef4444';
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'smoothstep',
      animated: src?.status === 'tested' || src?.status === 'undetected',
      style: { stroke: color, strokeWidth: 1.6 },
    };
  });
  return { nodes: layoutAttackGraph(rawNodes, rawEdges), edges: rawEdges };
}

export function AttackPathCanvas({
  path,
  canvasId = 'attack-path-canvas',
}: {
  path: AttackPath;
  canvasId?: string;
}) {
  const graph = useMemo(() => toFlow(path), [path]);

  return (
    <div
      id={canvasId}
      className="attack-path-canvas relative h-full min-h-[420px] w-full overflow-hidden rounded-md border border-border/60"
      style={{
        backgroundColor: '#070b12',
        backgroundImage:
          'linear-gradient(rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.06) 1px, transparent 1px)',
        backgroundSize: '28px 28px',
      }}
    >
      <ReactFlow
        nodes={graph.nodes}
        edges={graph.edges}
        nodeTypes={attackNodeTypes}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.25}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable
        panOnScroll
      >
        <Background variant={BackgroundVariant.Lines} gap={28} color="rgba(148,163,184,0.07)" />
        <Controls
          showInteractive={false}
          className="!m-3 !overflow-hidden !rounded-md !border-border !bg-card/90 !shadow-none [&>button]:!border-border [&>button]:!bg-transparent [&>button]:!fill-foreground"
        />
      </ReactFlow>
      <AttackStatusLegend className="pointer-events-none absolute bottom-3 right-3 z-10 max-w-[min(100%,520px)]" />
    </div>
  );
}

export async function exportAttackPathPng(filename: string, elementId = 'attack-path-canvas') {
  const el = document.getElementById(elementId);
  if (!el) return;
  const dataUrl = await toPng(el, {
    cacheBust: true,
    backgroundColor: '#070b12',
    pixelRatio: 2,
  });
  const link = document.createElement('a');
  link.download = filename;
  link.href = dataUrl;
  link.click();
}
