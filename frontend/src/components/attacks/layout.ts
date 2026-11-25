import Dagre from '@dagrejs/dagre';
import type { Edge, Node } from '@xyflow/react';
import type { AttackNodeKind } from './types';

const SIZE: Record<AttackNodeKind, { width: number; height: number }> = {
  attacker: { width: 92, height: 108 },
  technique: { width: 280, height: 76 },
  host: { width: 248, height: 92 },
  vulnerability: { width: 268, height: 92 },
};

type NodeSize = { width: number; height: number };

function defaultSize(node: Node): NodeSize {
  const kind = (node.type as AttackNodeKind) || 'technique';
  return SIZE[kind] || SIZE.technique;
}

export function layoutAttackGraph(
  nodes: Node[],
  edges: Edge[],
  opts: { sizeOf?: (node: Node) => NodeSize; nodesep?: number; ranksep?: number; /** null = centered ranks (symmetric fan-out). */ align?: 'UL' | 'UR' | 'DL' | 'DR' | null } = {}
): Node[] {
  const sizeOf = opts.sizeOf || defaultSize;
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: 'LR',
    nodesep: opts.nodesep ?? 56,
    ranksep: opts.ranksep ?? 88,
    marginx: 48,
    marginy: 48,
    ...(opts.align === null ? {} : { align: opts.align ?? 'UL' }),
  });

  nodes.forEach((node) => {
    const size = sizeOf(node);
    g.setNode(node.id, { width: size.width, height: size.height });
  });
  edges.forEach((edge) => g.setEdge(edge.source, edge.target));
  Dagre.layout(g);

  return nodes.map((node) => {
    const pos = g.node(node.id);
    const size = sizeOf(node);
    return {
      ...node,
      position: {
        x: (pos?.x || 0) - size.width / 2,
        y: (pos?.y || 0) - size.height / 2,
      },
      style: { width: size.width, height: size.height },
    };
  });
}
