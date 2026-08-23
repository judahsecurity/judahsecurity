import Dagre from '@dagrejs/dagre';
import type { Edge, Node } from '@xyflow/react';
import type { AttackNodeKind } from './types';

const SIZE: Record<AttackNodeKind, { width: number; height: number }> = {
  attacker: { width: 92, height: 108 },
  technique: { width: 280, height: 76 },
  host: { width: 248, height: 92 },
  vulnerability: { width: 268, height: 92 },
};

export function layoutAttackGraph(nodes: Node[], edges: Edge[]): Node[] {
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: 'LR',
    nodesep: 56,
    ranksep: 88,
    marginx: 48,
    marginy: 48,
    align: 'UL',
  });

  nodes.forEach((node) => {
    const kind = (node.type as AttackNodeKind) || 'technique';
    const size = SIZE[kind] || SIZE.technique;
    g.setNode(node.id, { width: size.width, height: size.height });
  });
  edges.forEach((edge) => g.setEdge(edge.source, edge.target));
  Dagre.layout(g);

  return nodes.map((node) => {
    const pos = g.node(node.id);
    const kind = (node.type as AttackNodeKind) || 'technique';
    const size = SIZE[kind] || SIZE.technique;
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
