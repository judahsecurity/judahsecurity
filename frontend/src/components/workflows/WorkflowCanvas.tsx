'use client';

import { useCallback, useEffect, useMemo, useRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  type Connection,
  type Node,
  type Edge,
  type OnSelectionChangeParams,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { WorkflowNode } from './WorkflowNode';
import type { WorkflowNodeRun } from './types';

const nodeTypes = { workflow: WorkflowNode };

interface Props {
  initialNodes?: Node[];
  initialEdges?: Edge[];
  nodeRuns?: WorkflowNodeRun[];
  onSelectionChange?: (node: Node | null) => void;
  onGraphChange?: (nodes: Node[], edges: Edge[]) => void;
}

function applyRunStatus(nodes: Node[], nodeRuns?: WorkflowNodeRun[]): Node[] {
  if (!nodeRuns?.length) return nodes;
  const byId = Object.fromEntries(nodeRuns.map((r) => [r.node_id, r]));
  return nodes.map((n) => ({
    ...n,
    data: {
      ...n.data,
      runStatus: byId[n.id]?.status,
    },
  }));
}

export function WorkflowCanvas({
  initialNodes = [],
  initialEdges = [],
  nodeRuns,
  onSelectionChange,
  onGraphChange,
}: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when node/edge membership changes (load or palette add), not on every parent render
  const initialKey = useMemo(
    () => `${initialNodes.map((n) => n.id).join(',')}|${initialEdges.map((e) => e.id).join(',')}`,
    [initialNodes, initialEdges]
  );
  const prevKey = useRef<string>('');
  useEffect(() => {
    if (initialKey !== prevKey.current) {
      prevKey.current = initialKey;
      setNodes(applyRunStatus(initialNodes, nodeRuns));
      setEdges(initialEdges);
    }
  }, [initialKey, initialNodes, initialEdges, nodeRuns, setNodes, setEdges]);

  // Overlay run status without resetting positions
  useEffect(() => {
    if (!nodeRuns) return;
    setNodes((curr) => applyRunStatus(curr, nodeRuns));
  }, [nodeRuns, setNodes]);

  const emitRef = useRef(onGraphChange);
  emitRef.current = onGraphChange;
  useEffect(() => {
    emitRef.current?.(nodes, edges);
  }, [nodes, edges]);

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) =>
        addEdge(
          {
            ...connection,
            id: `e-${connection.source}-${connection.sourceHandle}-${connection.target}-${connection.targetHandle}-${Date.now()}`,
          },
          eds
        )
      );
    },
    [setEdges]
  );

  const handleSelection = useCallback(
    ({ nodes: selected }: OnSelectionChangeParams) => {
      onSelectionChange?.(selected[0] || null);
    },
    [onSelectionChange]
  );

  const types = useMemo(() => nodeTypes, []);

  return (
    <div className="h-full w-full bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900/80 via-background to-background">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onSelectionChange={handleSelection}
        nodeTypes={types}
        fitView
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ style: { stroke: 'hsl(var(--muted-foreground))' } }}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="hsl(var(--border))" />
        <Controls className="!bg-card !border-border !shadow-none" />
        <MiniMap
          className="!bg-card !border-border"
          nodeColor={() => 'hsl(var(--primary))'}
          maskColor="rgba(0,0,0,0.55)"
        />
      </ReactFlow>
    </div>
  );
}

export function toFlowNodes(graphNodes: any[]): Node[] {
  return (graphNodes || []).map((n) => {
    const data = n.data || {};
    const kind = n.type || data.node_type || 'tool';
    return {
      id: n.id,
      type: 'workflow',
      position: n.position || { x: 0, y: 0 },
      data: {
        ...data,
        nodeKind: kind,
        label: data.label || n.id,
        inputPorts: data.inputPorts || inferPorts(kind, data, 'in'),
        outputPorts: data.outputPorts || inferPorts(kind, data, 'out'),
      },
    };
  });
}

function inferPorts(kind: string, data: any, dir: 'in' | 'out') {
  if (kind === 'primitive') {
    const name = data.port?.name || data.value_key || 'domain';
    return dir === 'out' ? [{ name, type: data.port?.type || 'STRING' }] : [];
  }
  if (kind === 'sink') {
    const name = data.port?.name || 'in';
    return dir === 'in' ? [{ name, type: data.port?.type || 'FILE_LIST' }] : [];
  }
  return [];
}

export function fromFlowGraph(nodes: Node[], edges: Edge[]) {
  return {
    nodes: nodes.map((n) => {
      const d = n.data as any;
      return {
        id: n.id,
        type: d.nodeKind || 'tool',
        position: n.position,
        data: {
          label: d.label,
          tool_id: d.tool_id,
          script_id: d.script_id,
          workflow_id: d.workflow_id,
          params: d.params || {},
          port: d.port,
          value_key: d.value_key,
          inputPorts: d.inputPorts,
          outputPorts: d.outputPorts,
          paramSchema: d.paramSchema,
        },
      };
    }),
    edges: edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      sourceHandle: e.sourceHandle,
      targetHandle: e.targetHandle,
    })),
  };
}
