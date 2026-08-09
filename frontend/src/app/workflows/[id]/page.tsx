'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import type { Node, Edge } from '@xyflow/react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Loader2, Play, Save, ArrowLeft, FileCode2 } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { NodePalette } from '@/components/workflows/NodePalette';
import { NodeInspector } from '@/components/workflows/NodeInspector';
import { RunSidebar } from '@/components/workflows/RunSidebar';
import { NodeIOPanel } from '@/components/workflows/NodeIOPanel';
import { ScriptEditor } from '@/components/workflows/ScriptEditor';
import {
  WorkflowCanvas,
  toFlowNodes,
  fromFlowGraph,
} from '@/components/workflows/WorkflowCanvas';
import type {
  ToolDef,
  WorkflowDetail,
  WorkflowRun,
  WorkflowScript,
  WorkflowSummary,
} from '@/components/workflows/types';

let _id = 0;
const nid = (prefix: string) => `${prefix}_${Date.now()}_${++_id}`;

export default function WorkflowEditorPage() {
  const params = useParams();
  const router = useRouter();
  const { toast } = useToast();
  const workflowId = parseInt(String(params.id), 10);

  const [workflow, setWorkflow] = useState<WorkflowDetail | null>(null);
  const [tools, setTools] = useState<ToolDef[]>([]);
  const [scripts, setScripts] = useState<WorkflowScript[]>([]);
  const [modules, setModules] = useState<WorkflowSummary[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [selected, setSelected] = useState<Node | null>(null);
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [activeRun, setActiveRun] = useState<WorkflowRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [runOpen, setRunOpen] = useState(false);
  const [runDomain, setRunDomain] = useState('');
  const [scriptOpen, setScriptOpen] = useState(false);
  const graphRef = useRef<{ nodes: Node[]; edges: Edge[] }>({ nodes: [], edges: [] });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const wf = await api.getWorkflow(workflowId);
      setWorkflow(wf);
      const orgId = wf.organization_id;
      const [toolList, scriptList, modList, runList] = await Promise.all([
        api.getWorkflowTools(),
        api.getWorkflowScripts(orgId),
        api.getWorkflows({ organization_id: orgId, kind: 'module' }),
        api.getWorkflowRuns({ workflow_id: workflowId, organization_id: orgId, limit: 30 }),
      ]);
      setTools(toolList || []);
      setScripts(scriptList || []);
      setModules((modList || []).filter((m: WorkflowSummary) => m.id !== workflowId));
      setRuns(runList || []);

      const graph = wf.latest_version?.graph || { nodes: [], edges: [] };
      const flowNodes = enrichNodes(toFlowNodes(graph.nodes || []), toolList || [], scriptList || []);
      setNodes(flowNodes);
      setEdges((graph.edges || []).map((e: any) => ({ ...e, type: e.type || 'default' })));
      graphRef.current = { nodes: flowNodes, edges: graph.edges || [] };
    } catch (e: any) {
      toast({ title: 'Failed to load workflow', description: e?.message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [workflowId, toast]);

  useEffect(() => {
    if (!Number.isNaN(workflowId)) loadAll();
  }, [workflowId, loadAll]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const onGraphChange = useCallback((n: Node[], e: Edge[]) => {
    graphRef.current = { nodes: n, edges: e };
  }, []);

  const persistNodes = (next: Node[]) => {
    setNodes(next);
    graphRef.current = { ...graphRef.current, nodes: next };
  };

  const addTool = (tool: ToolDef) => {
    const node: Node = {
      id: nid('tool'),
      type: 'workflow',
      position: { x: 280 + Math.random() * 120, y: 120 + Math.random() * 160 },
      data: {
        nodeKind: 'tool',
        label: tool.name,
        tool_id: tool.id,
        params: Object.fromEntries((tool.params || []).map((p) => [p.name, p.default ?? ''])),
        paramSchema: tool.params || [],
        inputPorts: tool.input_ports || [],
        outputPorts: tool.output_ports || [],
      },
    };
    persistNodes([...graphRef.current.nodes, node]);
  };

  const addScript = (script: WorkflowScript) => {
    const node: Node = {
      id: nid('script'),
      type: 'workflow',
      position: { x: 300 + Math.random() * 100, y: 180 + Math.random() * 100 },
      data: {
        nodeKind: 'script',
        label: script.name,
        script_id: script.id,
        inputPorts: script.input_ports || [{ name: 'hosts', type: 'FILE_LIST' }],
        outputPorts: script.output_ports || [{ name: 'hosts', type: 'FILE_LIST' }],
      },
    };
    persistNodes([...graphRef.current.nodes, node]);
  };

  const addModule = (mod: WorkflowSummary) => {
    const node: Node = {
      id: nid('module'),
      type: 'workflow',
      position: { x: 320, y: 200 },
      data: {
        nodeKind: 'module',
        label: mod.name,
        workflow_id: mod.id,
        inputPorts: [{ name: 'hosts', type: 'FILE_LIST' }],
        outputPorts: [{ name: 'urls', type: 'FILE_LIST' }],
      },
    };
    persistNodes([...graphRef.current.nodes, node]);
  };

  const addPrimitive = () => {
    const node: Node = {
      id: nid('in'),
      type: 'workflow',
      position: { x: 80, y: 180 },
      data: {
        nodeKind: 'primitive',
        label: 'Seed Domain',
        value_key: 'domain',
        port: { name: 'domain', type: 'STRING', required: true },
        inputPorts: [],
        outputPorts: [{ name: 'domain', type: 'STRING' }],
      },
    };
    persistNodes([...graphRef.current.nodes, node]);
  };

  const addSink = () => {
    const node: Node = {
      id: nid('sink'),
      type: 'workflow',
      position: { x: 720, y: 180 },
      data: {
        nodeKind: 'sink',
        label: 'Output',
        port: { name: 'urls', type: 'FILE_LIST' },
        inputPorts: [{ name: 'urls', type: 'FILE_LIST' }],
        outputPorts: [],
      },
    };
    persistNodes([...graphRef.current.nodes, node]);
  };

  const onNodeDataChange = (nodeId: string, data: Record<string, any>) => {
    const next = graphRef.current.nodes.map((n) => (n.id === nodeId ? { ...n, data } : n));
    persistNodes(next);
    if (selected?.id === nodeId) setSelected({ ...selected, data });
  };

  const onDeleteNode = (nodeId: string) => {
    const nextNodes = graphRef.current.nodes.filter((n) => n.id !== nodeId);
    const nextEdges = graphRef.current.edges.filter((e) => e.source !== nodeId && e.target !== nodeId);
    persistNodes(nextNodes);
    setEdges(nextEdges);
    graphRef.current.edges = nextEdges;
    setSelected(null);
  };

  const save = async () => {
    setSaving(true);
    try {
      const graph = fromFlowGraph(graphRef.current.nodes, graphRef.current.edges);
      await api.saveWorkflowVersion(workflowId, { graph });
      toast({ title: 'Workflow saved' });
      await loadAll();
    } catch (e: any) {
      toast({ title: 'Save failed', description: e?.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const startRun = async () => {
    try {
      await save();
      const run = await api.runWorkflow(workflowId, {
        inputs: runDomain.trim() ? { domain: runDomain.trim() } : {},
      });
      setRunOpen(false);
      toast({ title: `Run #${run.id} started` });
      const detail = await api.getWorkflowRun(run.id);
      setActiveRun(detail);
      setRuns((prev) => [detail, ...prev.filter((r) => r.id !== detail.id)]);
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const updated = await api.getWorkflowRun(run.id);
          setActiveRun(updated);
          setRuns((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
          if (['completed', 'failed', 'cancelled'].includes(updated.status)) {
            if (pollRef.current) clearInterval(pollRef.current);
          }
        } catch {
          /* ignore poll errors */
        }
      }, 2500);
    } catch (e: any) {
      toast({ title: 'Run failed to start', description: e?.message, variant: 'destructive' });
    }
  };

  const selectRun = async (run: WorkflowRun) => {
    try {
      const detail = await api.getWorkflowRun(run.id);
      setActiveRun(detail);
      if (['pending', 'running'].includes(detail.status)) {
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(async () => {
          const updated = await api.getWorkflowRun(run.id);
          setActiveRun(updated);
          if (['completed', 'failed', 'cancelled'].includes(updated.status)) {
            if (pollRef.current) clearInterval(pollRef.current);
          }
        }, 2500);
      }
    } catch (e: any) {
      toast({ title: 'Failed to load run', description: e?.message, variant: 'destructive' });
    }
  };

  const selectedNodeRun = useMemo(() => {
    if (!selected || !activeRun?.node_runs) return null;
    return activeRun.node_runs.find((r) => r.node_id === selected.id) || null;
  }, [selected, activeRun]);

  if (loading || !workflow) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-[70vh] text-muted-foreground gap-2">
          <Loader2 className="h-5 w-5 animate-spin" /> Loading editor…
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header
        title={workflow.name}
        subtitle={workflow.description || `${workflow.kind} · org ${workflow.organization_id}`}
      />

      <div className="flex items-center gap-2 px-6 py-2 border-b border-border bg-card/30">
        <Button variant="outline" size="sm" onClick={() => router.push('/workflows')}>
          <ArrowLeft className="h-4 w-4 mr-1" /> Back
        </Button>
        <Button variant="outline" size="sm" onClick={() => setScriptOpen(true)}>
          <FileCode2 className="h-4 w-4 mr-1" /> Scripts
        </Button>
        <div className="flex-1" />
        <Button variant="outline" size="sm" onClick={save} disabled={saving}>
          {saving ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Save className="h-4 w-4 mr-1" />}
          Save
        </Button>
        <Button size="sm" onClick={() => setRunOpen(true)}>
          <Play className="h-4 w-4 mr-1" /> Run
        </Button>
      </div>

      <div className="flex flex-col h-[calc(100vh-10rem)]">
        <div className="flex flex-1 min-h-0">
          <RunSidebar
            runs={runs}
            selectedRunId={activeRun?.id}
            onSelect={selectRun}
            onRefresh={() =>
              api
                .getWorkflowRuns({
                  workflow_id: workflowId,
                  organization_id: workflow.organization_id,
                })
                .then(setRuns)
            }
          />
          <div className="w-64 shrink-0">
            <NodePalette
              tools={tools}
              scripts={scripts}
              modules={modules}
              onAddTool={addTool}
              onAddScript={addScript}
              onAddModule={addModule}
              onAddPrimitive={addPrimitive}
              onAddSink={addSink}
            />
          </div>
          <div className="flex-1 min-w-0">
            <WorkflowCanvas
              initialNodes={nodes}
              initialEdges={edges}
              nodeRuns={activeRun?.node_runs}
              onSelectionChange={setSelected}
              onGraphChange={onGraphChange}
            />
          </div>
          <div className="w-72 shrink-0">
            <NodeInspector node={selected} onChange={onNodeDataChange} onDelete={onDeleteNode} />
          </div>
        </div>
        <NodeIOPanel nodeRun={selectedNodeRun} artifacts={activeRun?.artifacts || []} />
      </div>

      <Dialog open={runOpen} onOpenChange={setRunOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Run Loom workflow</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Seed domain</Label>
            <Input
              placeholder="example.com"
              value={runDomain}
              onChange={(e) => setRunDomain(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Mapped to primitive input key <code>domain</code>. Save happens before run.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRunOpen(false)}>
              Cancel
            </Button>
            <Button onClick={startRun}>
              <Play className="h-4 w-4 mr-1" /> Start run
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ScriptEditor
        open={scriptOpen}
        organizationId={workflow.organization_id}
        onOpenChange={setScriptOpen}
        onCreated={() => api.getWorkflowScripts(workflow.organization_id).then(setScripts)}
      />
    </MainLayout>
  );
}

function enrichNodes(nodes: Node[], tools: ToolDef[], scripts: WorkflowScript[]): Node[] {
  const toolMap = Object.fromEntries(tools.map((t) => [t.id, t]));
  const scriptMap = Object.fromEntries(scripts.map((s) => [s.id, s]));
  return nodes.map((n) => {
    const d = n.data as any;
    if (d.nodeKind === 'tool' && d.tool_id && toolMap[d.tool_id]) {
      const t = toolMap[d.tool_id];
      return {
        ...n,
        data: {
          ...d,
          inputPorts: d.inputPorts?.length ? d.inputPorts : t.input_ports,
          outputPorts: d.outputPorts?.length ? d.outputPorts : t.output_ports,
          paramSchema: t.params || [],
        },
      };
    }
    if (d.nodeKind === 'script' && d.script_id && scriptMap[d.script_id]) {
      const s = scriptMap[d.script_id];
      return {
        ...n,
        data: {
          ...d,
          inputPorts: d.inputPorts?.length ? d.inputPorts : s.input_ports,
          outputPorts: d.outputPorts?.length ? d.outputPorts : s.output_ports,
        },
      };
    }
    return n;
  });
}
