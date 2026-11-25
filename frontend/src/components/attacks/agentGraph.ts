/**
 * Entity-centric attack graph produced by backend/app/services/agent/attack_graph.py.
 *
 * Nodes are things (origin, host, endpoint, captured capabilities); `action`
 * nodes sit between them and carry the step evidence that links the two.
 */

export type AgentGraphStatus = 'proven' | 'observed' | 'inferred';

export type AgentGraphKind =
  | 'origin'
  | 'host'
  | 'endpoint'
  | 'action'
  | 'credential'
  | 'identity'
  | 'rce'
  | 'data';

export interface AgentGraphEvidence {
  iteration: number;
  phase: string;
  tool: string;
  args: string;
  output: string;
  thought: string;
  success?: boolean | null;
}

export interface AgentGraphNode {
  id: string;
  kind: AgentGraphKind;
  title: string;
  subtitle?: string;
  status: AgentGraphStatus;
  severity?: string;
  description?: string;
  host?: string | null;
  evidence?: AgentGraphEvidence;
  /** The agent step that first reported it, when a published finding was merged in. */
  step_evidence?: AgentGraphEvidence;
  /** Set when this action is a published finding (links to /findings?id=). */
  finding_id?: number | null;
  /** exploit_verified | source_verified | confirmed | '' */
  verification?: string;
  /** How many agent steps reported the same issue on the same endpoint. */
  occurrences?: number;
}

export interface AgentGraphEdge {
  id: string;
  source: string;
  target: string;
  status: AgentGraphStatus;
  label?: string;
}

export interface AgentAttackGraphData {
  nodes: AgentGraphNode[];
  edges: AgentGraphEdge[];
  meta: {
    session_id?: string | null;
    objective?: string | null;
    status?: string | null;
    hosts?: number;
    actions?: number;
    capabilities?: number;
    proven?: number;
    published?: number;
    /** Low-certainty actions left out to keep the graph readable. */
    hidden?: number;
    failed_attempts?: number;
  };
}

/** Node colour encodes what the thing is (like Upwind's blue resources / pink identities). */
export const KIND_META: Record<AgentGraphKind, { label: string; color: string }> = {
  origin: { label: 'Origin', color: '#94a3b8' },
  host: { label: 'Host', color: '#3b82f6' },
  endpoint: { label: 'Endpoint', color: '#0ea5e9' },
  action: { label: 'Action', color: '#64748b' },
  credential: { label: 'Credential', color: '#ec4899' },
  identity: { label: 'Privileged access', color: '#a855f7' },
  rce: { label: 'Code execution', color: '#ef4444' },
  data: { label: 'Sensitive data', color: '#f59e0b' },
};

/** Status encodes how sure we are: proven by exploit, observed, or only inferred. */
export const STATUS_STYLE: Record<
  AgentGraphStatus,
  { label: string; edge: string; dash?: string; opacity: number; hint: string }
> = {
  proven: {
    label: 'Proven',
    edge: '#ef4444',
    opacity: 1,
    hint: 'A published finding the verifier reproduced against the live target, or an analyst confirmed',
  },
  observed: {
    label: 'Observed',
    edge: '#64748b',
    opacity: 1,
    hint: 'The agent reported this from tool output; not independently verified',
  },
  inferred: {
    label: 'Inferred',
    edge: '#64748b',
    dash: '4 4',
    opacity: 0.55,
    hint: 'Hypothesis: the step failed or the agent hedged ("may be vulnerable")',
  },
};

const RANK: Record<AgentGraphStatus, number> = { inferred: 0, observed: 1, proven: 2 };

/**
 * Drop endpoint nodes and fold their path into the action labels
 * ("/v2/admin/users · http_request"). Saves one column for narrow panels.
 */
export function foldEndpoints(graph: AgentAttackGraphData): AgentAttackGraphData {
  const endpoints = new Map(graph.nodes.filter((n) => n.kind === 'endpoint').map((n) => [n.id, n]));
  if (endpoints.size === 0) return graph;
  const parentOf = new Map<string, string>();
  graph.edges.forEach((e) => {
    if (endpoints.has(e.target)) parentOf.set(e.target, e.source);
  });
  const prefix = new Map<string, string>();
  const edges = new Map<string, AgentGraphEdge>();
  const put = (e: AgentGraphEdge) => {
    const prev = edges.get(e.id);
    if (!prev || RANK[e.status] > RANK[prev.status]) edges.set(e.id, e);
  };
  graph.edges.forEach((e) => {
    if (endpoints.has(e.target)) return;
    if (endpoints.has(e.source)) {
      const parent = parentOf.get(e.source);
      if (!parent) return;
      prefix.set(e.target, endpoints.get(e.source)!.title);
      put({ ...e, id: `${parent}->${e.target}`, source: parent });
      return;
    }
    put(e);
  });
  const nodes = graph.nodes
    .filter((n) => !endpoints.has(n.id))
    .map((n) =>
      prefix.has(n.id) ? { ...n, subtitle: [prefix.get(n.id), n.subtitle].filter(Boolean).join(' · ') } : n
    );
  return { ...graph, nodes, edges: Array.from(edges.values()) };
}

/** Keep proven nodes and everything leading to them, so each path is unbroken. */
export function provenOnly(graph: AgentAttackGraphData): AgentAttackGraphData {
  const parents = new Map<string, string[]>();
  graph.edges.forEach((e) => parents.set(e.target, [...(parents.get(e.target) || []), e.source]));
  const keep = new Set<string>();
  const stack = graph.nodes.filter((n) => n.status === 'proven').map((n) => n.id);
  while (stack.length) {
    const id = stack.pop()!;
    if (keep.has(id)) continue;
    keep.add(id);
    (parents.get(id) || []).forEach((p) => stack.push(p));
  }
  return {
    ...graph,
    nodes: graph.nodes.filter((n) => keep.has(n.id)),
    edges: graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
  };
}
