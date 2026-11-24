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
    hint: 'A successful exploitation step produced this',
  },
  observed: {
    label: 'Observed',
    edge: '#64748b',
    opacity: 1,
    hint: 'The agent saw this succeed but did not exploit it',
  },
  inferred: {
    label: 'Inferred',
    edge: '#64748b',
    dash: '4 4',
    opacity: 0.55,
    hint: 'Hypothesis: the step failed or did not report success',
  },
};
