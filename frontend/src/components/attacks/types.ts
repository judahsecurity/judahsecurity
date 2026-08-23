export type AttackNodeStatus =
  | 'untested'
  | 'tested'
  | 'undetected'
  | 'logged'
  | 'alerted'
  | 'detected'
  | 'prevented';

export type AttackNodeKind = 'attacker' | 'technique' | 'host' | 'vulnerability';

export interface AttackGraphNode {
  id: string;
  kind: AttackNodeKind;
  title: string;
  subtitle?: string;
  status: AttackNodeStatus;
  mitre_id?: string;
  finding_id?: number | null;
  asset_id?: number | null;
  host?: string;
  env?: string;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
}

export interface AttackNarrativeStep {
  node_id: string;
  title: string;
  body: string;
  status: AttackNodeStatus;
  finding_id?: number | null;
}

export interface AttackPath {
  id: string;
  title: string;
  summary: string;
  target: string;
  hosts: string[];
  timeframe?: string | null;
  severity: string;
  demonstrated: boolean;
  status_counts: Record<string, number>;
  finding_ids: number[];
  session_id?: string | null;
  attack_path_class?: string;
  not_demonstrated?: string;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  narrative: AttackNarrativeStep[];
}

export interface AttackCapability {
  session_id: string;
  target: string;
  quality_score?: number | null;
  ready_for_attack?: boolean;
  authenticated?: boolean | null;
  capabilities: string[];
  ranked_hunt_queue: { hunt?: string; why?: string; priority?: string }[];
  updated_at?: string | null;
}

export interface AttackWorkspace {
  organization: { id: number; name: string; domain?: string | null } | null;
  paths: AttackPath[];
  capabilities: AttackCapability[];
  signatures: { template_id: string; count: number; hosts: string[]; severity: string }[];
  red_team: {
    id: number;
    name: string;
    target_url: string;
    phase: string;
    total_exploits_confirmed: number;
    total_exploits_attempted: number;
    started_at?: string | null;
  }[];
  phishing: { finding_id: number; title: string; host: string; severity: string; status: string }[];
  juicy_fruit: {
    finding_id: number;
    title: string;
    host: string;
    severity: string;
    status: string;
    demonstrated: boolean;
    attack_path_class?: string;
  }[];
}

export const STATUS_META: Record<
  AttackNodeStatus,
  { label: string; border: string; fill: string; text: string; glow: string }
> = {
  untested: {
    label: 'Untested',
    border: '#e5e7eb',
    fill: '#0f172a',
    text: '#e5e7eb',
    glow: 'rgba(229,231,235,0.25)',
  },
  tested: {
    label: 'Tested',
    border: '#ef4444',
    fill: '#450a0a',
    text: '#fecaca',
    glow: 'rgba(239,68,68,0.45)',
  },
  undetected: {
    label: 'Undetected',
    border: '#3b82f6',
    fill: '#172554',
    text: '#bfdbfe',
    glow: 'rgba(59,130,246,0.4)',
  },
  logged: {
    label: 'Logged',
    border: '#eab308',
    fill: '#422006',
    text: '#fde68a',
    glow: 'rgba(234,179,8,0.4)',
  },
  alerted: {
    label: 'Alerted',
    border: '#22d3ee',
    fill: '#083344',
    text: '#a5f3fc',
    glow: 'rgba(34,211,238,0.4)',
  },
  detected: {
    label: 'Detected',
    border: '#e879f9',
    fill: '#4a044e',
    text: '#f5d0fe',
    glow: 'rgba(232,121,249,0.45)',
  },
  prevented: {
    label: 'Prevented',
    border: '#22c55e',
    fill: '#052e16',
    text: '#bbf7d0',
    glow: 'rgba(34,197,94,0.4)',
  },
};

export const STATUS_ORDER: AttackNodeStatus[] = [
  'untested',
  'tested',
  'undetected',
  'logged',
  'alerted',
  'detected',
  'prevented',
];
