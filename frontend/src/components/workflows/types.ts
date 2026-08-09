export type PortType = 'STRING' | 'BOOLEAN' | 'URL' | 'JSON' | 'FILE' | 'FILE_LIST';

export interface PortDef {
  name: string;
  type: PortType | string;
  required?: boolean;
  description?: string;
}

export interface ToolDef {
  id: string;
  name: string;
  description: string;
  category: string;
  input_ports: PortDef[];
  output_ports: PortDef[];
  params?: { name: string; type: string; default?: any; description?: string; required?: boolean }[];
}

export interface WorkflowSummary {
  id: number;
  organization_id: number;
  name: string;
  description?: string;
  kind: 'workflow' | 'module';
  latest_version_id?: number;
  is_library?: boolean;
  updated_at?: string;
}

export interface WorkflowDetail extends WorkflowSummary {
  created_by?: string;
  created_at?: string;
  latest_version?: {
    id: number;
    workflow_id: number;
    version: number;
    graph: { nodes: any[]; edges: any[]; viewport?: any };
    input_ports?: PortDef[];
    output_ports?: PortDef[];
  };
}

export interface WorkflowScript {
  id: number;
  organization_id: number;
  name: string;
  description?: string;
  language: 'python' | 'bash';
  source: string;
  input_ports?: PortDef[];
  output_ports?: PortDef[];
}

export interface WorkflowNodeRun {
  id: number;
  run_id: number;
  node_id: string;
  node_type: string;
  node_label?: string;
  status: string;
  inputs?: Record<string, any>;
  outputs?: Record<string, any>;
  logs?: string;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
}

export interface WorkflowArtifact {
  id: number;
  run_id: number;
  node_id: string;
  port: string;
  path: string;
  filename?: string;
  content_type?: string;
  byte_size?: number;
}

export interface WorkflowRun {
  id: number;
  workflow_id: number;
  version_id: number;
  organization_id: number;
  status: string;
  inputs?: Record<string, any>;
  progress?: number;
  current_step?: string;
  error_message?: string;
  started_by?: string;
  started_at?: string;
  completed_at?: string;
  created_at?: string;
  node_runs?: WorkflowNodeRun[];
  artifacts?: WorkflowArtifact[];
}

export const STATUS_COLORS: Record<string, string> = {
  pending: 'border-muted-foreground/40',
  ready: 'border-sky-500',
  running: 'border-amber-400 animate-pulse',
  completed: 'border-emerald-500',
  failed: 'border-red-500',
  skipped: 'border-muted-foreground/30',
  cancelled: 'border-zinc-500',
};
