'use client';

import { Button } from '@/components/ui/button';
import type { WorkflowArtifact, WorkflowNodeRun } from './types';
import { api } from '@/lib/api';

interface Props {
  nodeRun?: WorkflowNodeRun | null;
  artifacts: WorkflowArtifact[];
}

export function NodeIOPanel({ nodeRun, artifacts }: Props) {
  if (!nodeRun) {
    return (
      <div className="h-40 border-t border-border px-4 py-3 text-sm text-muted-foreground bg-card/40">
        Select a node (and a run) to inspect inputs, outputs, and logs.
      </div>
    );
  }

  const nodeArts = artifacts.filter((a) => a.node_id === nodeRun.node_id);

  return (
    <div className="h-48 border-t border-border bg-card/50 flex flex-col">
      <div className="px-4 py-2 border-b border-border flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">{nodeRun.node_label || nodeRun.node_id}</div>
          <div className="text-[11px] text-muted-foreground capitalize">
            {nodeRun.status}
            {nodeRun.error_message ? ` · ${nodeRun.error_message}` : ''}
          </div>
        </div>
      </div>
      <div className="flex-1 overflow-auto grid grid-cols-3 gap-3 p-3 text-xs">
        <div>
          <div className="font-medium mb-1">Inputs</div>
          <pre className="whitespace-pre-wrap break-all text-muted-foreground bg-background/50 rounded p-2 max-h-28 overflow-auto">
            {JSON.stringify(nodeRun.inputs || {}, null, 2)}
          </pre>
        </div>
        <div>
          <div className="font-medium mb-1">Outputs</div>
          <pre className="whitespace-pre-wrap break-all text-muted-foreground bg-background/50 rounded p-2 max-h-28 overflow-auto">
            {JSON.stringify(nodeRun.outputs || {}, null, 2)}
          </pre>
          <div className="mt-2 space-y-1">
            {nodeArts.map((a) => (
              <a
                key={a.id}
                href={api.getWorkflowArtifactContentUrl(a.id)}
                target="_blank"
                rel="noreferrer"
                className="block"
              >
                <Button variant="outline" size="sm" className="h-7 text-[11px] w-full justify-start">
                  Download {a.port} ({a.filename || 'file'})
                </Button>
              </a>
            ))}
          </div>
        </div>
        <div>
          <div className="font-medium mb-1">Logs</div>
          <pre className="whitespace-pre-wrap break-all text-muted-foreground bg-background/50 rounded p-2 max-h-28 overflow-auto">
            {nodeRun.logs || '—'}
          </pre>
        </div>
      </div>
    </div>
  );
}
