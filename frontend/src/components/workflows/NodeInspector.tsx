'use client';

import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import type { Node } from '@xyflow/react';

interface Props {
  node: Node | null;
  onChange: (nodeId: string, data: Record<string, any>) => void;
  onDelete: (nodeId: string) => void;
}

export function NodeInspector({ node, onChange, onDelete }: Props) {
  if (!node) {
    return (
      <div className="p-4 text-sm text-muted-foreground border-l border-border h-full">
        Select a node to inspect
      </div>
    );
  }
  const d = node.data as any;
  const params = (d.params || {}) as Record<string, any>;

  return (
    <div className="p-4 border-l border-border h-full overflow-y-auto space-y-4 bg-card/30">
      <div>
        <div className="text-sm font-medium">Inspector</div>
        <div className="text-xs text-muted-foreground">{node.id}</div>
      </div>
      <div className="space-y-2">
        <Label>Label</Label>
        <Input
          value={d.label || ''}
          onChange={(e) => onChange(node.id, { ...d, label: e.target.value })}
        />
      </div>
      {d.nodeKind === 'primitive' && (
        <div className="space-y-2">
          <Label>Input key</Label>
          <Input
            value={d.value_key || d.port?.name || ''}
            onChange={(e) =>
              onChange(node.id, {
                ...d,
                value_key: e.target.value,
                port: { ...(d.port || {}), name: e.target.value, type: d.port?.type || 'STRING', required: true },
                inputPorts: [],
                outputPorts: [{ name: e.target.value || 'domain', type: d.port?.type || 'STRING' }],
              })
            }
          />
        </div>
      )}
      {d.nodeKind === 'tool' && d.paramSchema?.length > 0 && (
        <div className="space-y-3">
          <div className="text-xs uppercase text-muted-foreground">Params</div>
          {d.paramSchema.map((p: any) => (
            <div key={p.name} className="space-y-1">
              <Label>{p.name}</Label>
              <Input
                value={params[p.name] ?? p.default ?? ''}
                onChange={(e) =>
                  onChange(node.id, {
                    ...d,
                    params: { ...params, [p.name]: e.target.value },
                  })
                }
              />
            </div>
          ))}
        </div>
      )}
      {d.nodeKind === 'module' && (
        <div className="text-xs text-muted-foreground">Module workflow #{d.workflow_id}</div>
      )}
      {d.nodeKind === 'script' && (
        <div className="text-xs text-muted-foreground">Script #{d.script_id}</div>
      )}
      <Button variant="destructive" size="sm" onClick={() => onDelete(node.id)}>
        Delete node
      </Button>
    </div>
  );
}
