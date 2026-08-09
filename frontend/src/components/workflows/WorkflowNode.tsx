'use client';

import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { cn } from '@/lib/utils';
import { STATUS_COLORS } from './types';

function portColor(type?: string) {
  switch (type) {
    case 'FILE':
    case 'FILE_LIST':
      return 'bg-cyan-400';
    case 'JSON':
      return 'bg-violet-400';
    case 'URL':
      return 'bg-amber-400';
    case 'BOOLEAN':
      return 'bg-rose-400';
    default:
      return 'bg-emerald-400';
  }
}

function WorkflowNodeComponent({ data, selected }: NodeProps) {
  const d = data as any;
  const kind = d.nodeKind || 'tool';
  const status = d.runStatus as string | undefined;
  const inputs: { name: string; type?: string }[] = d.inputPorts || [];
  const outputs: { name: string; type?: string }[] = d.outputPorts || [];

  const kindTone =
    kind === 'primitive'
      ? 'from-emerald-950/80 to-card'
      : kind === 'script'
        ? 'from-violet-950/70 to-card'
        : kind === 'module'
          ? 'from-sky-950/70 to-card'
          : kind === 'sink'
            ? 'from-zinc-900 to-card'
            : 'from-slate-900 to-card';

  return (
    <div
      className={cn(
        'min-w-[180px] max-w-[240px] rounded-lg border bg-gradient-to-b shadow-md',
        kindTone,
        selected ? 'border-primary ring-1 ring-primary/40' : 'border-border',
        status && STATUS_COLORS[status]
      )}
    >
      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-border/60">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground truncate">
            {kind}
            {d.tool_id ? ` · ${d.tool_id}` : ''}
            {d.script_id ? ` · script` : ''}
          </div>
          <div className="text-sm font-medium truncate">{d.label || 'Node'}</div>
        </div>
        {status && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-background/60 capitalize shrink-0">
            {status}
          </span>
        )}
      </div>

      <div className="relative px-2 py-2 space-y-1">
        {inputs.map((p, i) => (
          <div key={`in-${p.name}`} className="relative flex items-center h-5 text-[11px] text-muted-foreground pl-2">
            <Handle
              type="target"
              position={Position.Left}
              id={p.name}
              className={cn('!w-2.5 !h-2.5 !border-0', portColor(p.type))}
              style={{ top: 28 + i * 22 }}
            />
            <span className="truncate">{p.name}</span>
          </div>
        ))}
        {outputs.map((p, i) => (
          <div key={`out-${p.name}`} className="relative flex items-center justify-end h-5 text-[11px] text-muted-foreground pr-2">
            <span className="truncate">{p.name}</span>
            <Handle
              type="source"
              position={Position.Right}
              id={p.name}
              className={cn('!w-2.5 !h-2.5 !border-0', portColor(p.type))}
              style={{ top: 28 + Math.max(inputs.length, 0) * 8 + i * 22 }}
            />
          </div>
        ))}
        {inputs.length === 0 && outputs.length === 0 && (
          <>
            <Handle type="target" position={Position.Left} id="in" className="!w-2.5 !h-2.5 !bg-muted-foreground" />
            <Handle type="source" position={Position.Right} id="out" className="!w-2.5 !h-2.5 !bg-muted-foreground" />
          </>
        )}
      </div>
    </div>
  );
}

export const WorkflowNode = memo(WorkflowNodeComponent);
