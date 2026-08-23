'use client';

import type { ReactNode } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Bug, Fingerprint, Server } from 'lucide-react';
import { cn } from '@/lib/utils';
import { STATUS_META, type AttackGraphNode } from './types';

function StatusFrame({
  status,
  className,
  children,
  round,
}: {
  status: AttackGraphNode['status'];
  className?: string;
  children: ReactNode;
  round?: boolean;
}) {
  const meta = STATUS_META[status] || STATUS_META.untested;
  return (
    <div
      className={cn(
        'relative h-full w-full border-2 shadow-[0_0_18px_var(--attack-glow)]',
        round ? 'rounded-full' : 'rounded-md',
        className
      )}
      style={{
        borderColor: meta.border,
        background: meta.fill,
        color: meta.text,
        ['--attack-glow' as string]: meta.glow,
      }}
    >
      {children}
    </div>
  );
}

function Handles() {
  return (
    <>
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-slate-400" />
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-slate-400" />
    </>
  );
}

export function AttackerNode({ data }: NodeProps) {
  const d = data as unknown as AttackGraphNode;
  return (
    <StatusFrame status={d.status} round className="flex flex-col items-center justify-center px-2">
      <Handles />
      <Fingerprint className="h-7 w-7" />
      <p className="mt-1 text-center text-[11px] font-semibold leading-tight">{d.title}</p>
    </StatusFrame>
  );
}

export function TechniqueNode({ data }: NodeProps) {
  const d = data as unknown as AttackGraphNode;
  return (
    <StatusFrame status={d.status} className="flex items-center px-3 py-2">
      <Handles />
      <div className="min-w-0">
        <p className="font-mono text-[11px] font-semibold leading-snug tracking-tight">{d.title}</p>
        {d.subtitle ? (
          <p className="mt-0.5 text-[10px] uppercase tracking-wide opacity-70">{d.subtitle}</p>
        ) : null}
      </div>
    </StatusFrame>
  );
}

export function HostNode({ data }: NodeProps) {
  const d = data as unknown as AttackGraphNode;
  return (
    <StatusFrame status={d.status} className="flex items-center gap-2.5 px-3 py-2">
      <Handles />
      <Server className="h-6 w-6 shrink-0 opacity-90" />
      <div className="min-w-0">
        <p className="truncate font-mono text-[12px] font-semibold">{d.title}</p>
        <p className="truncate text-[10px] opacity-75">{d.subtitle || d.env || 'Host'}</p>
      </div>
    </StatusFrame>
  );
}

export function VulnerabilityNode({ data }: NodeProps) {
  const d = data as unknown as AttackGraphNode;
  return (
    <StatusFrame status={d.status} className="flex items-center gap-2.5 rounded-full px-3 py-2 !rounded-full">
      <Handles />
      <Bug className="h-5 w-5 shrink-0" />
      <div className="min-w-0">
        <p className="line-clamp-2 text-[12px] font-semibold leading-snug">{d.title}</p>
        {d.subtitle ? <p className="mt-0.5 truncate text-[10px] opacity-70">{d.subtitle}</p> : null}
      </div>
    </StatusFrame>
  );
}

export const attackNodeTypes = {
  attacker: AttackerNode,
  technique: TechniqueNode,
  host: HostNode,
  vulnerability: VulnerabilityNode,
};
