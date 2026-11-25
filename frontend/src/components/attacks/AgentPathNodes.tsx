'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Database,
  Globe,
  KeyRound,
  Route,
  Server,
  Terminal,
  UserCog,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { KIND_META, STATUS_STYLE, type AgentGraphKind, type AgentGraphNode } from './agentGraph';

/** Every node shares one box so icon centres line up across a rank. */
export const AGENT_NODE_SIZE = { width: 156, height: 92 };
/** Vertical centre of the icon inside the box — handles anchor here. */
const ICON_CENTER_Y = 20;

const ICONS: Record<AgentGraphKind, LucideIcon> = {
  origin: Globe,
  host: Server,
  endpoint: Route,
  action: Zap,
  credential: KeyRound,
  identity: UserCog,
  rce: Terminal,
  data: Database,
};

function IconHandles({ radius }: { radius: number }) {
  const common = '!h-1.5 !w-1.5 !min-h-0 !min-w-0 !border-0 !bg-transparent';
  return (
    <>
      <Handle
        type="target"
        position={Position.Left}
        className={common}
        style={{ top: ICON_CENTER_Y, left: `calc(50% - ${radius}px)` }}
      />
      <Handle
        type="source"
        position={Position.Right}
        className={common}
        style={{ top: ICON_CENTER_Y, left: `calc(50% + ${radius}px)`, right: 'auto' }}
      />
    </>
  );
}

export function AgentPathNode({ data, selected }: NodeProps) {
  const d = data as unknown as AgentGraphNode;
  const isAction = d.kind === 'action';
  const kind = KIND_META[d.kind] || KIND_META.action;
  const status = STATUS_STYLE[d.status] || STATUS_STYLE.inferred;
  const Icon = ICONS[d.kind] || Zap;
  const size = isAction ? 28 : 40;
  const color = isAction && d.status === 'proven' ? STATUS_STYLE.proven.edge : kind.color;

  return (
    <div
      className="group flex h-full w-full cursor-pointer flex-col items-center"
      style={{ opacity: status.opacity }}
      title={d.description || d.title}
    >
      <IconHandles radius={size / 2} />
      <div
        className={cn(
          'relative flex shrink-0 items-center justify-center rounded-full transition-shadow',
          selected && 'ring-2 ring-offset-2 ring-offset-card'
        )}
        style={{
          width: size,
          height: size,
          marginTop: ICON_CENTER_Y - size / 2,
          background: isAction ? 'hsl(var(--card))' : color,
          border: `1.5px ${d.status === 'inferred' ? 'dashed' : 'solid'} ${color}`,
          color: isAction ? color : '#fff',
          ['--tw-ring-color' as string]: color,
          boxShadow: d.status === 'proven' && !isAction ? `0 0 0 4px ${color}33` : undefined,
        }}
      >
        <Icon className={isAction ? 'h-3.5 w-3.5' : 'h-[18px] w-[18px]'} strokeWidth={2} />
        {d.status === 'proven' && !isAction ? (
          <span
            className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-card"
            style={{ background: STATUS_STYLE.proven.edge }}
          />
        ) : null}
      </div>
      <p
        className={cn(
          'mt-2 line-clamp-2 w-full break-words px-1 text-center font-medium leading-tight text-foreground',
          isAction ? 'text-[10.5px]' : 'text-[11.5px]'
        )}
      >
        {d.title}
      </p>
      <p className="mt-0.5 w-full truncate px-1 text-center text-[10px] leading-tight text-muted-foreground">
        {d.subtitle || kind.label}
      </p>
    </div>
  );
}

export const agentPathNodeTypes = { agent: AgentPathNode };
