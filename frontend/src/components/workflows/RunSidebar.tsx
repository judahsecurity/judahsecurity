'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import type { WorkflowRun } from './types';
import { Loader2, RefreshCw } from 'lucide-react';

interface Props {
  runs: WorkflowRun[];
  selectedRunId?: number | null;
  loading?: boolean;
  onSelect: (run: WorkflowRun) => void;
  onRefresh: () => void;
}

function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (status === 'completed') return 'default';
  if (status === 'failed') return 'destructive';
  if (status === 'running' || status === 'pending') return 'secondary';
  return 'outline';
}

export function RunSidebar({ runs, selectedRunId, loading, onSelect, onRefresh }: Props) {
  return (
    <div className="flex flex-col h-full border-r border-border bg-card/20 w-56 shrink-0">
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <div className="text-sm font-medium">Runs</div>
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onRefresh}>
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {runs.length === 0 && (
          <div className="p-3 text-xs text-muted-foreground">No runs yet</div>
        )}
        {runs.map((r) => (
          <button
            key={r.id}
            type="button"
            onClick={() => onSelect(r)}
            className={cn(
              'w-full text-left px-3 py-2 border-b border-border/50 hover:bg-muted/40',
              selectedRunId === r.id && 'bg-muted/60'
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium">#{r.id}</span>
              <Badge variant={statusVariant(r.status)} className="text-[10px] capitalize">
                {r.status}
              </Badge>
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              {r.progress ?? 0}% {r.current_step ? `· ${r.current_step}` : ''}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
