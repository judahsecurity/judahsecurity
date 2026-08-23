'use client';

import { STATUS_META, STATUS_ORDER, type AttackNarrativeStep } from './types';
import { cn } from '@/lib/utils';

export function AttackPathNarrative({
  steps,
  notDemonstrated,
}: {
  steps: AttackNarrativeStep[];
  notDemonstrated?: string;
}) {
  return (
    <div className="h-full min-h-[420px] overflow-y-auto rounded-md border border-border/60 bg-[#070b12] p-6">
      <ol className="relative space-y-5 border-l border-slate-700/80 pl-6">
        {steps.map((step, idx) => {
          const meta = STATUS_META[step.status] || STATUS_META.untested;
          return (
            <li key={`${step.node_id}-${idx}`} className="relative">
              <span
                className="absolute -left-[29px] top-1.5 h-3 w-3 rounded-full border-2"
                style={{ borderColor: meta.border, background: meta.fill }}
              />
              <p className="text-sm font-semibold text-foreground">{step.title}</p>
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{step.body}</p>
              <p className="mt-1 font-mono text-[10px] uppercase tracking-widest" style={{ color: meta.border }}>
                {meta.label}
              </p>
            </li>
          );
        })}
      </ol>
      {notDemonstrated ? (
        <div className="mt-6 rounded-md border border-border/70 bg-card/40 px-4 py-3">
          <p className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">Not demonstrated</p>
          <p className="mt-1 text-sm text-muted-foreground">{notDemonstrated}</p>
        </div>
      ) : null}
    </div>
  );
}

export function AttackStatusLegend({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'pointer-events-none flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md bg-[#070b12]/80 px-3 py-2 text-[11px] text-slate-300 backdrop-blur-sm',
        className
      )}
    >
      {STATUS_ORDER.map((status) => {
        const meta = STATUS_META[status];
        return (
          <span key={status} className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full border" style={{ background: meta.border, borderColor: meta.border }} />
            {meta.label}
          </span>
        );
      })}
    </div>
  );
}
