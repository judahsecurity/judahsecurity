'use client';

import { cn } from '@/lib/utils';
import type { AgentRunLedger } from './RunLedgerPanel';

const TESTED = ['proven_with_evidence', 'proven_unverified', 'negative_with_evidence', 'tested_no_evidence'];
const AGENT_CONFIRMED = ['proven_with_evidence', 'proven_unverified'];

export interface FunnelStage {
  key: string;
  label: string;
  value: number;
  hint: string;
}

function sum(counts: Record<string, number> | undefined, keys: string[]): number {
  return keys.reduce((n, k) => n + (counts?.[k] || 0), 0);
}

/**
 * Surface → hypotheses → tested → agent-confirmed → published → verified.
 * "Agent-confirmed" is the agent's own verdict; "Verified" is the independent
 * verifier (or an analyst) — the same bar the Path graph calls "proven".
 */
export function funnelStages(run: AgentRunLedger | null | undefined, verified: number): FunnelStage[] {
  const byState = run?.coverage?.hypotheses_by_state;
  const hypotheses =
    run?.hypotheses?.length ?? Object.values(byState || {}).reduce((a, b) => a + b, 0);
  return [
    { key: 'surface', label: 'Surface', value: run?.scenario_surface?.items?.length || 0,
      hint: 'External observations the agent recorded' },
    { key: 'hypotheses', label: 'Hypotheses', value: hypotheses || 0,
      hint: 'Attack scenarios generated from the surface' },
    { key: 'tested', label: 'Tested', value: sum(byState, TESTED),
      hint: 'Hypotheses actually exercised, with or without a hit' },
    { key: 'confirmed', label: 'Agent-confirmed', value: sum(byState, AGENT_CONFIRMED),
      hint: "The agent's own verdict that the scenario worked" },
    { key: 'published', label: 'Published', value: run?.coverage?.published_findings || 0,
      hint: 'Findings that passed the publish gate' },
    { key: 'verified', label: 'Verified', value: verified,
      hint: 'Reproduced by the independent verifier or confirmed by an analyst' },
  ];
}

export function ProofFunnel({
  run,
  verified,
  className,
}: {
  run: AgentRunLedger | null | undefined;
  verified: number;
  className?: string;
}) {
  const stages = funnelStages(run, verified);
  const max = Math.max(1, ...stages.map((s) => s.value));
  if (stages.every((s) => s.value === 0)) return null;

  return (
    <div className={cn('grid grid-cols-6 gap-1 px-3 py-2', className)}>
      {stages.map((s, i) => {
        // sqrt keeps small late-stage counts visible next to a big surface count
        const h = s.value ? Math.max(6, Math.round(Math.sqrt(s.value / max) * 28)) : 2;
        const last = i === stages.length - 1;
        return (
          <div key={s.key} title={s.hint} className="flex min-w-0 flex-col items-center">
            <div className="flex h-7 w-full items-center">
              <div
                className={cn('w-full rounded-sm', last ? 'bg-red-500' : 'bg-primary')}
                style={{ height: h, opacity: last ? 0.9 : 0.25 + 0.6 * ((i + 1) / stages.length) }}
              />
            </div>
            <span className={cn('mt-1 font-mono text-xs tabular-nums', last && s.value ? 'text-red-400' : 'text-foreground')}>
              {s.value.toLocaleString()}
            </span>
            <span className="w-full truncate text-center text-[9.5px] text-muted-foreground">{s.label}</span>
          </div>
        );
      })}
    </div>
  );
}
