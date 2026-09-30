'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import type { AgentRunLedger } from './RunLedgerPanel';

/** The graph and the ledger are separate evidence sources. Neither implies the other. */
export interface MapScenarioNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
}

export interface ScenarioSurfaceItem {
  kind: 'target' | 'page' | 'directory' | 'endpoint' | 'form' | 'parameter';
  label: string;
  origin: string;
  path: string;
  method?: string;
  location?: string;
}

export interface ScenarioSurface {
  target: string;
  items: ScenarioSurfaceItem[];
  contexts: Array<{ id: string; origin: string; path: string; parameter: string }>;
}

export const TRUST_COLORS = {
  green: '#34d399', gray: '#94a3b8', orange: '#fb923c', yellow: '#fbbf24',
  red: '#f87171', salmon: '#fb7185', purple: '#c084fc', pink: '#f472b6',
  blue: '#60a5fa', bg: '#070b12',
} as const;

type Hypothesis = NonNullable<AgentRunLedger['hypotheses']>[number];

type SurfaceGroup = {
  key: string;
  origin: string;
  path: string;
  kinds: string[];
  parameters: ScenarioSurfaceItem[];
  operations: ScenarioSurfaceItem[];
};

function statusStyle(state: string) {
  if (state === 'proven_with_evidence') return { label: 'proven · evidence', color: TRUST_COLORS.green };
  if (state === 'negative_with_evidence') return { label: 'tested · negative', color: TRUST_COLORS.blue };
  if (state === 'proven_unverified') return { label: 'claimed · unverified', color: TRUST_COLORS.yellow };
  if (state === 'tested_no_evidence') return { label: 'tested · no evidence', color: TRUST_COLORS.yellow };
  if (state === 'in_progress') return { label: 'testing', color: TRUST_COLORS.orange };
  if (state === 'blocked' || state === 'interrupted') return { label: state, color: TRUST_COLORS.salmon };
  if (state === 'skipped_by_budget') return { label: 'not attempted · budget', color: TRUST_COLORS.gray };
  return { label: 'not attempted', color: TRUST_COLORS.gray };
}

function ScenarioCard({ hypothesis, context }: {
  hypothesis: Hypothesis;
  context?: ScenarioSurface['contexts'][number];
}) {
  const status = statusStyle(hypothesis.state);
  return (
    <div className="rounded-lg border border-white/10 bg-slate-950/65 px-2.5 py-2">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: status.color }} />
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-medium text-slate-100 break-words">{hypothesis.title || hypothesis.id}</p>
          <p className="mt-0.5 text-[10px] font-mono" style={{ color: status.color }}>
            {status.label}{hypothesis.attempts ? ` · ${hypothesis.attempts} attempt${hypothesis.attempts === 1 ? '' : 's'}` : ''}
          </p>
          {context?.parameter && (
            <p className="mt-0.5 text-[10px] text-slate-400">Parameter: <code>{context.parameter}</code></p>
          )}
          {hypothesis.evidence_ids?.length ? (
            <p className="mt-0.5 text-[10px] text-slate-400 truncate" title={hypothesis.evidence_ids.join(', ')}>
              Evidence: {hypothesis.evidence_ids.join(', ')}
            </p>
          ) : null}
          {hypothesis.blocked_reason && (
            <p className="mt-0.5 text-[10px] text-slate-400 line-clamp-2">{hypothesis.blocked_reason}</p>
          )}
        </div>
      </div>
    </div>
  );
}

interface TrustBoundaryMapProps {
  steps: MapScenarioNode[];
  findings: MapScenarioNode[];
  runLedger?: AgentRunLedger | null;
  isRunning?: boolean;
  className?: string;
}

export function TrustBoundaryMap({ steps, findings, runLedger, isRunning = false, className }: TrustBoundaryMapProps) {
  const surface = runLedger?.scenario_surface;
  const hypotheses = useMemo(() => runLedger?.hypotheses || [], [runLedger?.hypotheses]);
  const groups = useMemo(() => {
    const byPath = new Map<string, SurfaceGroup>();
    for (const item of surface?.items || []) {
      const key = `${item.origin}|${item.path}`;
      let group = byPath.get(key);
      if (!group) {
        group = { key, origin: item.origin, path: item.path, kinds: [], parameters: [], operations: [] };
        byPath.set(key, group);
      }
      if (item.kind === 'parameter') group.parameters.push(item);
      else {
        if (!group.kinds.includes(item.kind)) group.kinds.push(item.kind);
        group.operations.push(item);
      }
    }
    if (!byPath.size) {
      const targets = new Set([surface?.target, ...(runLedger?.actions || []).map((action) => action.target)].filter(Boolean));
      for (const origin of targets) {
        byPath.set(`${origin}|/`, { key: `${origin}|/`, origin: origin as string,
          path: '/', kinds: ['target'], parameters: [], operations: [] });
      }
    }
    return [...byPath.values()].sort((a, b) => a.path.localeCompare(b.path));
  }, [surface?.items, surface?.target, runLedger?.actions]);

  const contextById = useMemo(() => new Map((surface?.contexts || []).map((item) => [item.id, item])), [surface?.contexts]);
  const linked = useMemo(() => {
    const byGroup = new Map<string, Hypothesis[]>();
    const unmatched: Hypothesis[] = [];
    for (const hypothesis of hypotheses) {
      const context = contextById.get(hypothesis.id);
      let group: SurfaceGroup | undefined;
      if (context?.path && context.path !== '/') {
        group = groups.find((candidate) => candidate.origin === context.origin && candidate.path === context.path);
      } else if (context?.parameter) {
        const candidates = groups.filter((candidate) =>
          candidate.origin === context.origin && candidate.parameters.some((p) => p.label === context.parameter)
        );
        if (candidates.length === 1) group = candidates[0];
      }
      if (group) byGroup.set(group.key, [...(byGroup.get(group.key) || []), hypothesis]);
      else unmatched.push(hypothesis);
    }
    return { byGroup, unmatched };
  }, [hypotheses, contextById, groups]);

  const recentActions = runLedger?.actions?.slice(-4).reverse() || [];
  const hasObservations = groups.length > 0 || hypotheses.length > 0 || findings.length > 0;

  return (
    <div className={cn('flex flex-col h-full min-h-0 text-slate-200', className)} style={{ backgroundColor: TRUST_COLORS.bg }}>
      <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-white/10 px-3 py-2 text-[10px] font-mono text-slate-400">
        <span>{groups.length} observed paths</span>
        <span>{hypotheses.length} potential scenarios</span>
        <span>{runLedger?.coverage?.actions || 0} actions</span>
        <span>{Math.max(findings.length, runLedger?.coverage?.published_findings || 0)} findings</span>
      </div>
      <div className="flex-1 overflow-y-auto px-3 py-3 space-y-4" style={{
        backgroundImage: 'linear-gradient(rgba(148,163,184,0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.045) 1px, transparent 1px)',
        backgroundSize: '20px 20px',
      }}>
        {!hasObservations && (
          <div className="rounded-xl border border-dashed border-slate-600/50 bg-slate-950/60 px-4 py-8 text-center">
            <p className="text-xs text-slate-300">{isRunning ? 'Mapping the external surface…' : 'No observed surface or scenarios recorded'}</p>
            <p className="mt-1 text-[10px] text-slate-500">Paths, parameters and hypotheses appear as the agent records them.</p>
          </div>
        )}

        {groups.length > 0 && (
          <section aria-label="Observed external surface" className="space-y-2">
            <h3 className="text-[10px] font-mono uppercase tracking-widest" style={{ color: TRUST_COLORS.green }}>Observed external surface</h3>
            {groups.map((group) => {
              const scenarios = linked.byGroup.get(group.key) || [];
              return (
                <div key={group.key} className="rounded-xl border border-emerald-400/20 bg-slate-950/75 p-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-[10px] text-slate-500" title={group.origin}>{group.origin || surface?.target}</p>
                      <p className="font-mono text-xs text-slate-100 break-all">{group.path}</p>
                    </div>
                    <span className="shrink-0 rounded border border-emerald-400/30 px-1.5 py-0.5 text-[9px] uppercase text-emerald-300">
                      {group.kinds.includes('directory') ? 'directory' : group.kinds.includes('endpoint') ? 'endpoint' : group.kinds.includes('form') ? 'form' : group.kinds.includes('target') ? 'target' : 'page'}
                    </span>
                  </div>
                  {group.operations.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {group.operations.filter((item) => item.kind === 'endpoint' || item.kind === 'form').slice(0, 5).map((item, index) => (
                        <span key={`${item.kind}-${item.label}-${index}`} className="rounded bg-slate-800/70 px-1.5 py-0.5 text-[9px] font-mono text-slate-300">{item.label}</span>
                      ))}
                    </div>
                  )}
                  {group.parameters.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1">
                      <span className="text-[9px] uppercase text-slate-500">Parameters</span>
                      {[...new Map(group.parameters.map((p) => [`${p.label}:${p.location}`, p])).values()].slice(0, 16).map((p) => (
                        <span key={`${p.label}:${p.location}`} className="rounded border border-sky-400/25 px-1.5 py-0.5 text-[9px] font-mono text-sky-300" title={p.location}>{p.label}</span>
                      ))}
                    </div>
                  )}
                  {group.kinds.includes('target') && (
                    <p className="mt-1 text-[10px] text-slate-500">Target recorded; no path or parameter observations saved yet.</p>
                  )}
                  {scenarios.length > 0 && (
                    <div className="mt-2 space-y-1.5 border-t border-white/10 pt-2">
                      <p className="text-[9px] font-mono uppercase text-amber-300">Potential scenarios on this surface</p>
                      {scenarios.map((hypothesis) => <ScenarioCard key={hypothesis.id} hypothesis={hypothesis} context={contextById.get(hypothesis.id)} />)}
                    </div>
                  )}
                </div>
              );
            })}
          </section>
        )}

        {linked.unmatched.length > 0 && (
          <section aria-label="Other potential scenarios" className="space-y-2">
            <h3 className="text-[10px] font-mono uppercase tracking-widest" style={{ color: TRUST_COLORS.orange }}>Target-wide or unlinked scenarios</h3>
            <p className="text-[10px] text-slate-500">The agent has not tied these hypotheses to a specific observed path.</p>
            {linked.unmatched.map((hypothesis) => <ScenarioCard key={hypothesis.id} hypothesis={hypothesis} context={contextById.get(hypothesis.id)} />)}
          </section>
        )}

        {findings.length > 0 && (
          <section aria-label="Recorded findings" className="space-y-1.5">
            <h3 className="text-[10px] font-mono uppercase tracking-widest" style={{ color: TRUST_COLORS.pink }}>Recorded findings</h3>
            {findings.map((finding) => (
              <p key={finding.id} className="rounded-lg border border-pink-400/20 bg-slate-950/75 px-2.5 py-2 text-[11px] break-words">{finding.label}</p>
            ))}
          </section>
        )}
        {findings.length === 0 && Boolean(runLedger?.coverage?.published_findings) && (
          <p className="rounded-lg border border-pink-400/20 bg-slate-950/75 px-2.5 py-2 text-[10px] text-slate-400">
            {runLedger?.coverage?.published_findings} published finding{runLedger?.coverage?.published_findings === 1 ? '' : 's'} recorded in the run ledger. Open Findings for details.
          </p>
        )}
      </div>
      {recentActions.length > 0 && (
        <div className="border-t border-white/10 px-3 py-2">
          <p className="mb-1 text-[9px] font-mono uppercase tracking-widest text-slate-500">Recent recorded actions</p>
          <div className="flex flex-wrap gap-1">
            {recentActions.map((action) => (
              <span key={action.id} className="max-w-full truncate rounded bg-slate-800/65 px-1.5 py-0.5 text-[9px] font-mono text-slate-300" title={`${action.tool_name} · ${action.status}`}>
                {action.tool_name} · {action.status}
              </span>
            ))}
          </div>
        </div>
      )}
      {steps.length > 0 && !runLedger?.run_id && (
        <p className="border-t border-white/10 px-3 py-2 text-[10px] text-slate-500">{steps.length} chain steps recorded; surface details are unavailable for this run.</p>
      )}
    </div>
  );
}
