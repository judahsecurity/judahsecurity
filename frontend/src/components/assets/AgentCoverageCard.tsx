'use client';

import { useEffect, useState } from 'react';
import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { api, getApiErrorMessage } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

type Outcome =
  | 'reported'
  | 'no_issue_found'
  | 'ruled_out'
  | 'not_applicable'
  | 'needs_follow_up'
  | 'in_progress'
  | 'untested';

interface CoverageCell {
  surface: string;
  parameter: string;
  identity: string;
  risk_area: string;
  outcome: Outcome;
  reason: string;
  finding_title: string;
  attempts: number;
  last_session_id: string;
  last_tested_at?: string | null;
}

interface AssetAgentCoverage {
  asset_id: number;
  total: number;
  tested: number;
  by_outcome: Record<Outcome, number>;
  by_risk_area: Record<string, Partial<Record<Outcome, number>>>;
  last_tested_at?: string | null;
  cells: CoverageCell[];
  exploitable_findings: { id: number; title: string; exploit_score: number; tier: string }[];
  exploitable_untested: boolean;
}

const OUTCOME_META: Record<Outcome, { label: string; className: string }> = {
  reported: { label: 'Reported', className: 'border-red-500/50 text-red-300' },
  no_issue_found: { label: 'Nothing found', className: 'border-emerald-500/50 text-emerald-300' },
  ruled_out: { label: 'Ruled out', className: 'border-emerald-500/30 text-emerald-200' },
  not_applicable: { label: 'Not applicable', className: 'border-slate-500/50 text-slate-300' },
  needs_follow_up: { label: 'Needs follow-up', className: 'border-amber-500/50 text-amber-300' },
  in_progress: { label: 'In progress', className: 'border-sky-500/50 text-sky-300' },
  untested: { label: 'Untested', className: 'border-border text-muted-foreground' },
};

const ORDER: Outcome[] = [
  'reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable', 'in_progress', 'untested',
];

export function AgentCoverageCard({ assetId }: { assetId: number }) {
  const [data, setData] = useState<AssetAgentCoverage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Outcome | null>(null);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    api
      .getAssetAgentCoverage(assetId)
      .then((d: AssetAgentCoverage) => live && setData(d))
      .catch((e: unknown) => live && setError(getApiErrorMessage(e)));
    return () => {
      live = false;
    };
  }, [assetId]);

  if (error) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">{error}</CardContent>
      </Card>
    );
  }
  if (!data) {
    return (
      <Card>
        <CardContent className="flex justify-center py-10">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  const cells = filter ? data.cells.filter((c) => c.outcome === filter) : data.cells;
  const areas = Object.entries(data.by_risk_area).sort(
    (a, b) => Object.values(b[1]).reduce((x, y) => x + (y || 0), 0) - Object.values(a[1]).reduce((x, y) => x + (y || 0), 0)
  );

  return (
    <div className="space-y-4">
      {data.exploitable_untested ? (
        <div className="flex items-start gap-3 rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
          <div>
            <p className="font-medium text-red-200">Exploitable findings, never tested by the agent</p>
            <p className="text-red-200/80">
              {data.exploitable_findings.map((f) => `${f.title} (exploit ${f.exploit_score})`).join(' · ')}
            </p>
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <CardTitle>Agent test coverage</CardTitle>
          </div>
          <CardDescription>
            What the pentest agent tested on this asset across sessions, including tests that found nothing.
            {data.last_tested_at ? ` Last tested ${formatDate(data.last_tested_at)}.` : ' Not tested yet.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {ORDER.filter((o) => data.by_outcome[o]).map((o) => (
              <button
                key={o}
                type="button"
                onClick={() => setFilter(filter === o ? null : o)}
                className={cn('rounded-md', filter && filter !== o && 'opacity-40')}
              >
                <Badge variant="outline" className={OUTCOME_META[o].className}>
                  {OUTCOME_META[o].label} · {data.by_outcome[o]}
                </Badge>
              </button>
            ))}
            {!data.total ? <span className="text-sm text-muted-foreground">No agent tests recorded for this asset.</span> : null}
          </div>

          {areas.length ? (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {areas.map(([area, counts]) => (
                <div key={area} className="rounded-md border border-border/60 px-3 py-2">
                  <p className="font-mono text-xs">{area}</p>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {ORDER.filter((o) => counts[o]).map((o) => `${OUTCOME_META[o].label} ${counts[o]}`).join(' · ')}
                  </p>
                </div>
              ))}
            </div>
          ) : null}

          {cells.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-[11px] uppercase tracking-wide text-muted-foreground">
                  <tr>
                    <th className="py-2 pr-3">Surface</th>
                    <th className="py-2 pr-3">Parameter</th>
                    <th className="py-2 pr-3">Test</th>
                    <th className="py-2 pr-3">Outcome</th>
                    <th className="py-2 pr-3">Why</th>
                    <th className="py-2">Last tested</th>
                  </tr>
                </thead>
                <tbody>
                  {cells.slice(0, 200).map((c, i) => (
                    <tr key={`${c.surface}-${c.parameter}-${c.risk_area}-${i}`} className="border-t border-border/50">
                      <td className="max-w-[280px] truncate py-1.5 pr-3 font-mono" title={c.surface}>{c.surface}</td>
                      <td className="py-1.5 pr-3 font-mono">{c.parameter}</td>
                      <td className="py-1.5 pr-3">{c.risk_area}</td>
                      <td className="py-1.5 pr-3">
                        <Badge variant="outline" className={OUTCOME_META[c.outcome]?.className}>
                          {OUTCOME_META[c.outcome]?.label || c.outcome}
                        </Badge>
                      </td>
                      <td className="max-w-[320px] truncate py-1.5 pr-3 text-muted-foreground" title={c.finding_title || c.reason}>
                        {c.finding_title || c.reason || '—'}
                      </td>
                      <td className="whitespace-nowrap py-1.5 text-muted-foreground">
                        {c.last_tested_at ? formatDate(c.last_tested_at) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
