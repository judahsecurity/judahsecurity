'use client';

import { useEffect, useState } from 'react';
import { Loader2, AlertTriangle, Bot, Building2, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

type FactorSource = 'auto' | 'assumed' | 'agent' | 'analyst';

export interface BusinessAppSummary {
  id: number;
  app_id?: string | null;
  name: string;
  business_criticality?: string | null;
  criticality_level?: number | null;
  owner?: string | null;
  external_url?: string | null;
  inherited_from_asset?: boolean;
}

interface FactorView {
  score: number;
  rating: string;
  reason: string;
  source: FactorSource;
  by?: string;
  at?: string;
  auto?: { score: number; rating: string; reason: string } | null;
  confidence?: 'high' | 'medium' | 'low' | null;
}

interface RealismView {
  tier: string;
  score?: number;
  reasons: string[];
  source?: 'analyst';
  by?: string;
  auto?: { tier: string } | null;
}

interface WeightView {
  weight: number;
  source: 'default' | 'analyst';
  default: number;
  by?: string;
}

export interface RiskFactorsView {
  status: 'triaged' | 'needs_analyst' | 'incomplete';
  factors: Record<string, FactorView>;
  weights?: Record<string, WeightView>;
  weight_labels?: Record<string, string>;
  exploit_realism?: RealismView | null;
  needs_analyst: string[];
  ratings: Record<string, Record<string, string>>;
  score?: number;
  level?: string;
  impact?: number;
  likelihood?: number;
  likelihood_uncapped?: number;
}

const GROUPS: { title: string; keys: [string, string][] }[] = [
  {
    title: 'Impact',
    keys: [
      ['business_impact', 'Business Impact'],
      ['network_location', 'Network Location'],
      ['vulnerability_severity', 'Vulnerability Severity'],
    ],
  },
  {
    title: 'Likelihood',
    keys: [
      ['skill_level', 'Skill Level'],
      ['ease_of_discovery', 'Ease of Discovery'],
      ['ease_of_exploit', 'Ease of Exploit'],
      ['awareness', 'Awareness'],
    ],
  },
];

const REALISM_TIERS: [string, string][] = [
  ['confirmed', 'Confirmed — exploit proven on this asset'],
  ['likely', 'Likely — feature live, conditions met'],
  ['unverified', 'Unverified — version match only'],
  ['conditional', 'Conditional — needs foothold / creds / victim'],
  ['blocked', 'Blocked — required condition not met here'],
];

const LEVEL_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  informational: 'bg-muted text-muted-foreground',
};

const SOURCE_LABEL: Record<FactorSource, string> = {
  auto: 'auto',
  assumed: 'needs analyst',
  agent: 'agent proposal',
  analyst: 'analyst',
};

// '' = leave as is, 'auto' = clear analyst value, otherwise a score.
type Edit = { score: string; note: string };

interface RiskFactorTriagePanelProps {
  findingId: number;
  assetId?: number;
  businessApp?: BusinessAppSummary | null;
  /** Called after any change so the findings table row can update. */
  onUpdated?: (view: RiskFactorsView, businessApp?: BusinessAppSummary | null) => void;
}

export function RiskFactorTriagePanel({ findingId, assetId, businessApp, onUpdated }: RiskFactorTriagePanelProps) {
  const [view, setView] = useState<RiskFactorsView | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [edits, setEdits] = useState<Record<string, Edit>>({});
  const [realismEdit, setRealismEdit] = useState<Edit>({ score: '', note: '' });
  // '' = keep, 'default' = back to the default weight, '1'–'4' = new weight.
  const [weightEdits, setWeightEdits] = useState<Record<string, string>>({});
  const [asking, setAsking] = useState(false);
  const [app, setApp] = useState<BusinessAppSummary | null>(businessApp ?? null);
  const [appQuery, setAppQuery] = useState('');
  const [appResults, setAppResults] = useState<BusinessAppSummary[]>([]);
  const [linking, setLinking] = useState(false);
  const { toast } = useToast();

  useEffect(() => setApp(businessApp ?? null), [findingId, businessApp]);

  useEffect(() => {
    if (appQuery.trim().length < 2) {
      setAppResults([]);
      return;
    }
    const t = setTimeout(() => {
      api.listBusinessApps(appQuery.trim(), 10).then(setAppResults).catch(() => setAppResults([]));
    }, 250);
    return () => clearTimeout(t);
  }, [appQuery]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setEdits({});
    setRealismEdit({ score: '', note: '' });
    setWeightEdits({});
    api
      .getRiskFactors(findingId)
      .then((v) => !cancelled && setView(v))
      .catch(() => !cancelled && setView(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [findingId]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground p-3">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading risk factors…
      </div>
    );
  }
  if (!view) return null;

  const dirty =
    Object.values(edits).some((e) => e.score !== '') ||
    realismEdit.score !== '' ||
    Object.values(weightEdits).some((w) => w !== '');

  const setEdit = (key: string, patch: Partial<Edit>) =>
    setEdits((prev) => ({ ...prev, [key]: { ...(prev[key] ?? { score: '', note: '' }), ...patch } }));

  const save = async () => {
    const factors: Record<string, { score: number; note: string } | null> = {};
    for (const [key, e] of Object.entries(edits)) {
      if (e.score === '') continue;
      factors[key] = e.score === 'auto' ? null : { score: Number(e.score), note: e.note };
    }
    const weights: Record<string, number | null> = {};
    for (const [key, w] of Object.entries(weightEdits)) {
      if (w === '') continue;
      weights[key] = w === 'default' ? null : Number(w);
    }
    const payload: Parameters<typeof api.saveRiskFactors>[1] = { factors, weights };
    if (realismEdit.score !== '') {
      payload.exploit_realism = {
        tier: realismEdit.score === 'auto' ? null : realismEdit.score,
        note: realismEdit.note,
      };
    }
    setSaving(true);
    try {
      const next = await api.saveRiskFactors(findingId, payload);
      setView(next);
      onUpdated?.(next);
      setEdits({});
      setRealismEdit({ score: '', note: '' });
      setWeightEdits({});
      toast({ title: 'Risk factors saved' });
    } catch (err) {
      toast({ title: 'Could not save risk factors', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const askAgent = async () => {
    setAsking(true);
    try {
      const next = await api.proposeRiskFactors(findingId);
      setView(next);
      onUpdated?.(next);
      toast({ title: 'Agent proposals ready', description: 'Review each proposal, then accept or correct it.' });
    } catch (err) {
      toast({ title: 'Severity agent unavailable', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setAsking(false);
    }
  };

  const link = async (target: 'finding' | 'asset', appId: number | null) => {
    setLinking(true);
    try {
      const res =
        target === 'asset' && assetId
          ? await api.linkAssetBusinessApp(assetId, appId)
          : await api.linkFindingBusinessApp(findingId, appId);
      const linked: BusinessAppSummary | null = res.business_app ?? null;
      setApp(linked);
      setAppQuery('');
      setAppResults([]);
      const next = await api.getRiskFactors(findingId);
      setView(next);
      onUpdated?.(next, linked);
      toast({
        title: appId ? 'Business application linked' : 'Business application cleared',
        description:
          target === 'asset' && res.findings_updated !== undefined
            ? `${res.findings_updated} open finding(s) on this asset re-evaluated.`
            : undefined,
      });
    } catch (err) {
      toast({ title: 'Could not link business application', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setLinking(false);
    }
  };

  const realism = view.exploit_realism;

  return (
    <div className="rounded-lg border p-3 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <p className="text-sm font-semibold">Risk Scoring</p>
        {view.level && (
          <Badge variant="outline" className={cn('capitalize', LEVEL_STYLE[view.level])}>
            {view.level} · {view.score?.toFixed(1)}/100
          </Badge>
        )}
        {view.needs_analyst.length > 0 && (
          <Badge variant="outline" className="border-amber-500/40 text-amber-400">
            <AlertTriangle className="h-3 w-3 mr-1" />
            {view.needs_analyst.length} factor{view.needs_analyst.length > 1 ? 's' : ''} need triage
          </Badge>
        )}
        {view.status === 'triaged' && (
          <Badge variant="outline" className="border-green-500/40 text-green-400">Triaged</Badge>
        )}
        {view.needs_analyst.length > 0 && (
          <Button size="sm" variant="outline" className="ml-auto h-7 text-xs" disabled={asking} onClick={askAgent}>
            {asking ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Bot className="h-3.5 w-3.5 mr-1" />}
            Ask agent to estimate
          </Button>
        )}
      </div>

      <div className="rounded-md border p-2 space-y-1.5">
        <div className="flex items-center gap-2 text-xs flex-wrap">
          <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="font-medium">Business application</span>
          {app ? (
            <>
              <span className="font-mono">{app.app_id}</span>
              <span>{app.name}</span>
              {app.business_criticality && <span className="text-muted-foreground">· {app.business_criticality}</span>}
              {app.inherited_from_asset && <span className="text-muted-foreground">(from asset)</span>}
              {app.external_url && (
                <a href={app.external_url} target="_blank" rel="noopener noreferrer" className="text-primary">
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {!app.inherited_from_asset && (
                <Button size="sm" variant="ghost" className="h-6 text-xs" disabled={linking} onClick={() => link('finding', null)}>
                  Clear
                </Button>
              )}
            </>
          ) : (
            <span className="text-amber-400">not linked</span>
          )}
        </div>
        <Input
          className="h-8 text-xs"
          placeholder="Search by application id (e.g. APM0001234) or name"
          value={appQuery}
          onChange={(e) => setAppQuery(e.target.value)}
        />
        {appResults.length > 0 && (
          <div className="rounded-md border divide-y max-h-48 overflow-y-auto">
            {appResults.map((a) => (
              <div key={a.id} className="flex items-center gap-2 p-1.5 text-xs">
                <span className="font-mono shrink-0">{a.app_id}</span>
                <span className="truncate">{a.name}</span>
                {a.business_criticality && <span className="text-muted-foreground shrink-0">{a.business_criticality}</span>}
                <div className="ml-auto flex gap-1 shrink-0">
                  <Button size="sm" variant="outline" className="h-6 text-xs" disabled={linking} onClick={() => link('finding', a.id)}>
                    This finding
                  </Button>
                  {assetId && (
                    <Button size="sm" variant="outline" className="h-6 text-xs" disabled={linking} onClick={() => link('asset', a.id)}>
                      Whole asset
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {view.impact !== undefined && (
        <p className="text-xs text-muted-foreground">
          Impact {view.impact.toFixed(2)}/4 × Likelihood {view.likelihood?.toFixed(2)}/4
          <span className="opacity-70"> (weighted averages of the factors below)</span>
          {view.likelihood_uncapped !== undefined && view.likelihood !== undefined && view.likelihood_uncapped > view.likelihood && (
            <span className="text-yellow-400"> (capped from {view.likelihood_uncapped.toFixed(2)} by exploit realism)</span>
          )}
        </p>
      )}
      {view.status === 'incomplete' && (
        <p className="text-xs text-amber-400">
          No automatic scoring for this finding yet — score the missing factors below, or run Oracle analysis.
        </p>
      )}

      {GROUPS.map((group) => (
        <div key={group.title} className="space-y-1.5">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{group.title}</p>
          {group.keys.map(([key, label]) => {
            const f = view.factors[key];
            const needs = view.needs_analyst.includes(key);
            const edit = edits[key] ?? { score: '', note: '' };
            const options = Object.entries(view.ratings[key] ?? {}).sort((a, b) => Number(b[0]) - Number(a[0]));
            return (
              <div
                key={key}
                className={cn('rounded-md border p-2 space-y-1.5', needs && 'border-amber-500/40 bg-amber-500/5')}
              >
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  <span className="font-medium w-40 shrink-0">{label}</span>
                  {f ? (
                    <>
                      <span className="font-semibold">{f.score}</span>
                      <span>{f.rating}</span>
                      <Badge
                        variant="outline"
                        className={cn(
                          'text-[10px] px-1.5 py-0',
                          f.source === 'assumed' && 'border-amber-500/40 text-amber-400',
                          f.source === 'agent' && 'border-purple-500/40 text-purple-400',
                          f.source === 'analyst' && 'border-blue-500/40 text-blue-400',
                        )}
                      >
                        {SOURCE_LABEL[f.source]}
                        {f.source === 'agent' && f.confidence ? ` · ${f.confidence} confidence` : ''}
                        {f.source === 'analyst' && f.by ? ` · ${f.by}` : ''}
                      </Badge>
                      {f.source === 'agent' && edit.score === '' && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-6 text-xs"
                          onClick={() => setEdit(key, { score: String(f.score), note: `Accepted agent proposal: ${f.reason}` })}
                        >
                          Accept
                        </Button>
                      )}
                    </>
                  ) : (
                    <span className="text-amber-400">not scored</span>
                  )}
                </div>
                {f && (
                  <p className="text-xs text-muted-foreground">
                    {f.reason}
                    {f.source === 'analyst' && f.auto && ` (automatic: ${f.auto.score} ${f.auto.rating})`}
                  </p>
                )}
                <div className="flex gap-2">
                  <select
                    aria-label={`${label} score`}
                    className="h-8 rounded-md border bg-background px-2 text-xs"
                    value={edit.score}
                    onChange={(e) => setEdit(key, { score: e.target.value })}
                  >
                    <option value="">{needs ? 'Select…' : 'Keep'}</option>
                    {options.map(([score, rating]) => (
                      <option key={score} value={score}>
                        {score} — {rating}
                      </option>
                    ))}
                    {f?.source === 'analyst' && <option value="auto">Use automatic score</option>}
                  </select>
                  {(() => {
                    const w = view.weights?.[key];
                    const labels = view.weight_labels ?? {};
                    return (
                      <select
                        aria-label={`${label} weight`}
                        title="How much this factor counts on this finding"
                        className={cn(
                          'h-8 rounded-md border bg-background px-2 text-xs shrink-0',
                          w?.source === 'analyst' && 'border-blue-500/40 text-blue-400',
                        )}
                        value={weightEdits[key] ?? ''}
                        onChange={(e) => setWeightEdits((prev) => ({ ...prev, [key]: e.target.value }))}
                      >
                        <option value="">
                          Weight ×{w?.weight ?? '?'}
                          {w?.source === 'analyst' ? ' (set)' : ''}
                        </option>
                        {[4, 3, 2, 1].map((n) => (
                          <option key={n} value={String(n)}>
                            ×{n} — {labels[String(n)] ?? ''}
                            {w && n === w.default ? ' (default)' : ''}
                          </option>
                        ))}
                        {w?.source === 'analyst' && <option value="default">Reset to default ×{w.default}</option>}
                      </select>
                    );
                  })()}
                  {edit.score !== '' && edit.score !== 'auto' && (
                    <Input
                      className="h-8 text-xs"
                      placeholder="Why? (e.g. customer data, vendor-hosted)"
                      value={edit.note}
                      onChange={(e) => setEdit(key, { note: e.target.value })}
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ))}

      <div className="space-y-1.5">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Exploit Realism</p>
        <div className="rounded-md border p-2 space-y-1.5">
          <div className="flex items-center gap-2 text-xs flex-wrap">
            <span className="font-medium capitalize">{realism?.tier ?? 'unknown'}</span>
            {realism?.source === 'analyst' && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-blue-500/40 text-blue-400">
                verified{realism.by ? ` · ${realism.by}` : ''}
              </Badge>
            )}
          </div>
          {realism?.reasons?.map((r, i) => (
            <p key={i} className="text-xs text-muted-foreground">• {r}</p>
          ))}
          <div className="flex gap-2">
            <select
              aria-label="Exploit realism"
              className="h-8 rounded-md border bg-background px-2 text-xs"
              value={realismEdit.score}
              onChange={(e) => setRealismEdit((p) => ({ ...p, score: e.target.value }))}
            >
              <option value="">Keep</option>
              {REALISM_TIERS.map(([tier, label]) => (
                <option key={tier} value={tier}>
                  {label}
                </option>
              ))}
              {realism?.source === 'analyst' && <option value="auto">Use automatic</option>}
            </select>
            {realismEdit.score !== '' && realismEdit.score !== 'auto' && (
              <Input
                className="h-8 text-xs"
                placeholder="How was this verified?"
                value={realismEdit.note}
                onChange={(e) => setRealismEdit((p) => ({ ...p, note: e.target.value }))}
              />
            )}
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <Button size="sm" disabled={!dirty || saving} onClick={save}>
          {saving && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />}
          Save triage
        </Button>
      </div>
    </div>
  );
}
