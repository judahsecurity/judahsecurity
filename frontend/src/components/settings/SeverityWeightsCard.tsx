'use client';

import { useEffect, useState } from 'react';
import { Loader2, Scale } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface OrgWeight {
  weight: number;
  platform_default: number;
  source: 'organization' | 'default';
}

const IMPACT_BASE_WEIGHTS: Record<string, number> = {
  business_impact: 2,
  network_location: 1,
  vulnerability_severity: 7,
};

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

/** Organization-wide default weight (1–4) for each severity factor. Analysts
 *  can still change a factor's weight on an individual finding. */
export function SeverityWeightsCard() {
  const [weights, setWeights] = useState<Record<string, OrgWeight> | null>(null);
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [draft, setDraft] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    api
      .getSeverityWeights()
      .then((res) => {
        setWeights(res.weights);
        setLabels(res.weight_labels ?? {});
      })
      .catch(() => setWeights(null));
  }, []);

  if (!weights) return null;

  const current = (key: string) => draft[key] ?? weights[key]?.weight;
  const dirty = Object.entries(draft).some(([k, v]) => v !== weights[k]?.weight);

  const save = async (reset = false) => {
    setSaving(true);
    try {
      const payload: Record<string, number | null> = {};
      if (reset) {
        for (const k of Object.keys(weights)) payload[k] = null;
      } else {
        for (const [k, v] of Object.entries(draft)) {
          payload[k] = v === weights[k]?.platform_default ? null : v;
        }
      }
      const res = await api.setSeverityWeights(payload);
      setWeights(res.weights);
      setDraft({});
      toast({ title: 'Default weights saved', description: 'Open findings are being re-scored.' });
    } catch (err) {
      toast({ title: 'Could not save weights', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const shareOf = (keys: [string, string][]) => {
    const effective = (k: string) => (current(k) ?? 0) * (IMPACT_BASE_WEIGHTS[k] ?? 1);
    const total = keys.reduce((sum, [k]) => sum + effective(k), 0) || 1;
    return (k: string) => Math.round((effective(k) / total) * 100);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Scale className="h-5 w-5" />
          Severity Scoring Weights
        </CardTitle>
        <CardDescription>
          How much each factor counts in Risk = Likelihood × Impact for your organization. Analysts can still
          change a factor&apos;s weight on an individual finding during triage. Standard weights preserve the
          impact baseline: 70% vulnerability severity, 20% business impact, 10% network location.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {GROUPS.map((group) => {
          const pct = shareOf(group.keys);
          return (
            <div key={group.title} className="space-y-2">
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{group.title}</p>
              {group.keys.map(([key, label]) => {
                const w = weights[key];
                const custom = current(key) !== w?.platform_default;
                return (
                  <div key={key} className="flex items-center gap-3 text-sm flex-wrap">
                    <span className="w-48 shrink-0">{label}</span>
                    <select
                      aria-label={`${label} default weight`}
                      className={cn(
                        'h-8 rounded-md border bg-background px-2 text-xs',
                        custom && 'border-blue-500/40 text-blue-400',
                      )}
                      value={current(key)}
                      onChange={(e) => setDraft((prev) => ({ ...prev, [key]: Number(e.target.value) }))}
                    >
                      {[4, 3, 2, 1].map((n) => (
                        <option key={n} value={n}>
                          ×{n} — {labels[String(n)] ?? ''}
                          {n === w?.platform_default ? ' (platform default)' : ''}
                        </option>
                      ))}
                    </select>
                    <span className="text-xs text-muted-foreground">
                      {pct(key)}% of {group.title.toLowerCase()}
                    </span>
                  </div>
                );
              })}
            </div>
          );
        })}
        <div className="flex gap-2 justify-end">
          <Button variant="outline" size="sm" disabled={saving} onClick={() => save(true)}>
            Reset to platform defaults
          </Button>
          <Button size="sm" disabled={!dirty || saving} onClick={() => save(false)}>
            {saving && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />}
            Save weights
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
