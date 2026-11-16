'use client';

import { useEffect, useMemo, useState } from 'react';
import { Check, Loader2, Minus, Wrench } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { api, getApiErrorMessage, type AgentToolAccess, type ToolDecision } from '@/lib/api';

const PHASE_LABELS: Record<string, string> = {
  informational: 'Recon',
  exploitation: 'Exploit',
  post_exploitation: 'Post-exploit',
};

const DECISION_VARIANT: Record<ToolDecision, 'low' | 'medium' | 'critical'> = {
  auto: 'low',
  confirm: 'medium',
  deny: 'critical',
};

const MAIN_AGENT = '__main__';

function DecisionBadge({ decision, reason }: { decision: ToolDecision; reason: string }) {
  return (
    <Badge variant={DECISION_VARIANT[decision]} title={reason}>
      {decision}
    </Badge>
  );
}

/** Read-only view: which tools the agent and each specialist may call, and how approval works. */
export function AgentToolAccessCard() {
  const [data, setData] = useState<AgentToolAccess | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [actor, setActor] = useState(MAIN_AGENT);

  useEffect(() => {
    api
      .getAgentToolAccess()
      .then(setData)
      .catch((e) => setError(getApiErrorMessage(e, 'Could not load tool access')));
  }, []);

  const rows = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.tools.filter((t) => {
      if (q && !t.name.toLowerCase().includes(q)) return false;
      if (actor === MAIN_AGENT) return t.phases.length > 0;
      return t.specialists.includes(actor);
    });
  }, [data, query, actor]);

  const specialist = data?.specialists.find((s) => s.name === actor);
  const missing = data?.tools.filter((t) => t.installed === false).length ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wrench className="h-5 w-5" />
          Agent Tool Access
        </CardTitle>
        <CardDescription>
          Which tools Prowl can call in each phase, which specialists can call them, and whether a
          call runs automatically, waits for approval, or is refused under this organization&apos;s
          policy.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-destructive">{error}</p>}
        {!data && !error && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading tools…
          </div>
        )}
        {data && (
          <>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Select value={actor} onValueChange={setActor}>
                <SelectTrigger className="sm:w-72" aria-label="Agent or specialist">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={MAIN_AGENT}>Main agent (phase-gated)</SelectItem>
                  {data.specialists.map((s) => (
                    <SelectItem key={s.name} value={s.name}>
                      {s.epithet} — {s.name.replace(/_/g, ' ')}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                placeholder="Filter tools…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="sm:w-64"
                aria-label="Filter tools"
              />
            </div>

            <p className="text-xs text-muted-foreground">
              {specialist
                ? `${specialist.role}. Specialists are not phase-gated; this allowlist is their boundary.`
                : 'The main agent may only call a tool in the phases marked below.'}{' '}
              {rows.length} tools shown
              {missing > 0 && ` · ${missing} not installed on this worker`}.
            </p>

            <div className="max-h-[28rem] overflow-auto rounded-md border">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-card">
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="px-3 py-2 font-medium">Tool</th>
                    {data.phases.map((p) => (
                      <th key={p} className="px-2 py-2 text-center font-medium">
                        {PHASE_LABELS[p] ?? p}
                      </th>
                    ))}
                    <th className="px-2 py-2 font-medium" title="Interactive session">
                      Approval
                    </th>
                    <th className="px-2 py-2 font-medium" title="Unattended scheduled run">
                      Autonomous
                    </th>
                    <th className="px-2 py-2 font-medium">Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((t) => (
                    <tr key={t.name} className="border-b last:border-0">
                      <td className="px-3 py-1.5 font-mono text-xs">{t.name}</td>
                      {data.phases.map((p) => (
                        <td key={p} className="px-2 py-1.5 text-center">
                          {t.phases.includes(p) ? (
                            <Check className="mx-auto h-4 w-4 text-green-500" aria-label="allowed" />
                          ) : (
                            <Minus className="mx-auto h-4 w-4 text-muted-foreground/40" aria-label="not allowed" />
                          )}
                        </td>
                      ))}
                      <td className="px-2 py-1.5">
                        <DecisionBadge decision={t.confirmation.interactive} reason={t.confirmation.reason} />
                      </td>
                      <td className="px-2 py-1.5">
                        <DecisionBadge decision={t.confirmation.autonomous} reason={t.confirmation.reason} />
                      </td>
                      <td className="space-x-1 px-2 py-1.5 whitespace-nowrap">
                        {t.source === 'recipe' && <Badge variant="info">recipe</Badge>}
                        {t.installed === false && <Badge variant="outline">not installed</Badge>}
                        {t.requires_grant && <Badge variant="outline">needs OOB grant</Badge>}
                        {!t.registered && <Badge variant="outline">unregistered</Badge>}
                      </td>
                    </tr>
                  ))}
                  {rows.length === 0 && (
                    <tr>
                      <td colSpan={data.phases.length + 4} className="px-3 py-6 text-center text-muted-foreground">
                        No tools match.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              {data.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
              <li>Approval rules are edited in the agent policy; this view reflects the current saved policy.</li>
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}
