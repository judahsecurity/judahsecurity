'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { api, getApiErrorMessage, type VerdictSummary } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';

export interface UnverifiedLead {
  vulnerability_class?: string;
  requested_severity?: string;
  published_severity?: string;
  verifier_summary?: string;
  proof_gap?: { reason?: string; next_step?: string };
  hunter_evidence_ids?: string[];
}

interface ReviewableFinding {
  id: number;
  status?: string;
  verification_level?: string | null;
  unverified_lead?: UnverifiedLead | null;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Analyst decision for an agent finding the independent verifier could not
 * confirm. Promote restores the hunter's severity (or a chosen one) and marks
 * it analyst_verified; dismiss closes it as a false positive.
 */
export function UnverifiedReviewPanel<T extends ReviewableFinding>({ finding, onReviewed }: {
  finding: T;
  onReviewed: (updated: T) => void;
}) {
  const lead = finding.unverified_lead || {};
  const [severity, setSeverity] = useState(lead.requested_severity || 'medium');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<'promote' | 'dismiss' | null>(null);
  const [error, setError] = useState('');
  const open = finding.status === 'open' || !finding.status;

  const submit = async (action: 'promote' | 'dismiss') => {
    setBusy(action); setError('');
    try {
      const updated = await api.reviewUnverifiedFinding(finding.id, {
        action, note, ...(action === 'promote' ? { severity } : {}),
      });
      onReviewed({ ...finding, ...updated });
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="space-y-3 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-sm">
      <div>
        <p className="font-medium text-foreground">Not independently verified</p>
        <p className="text-xs text-muted-foreground">
          The hunter reported this with evidence, but no supported proof recipe reproduced it.
          Severity is capped at medium until you promote it.
        </p>
      </div>
      <dl className="grid gap-2 text-xs">
        {lead.vulnerability_class && <div><dt className="text-muted-foreground">Class</dt><dd>{lead.vulnerability_class}</dd></div>}
        {lead.requested_severity && <div><dt className="text-muted-foreground">Hunter severity</dt><dd className="capitalize">{lead.requested_severity}</dd></div>}
        {lead.proof_gap?.reason && <div><dt className="text-muted-foreground">Why it was not confirmed</dt><dd className="whitespace-pre-wrap break-words">{lead.proof_gap.reason}</dd></div>}
        {lead.proof_gap?.next_step && <div><dt className="text-muted-foreground">Suggested check</dt><dd className="whitespace-pre-wrap break-words">{lead.proof_gap.next_step}</dd></div>}
        {!!lead.hunter_evidence_ids?.length && <div><dt className="text-muted-foreground">Hunter evidence</dt><dd className="break-all font-mono">{lead.hunter_evidence_ids.join(', ')}</dd></div>}
      </dl>
      {open ? (
        <div className="space-y-2">
          <label className="block text-xs text-muted-foreground">Severity if promoted
            <select aria-label="Severity if promoted" value={severity} onChange={(e) => setSeverity(e.target.value)}
              className="mt-1 w-full rounded-md border border-input bg-background p-2 text-sm text-foreground capitalize">
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <Textarea aria-label="Review note" placeholder="What you checked (optional)" value={note}
            onChange={(e) => setNote(e.target.value)} className="min-h-[60px] text-sm" />
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={!!busy} onClick={() => submit('promote')}>
              {busy === 'promote' && <Loader2 className="mr-2 h-3 w-3 animate-spin" />}Promote to finding
            </Button>
            <Button size="sm" variant="outline" disabled={!!busy} onClick={() => submit('dismiss')}>
              {busy === 'dismiss' && <Loader2 className="mr-2 h-3 w-3 animate-spin" />}Dismiss
            </Button>
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">Closed ({finding.status?.replace('_', ' ')}).</p>
      )}
    </section>
  );
}

/** Verifier verdicts by class: which proof recipes reject candidates most often. */
export function VerdictSummaryPanel({ days = 30 }: { days?: number }) {
  const [data, setData] = useState<VerdictSummary | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let live = true;
    api.getVerdictSummary(days)
      .then((d) => { if (live) setData(d); })
      .catch((err) => { if (live) setError(getApiErrorMessage(err)); });
    return () => { live = false; };
  }, [days]);

  if (error) return <p className="text-xs text-muted-foreground">Verifier stats unavailable: {error}</p>;
  if (!data) return <p className="text-xs text-muted-foreground"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" />Loading verifier stats…</p>;
  if (!data.classes.length) return <p className="text-xs text-muted-foreground">No verifier verdicts in the last {data.days} days.</p>;

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        Verifier verdicts, last {data.days} days: {data.totals.confirmed} confirmed, {data.totals.inconclusive} inconclusive, {data.totals.refuted} refuted.
        Classes with many inconclusive verdicts are where proof recipes may be too strict.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-left text-muted-foreground">
            <tr><th className="py-1 pr-3 font-medium">Class</th><th className="py-1 pr-3 font-medium">Confirmed</th><th className="py-1 pr-3 font-medium">Inconclusive</th><th className="py-1 pr-3 font-medium">Refuted</th><th className="py-1 pr-3 font-medium">Not confirmed</th><th className="py-1 font-medium">Top gap</th></tr>
          </thead>
          <tbody>
            {data.classes.map((row) => (
              <tr key={row.vulnerability_class} className="border-t border-border/50 align-top">
                <td className="py-1 pr-3 font-mono">{row.vulnerability_class}</td>
                <td className="py-1 pr-3">{row.confirmed}</td>
                <td className="py-1 pr-3">{row.inconclusive}</td>
                <td className="py-1 pr-3">{row.refuted}</td>
                <td className="py-1 pr-3">{Math.round(row.rejection_rate * 100)}%</td>
                <td className="py-1 break-words text-muted-foreground">{row.top_inconclusive_reasons[0]?.reason || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
