'use client';

import { ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { Loader2 } from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { FindingWriteup } from './FindingWriteup';
import { FindingProse } from './FindingProse';
import { FindingAssetContext } from './FindingAssetContext';
import { FindingScreenshot, FindingTechnicalEvidence } from './FindingEvidence';
import { emptyDecision, FindingRecord, ReviewDecision, TriageState } from './finding-record';

interface Props<T extends FindingRecord> {
  finding: T;
  overview: ReactNode;
  remediation: ReactNode;
  assessment: ReactNode;
  validation: ReactNode;
  metadata: ReactNode;
  statusActions: ReactNode;
  riskTriage?: (onSaved: () => Promise<void>, onDirtyChange: (dirty: boolean) => void) => ReactNode;
  onOpenFinding: (id: number) => void;
  onRefreshFinding: (finding: T) => void;
  onDirtyChange: (dirty: boolean) => void;
}

export function FindingDetailWorkspace<T extends FindingRecord>({ finding, overview, remediation, assessment, validation, metadata, statusActions, riskTriage, onOpenFinding, onRefreshFinding, onDirtyChange }: Props<T>) {
  const [tab, setTab] = useState('overview');
  const [context, setContext] = useState('evidence');
  const [triage, setTriage] = useState<TriageState | null>(null);
  const [itemId, setItemId] = useState('evidence');
  const [drafts, setDrafts] = useState<Record<string, ReviewDecision>>({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [saveError, setSaveError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState('');
  const [conflict, setConflict] = useState(false);
  const [riskDirty, setRiskDirty] = useState(false);
  const refreshFinding = useRef(onRefreshFinding);
  refreshFinding.current = onRefreshFinding;
  const dirty = Object.keys(drafts).length > 0 || riskDirty;
  const current = triage?.items.find(item => item.id === itemId);
  const draft = drafts[itemId] || current?.review || emptyDecision();
  const selectClass = 'mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground';

  const loadReview = useCallback(async () => {
    setLoading(true); setLoadError('');
    try {
      // Load the evidence and its review version from the same response. A conflict
      // reload must never authorize saving while the analyst still sees old evidence.
      const full = await api.getVulnerability(finding.id);
      if (!full.analyst_triage) throw new Error('Analyst review is unavailable. Update the backend to enable triage.');
      refreshFinding.current(full);
      setTriage(full.analyst_triage); setConflict(false);
    } catch (cause) { setLoadError(getApiErrorMessage(cause)); }
    finally { setLoading(false); }
  }, [finding.id]);

  useEffect(() => { void loadReview(); }, [loadReview]);
  useEffect(() => { onDirtyChange(dirty || saving); }, [dirty, saving, onDirtyChange]);
  useEffect(() => {
    if (!dirty) return;
    const beforeUnload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', beforeUnload);
    return () => window.removeEventListener('beforeunload', beforeUnload);
  }, [dirty]);

  const edit = (patch: Partial<ReviewDecision>) => {
    setDrafts(previous => ({ ...previous, [itemId]: { ...(previous[itemId] || current?.review || emptyDecision()), ...patch } }));
    setSaved(''); setSaveError('');
  };
  const cite = (reference: string) => {
    const next = Array.from(new Set([...draft.evidence_references, reference]));
    edit({ evidence_references: next.slice(0, 20) });
    setSaved('Evidence reference added to this decision.');
  };
  const chooseItem = (id: string) => {
    setItemId(id); setSaved(''); setSaveError('');
    setContext(triage?.items.find(item => item.id === id)?.context || 'evidence');
  };
  const saveReview = async (state: 'draft' | 'reviewed', next = false) => {
    if (!triage || saving || loading || conflict) return;
    const references = draft.evidence_references.map(value => value.trim()).filter(Boolean);
    if (state === 'reviewed') {
      if (!draft.decision || !draft.rationale.trim()) { setSaveError('Choose a decision and add its rationale.'); return; }
      if (draft.decision === 'correct' && !draft.correction.trim()) { setSaveError('Describe the corrected assessment.'); return; }
      if (draft.decision !== 'needs_evidence' && !references.length) { setSaveError('Cite supporting evidence before completing this review item.'); return; }
    }
    setSaving(true); setSaveError(''); setSaved('');
    const savingItem = itemId;
    try {
      const { data }: { data: TriageState } = await api.put(`/vulnerabilities/${finding.id}/triage`, {
        task_id: savingItem, expected_revision: triage.revision, evidence_version: triage.evidence_version,
        state, decision: draft.decision, rationale: draft.rationale.trim(), correction: draft.correction.trim(), evidence_references: references,
      });
      setTriage(data);
      setDrafts(previous => { const copy = { ...previous }; delete copy[savingItem]; return copy; });
      setSaved(state === 'draft' ? 'Draft saved. This item remains open.' : draft.decision === 'needs_evidence' ? 'Decision saved. This item still needs evidence.' : 'Review decision saved. Remediation status is unchanged.');
      if (next) {
        const index = data.items.findIndex(item => item.id === savingItem);
        const remaining = [...data.items.slice(index + 1), ...data.items.slice(0, index)].find(item => !item.reviewed);
        if (remaining) { setItemId(remaining.id); setContext(remaining.context); }
      }
    } catch (cause) {
      setSaveError(getApiErrorMessage(cause));
      if ((cause as { response?: { status?: number } }).response?.status === 409) setConflict(true);
    } finally { setSaving(false); }
  };

  const tabs = <TabsList className="h-auto w-full justify-start flex-wrap overflow-visible bg-transparent border-b rounded-none p-0 gap-1">
    <TabsTrigger value="overview">Overview</TabsTrigger>
    <TabsTrigger value="triage">Analyst triage{triage ? ` (${triage.pending})` : ''}</TabsTrigger>
    <TabsTrigger value="evidence">Evidence</TabsTrigger>
    <TabsTrigger value="remediation">Remediation</TabsTrigger>
    <TabsTrigger value="assets">Assets</TabsTrigger>
    <TabsTrigger value="activity">Activity</TabsTrigger>
  </TabsList>;

  return <div className="space-y-4 py-4">
    <div className="flex justify-between gap-3 items-center flex-wrap rounded-md border bg-muted/25 p-3">
      <div className="text-sm">
        <p className="font-medium">Analyst review: {triage?.status.replaceAll('_', ' ') || (loading ? 'Loading…' : 'Unavailable')}</p>
        <p className="text-xs text-muted-foreground">{triage ? `${triage.pending} review item${triage.pending === 1 ? '' : 's'} outstanding` : 'Review state is separate from finding status.'}{finding.validation_status === 'failed' ? ' · Latest validation could not run' : ''}</p>
      </div>
      <Button size="sm" variant="outline" onClick={() => setTab('triage')}>Review work</Button>
    </div>
    <Tabs value={tab} onValueChange={setTab} className="min-w-0">
      {tabs}
      <TabsContent value="overview" className="space-y-5 pt-4">
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_260px]">
          <div className="min-w-0 space-y-5">
            <FindingWriteup description={finding.description} impact={finding.impact} notDemonstrated={finding.agent_detection?.not_demonstrated} />
            <FindingWriteup references={finding.agent_detection?.references?.length ? finding.agent_detection.references : finding.references || finding.reference} />
            {!!finding.tags?.length && <div className="flex flex-wrap gap-1">{finding.tags.map(tag => <Badge key={tag} variant="secondary">{tag}</Badge>)}</div>}
            <details className="rounded-md border p-3"><summary className="cursor-pointer text-sm font-medium">Priority and automated assessments</summary><div className="space-y-5 pt-4">{overview}{assessment}</div></details>
          </div>
          <aside className="space-y-4 lg:border-l lg:pl-5">
            <h3 className="text-sm font-semibold">Record context</h3>{metadata}
            {finding.asset_id && <Link href={`/assets/${finding.asset_id}`} target="_blank" rel="noopener noreferrer" className="block text-sm text-primary hover:underline">Open linked asset record ↗</Link>}
            {statusActions}
          </aside>
        </div>
      </TabsContent>
      <TabsContent value="triage" forceMount className="space-y-4 pt-4 data-[state=inactive]:hidden">
        {loading && <p role="status" className="text-sm text-muted-foreground">Loading analyst review…</p>}
        {loadError && <div role="alert" className="text-sm text-destructive">{loadError} <Button variant="link" onClick={loadReview}>Retry</Button></div>}
        {triage && <>
          <div className="flex items-end justify-between gap-3 flex-wrap">
            <label className="text-xs text-muted-foreground min-w-0 flex-1 max-w-xl">Review item
              <select className={selectClass} value={itemId} disabled={saving} onChange={event => chooseItem(event.target.value)}>
                {triage.items.map(item => <option key={item.id} value={item.id}>{item.title} · {item.stale ? 'Evidence changed' : item.reviewed ? 'Reviewed' : 'Needs review'}{drafts[item.id] ? ' · Unsaved' : ''}</option>)}
              </select>
            </label>
            <Badge variant="outline">{triage.items.length - triage.pending} / {triage.items.length} reviewed</Badge>
          </div>
          <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
            <section className="min-w-0 space-y-4" aria-label="Vulnerability context and evidence">
              <div className="space-y-2 border-b pb-4"><h3 className="text-sm font-semibold">About this vulnerability</h3>
                <FindingProse text={finding.description ? finding.description.slice(0, 420) + (finding.description.length > 420 ? '…' : '') : 'No vulnerability description was supplied.'} />
                <details><summary className="text-sm text-primary cursor-pointer">Full description, impact, and recommendation</summary><div className="pt-3"><FindingWriteup description={finding.description} impact={finding.impact} recommendation={finding.remediation} notDemonstrated={finding.agent_detection?.not_demonstrated} /></div></details>
                <div className="flex gap-2 flex-wrap"><Badge variant="outline">Scanner: {finding.severity}</Badge>{finding.oracle?.opes_score != null && <Badge variant="outline">OPES {finding.oracle.opes_score} · {finding.oracle.opes_category}</Badge>}{finding.cvss_score != null && <Badge variant="outline">CVSS {finding.cvss_score}</Badge>}</div>
              </div>
              <Tabs value={context} onValueChange={setContext}>
                <TabsList className="w-full h-auto flex-wrap justify-start"><TabsTrigger value="evidence">Detection evidence</TabsTrigger><TabsTrigger value="screenshot">Screenshot</TabsTrigger><TabsTrigger value="assets">Asset context</TabsTrigger></TabsList>
                <TabsContent value="evidence" className="pt-3 space-y-4"><FindingTechnicalEvidence finding={finding} onCite={saving || loading || conflict ? undefined : cite} /><details><summary className="text-sm cursor-pointer">Validation and automated assessment</summary><div className="space-y-5 pt-4">{validation}{assessment}</div></details></TabsContent>
                <TabsContent value="screenshot" className="pt-3"><FindingScreenshot finding={finding} onCite={saving || loading || conflict ? undefined : cite} /></TabsContent>
                <TabsContent value="assets" className="pt-3"><FindingAssetContext finding={finding} onCite={saving || loading || conflict ? undefined : cite} onOpenFinding={onOpenFinding} /></TabsContent>
              </Tabs>
            </section>
            <div className="min-w-0 space-y-4">
            <section className="min-w-0 rounded-lg border p-4 space-y-4" aria-label="Analyst decision">
              <div><h3 className="font-semibold">{current?.title}</h3><p className="mt-1 text-sm text-muted-foreground">{current?.guidance}</p></div>
              {current?.stale && <p role="status" className="text-sm text-amber-600 dark:text-amber-400">Evidence changed since the previous review. Recheck the previous decision before completing this item.</p>}
              {current?.review?.reviewer && <p className="text-xs text-muted-foreground">Last saved by {current.review.reviewer} · {formatDate(current.review.saved_at || '')}</p>}
              <fieldset disabled={saving || loading || conflict} className="space-y-4">
                <label className="block text-xs text-muted-foreground">Decision<select className={selectClass} value={draft.decision || ''} onChange={event => edit({ decision: (event.target.value || null) as ReviewDecision['decision'] })}><option value="">Choose a decision…</option><option value="confirm">Confirm assessment</option><option value="correct">Record correction</option><option value="needs_evidence">Need more evidence</option></select></label>
                {draft.decision === 'correct' && <label className="block space-y-1 text-xs text-muted-foreground">Corrected assessment<Textarea value={draft.correction} maxLength={2000} onChange={event => edit({ correction: event.target.value })} placeholder="Describe the supported rating or conclusion." /><span className="block">This records your correction; it does not automatically change the finding’s severity or asset links.</span></label>}
                <label className="block space-y-1 text-xs text-muted-foreground">Rationale / next action<Textarea value={draft.rationale} rows={5} maxLength={6000} onChange={event => edit({ rationale: event.target.value })} placeholder="Explain the decision, what was verified, and what remains unknown." /></label>
                <label className="block space-y-1 text-xs text-muted-foreground">Evidence references · one per line<Textarea value={draft.evidence_references.join('\n')} rows={3} maxLength={20000} onChange={event => edit({ evidence_references: event.target.value.split('\n').slice(0, 20) })} placeholder="Use Cite beside the evidence, or add an existing evidence reference." /></label>
                <div className="flex gap-2 flex-wrap"><Button size="sm" variant="outline" onClick={() => saveReview('draft')}>Save draft</Button><Button size="sm" onClick={() => saveReview('reviewed', true)}>{saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Save decision &amp; next</Button></div>
              </fieldset>
              {saveError && <p role="alert" className="text-sm text-destructive">{saveError}</p>}
              {conflict && <Button size="sm" variant="outline" onClick={loadReview}>Reload review · keep my draft</Button>}
              {saved && <p role="status" className="text-sm text-muted-foreground">{saved}</p>}
              <p className="text-xs text-muted-foreground">Drafts and “Need more evidence” stay open. A completed review does not resolve the finding.</p>
            </section>
            {riskTriage && <details className="rounded-lg border p-4" open>
              <summary className="cursor-pointer text-sm font-semibold">Risk ratings &amp; business application</summary>
              <p className="my-3 text-xs text-muted-foreground">Update the ratings used to calculate business risk here. Save them before completing the review above.</p>
              {riskTriage(loadReview, setRiskDirty)}
            </details>}
            </div>
          </div>
        </>}
      </TabsContent>
      <TabsContent value="evidence" className="space-y-6 pt-4"><FindingTechnicalEvidence finding={finding} /><FindingScreenshot finding={finding} />{validation}</TabsContent>
      <TabsContent value="remediation" className="space-y-5 pt-4"><FindingWriteup recommendation={finding.remediation} />{remediation}{statusActions}</TabsContent>
      <TabsContent value="assets" className="pt-4"><FindingAssetContext finding={finding} onOpenFinding={onOpenFinding} /></TabsContent>
      <TabsContent value="activity" className="space-y-5 pt-4">
        <h3 className="text-sm font-semibold">Detection and review history</h3>
        <dl className="grid gap-3 sm:grid-cols-2 text-sm">{[['First detected', finding.first_detected || finding.created_at], ['Last detected', finding.last_detected], ['Last validated', finding.last_validated_at], ['Resolved', finding.resolved_at]].map(([label, date]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd>{date ? formatDate(date) : 'Not recorded'}</dd></div>)}</dl>
        {loadError && <p role="alert" className="text-sm text-destructive">Review history unavailable: {loadError}</p>}
        {triage?.history.length === 0 && <p className="text-sm text-muted-foreground">No analyst decisions recorded yet.</p>}
        {triage?.history.slice().reverse().map((entry, index) => <details key={`${entry.saved_at}-${index}`} className="rounded-md border p-3">
          <summary className="text-sm cursor-pointer">{entry.state === 'draft' ? 'Draft saved' : 'Decision recorded'} · {triage.items.find(item => item.id === entry.task_id)?.title} · {entry.reviewer} · {formatDate(entry.saved_at || '')}</summary>
          <div className="space-y-2 pt-3 text-sm"><p>{entry.decision?.replaceAll('_', ' ') || 'No decision yet'}</p><p className="whitespace-pre-wrap">{entry.rationale}</p>{entry.correction && <p className="whitespace-pre-wrap">Correction: {entry.correction}</p>}<ul className="space-y-1 text-xs text-muted-foreground">{entry.evidence_references.map((reference, i) => <li key={i} className="break-all">{reference}</li>)}</ul></div>
        </details>)}
      </TabsContent>
    </Tabs>
  </div>;
}
