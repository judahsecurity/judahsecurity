'use client';

import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, getApiErrorMessage } from '@/lib/api';

interface Check {
  id: string; signal_path: string; description: string; method: string;
  match_kind: string; match_value?: string; status: string; reason?: string;
  source_reference?: string;
}

interface Observation {
  value: string; freshness: string; reference: string; note: string;
  collected_by: string; observed_at: string; valid_until: string;
}

interface EvidenceView {
  state: string; summary?: string; checks: Check[];
  observations: Record<string, Observation>;
}

const METHODS = [
  ['deployment_config', 'Deployment configuration'], ['runtime_inventory', 'Runtime inventory'],
  ['source_review', 'Source or image review'], ['network_policy', 'Network / ingress policy'],
  ['owner_attestation', 'Application owner confirmation'],
];

export function ApplicabilityEvidencePanel({ findingId, refreshKey, onUpdated }: {
  findingId: number; refreshKey?: string;
  onUpdated: (oracle: any, risk: any) => void;
}) {
  const [view, setView] = useState<EvidenceView | null>(null);
  const [selected, setSelected] = useState('');
  const [value, setValue] = useState('');
  const [method, setMethod] = useState('deployment_config');
  const [reference, setReference] = useState('');
  const [note, setNote] = useState('');
  const [observedAt, setObservedAt] = useState('');
  const [hours, setHours] = useState('24');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let cancelled = false;
    setView(null);
    api.getApplicabilityEvidence(findingId).then(v => { if (!cancelled) setView(v); })
      .catch(e => { if (!cancelled) setMessage(getApiErrorMessage(e)); });
    return () => { cancelled = true; };
  }, [findingId, refreshKey]);

  async function save(withdraw = false) {
    if (!selected || !reference.trim() || !note.trim() || !observedAt) return;
    setBusy(true); setMessage('');
    try {
      const result = await api.saveApplicabilityEvidence(findingId, [{
        signal_path: selected, value: withdraw ? null : value, method, reference, note,
        observed_at: new Date(observedAt).toISOString(), valid_for_hours: Number(hours),
      }]);
      setView(result);
      onUpdated(result.oracle, result.risk);
      setMessage(result.refresh_error ? 'Evidence saved. Oracle could not refresh; the assessment needs verification. Retry with Refresh Oracle.' : 'Evidence saved and assessment updated.');
      setSelected('');
    } catch (e) { setMessage(getApiErrorMessage(e)); }
    finally { setBusy(false); }
  }

  return (
    <details className="rounded border p-3 text-xs">
      <summary className="cursor-pointer font-medium">Verify applicability on this asset</summary>
      <p className="mt-2 text-muted-foreground">Record deployment or runtime evidence for the required conditions. A package match identifies a candidate; the checks below establish the affected component and attack path.</p>
      {view?.summary && <p className="mt-2">{view.summary}</p>}
      {view && !view.checks.length && <p className="mt-2 text-muted-foreground">Run or refresh Oracle to obtain component-specific verification checks.</p>}
      <div className="mt-3 space-y-3">
        {view?.checks.map(check => {
          const saved = view.observations[check.signal_path];
          return <div key={`${check.id}:${check.signal_path}`} className="border-l-2 pl-2">
            <p className="font-medium">{check.description} · {check.status.replaceAll('_', ' ')}</p>
            <p className="text-muted-foreground">{check.method}</p>
            {check.source_reference && <p className="break-all text-muted-foreground">Advisory / source: {check.source_reference}</p>}
            {saved && <p className="mt-1 text-muted-foreground">Recorded by {saved.collected_by}: {saved.freshness === 'unknown' ? 'withdrawn' : saved.value}. Observed {new Date(saved.observed_at).toLocaleString()}; expires {new Date(saved.valid_until).toLocaleString()}. Reference: {saved.reference}</p>}
            {saved?.note && <p className="text-muted-foreground">{saved.note}</p>}
            <Button type="button" size="sm" variant="outline" className="mt-1" disabled={busy} onClick={() => {
              setSelected(check.signal_path); setValue(''); setReference(''); setNote(''); setObservedAt('');
            }}>Record evidence</Button>
          </div>;
        })}
      </div>
      {selected && <div className="mt-3 grid gap-2 rounded bg-muted/30 p-3">
        <p className="font-medium">{view?.checks.find(c => c.signal_path === selected)?.description}</p>
        <p className="text-muted-foreground">Required condition: {view?.checks.find(c => c.signal_path === selected)?.match_kind} {view?.checks.find(c => c.signal_path === selected)?.match_value}</p>
        <label>Observed value
          <Input value={value} onChange={e => setValue(e.target.value)} placeholder="true / false, version, or configuration value" />
        </label>
        <p className="text-muted-foreground">Enter the actual configuration value. For a true/false condition, use false only after checking that specific condition. A scan miss is unknown.</p>
        <label>Evidence source
          <select className="block w-full rounded border bg-background p-2" value={method} onChange={e => setMethod(e.target.value)}>
            {METHODS.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
        </label>
        <label>Evidence reference<Input value={reference} onChange={e => setReference(e.target.value)} placeholder="Inventory record, image digest, config revision, or ticket" /></label>
        <label>What was checked<Input value={note} onChange={e => setNote(e.target.value)} placeholder="Component, environment and result" /></label>
        <label>Observed at (your local time)<Input type="datetime-local" value={observedAt} onChange={e => setObservedAt(e.target.value)} /></label>
        <label>Valid for (hours, maximum 168)<Input type="number" min={1} max={168} value={hours} onChange={e => setHours(e.target.value)} /></label>
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" disabled={busy || !value.trim() || !note.trim() || !reference.trim() || !observedAt} onClick={() => save()}>{busy ? 'Saving and evaluating…' : 'Save and reevaluate'}</Button>
          <Button type="button" size="sm" variant="outline" disabled={busy || !note.trim() || !reference.trim() || !observedAt} onClick={() => save(true)}>Withdraw previous observation</Button>
        </div>
      </div>}
      {message && <p role="status" className="mt-2">{message}</p>}
    </details>
  );
}
