'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ExternalLink, Loader2 } from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { AssetContextRow, FindingRecord, findingType } from './finding-record';

export function FindingAssetContext({ finding, onCite, onOpenFinding }: {
  finding: FindingRecord;
  onCite?: (reference: string) => void;
  onOpenFinding: (id: number) => void;
}) {
  const [rows, setRows] = useState<AssetContextRow[]>([]);
  const [assetId, setAssetId] = useState<number | null>(finding.asset_id || null);
  const [asset, setAsset] = useState<{ value?: string; criticality?: string; asset_type?: string } | null>(null);
  const [related, setRelated] = useState<FindingRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [contextError, setContextError] = useState('');
  const [relatedError, setRelatedError] = useState('');
  const [page, setPage] = useState(0);
  const [more, setMore] = useState(false);
  const [type, setType] = useState('all');
  const [status, setStatus] = useState('open');
  const [retry, setRetry] = useState(0);
  const selectClass = 'w-full rounded-md border border-input bg-background px-3 py-2 text-sm';

  useEffect(() => {
    let active = true;
    setContextError('');
    api.get(`/vulnerabilities/${finding.id}/asset-context`).then(({ data }) => {
      if (active) setRows(data.assets || []);
    }).catch(error => { if (active) setContextError(getApiErrorMessage(error)); });
    return () => { active = false; };
  }, [finding.id, retry]);

  useEffect(() => {
    let active = true;
    setAsset(null);
    if (!assetId) return;
    api.getAsset(assetId).then(data => { if (active) setAsset(data); }).catch(error => {
      if (active) setRelatedError(getApiErrorMessage(error));
    });
    return () => { active = false; };
  }, [assetId, retry]);

  useEffect(() => {
    let active = true;
    if (!assetId) { setLoading(false); return; }
    setLoading(true); setRelatedError('');
    api.getVulnerabilitiesForAsset(assetId, { skip: page * 100, limit: 100 }).then(data => {
      if (!active) return;
      const items: FindingRecord[] = Array.isArray(data) ? data : [];
      setRelated(previous => page ? [...previous, ...items] : items);
      setMore(items.length === 100);
    }).catch(error => { if (active) setRelatedError(getApiErrorMessage(error)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [assetId, page, retry]);

  const visible = related.filter(item => item.id !== finding.id)
    .filter(item => type === 'all' || findingType(item) === type)
    .filter(item => status === 'all' || ['open', 'in_progress'].includes(item.status || 'open'));
  const known = rows.filter(row => row.asset_id !== null);
  const options = known.filter((row, index) => known.findIndex(candidate => candidate.asset_id === row.asset_id) === index);
  const selected = options.find(row => row.asset_id === assetId);

  return <div className="space-y-4">
    {contextError && <p role="alert" className="text-sm text-destructive">Asset mapping could not load: {contextError} <Button variant="link" onClick={() => setRetry(n => n + 1)}>Retry</Button></p>}
    {options.length > 0 && <label className="block space-y-1 text-xs text-muted-foreground">Asset record
      <select className={selectClass} value={assetId || ''} onChange={event => {
        setAssetId(Number(event.target.value)); setRelated([]); setPage(0); setType('all');
      }}>{options.map(row => <option key={row.asset_id} value={row.asset_id!}>{row.value} · {row.relationship === 'linked' ? 'Linked' : 'Mentioned'}</option>)}</select>
    </label>}
    {assetId ? <div className="space-y-2">
      <Link href={`/assets/${assetId}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
        {asset?.value || selected?.value || finding.host || `Asset ${assetId}`} <ExternalLink className="h-3.5 w-3.5" />
        <span className="sr-only">Open full asset record in a new tab</span>
      </Link>
      {selected?.relationship === 'mentioned' && <p className="text-xs text-amber-600 dark:text-amber-400">Mentioned in the writeup; its association with this finding has not been confirmed.</p>}
      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div><dt className="text-xs text-muted-foreground">Asset criticality</dt><dd>{asset?.criticality || 'Not recorded'}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Type</dt><dd>{asset?.asset_type?.replaceAll('_', ' ') || 'Not recorded'}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Finding assignee</dt><dd>{finding.assigned_to || 'Unassigned'}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Business context</dt><dd>{finding.impact ? 'See finding impact' : 'Needs analyst review'}</dd></div>
      </dl>
      {onCite && <Button size="sm" variant="outline" onClick={() => onCite(`Asset #${assetId}: ${asset?.value || selected?.value || finding.host}; relationship: ${selected?.relationship || 'linked'}`)}>Cite asset context</Button>}
    </div> : <p className="text-sm text-muted-foreground">No asset record linked.</p>}
    {rows.some(row => !row.asset_id) && <details className="text-sm"><summary className="cursor-pointer">Unresolved asset mentions ({rows.filter(row => !row.asset_id).length})</summary>
      <ul className="mt-2 space-y-1 text-xs text-muted-foreground">{rows.filter(row => !row.asset_id).map(row => <li key={row.value} className="break-all">{row.value} — no unique matching record</li>)}</ul>
    </details>}
    <div className="border-t pt-4 space-y-3">
      <h4 className="text-sm font-semibold">Other findings on this asset</h4>
      <div className="grid grid-cols-2 gap-2">
        <label className="text-xs text-muted-foreground">Finding type<select className={selectClass} value={type} onChange={event => setType(event.target.value)}>
          <option value="all">All types</option>{['CVE vulnerability', 'TLS / certificate', 'Service exposure', 'Misconfiguration', 'Other finding'].map(value => <option key={value}>{value}</option>)}
        </select></label>
        <label className="text-xs text-muted-foreground">Status<select className={selectClass} value={status} onChange={event => setStatus(event.target.value)}><option value="open">Open / in progress</option><option value="all">All statuses</option></select></label>
      </div>
      {relatedError && <div role="alert" className="text-sm text-destructive">Could not load asset findings. <Button variant="link" onClick={() => setRetry(n => n + 1)}>Retry</Button></div>}
      {visible.map(item => <button key={item.id} type="button" className="w-full border-b py-3 text-left hover:bg-muted/50" onClick={() => onOpenFinding(item.id)}>
        <div className="flex gap-2 items-start"><Badge variant="outline" className="capitalize shrink-0">{item.severity}</Badge><span className="text-sm">{item.title}</span></div>
        <p className="mt-1 text-xs text-muted-foreground">{findingType(item)} · {item.status?.replaceAll('_', ' ') || 'Open'} · {item.detected_by || 'Unknown source'}</p>
      </button>)}
      {loading && <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading findings…</p>}
      {!loading && !relatedError && !visible.length && <p className="text-sm text-muted-foreground">No other findings match these filters{more ? ' in the loaded results' : ''}.</p>}
      {more && <Button size="sm" variant="outline" disabled={loading} onClick={() => setPage(n => n + 1)}>Load more findings</Button>}
      {more && <p className="text-xs text-muted-foreground">Filters apply to the {related.length} loaded findings.</p>}
    </div>
  </div>;
}
