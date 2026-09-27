'use client';

import { useEffect, useState } from 'react';
import { Camera, Expand, Loader2 } from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { formatDate } from '@/lib/utils';
import { DetectionPanel, hasScannerDetection } from './DetectionPanel';
import { DemonstratedChain } from './DemonstratedChain';
import { captureUrl, FindingRecord, webUrl } from './finding-record';

interface Screenshot {
  id: number; url: string; status: string; page_title?: string;
  captured_at?: string; http_status?: number; error_message?: string;
}

export function FindingScreenshot({ finding, onCite }: { finding: FindingRecord; onCite?: (reference: string) => void }) {
  const [shots, setShots] = useState<Screenshot[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [capturing, setCapturing] = useState(false);
  const [error, setError] = useState('');
  const [imageFailed, setImageFailed] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const shot = shots.find(item => item.id === selectedId);
  const sameEndpoint = Boolean(shot && target && webUrl(shot.url) === target);

  useEffect(() => {
    let active = true;
    setLoading(true); setError('');
    if (!finding.asset_id) { setLoading(false); return; }
    Promise.all([
      api.getAssetScreenshots(finding.asset_id),
      api.getAsset(finding.asset_id),
    ]).then(([history, asset]) => {
      if (!active) return;
      const url = captureUrl(finding, asset.live_url);
      const items: Screenshot[] = history.screenshots || [];
      const successful = items.filter(item => item.status === 'success');
      setShots(items); setTarget(url);
      setSelectedId(successful.find(item => url && webUrl(item.url) === url)?.id || successful[0]?.id || null);
    }).catch(cause => { if (active) setError(getApiErrorMessage(cause)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [finding, refresh]);

  useEffect(() => { setImageFailed(false); }, [selectedId]);

  const capture = async () => {
    if (!finding.asset_id || !target) return;
    setCapturing(true); setError('');
    try {
      const { data } = await api.post(`/screenshots/capture/asset/${finding.asset_id}`, undefined, { params: { url: target } });
      const result: Screenshot = data;
      setShots(previous => [result, ...previous]);
      if (result.status !== 'success') throw new Error(result.error_message || 'Capture did not produce an image.');
      setSelectedId(result.id);
    } catch (cause) { setError(getApiErrorMessage(cause, 'Could not capture this endpoint.')); }
    finally { setCapturing(false); }
  };

  return <section aria-label="Screenshot evidence" className="space-y-3">
    <div className="flex items-center justify-between gap-2 flex-wrap">
      <h4 className="text-sm font-semibold flex items-center gap-2"><Camera className="h-4 w-4" />Page screenshot</h4>
      <Button size="sm" variant="outline" disabled={loading || capturing || !target} onClick={capture}>
        {capturing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}{capturing ? 'Capturing…' : shot ? 'Capture again' : 'Capture page'}
      </Button>
    </div>
    {target && <p className="text-xs text-muted-foreground break-all">Capture endpoint: {target}</p>}
    {!target && !loading && <p className="text-xs text-muted-foreground">No verified HTTP(S) endpoint is available for this asset. Non-web services should be reviewed using their service responses.</p>}
    {loading && <p role="status" className="text-sm text-muted-foreground">Loading capture history…</p>}
    {error && <div role="alert" className="text-sm text-destructive">{error} <Button variant="link" size="sm" onClick={() => setRefresh(n => n + 1)}>Reload history</Button></div>}
    {shots.length > 0 && <label className="block text-xs text-muted-foreground">Capture history
      <select aria-label="Select capture" className="mt-1 w-full rounded-md border border-input bg-background p-2 text-sm" value={selectedId || ''} onChange={event => setSelectedId(Number(event.target.value))}>
        <option value="" disabled>Select a capture</option>{shots.map(item => <option key={item.id} value={item.id}>{formatDate(item.captured_at || '')} · {item.status} · {item.url}</option>)}
      </select>
    </label>}
    {shot?.status === 'success' && !imageFailed ? <div className="overflow-hidden rounded-lg border bg-muted/20">
      <button type="button" className="block w-full" aria-label="Expand screenshot" onClick={() => setExpanded(true)}>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={api.getScreenshotImageUrl(shot.id)} alt={shot.page_title || `Capture of ${shot.url}`} onError={() => setImageFailed(true)} className="max-h-80 w-full object-contain" />
      </button>
      <div className="space-y-1 border-t p-3 text-xs text-muted-foreground">
        <p className="break-all">URL: {shot.url}</p><p>Captured: {shot.captured_at ? formatDate(shot.captured_at) : 'Not recorded'} · HTTP {shot.http_status ?? 'unknown'}</p>
        <p>Login state: not recorded</p><p>{sameEndpoint ? 'Matches the finding endpoint' : 'Asset context — not verified against this finding endpoint'}</p>
      </div>
    </div> : !loading && <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
      {imageFailed ? 'The saved image could not be loaded.' : shot?.status && shot.status !== 'success' ? `Capture ${shot.status}: ${shot.error_message || 'No image produced.'}` : 'No successful screenshot attached to this asset.'}
    </div>}
    {shot?.status === 'success' && <div className="flex gap-2 flex-wrap">
      <Button size="sm" variant="outline" disabled={imageFailed} onClick={() => setExpanded(true)}><Expand className="mr-2 h-3.5 w-3.5" />Expand</Button>
      {onCite && <Button size="sm" variant="outline" onClick={() => onCite(`Screenshot #${shot.id}: ${shot.url}; captured ${shot.captured_at || 'unknown'}; login state not recorded${sameEndpoint ? '' : '; asset context only'}`)}>Cite screenshot</Button>}
    </div>}
    <p className="text-xs text-muted-foreground">Screenshots document appearance. Use the technical evidence to confirm the vulnerability. Earlier captures are retained.</p>
    <Dialog open={expanded} onOpenChange={setExpanded}><DialogContent className="max-w-6xl max-h-[90vh] overflow-auto"><DialogHeader><DialogTitle>{shot?.page_title || 'Page screenshot'}</DialogTitle></DialogHeader>
      {shot && <>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={api.getScreenshotImageUrl(shot.id)} alt={shot.page_title || shot.url} className="w-full" />
        <p className="text-xs text-muted-foreground break-all">{shot.url} · {formatDate(shot.captured_at || '')}</p>
      </>}
    </DialogContent></Dialog>
  </section>;
}

export function FindingTechnicalEvidence({ finding, onCite }: { finding: FindingRecord; onCite?: (reference: string) => void }) {
  const hasEvidence = Boolean(hasScannerDetection(finding.detection) || finding.agent_detection?.chain?.length || finding.evidence || finding.proof_of_concept);
  return <div className="space-y-5">
    <div className="flex gap-2 justify-between items-start"><div><h4 className="text-sm font-semibold">Detection evidence</h4><p className="text-xs text-muted-foreground">{finding.detected_by || 'Unknown source'} · Last detected {formatDate(finding.last_detected || finding.created_at || '')}</p></div>
      {onCite && hasEvidence && <Button size="sm" variant="outline" onClick={() => onCite(`Finding #${finding.id}: detection evidence from ${finding.detected_by || 'unknown source'}, last detected ${finding.last_detected || finding.created_at || 'unknown'}`)}>Cite evidence</Button>}
    </div>
    {!hasEvidence && <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">No technical evidence is attached. Record the missing evidence before confirming the claim.</p>}
    <DetectionPanel detection={finding.detection} />
    <DemonstratedChain detection={finding.agent_detection} />
    {[['Recorded evidence', finding.evidence], ['Proof of concept', finding.proof_of_concept], ['Steps to reproduce', finding.steps_to_reproduce], ['Not demonstrated', finding.agent_detection?.not_demonstrated]].map(([label, content]) => content ? <section key={label} className="space-y-2"><h5 className="text-sm font-medium">{label}</h5><pre className="max-h-96 overflow-auto rounded-md border bg-muted/30 p-3 text-xs whitespace-pre-wrap break-words">{content}</pre></section> : null)}
  </div>;
}
