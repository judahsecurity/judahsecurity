'use client';

import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, Link2, Loader2, Network, Search, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { TrafficExchangeView, TrafficLine } from '@/components/traffic/TrafficExchangeView';
import { api, type FindingTrafficRef, type TrafficSummary } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

/** Recorded request/response pairs cited as evidence for one finding. */
export function FindingTraffic({ findingId, host }: { findingId: number; host?: string }) {
  const { toast } = useToast();
  const [refs, setRefs] = useState<FindingTrafficRef[] | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [picking, setPicking] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<TrafficSummary[]>([]);
  const [searching, setSearching] = useState(false);

  const load = useCallback(async () => {
    try {
      setRefs((await api.getFindingTraffic(findingId)).items);
    } catch {
      setRefs([]);
    }
  }, [findingId]);

  useEffect(() => { setRefs(null); setOpen(null); setPicking(false); load(); }, [load]);

  const search = async () => {
    setSearching(true);
    try {
      setResults((await api.getTraffic({ q: query || undefined, host: host || undefined, limit: 25 })).items);
    } catch {
      setResults([]);
    } finally {
      setSearching(false);
    }
  };

  const bind = async (trafficId: number) => {
    try {
      await api.bindFindingTraffic(findingId, trafficId);
      await load();
      toast({ title: 'Exchange attached as evidence' });
    } catch (e: any) {
      toast({ title: 'Could not attach exchange', description: e?.message, variant: 'destructive' });
    }
  };

  const unbind = async (refId: number) => {
    try {
      await api.unbindFindingTraffic(findingId, refId);
      await load();
    } catch (e: any) {
      toast({ title: 'Could not remove exchange', description: e?.message, variant: 'destructive' });
    }
  };

  const boundIds = new Set((refs || []).map((r) => r.exchange?.id).filter(Boolean));

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="flex items-center gap-2 text-sm font-medium"><Network className="h-4 w-4" />Recorded traffic</p>
        <Button size="sm" variant="outline" onClick={() => { setPicking((p) => !p); if (!picking) search(); }}>
          <Link2 className="mr-2 h-4 w-4" />{picking ? 'Done' : 'Attach exchange'}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Requests and responses that reproduce this finding, in order. The agent binds the exchanges its verifier used;
        analysts can attach more from recorded agent or browser-extension traffic.
      </p>

      {refs === null && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
      {refs?.length === 0 && <p className="text-xs text-muted-foreground">No traffic is bound to this finding yet.</p>}
      <ol className="space-y-1">
        {refs?.map((ref, index) => (
          <li key={ref.ref_id} className="rounded-md border border-border">
            <div className="flex items-center gap-2 px-2 py-1.5">
              <span className="w-5 shrink-0 text-xs text-muted-foreground">{index + 1}.</span>
              {ref.exchange ? (
                <button type="button" className="flex min-w-0 flex-1 items-center gap-1 text-left"
                  onClick={() => setOpen(open === ref.ref_id ? null : ref.ref_id)}>
                  {open === ref.ref_id ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
                  <TrafficLine item={ref.exchange} className="flex-1" />
                </button>
              ) : (
                <span className="flex-1 text-xs text-muted-foreground">
                  Exchange {ref.artifact_id?.slice(0, 8)} is still being recorded, or has expired.
                </span>
              )}
              <span className="shrink-0 text-[10px] text-muted-foreground">{ref.bound_by === 'user' ? 'added by analyst' : 'bound by agent'}</span>
              <Button size="icon" variant="ghost" className="h-6 w-6" aria-label="Remove exchange" onClick={() => unbind(ref.ref_id)}>
                <X className="h-3 w-3" />
              </Button>
            </div>
            {ref.note && <p className="px-9 pb-1 text-xs text-muted-foreground">{ref.note}</p>}
            {open === ref.ref_id && ref.exchange && <div className="border-t border-border p-2"><TrafficExchangeView id={ref.exchange.id} /></div>}
          </li>
        ))}
      </ol>

      {picking && (
        <div className="space-y-2 rounded-md border border-dashed border-border p-2">
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); search(); }}>
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Search traffic${host ? ` on ${host}` : ''} (URL or body)`} className="h-8" />
            <Button size="sm" type="submit" variant="secondary" disabled={searching}>
              {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </Button>
          </form>
          {results.length === 0 && !searching && <p className="text-xs text-muted-foreground">No recorded exchanges match.</p>}
          <ul className="max-h-64 space-y-1 overflow-auto">
            {results.map((item) => (
              <li key={item.id} className="flex items-center gap-2">
                <TrafficLine item={item} className="flex-1" />
                <Button size="sm" variant="ghost" className="h-6" disabled={boundIds.has(item.id)} onClick={() => bind(item.id)}>
                  {boundIds.has(item.id) ? 'Attached' : 'Attach'}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
