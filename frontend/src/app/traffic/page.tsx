'use client';

import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, Loader2, RefreshCw, Search } from 'lucide-react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TrafficExchangeView, TrafficLine } from '@/components/traffic/TrafficExchangeView';
import { api, type TrafficSummary } from '@/lib/api';

const PAGE = 50;

export default function TrafficPage() {
  const [items, setItems] = useState<TrafficSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState('');
  const [host, setHost] = useState('');
  const [source, setSource] = useState('all');
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<number | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    setLoading(true);
    try {
      const res = await api.getTraffic({
        q: q || undefined, host: host || undefined,
        source: source === 'all' ? undefined : source, limit: PAGE, offset: nextOffset,
      });
      setItems(res.items);
      setTotal(res.total);
      setOffset(nextOffset);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [q, host, source]);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(0); }, [source]);

  return (
    <MainLayout>
      <Header title="Traffic" subtitle="Requests Prowl sent and traffic captured by the browser extension" />
      <div className="space-y-4 p-6">
        <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); load(0); }}>
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search URL or body" className="w-64" />
          <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="Exact host" className="w-56" />
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All sources</SelectItem>
              <SelectItem value="agent">Agent</SelectItem>
              <SelectItem value="extension">Browser extension</SelectItem>
            </SelectContent>
          </Select>
          <Button type="submit" variant="secondary"><Search className="mr-2 h-4 w-4" />Search</Button>
          <Button type="button" variant="ghost" size="icon" aria-label="Refresh" onClick={() => load(offset)}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <span className="ml-auto text-xs text-muted-foreground">{total.toLocaleString()} exchanges</span>
        </form>

        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex justify-center p-8"><Loader2 className="h-5 w-5 animate-spin text-muted-foreground" /></div>
            ) : items.length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground">
                No traffic recorded yet. Prowl records every request it sends; operators can add logged-in browsing with the
                browser extension in <code>extension/</code>.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {items.map((item) => (
                  <li key={item.id}>
                    <button type="button" className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40"
                      onClick={() => setOpen(open === item.id ? null : item.id)}>
                      {open === item.id ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
                      <TrafficLine item={item} className="flex-1" />
                      <span className="hidden w-40 shrink-0 text-right text-xs text-muted-foreground md:block">
                        {item.created_at ? new Date(item.created_at).toLocaleString() : ''}
                      </span>
                    </button>
                    {open === item.id && <div className="border-t border-border bg-background p-3"><TrafficExchangeView id={item.id} /></div>}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {total > PAGE && (
          <div className="flex items-center justify-end gap-2 text-sm">
            <Button variant="outline" size="sm" disabled={offset === 0 || loading} onClick={() => load(Math.max(0, offset - PAGE))}>Previous</Button>
            <span className="text-muted-foreground">{offset + 1}–{Math.min(offset + PAGE, total)} of {total}</span>
            <Button variant="outline" size="sm" disabled={offset + PAGE >= total || loading} onClick={() => load(offset + PAGE)}>Next</Button>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
