'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { api, type TrafficDetail, type TrafficSummary } from '@/lib/api';
import { cn } from '@/lib/utils';

export function statusTone(status?: number | null) {
  if (!status) return 'text-muted-foreground';
  if (status >= 500) return 'text-red-400';
  if (status >= 400) return 'text-amber-400';
  if (status >= 300) return 'text-sky-400';
  return 'text-green-400';
}

export function TrafficLine({ item, className }: { item: TrafficSummary; className?: string }) {
  return (
    <div className={cn('flex min-w-0 items-center gap-2 text-xs font-mono', className)}>
      <span className="w-14 shrink-0 font-semibold">{item.method}</span>
      <span className={cn('w-10 shrink-0', statusTone(item.status_code))}>{item.status_code ?? '—'}</span>
      <span className="min-w-0 flex-1 truncate" title={item.url}>{item.url}</span>
      <Badge variant="outline" className="shrink-0 text-[10px]">{item.source}</Badge>
    </div>
  );
}

function headerText(headers: Record<string, string>) {
  return Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function prettyBody(body?: string | null) {
  if (!body) return '';
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function Pane({ title, head, body, truncated }: { title: string; head: string; body: string; truncated: boolean }) {
  return (
    <div className="min-w-0 space-y-1">
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-muted/30 p-2 text-xs">
        {head}
        {body ? `\n\n${body}` : ''}
        {truncated ? '\n\n… truncated at 256 KiB' : ''}
      </pre>
    </div>
  );
}

/** Lazily loads and renders one recorded request/response pair. */
export function TrafficExchangeView({ id }: { id: number }) {
  const [detail, setDetail] = useState<TrafficDetail | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setError('');
    api.getTrafficExchange(id)
      .then((d) => { if (!cancelled) setDetail(d); })
      .catch(() => { if (!cancelled) setError('Could not load this exchange.'); });
    return () => { cancelled = true; };
  }, [id]);

  if (error) return <p className="text-xs text-amber-500">{error}</p>;
  if (!detail) return <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />;

  const requestHead = `${detail.method} ${detail.path || detail.url}\n${headerText(detail.request_headers)}`;
  const responseHead = `HTTP ${detail.status_code ?? '—'}${detail.elapsed_ms != null ? `  (${detail.elapsed_ms} ms)` : ''}\n${headerText(detail.response_headers)}`;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>Host: {detail.host}</span>
        {detail.identity && <span>Identity: {detail.identity}</span>}
        {detail.session_id && <span>Session: {detail.session_id}</span>}
        {detail.page_url && <span className="truncate">Page: {detail.page_url}</span>}
        {detail.created_at && <span>{new Date(detail.created_at).toLocaleString()}</span>}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Pane title="Request" head={requestHead} body={prettyBody(detail.request_body)} truncated={detail.truncated.request_body} />
        <Pane title="Response" head={responseHead} body={prettyBody(detail.response_body)} truncated={detail.truncated.response_body} />
      </div>
      <p className="text-[11px] text-muted-foreground">Credentials, cookies and tokens are redacted before storage.</p>
    </div>
  );
}
