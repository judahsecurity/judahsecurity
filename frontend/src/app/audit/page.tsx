'use client';

import { Fragment, useCallback, useEffect, useState } from 'react';
import { Download, Loader2, RefreshCw } from 'lucide-react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { api, getApiErrorMessage, type AuditLogEntry } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

const PAGE = 50;
const ACTIONS = ['all', 'auth.*', 'user.*', 'settings.*', 'agent.*', 'report.*', 'mcp.*', 'notifications.*', 'audit.*'];

const outcomeVariant = (outcome: string) =>
  outcome === 'success' ? 'secondary' : outcome === 'denied' ? 'destructive' : 'outline';

export default function AuditPage() {
  const { toast } = useToast();
  const [items, setItems] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState('all');
  const [outcome, setOutcome] = useState('all');
  const [actor, setActor] = useState('');
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);

  const filters = useCallback(() => ({
    action: action === 'all' ? undefined : action,
    outcome: outcome === 'all' ? undefined : outcome,
    actor: actor.trim() || undefined,
  }), [action, outcome, actor]);

  const load = useCallback(async (nextOffset = 0) => {
    setLoading(true);
    try {
      const data = await api.getAuditLogs({ ...filters(), limit: PAGE, offset: nextOffset });
      setItems(data.items);
      setTotal(data.total);
      setOffset(nextOffset);
    } catch (error) {
      toast({ title: 'Could not load audit log', description: getApiErrorMessage(error, 'Admin access required'), variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [filters, toast]);

  useEffect(() => { load(0); }, [action, outcome]); // eslint-disable-line react-hooks/exhaustive-deps

  const exportCsv = async () => {
    try {
      const data = await api.exportAuditLogs(filters());
      const url = window.URL.createObjectURL(new Blob([data], { type: 'text/csv' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit_log.csv';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      toast({ title: 'Export failed', description: getApiErrorMessage(error, 'Export failed'), variant: 'destructive' });
    }
  };

  return (
    <MainLayout>
      <Header title="Audit Log" subtitle="Who signed in, changed settings, approved tool calls, exported reports or managed users" />
      <div className="p-6 space-y-4">
        <div className="flex flex-wrap gap-2 items-center">
          <Select value={action} onValueChange={setAction}>
            <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
            <SelectContent>
              {ACTIONS.map((a) => <SelectItem key={a} value={a}>{a === 'all' ? 'All actions' : a}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={outcome} onValueChange={setOutcome}>
            <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['all', 'success', 'denied', 'failed'].map((o) => (
                <SelectItem key={o} value={o}>{o === 'all' ? 'All outcomes' : o}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input className="w-56" placeholder="Actor contains…" value={actor}
                 onChange={(e) => setActor(e.target.value)}
                 onKeyDown={(e) => { if (e.key === 'Enter') load(0); }} />
          <Button variant="outline" onClick={() => load(0)} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Refresh
          </Button>
          <Button variant="outline" onClick={exportCsv}>
            <Download className="h-4 w-4 mr-2" /> Export CSV
          </Button>
          <span className="text-sm text-muted-foreground ml-auto">{total} events</span>
        </div>
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time (UTC)</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((e) => (
                  <Fragment key={e.id}>
                    <TableRow className="cursor-pointer" onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <TableCell className="whitespace-nowrap font-mono text-xs">{e.created_at.replace('T', ' ').slice(0, 19)}</TableCell>
                      <TableCell>{e.actor || '—'}</TableCell>
                      <TableCell className="font-mono text-xs">{e.action}</TableCell>
                      <TableCell className="max-w-xs truncate" title={e.target}>{e.target || '—'}</TableCell>
                      <TableCell><Badge variant={outcomeVariant(e.outcome)}>{e.outcome}</Badge></TableCell>
                      <TableCell className="font-mono text-xs">{e.ip || '—'}</TableCell>
                    </TableRow>
                    {expanded === e.id && (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <pre className="text-xs whitespace-pre-wrap break-all bg-muted/40 rounded p-2">
                            {JSON.stringify(e.detail, null, 2)}
                          </pre>
                          {e.user_agent && <p className="text-xs text-muted-foreground mt-1">{e.user_agent}</p>}
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
                {!items.length && !loading && (
                  <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-8">No audit events match these filters.</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <div className="flex gap-2 justify-end">
          <Button variant="outline" disabled={offset === 0 || loading} onClick={() => load(Math.max(0, offset - PAGE))}>Previous</Button>
          <Button variant="outline" disabled={offset + PAGE >= total || loading} onClick={() => load(offset + PAGE)}>Next</Button>
        </div>
      </div>
    </MainLayout>
  );
}
