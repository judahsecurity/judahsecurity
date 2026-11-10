'use client';

import { useEffect, useState } from 'react';
import { AlertCircle, CheckCircle2, Eye, Loader2, Play, Plus, Settings2, Table2, Trash2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  getApiErrorMessage,
  type WizCustomQuery,
  type WizCustomQueryRecord,
  type WizQueryPreview,
  type WizQueryTemplate,
} from '@/lib/api';

type QueryForm = {
  name: string;
  description: string;
  source: string;
  variables: string;
  connection_path: string;
  asset_host_field: string;
  page_size: number;
  max_pages: number;
  is_active: boolean;
};

const EMPTY_FORM: QueryForm = {
  name: '',
  description: '',
  source: '',
  variables: '{}',
  connection_path: '',
  asset_host_field: '',
  page_size: 100,
  max_pages: 50,
  is_active: true,
};

const PYTHON_SCRIPT = /^\s*QUERY\s*=/m;

function pretty(value: unknown) {
  return JSON.stringify(value ?? {}, null, 2);
}

export function WizCustomQueries({ integrationId, disabled }: { integrationId: number; disabled?: boolean }) {
  const { toast } = useToast();
  const [queries, setQueries] = useState<WizCustomQuery[]>([]);
  const [templates, setTemplates] = useState<WizQueryTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<WizCustomQuery | null>(null);
  const [form, setForm] = useState<QueryForm>(EMPTY_FORM);
  const [preview, setPreview] = useState<WizQueryPreview | null>(null);
  const [working, setWorking] = useState<'preview' | 'save' | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<WizCustomQuery | null>(null);
  const [recordsFor, setRecordsFor] = useState<WizCustomQuery | null>(null);
  const [records, setRecords] = useState<{ total: number; items: WizCustomQueryRecord[] } | null>(null);

  useEffect(() => { void load(); }, [integrationId]);

  async function load() {
    setLoading(true);
    try {
      setQueries(await api.getWizCustomQueries(integrationId));
    } catch {
      setQueries([]);
    } finally {
      setLoading(false);
    }
  }

  async function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setPreview(null);
    setEditorOpen(true);
    if (!templates.length) {
      try { setTemplates(await api.getWizQueryTemplates()); } catch { /* templates are optional */ }
    }
  }

  function openEdit(item: WizCustomQuery) {
    setEditing(item);
    setForm({
      name: item.name,
      description: item.description || '',
      source: item.query,
      variables: pretty(item.variables),
      connection_path: item.connection_path || '',
      asset_host_field: item.asset_host_field || '',
      page_size: item.page_size,
      max_pages: item.max_pages,
      is_active: item.is_active,
    });
    setPreview(null);
    setEditorOpen(true);
  }

  function applyTemplate(key: string) {
    const template = templates.find((item) => item.key === key);
    if (!template) return;
    setForm({
      ...form,
      name: form.name || template.name,
      description: template.description,
      source: template.query,
      variables: pretty(template.variables),
      connection_path: template.connection_path || '',
      asset_host_field: template.asset_host_field || '',
    });
    setPreview(null);
  }

  /** Resolve the editor into a query + variables, extracting from a pasted Wiz Python script if needed. */
  async function resolveSource(): Promise<{ query: string; variables: Record<string, unknown> } | null> {
    const source = form.source.trim();
    if (!source) {
      toast({ title: 'Paste a Wiz script or a GraphQL query first.', variant: 'destructive' });
      return null;
    }
    if (PYTHON_SCRIPT.test(source)) {
      const parsed = await api.parseWizQueryScript(source);
      setForm((current) => ({ ...current, source: parsed.query, variables: pretty(parsed.variables) }));
      return parsed;
    }
    let variables: Record<string, unknown>;
    try {
      const value = JSON.parse(form.variables.trim() || '{}');
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
      variables = value;
    } catch {
      toast({ title: 'Variables must be a JSON object.', variant: 'destructive' });
      return null;
    }
    return { query: source, variables };
  }

  async function runPreview() {
    setWorking('preview');
    try {
      const resolved = await resolveSource();
      if (!resolved) return;
      const result = await api.previewWizCustomQuery(integrationId, {
        ...resolved,
        connection_path: form.connection_path.trim() || null,
      });
      setPreview(result);
      if (result.ok && result.connection_path && !form.connection_path) {
        setForm((current) => ({ ...current, connection_path: result.connection_path || '' }));
      }
    } catch (error) {
      setPreview({ ok: false, message: getApiErrorMessage(error), rows: [], fields: [] });
    } finally {
      setWorking(null);
    }
  }

  async function save() {
    if (!form.name.trim()) {
      toast({ title: 'Give the query a name.', variant: 'destructive' });
      return;
    }
    setWorking('save');
    try {
      const resolved = await resolveSource();
      if (!resolved) return;
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        query: resolved.query,
        variables: resolved.variables,
        connection_path: form.connection_path.trim() || null,
        asset_host_field: form.asset_host_field.trim() || null,
        page_size: form.page_size,
        max_pages: form.max_pages,
        is_active: form.is_active,
      };
      if (editing) {
        await api.updateWizCustomQuery(integrationId, editing.id, payload);
      } else {
        await api.createWizCustomQuery(integrationId, payload);
      }
      toast({ title: editing ? 'Custom query updated.' : 'Custom query added. It runs with every Wiz sync.' });
      setEditorOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save custom query', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setWorking(null);
    }
  }

  async function run(item: WizCustomQuery) {
    setBusyId(item.id);
    try {
      const result = await api.runWizCustomQuery(integrationId, item.id);
      toast({
        title: result.ok ? 'Query complete' : 'Query failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Query failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function openRecords(item: WizCustomQuery) {
    setRecordsFor(item);
    setRecords(null);
    try {
      setRecords(await api.getWizCustomQueryRecords(integrationId, item.id, { limit: 200 }));
    } catch (error) {
      toast({ title: 'Could not load rows', description: getApiErrorMessage(error), variant: 'destructive' });
      setRecordsFor(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteWizCustomQuery(integrationId, deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Custom query removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove custom query', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  const isScript = PYTHON_SCRIPT.test(form.source);

  return (
    <div className="rounded-md border border-dashed border-border p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-sm font-medium">Custom queries</p>
          <p className="text-xs text-muted-foreground">
            Pull any Wiz table (application endpoints, attack-surface findings, issues) by pasting its &quot;Copy as Python&quot; script.
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add query</Button>
      </div>

      {loading ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : queries.length ? (
        <div className="space-y-2">
          {queries.map((item) => (
            <div key={item.id} className="rounded-md bg-muted/30 p-2 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium">{item.name}</p>
                {!item.is_active && <Badge variant="outline" className="text-xs text-muted-foreground">Paused</Badge>}
                {item.last_run_ok === true && (
                  <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/30">
                    <CheckCircle2 className="h-3 w-3 mr-1" />{item.record_count} rows
                  </Badge>
                )}
                {item.last_run_ok === false && (
                  <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                    <AlertCircle className="h-3 w-3 mr-1" />Failed
                  </Badge>
                )}
                {item.asset_host_field && <Badge variant="outline" className="text-xs">Imports assets from {item.asset_host_field}</Badge>}
              </div>
              <div className="flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                <span>{item.connection_path || 'Connection auto-detected on first run'}</span>
                {item.last_run_at && <span>Last run: {new Date(item.last_run_at).toLocaleString()}</span>}
                {item.last_run_ok && item.last_run_stats && (
                  <span>
                    {item.last_run_stats.records_created || 0} new, {item.last_run_stats.records_gone || 0} gone,{' '}
                    {item.last_run_stats.assets_created || 0} new assets
                  </span>
                )}
              </div>
              {item.last_error && <p className={`text-xs ${item.last_run_ok ? 'text-amber-400' : 'text-red-400'}`}>{item.last_error}</p>}
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => run(item)} disabled={disabled || busyId === item.id}>
                  {busyId === item.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}Run now
                </Button>
                <Button size="sm" variant="outline" onClick={() => openRecords(item)}><Table2 className="h-4 w-4 mr-2" />Rows</Button>
                <Button size="sm" variant="outline" onClick={() => openEdit(item)}><Settings2 className="h-4 w-4 mr-2" />Edit</Button>
                <Button size="sm" variant="outline" className="border-red-600/30 text-red-400" onClick={() => setDeleteTarget(item)}>
                  <Trash2 className="h-4 w-4 mr-2" />Remove
                </Button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">No custom queries yet.</p>
      )}

      <Dialog open={editorOpen} onOpenChange={(open) => { if (!working) setEditorOpen(open); }}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit custom query' : 'Add custom Wiz query'}</DialogTitle>
            <DialogDescription>
              In Wiz, open the table you want, then use its API / &quot;Copy as Python&quot; option and paste the whole script here.
              Only read queries are accepted; the script is parsed, never run, and its credentials are ignored. Results are paged
              automatically, so a copied cursor or page size does not matter.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {!editing && templates.length > 0 && (
              <Select onValueChange={applyTemplate}>
                <SelectTrigger><SelectValue placeholder="Start from a template (optional)" /></SelectTrigger>
                <SelectContent>
                  {templates.map((item) => <SelectItem key={item.key} value={item.key}>{item.name}</SelectItem>)}
                </SelectContent>
              </Select>
            )}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Name</label>
                <Input value={form.name} placeholder="e.g. Attack surface findings" onChange={(event) => setForm({ ...form, name: event.target.value })} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Description (optional)</label>
                <Input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Wiz Python script or GraphQL query</label>
              <Textarea
                className="font-mono text-xs min-h-[220px]"
                spellCheck={false}
                value={form.source}
                placeholder={'QUERY = """\n    query ApplicationEndpointsTable($first: Int, $after: String) { ... }\n"""\nVARIABLES = { ... }'}
                onChange={(event) => { setForm({ ...form, source: event.target.value }); setPreview(null); }}
              />
              {isScript && (
                <p className="text-xs text-muted-foreground">Python script detected: QUERY and VARIABLES will be extracted when you preview or save.</p>
              )}
            </div>
            {!isScript && (
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Variables (JSON)</label>
                <Textarea className="font-mono text-xs min-h-[100px]" spellCheck={false} value={form.variables} onChange={(event) => setForm({ ...form, variables: event.target.value })} />
              </div>
            )}
            <details className="rounded-lg border border-border p-3" open={Boolean(form.asset_host_field || preview?.fields.length)}>
              <summary className="text-sm font-medium cursor-pointer">Results and inventory</summary>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Result list path</label>
                  <Input value={form.connection_path} placeholder="Auto-detect, e.g. applicationEndpoints" onChange={(event) => setForm({ ...form, connection_path: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Import hostname/URL field as assets</label>
                  <Input value={form.asset_host_field} placeholder="e.g. host (blank = store rows only)" list={`wiz-fields-${integrationId}`} onChange={(event) => setForm({ ...form, asset_host_field: event.target.value })} />
                  <datalist id={`wiz-fields-${integrationId}`}>
                    {(preview?.fields || []).map((field) => <option key={field} value={field} />)}
                  </datalist>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Rows per page</label>
                  <Input type="number" min={1} max={500} value={form.page_size} onChange={(event) => setForm({ ...form, page_size: Number(event.target.value) || 100 })} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Max pages per run</label>
                  <Input type="number" min={1} max={1000} value={form.max_pages} onChange={(event) => setForm({ ...form, max_pages: Number(event.target.value) || 50 })} />
                </div>
              </div>
              <div className="flex items-center gap-2 mt-3">
                <Checkbox id={`wiz-cq-active-${integrationId}`} checked={form.is_active} onCheckedChange={(checked) => setForm({ ...form, is_active: Boolean(checked) })} />
                <label htmlFor={`wiz-cq-active-${integrationId}`} className="text-sm cursor-pointer">Run with every Wiz sync</label>
              </div>
            </details>
            {preview && (
              <div className={`rounded-lg border p-3 space-y-2 ${preview.ok ? 'border-green-500/30' : 'border-red-500/30'}`}>
                <p className={`text-sm ${preview.ok ? 'text-green-400' : 'text-red-400'}`}>{preview.message}</p>
                {preview.ok && preview.fields.length > 0 && (
                  <p className="text-xs text-muted-foreground">Fields: {preview.fields.join(', ')}</p>
                )}
                {preview.ok && preview.rows[0] && (
                  <pre className="text-xs bg-muted/40 rounded p-2 max-h-60 overflow-auto">{pretty(preview.rows[0])}</pre>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditorOpen(false)} disabled={Boolean(working)}>Cancel</Button>
            <Button variant="outline" onClick={runPreview} disabled={Boolean(working)}>
              {working === 'preview' ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Eye className="h-4 w-4 mr-2" />}Preview
            </Button>
            <Button onClick={save} disabled={Boolean(working)}>
              {working === 'save' && <Loader2 className="h-4 w-4 animate-spin mr-2" />}{editing ? 'Save changes' : 'Save query'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(recordsFor)} onOpenChange={(open) => { if (!open) setRecordsFor(null); }}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{recordsFor?.name}</DialogTitle>
            <DialogDescription>
              {records ? `${records.total} row(s) currently returned by Wiz${records.total > records.items.length ? `; showing the first ${records.items.length}` : ''}.` : 'Loading rows...'}
            </DialogDescription>
          </DialogHeader>
          {!records ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : (
            <div className="space-y-2">
              {records.items.map((record) => (
                <details key={record.id} className="rounded border border-border p-2">
                  <summary className="text-xs cursor-pointer font-mono truncate">
                    {String(record.data.name ?? record.data.host ?? record.external_id)}
                    {record.asset_id ? ' · asset linked' : ''}
                  </summary>
                  <pre className="text-xs bg-muted/40 rounded p-2 mt-2 max-h-72 overflow-auto">{pretty(record.data)}</pre>
                </details>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove custom query?</DialogTitle>
            <DialogDescription>Its stored rows are deleted. Assets it imported are kept.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={remove} disabled={busyId === deleteTarget?.id}>Remove</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
