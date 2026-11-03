'use client';

import { useEffect, useState } from 'react';
import { AlertCircle, CheckCircle2, Download, Loader2, Plus, RefreshCw, Settings2, Trash2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage, type CrowdStrikeIntegration } from '@/lib/api';

type CrowdStrikeForm = {
  connection_name: string;
  cloud_region: CrowdStrikeIntegration['cloud_region'];
  client_id: string;
  client_secret: string;
  import_external_assets: boolean;
  import_hosts: boolean;
  import_spotlight: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: CrowdStrikeForm = {
  connection_name: '', cloud_region: 'us-1', client_id: '', client_secret: '',
  import_external_assets: true, import_hosts: true, import_spotlight: true,
  continuous_sync_enabled: true, sync_interval_minutes: 1440,
};

export function CrowdStrikeSection() {
  const { toast } = useToast();
  const [connections, setConnections] = useState<CrowdStrikeIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<CrowdStrikeIntegration | null>(null);
  const [form, setForm] = useState<CrowdStrikeForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CrowdStrikeIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try { setConnections(await api.getCrowdStrikeIntegrations()); }
    catch { setConnections([]); }
    finally { setLoading(false); }
  }

  function edit(item: CrowdStrikeIntegration | null) {
    setEditing(item);
    setForm(item ? {
      connection_name: item.connection_name, cloud_region: item.cloud_region,
      client_id: '', client_secret: '', import_external_assets: item.import_external_assets,
      import_hosts: item.import_hosts, import_spotlight: item.import_spotlight,
      continuous_sync_enabled: item.continuous_sync_enabled, sync_interval_minutes: item.sync_interval_minutes,
    } : DEFAULT_FORM);
    setOpen(true);
  }

  async function save() {
    if (!form.connection_name.trim() || (!editing && (!form.client_id.trim() || !form.client_secret.trim()))) {
      toast({ title: 'Connection name and API credentials are required.', variant: 'destructive' }); return;
    }
    if (!form.import_external_assets && !form.import_hosts && !form.import_spotlight) {
      toast({ title: 'Enable at least one module.', variant: 'destructive' }); return;
    }
    if (form.import_spotlight && !form.import_hosts) {
      toast({ title: 'Spotlight requires Hosts for asset correlation.', variant: 'destructive' }); return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateCrowdStrikeIntegration(editing.id, {
          ...form, ...(form.client_id ? { client_id: form.client_id } : {}),
          ...(form.client_secret ? { client_secret: form.client_secret } : {}),
          client_id: form.client_id || undefined, client_secret: form.client_secret || undefined,
        });
      } else {
        await api.createCrowdStrikeIntegration(form);
      }
      toast({ title: editing ? 'CrowdStrike connection updated.' : 'CrowdStrike connection added.' });
      setOpen(false); await load();
    } catch (error) {
      toast({ title: 'Could not save CrowdStrike connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setSaving(false); }
  }

  async function run(item: CrowdStrikeIntegration, kind: 'test' | 'sync') {
    setBusyId(item.id);
    try {
      const result = kind === 'test' ? await api.testCrowdStrikeIntegration(item.id) : await api.syncCrowdStrikeIntegration(item.id);
      toast({ title: result.ok ? `CrowdStrike ${kind} complete` : `CrowdStrike ${kind} failed`, description: result.message, variant: result.ok ? undefined : 'destructive' });
      await load();
    } catch (error) {
      toast({ title: `CrowdStrike ${kind} failed`, description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteCrowdStrikeIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'CrowdStrike connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove CrowdStrike connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">CrowdStrike Falcon Exposure Management</CardTitle>
          <CardDescription>Import external assets, Falcon hosts, exposed services, and Spotlight CVEs for Judah analysis.</CardDescription>
        </div>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : connections.length ? (
          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />{connections.length} connected</Badge>
        ) : <Badge variant="outline">Not configured</Badge>}
      </CardHeader>
      <CardContent className="space-y-3">
        {connections.map((item) => (
          <div key={item.id} className="rounded-lg border border-border p-3 space-y-2">
            <div className="flex items-center gap-2">
              <p className="font-medium text-sm">{item.connection_name} · {item.cloud_region}</p>
              {item.last_test_ok === false && <Badge variant="outline" className="text-red-400"><AlertCircle className="h-3 w-3 mr-1" />Access issue</Badge>}
            </div>
            <p className="text-xs text-muted-foreground">
              {[item.import_external_assets && 'External assets', item.import_hosts && 'Hosts', item.import_spotlight && 'Spotlight'].filter(Boolean).join(' · ')}
              {item.last_sync_at && ` · Last sync ${new Date(item.last_sync_at).toLocaleString()}`}
            </p>
            {item.last_sync_ok && item.last_sync_stats && <p className="text-xs text-muted-foreground">{item.last_sync_stats.assets_created || 0} new assets · {item.last_sync_stats.vulns_created || 0} new CVEs</p>}
            {item.last_error && !item.last_sync_ok && <p className="text-xs text-red-400">{item.last_error}</p>}
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={busyId === item.id || !item.is_active} onClick={() => void run(item, 'sync')}><Download className="h-4 w-4 mr-2" />Sync now</Button>
              <Button size="sm" variant="outline" disabled={busyId === item.id} onClick={() => void run(item, 'test')}><RefreshCw className="h-4 w-4 mr-2" />Test</Button>
              <Button size="sm" variant="outline" onClick={() => edit(item)}><Settings2 className="h-4 w-4 mr-2" />Edit</Button>
              <Button size="sm" variant="outline" className="text-red-400" onClick={() => setDeleteTarget(item)}><Trash2 className="h-4 w-4 mr-2" />Remove</Button>
            </div>
          </div>
        ))}
        <Button size="sm" onClick={() => edit(null)}><Plus className="h-4 w-4 mr-2" />Connect CrowdStrike</Button>
        <p className="text-xs text-muted-foreground">Imported assets start outside scan scope. Review ownership and scope before running Judah validation. Falcon attack-path visualization is not available through the documented Exposure Management asset API.</p>
      </CardContent>

      <Dialog open={open} onOpenChange={(value) => { if (!saving) setOpen(value); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit CrowdStrike connection' : 'Connect CrowdStrike'}</DialogTitle>
            <DialogDescription>Use a dedicated API client with Assets: Read, Hosts: Read, and/or Vulnerabilities: Read for the modules you enable.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <Input aria-label="Connection name" placeholder="Connection name" value={form.connection_name} onChange={(e) => setForm({ ...form, connection_name: e.target.value })} />
            <Select value={form.cloud_region} onValueChange={(cloud_region) => setForm({ ...form, cloud_region: cloud_region as CrowdStrikeForm['cloud_region'] })}>
              <SelectTrigger aria-label="Falcon cloud region"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="us-1">US 1</SelectItem><SelectItem value="us-2">US 2</SelectItem>
                <SelectItem value="eu-1">EU 1</SelectItem><SelectItem value="us-gov-1">US Gov 1</SelectItem>
              </SelectContent>
            </Select>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Input aria-label="Client ID" type="password" placeholder={editing ? 'Client ID (leave blank to keep)' : 'Client ID'} value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
              <Input aria-label="Client Secret" type="password" placeholder={editing ? 'Client Secret (leave blank to keep)' : 'Client Secret'} value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
            </div>
            {([
              ['import_external_assets', 'External assets and services'],
              ['import_hosts', 'Falcon managed hosts'],
              ['import_spotlight', 'Spotlight vulnerability findings'],
              ['continuous_sync_enabled', 'Automatically re-sync'],
            ] as const).map(([key, label]) => (
              <div key={key} className="flex items-center gap-3">
                <Checkbox id={`cs-${key}`} checked={form[key]} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked), ...(key === 'import_hosts' && !checked ? { import_spotlight: false } : {}), ...(key === 'import_spotlight' && checked ? { import_hosts: true } : {}) })} />
                <label htmlFor={`cs-${key}`} className="text-sm cursor-pointer">{label}</label>
              </div>
            ))}
            {form.continuous_sync_enabled && <Select value={String(form.sync_interval_minutes)} onValueChange={(value) => setForm({ ...form, sync_interval_minutes: Number(value) })}>
              <SelectTrigger aria-label="Sync interval"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="60">Hourly</SelectItem><SelectItem value="360">Every 6 hours</SelectItem><SelectItem value="1440">Daily</SelectItem></SelectContent>
            </Select>}
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>Cancel</Button><Button onClick={() => void save()} disabled={saving}>{saving && <Loader2 className="h-4 w-4 animate-spin mr-2" />}{editing ? 'Save changes' : 'Connect and validate'}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(value) => { if (!value) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm"><DialogHeader><DialogTitle>Remove CrowdStrike connection?</DialogTitle><DialogDescription>Stored credentials and source links are deleted. Imported assets and findings are retained.</DialogDescription></DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button><Button variant="destructive" disabled={busyId === deleteTarget?.id} onClick={() => void remove()}>Remove</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
