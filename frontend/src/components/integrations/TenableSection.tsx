'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Loader2,
  Plus,
  RefreshCw,
  RotateCw,
  Settings2,
  ShieldAlert,
  Trash2,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage, type TenableIntegration } from '@/lib/api';

type TenableForm = {
  connection_name: string;
  base_url: string;
  access_key: string;
  secret_key: string;
  import_assets: boolean;
  import_vulnerabilities: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: TenableForm = {
  connection_name: 'Tenable VM',
  base_url: 'https://cloud.tenable.com',
  access_key: '',
  secret_key: '',
  import_assets: true,
  import_vulnerabilities: true,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const INTERVALS = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

export function TenableSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<TenableIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<TenableIntegration | null>(null);
  const [form, setForm] = useState<TenableForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TenableIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getTenableIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(DEFAULT_FORM);
    setSetupOpen(true);
  }

  function openEdit(item: TenableIntegration) {
    setEditing(item);
    setForm({
      connection_name: item.connection_name,
      base_url: item.base_url,
      access_key: '',
      secret_key: '',
      import_assets: item.import_assets,
      import_vulnerabilities: item.import_vulnerabilities,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function save() {
    if (!form.connection_name.trim() || !form.base_url.trim()) {
      toast({ title: 'Connection name and Tenable VM URL are required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.access_key.trim() || !form.secret_key.trim())) {
      toast({ title: 'Access Key and Secret Key are required.', variant: 'destructive' });
      return;
    }
    if (!form.import_assets && !form.import_vulnerabilities) {
      toast({ title: 'Choose at least one thing to import.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateTenableIntegration(editing.id, {
          connection_name: form.connection_name,
          base_url: form.base_url,
          ...(form.access_key ? { access_key: form.access_key } : {}),
          ...(form.secret_key ? { secret_key: form.secret_key } : {}),
          import_assets: form.import_assets,
          import_vulnerabilities: form.import_vulnerabilities,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
      } else {
        await api.createTenableIntegration(form);
      }
      toast({ title: editing ? 'Tenable VM connection updated.' : 'Tenable VM connected.' });
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save Tenable VM connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: TenableIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testTenableConnection(item.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Connection test failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function sync(item: TenableIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncTenableIntegration(item.id);
      toast({
        title: result.ok ? 'Tenable VM sync complete' : 'Tenable VM sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Tenable VM sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteTenableIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Tenable VM connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove Tenable VM connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-sky-600/20 flex items-center justify-center shrink-0">
          <ShieldAlert className="w-5 h-5 text-sky-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <CardTitle className="text-base">Tenable VM</CardTitle>
            <Badge variant="outline" className="text-xs text-muted-foreground">Vulnerability Management</Badge>
          </div>
          <CardDescription>
            Import assets and open vulnerabilities from Tenable Vulnerability Management, rated by CVSS. Read-only.
          </CardDescription>
        </div>
        {loading ? (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        ) : integrations.length ? (
          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
            <CheckCircle2 className="h-3 w-3 mr-1" />{integrations.length} connected
          </Badge>
        ) : (
          <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {integrations.length ? (
          <div className="space-y-3">
            {integrations.map((item) => (
              <div key={item.id} className="rounded-lg border border-border p-3 space-y-3">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-sm">{item.connection_name}</p>
                    {item.last_test_ok === false && (
                      <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                        <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground truncate">{item.base_url}</p>
                  <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                    <span>
                      {[item.import_assets && 'Assets', item.import_vulnerabilities && 'Vulnerabilities'].filter(Boolean).join(' + ')}
                    </span>
                    <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                    {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                  </div>
                  {item.last_sync_stats && item.last_sync_ok && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.last_sync_stats.assets_created || 0} new assets, {item.last_sync_stats.vulns_created || 0} new findings,{' '}
                      {item.last_sync_stats.assets_skipped || 0} private/internal/cloud assets skipped.
                    </p>
                  )}
                  {item.last_error && item.last_sync_ok === false && (
                    <p className="text-xs text-red-400 mt-1">{item.last_error}</p>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={() => sync(item)} disabled={busyId === item.id || !item.is_active}>
                    {busyId === item.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}Sync now
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => test(item)} disabled={busyId === item.id}>
                    <RefreshCw className="h-4 w-4 mr-2" />Test
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openEdit(item)}>
                    <Settings2 className="h-4 w-4 mr-2" />Edit
                  </Button>
                  <Button size="sm" variant="outline" className="border-red-600/30 text-red-400" onClick={() => setDeleteTarget(item)}>
                    <Trash2 className="h-4 w-4 mr-2" />Remove
                  </Button>
                </div>
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add connection</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Use a Standard User service account with API Key Authentication and the <span className="font-medium">Can View</span> permission on <span className="font-medium">All Assets</span>.
            </p>
            <Button onClick={openCreate}><ShieldAlert className="h-4 w-4 mr-2" />Integrate</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Tenable VM connection' : 'Connect Tenable VM'}</DialogTitle>
            <DialogDescription>
              Keys are checked by requesting an asset export and a vulnerability export, then encrypted at rest. The integration never writes to Tenable.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input value={form.connection_name} onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Tenable VM URL</label>
              <Input value={form.base_url} placeholder="https://cloud.tenable.com" onChange={(event) => setForm({ ...form, base_url: event.target.value })} />
              <p className="text-xs text-muted-foreground">Use https://fedcloud.tenable.com for FedRAMP tenants.</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Access Key {editing && '(optional)'}</label>
                <Input type="password" autoComplete="off" value={form.access_key} placeholder={editing ? 'Leave blank to keep existing' : 'Service account Access Key'} onChange={(event) => setForm({ ...form, access_key: event.target.value })} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Secret Key {editing && '(optional)'}</label>
                <Input type="password" autoComplete="off" value={form.secret_key} placeholder={editing ? 'Leave blank to keep existing' : 'Service account Secret Key'} onChange={(event) => setForm({ ...form, secret_key: event.target.value })} />
              </div>
            </div>
            <div className="space-y-2">
              {[
                ['tenable-assets', 'Import Assets', 'Imports external assets Tenable assessed in the last 30 days, named by FQDN or IPv4. Private, internal, and cloud-provider addresses are skipped.', 'import_assets'],
                ['tenable-vulns', 'Import Vulnerabilities', 'Imports open and reopened Low–Critical findings from the last 30 days, and their associated assets, rated by CVSSv3.', 'import_vulnerabilities'],
                ['tenable-sync', 'Automatically re-sync', 'Keeps Tenable assets and findings current in the background.', 'continuous_sync_enabled'],
              ].map(([id, title, description, key]) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox id={id} checked={Boolean(form[key as keyof TenableForm])} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })} className="mt-0.5" />
                  <label htmlFor={id} className="text-sm cursor-pointer">
                    <span className="font-medium">{title}</span>
                    <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
                  </label>
                </div>
              ))}
              {form.continuous_sync_enabled && (
                <Select value={String(form.sync_interval_minutes)} onValueChange={(value) => setForm({ ...form, sync_interval_minutes: Number(value) })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{INTERVALS.map((item) => <SelectItem key={item.value} value={String(item.value)}>{item.label}</SelectItem>)}</SelectContent>
                </Select>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={save} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RotateCw className="h-4 w-4 mr-2" />}{editing ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove Tenable VM connection?</DialogTitle>
            <DialogDescription>Stored API keys will be deleted. Previously imported assets and findings are retained.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={remove} disabled={busyId === deleteTarget?.id}>Remove</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
