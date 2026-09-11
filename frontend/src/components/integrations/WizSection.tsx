'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Cloud,
  Download,
  ExternalLink,
  Loader2,
  Plus,
  RefreshCw,
  RotateCw,
  Settings2,
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
import { api, getApiErrorMessage, type WizIntegration } from '@/lib/api';

type WizForm = {
  connection_name: string;
  api_endpoint: string;
  auth_url: string;
  audience: string;
  client_id: string;
  client_secret: string;
  import_assets: boolean;
  import_vulnerabilities: boolean;
  internet_exposed_only: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: WizForm = {
  connection_name: '',
  api_endpoint: '',
  auth_url: 'https://auth.app.wiz.io/oauth/token',
  audience: 'wiz-api',
  client_id: '',
  client_secret: '',
  import_assets: true,
  import_vulnerabilities: true,
  internet_exposed_only: true,
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

export function WizSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<WizIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<WizIntegration | null>(null);
  const [form, setForm] = useState<WizForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<WizIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getWizIntegrations());
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

  function openEdit(item: WizIntegration) {
    setEditing(item);
    setForm({
      connection_name: item.connection_name,
      api_endpoint: item.api_endpoint,
      auth_url: item.auth_url,
      audience: item.audience,
      client_id: '',
      client_secret: '',
      import_assets: item.import_assets,
      import_vulnerabilities: item.import_vulnerabilities,
      internet_exposed_only: item.internet_exposed_only,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function save() {
    if (!form.connection_name.trim() || !form.api_endpoint.trim()) {
      toast({ title: 'Connection name and API endpoint are required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.client_id.trim() || !form.client_secret.trim())) {
      toast({ title: 'Client ID and Client Secret are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateWizIntegration(editing.id, {
          connection_name: form.connection_name,
          api_endpoint: form.api_endpoint,
          auth_url: form.auth_url,
          audience: form.audience,
          ...(form.client_id ? { client_id: form.client_id } : {}),
          ...(form.client_secret ? { client_secret: form.client_secret } : {}),
          import_assets: form.import_assets,
          import_vulnerabilities: form.import_vulnerabilities,
          internet_exposed_only: form.internet_exposed_only,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
      } else {
        await api.createWizIntegration(form);
      }
      toast({ title: editing ? 'Wiz connection updated.' : 'Wiz connection added.' });
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save Wiz connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: WizIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testWizConnection(item.id);
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

  async function sync(item: WizIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncWizIntegration(item.id);
      toast({
        title: result.ok ? 'Wiz sync complete' : 'Wiz sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Wiz sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteWizIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Wiz connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove Wiz connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-violet-600/20 flex items-center justify-center shrink-0">
          <Cloud className="w-5 h-5 text-violet-400" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Wiz</CardTitle>
          <CardDescription>
            Import internet-exposed virtual machines and their vulnerability findings from Wiz. Read-only.
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
                  <p className="text-xs text-muted-foreground truncate">{item.api_endpoint}</p>
                  <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                    <span>{item.internet_exposed_only ? 'Internet-exposed VMs only' : 'All VMs'}</span>
                    <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                    {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                  </div>
                  {item.last_sync_stats && item.last_sync_ok && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.last_sync_stats.assets_created || 0} new assets, {item.last_sync_stats.vulns_created || 0} new findings.
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
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add tenant</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Use a read-only Custom Integration (GraphQL) service account with Read graph resources and Read vulnerabilities scopes.
            </p>
            <Button onClick={openCreate}><Cloud className="h-4 w-4 mr-2" />Connect Wiz</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Wiz connection' : 'Connect Wiz'}</DialogTitle>
            <DialogDescription>
              Credentials are validated before saving and encrypted at rest. The integration never writes to Wiz.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input value={form.connection_name} placeholder="e.g. Production" onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Wiz API endpoint</label>
              <Input value={form.api_endpoint} placeholder="https://api.us17.app.wiz.io/graphql" onChange={(event) => setForm({ ...form, api_endpoint: event.target.value })} />
              <a href="https://app.wiz.io/user/tenant" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Find it in Wiz Tenant Info <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Client ID {editing && '(optional)'}</label>
                <Input type="password" value={form.client_id} placeholder={editing ? 'Leave blank to keep existing' : 'Service account Client ID'} onChange={(event) => setForm({ ...form, client_id: event.target.value })} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Client Secret {editing && '(optional)'}</label>
                <Input type="password" value={form.client_secret} placeholder={editing ? 'Leave blank to keep existing' : 'Service account Client Secret'} onChange={(event) => setForm({ ...form, client_secret: event.target.value })} />
              </div>
            </div>
            <details className="rounded-lg border border-border p-3">
              <summary className="text-sm font-medium cursor-pointer">Advanced authentication</summary>
              <div className="grid grid-cols-1 gap-3 mt-3">
                <Input value={form.auth_url} aria-label="Authentication URL" onChange={(event) => setForm({ ...form, auth_url: event.target.value })} />
                <Input value={form.audience} aria-label="OAuth audience" onChange={(event) => setForm({ ...form, audience: event.target.value })} />
              </div>
            </details>
            <div className="space-y-2">
              {[
                ['wiz-assets', 'Import virtual-machine assets', 'Creates or enriches cloud-resource assets with OS, IP, provider, subscription, region, and Wiz metadata.', 'import_assets'],
                ['wiz-vulns', 'Import vulnerability findings', 'Maps CVEs, CVSS scores, severity, affected/fixed versions, and remediation guidance.', 'import_vulnerabilities'],
                ['wiz-exposed', 'Internet-exposed VMs only', 'Filters findings to assets marked by Wiz as having limited or wide internet exposure.', 'internet_exposed_only'],
                ['wiz-sync', 'Automatically re-sync', 'Keeps Wiz findings current in the background.', 'continuous_sync_enabled'],
              ].map(([id, title, description, key]) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox id={id} checked={Boolean(form[key as keyof WizForm])} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })} className="mt-0.5" />
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
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RotateCw className="h-4 w-4 mr-2" />}{editing ? 'Save changes' : 'Connect and validate'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove Wiz connection?</DialogTitle>
            <DialogDescription>Stored credentials will be deleted. Previously imported assets and findings are retained.</DialogDescription>
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
