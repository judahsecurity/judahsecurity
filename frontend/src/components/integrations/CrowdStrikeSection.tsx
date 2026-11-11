'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  Loader2,
  Plus,
  RefreshCw,
  RotateCw,
  Settings2,
  ShieldCheck,
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
import {
  api,
  getApiErrorMessage,
  type CrowdStrikeIntegration,
  type FalconCloud,
} from '@/lib/api';

type CrowdStrikeForm = {
  connection_name: string;
  cloud: FalconCloud;
  client_id: string;
  client_secret: string;
  member_cid: string;
  asset_filter: string;
  import_assets: boolean;
  import_vulnerabilities: boolean;
  import_policies: boolean;
  internet_exposed_only: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

type BooleanKey = {
  [K in keyof CrowdStrikeForm]: CrowdStrikeForm[K] extends boolean ? K : never;
}[keyof CrowdStrikeForm];

const DEFAULT_FORM: CrowdStrikeForm = {
  connection_name: '',
  cloud: 'us-1',
  client_id: '',
  client_secret: '',
  member_cid: '',
  asset_filter: '',
  import_assets: true,
  import_vulnerabilities: true,
  import_policies: true,
  internet_exposed_only: true,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const CLOUDS: { value: FalconCloud; label: string }[] = [
  { value: 'us-1', label: 'US-1 (api.crowdstrike.com)' },
  { value: 'us-2', label: 'US-2' },
  { value: 'eu-1', label: 'EU-1' },
  { value: 'us-gov-1', label: 'US-GOV-1' },
  { value: 'us-gov-2', label: 'US-GOV-2' },
];

const INTERVALS = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

const OPTIONS: { id: string; title: string; description: string; key: BooleanKey }[] = [
  {
    id: 'cs-assets',
    title: 'Import external assets',
    description: 'Creates IP and domain assets with their exposed ports, services and Exposure Management metadata.',
    key: 'import_assets',
  },
  {
    id: 'cs-vulns',
    title: 'Import exposure paths',
    description:
      'Imports Spotlight CVEs (ExPRT, CISA KEV) on hosts behind internet-facing assets. Each finding can be revalidated from the internet.',
    key: 'import_vulnerabilities',
  },
  {
    id: 'cs-policies',
    title: 'Pull prevention policies',
    description:
      'Marks each host as blocking (prevent mode), detect-only, degraded, or unknown — the real mitigation on the path.',
    key: 'import_policies',
  },
  {
    id: 'cs-exposed',
    title: 'Internet-exposed assets only',
    description: 'Skips external assets that Falcon marks as not internet exposed or inactive.',
    key: 'internet_exposed_only',
  },
  {
    id: 'cs-sync',
    title: 'Automatically re-sync',
    description: 'Keeps CrowdStrike data current and closes findings Falcon no longer reports.',
    key: 'continuous_sync_enabled',
  },
];

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

function stat(item: CrowdStrikeIntegration, key: string): number {
  const value = item.last_sync_stats?.[key];
  return typeof value === 'number' ? value : 0;
}

export function CrowdStrikeSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<CrowdStrikeIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<CrowdStrikeIntegration | null>(null);
  const [form, setForm] = useState<CrowdStrikeForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CrowdStrikeIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getCrowdStrikeIntegrations());
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

  function openEdit(item: CrowdStrikeIntegration) {
    setEditing(item);
    setForm({
      connection_name: item.connection_name,
      cloud: item.cloud,
      client_id: '',
      client_secret: '',
      member_cid: item.member_cid || '',
      asset_filter: item.asset_filter || '',
      import_assets: item.import_assets,
      import_vulnerabilities: item.import_vulnerabilities,
      import_policies: item.import_policies,
      internet_exposed_only: item.internet_exposed_only,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function save() {
    if (!form.connection_name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.client_id.trim() || !form.client_secret.trim())) {
      toast({ title: 'Client ID and Client Secret are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        const { client_id, client_secret, ...rest } = form;
        await api.updateCrowdStrikeIntegration(editing.id, {
          ...rest,
          ...(client_id ? { client_id } : {}),
          ...(client_secret ? { client_secret } : {}),
        });
      } else {
        await api.createCrowdStrikeIntegration(form);
      }
      toast({ title: editing ? 'CrowdStrike connection updated.' : 'CrowdStrike connection added.' });
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save CrowdStrike connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: CrowdStrikeIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testCrowdStrikeConnection(item.id);
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

  async function sync(item: CrowdStrikeIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncCrowdStrikeIntegration(item.id);
      toast({
        title: result.ok ? 'CrowdStrike sync complete' : 'CrowdStrike sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'CrowdStrike sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
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
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-red-600/20 flex items-center justify-center shrink-0">
          <ShieldCheck className="w-5 h-5 text-red-400" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">CrowdStrike Falcon Exposure Management</CardTitle>
          <CardDescription>
            Import internet-facing assets, the CVEs on the hosts behind them, and whether each host&apos;s
            prevention policy is blocking or detect-only. Read-only.
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
                  <p className="text-xs text-muted-foreground truncate">
                    Falcon cloud {item.cloud}{item.member_cid ? ` · CID ${item.member_cid}` : ''}
                  </p>
                  <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                    <span>{item.internet_exposed_only ? 'Internet-exposed assets only' : 'All external assets'}</span>
                    <span>{item.import_policies ? 'Prevention posture on' : 'Prevention posture off'}</span>
                    <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                    {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                  </div>
                  {item.last_sync_stats && item.last_sync_ok && (
                    <div className="mt-2 space-y-1.5">
                      <p className="text-xs text-muted-foreground">
                        {stat(item, 'external_assets_seen')} external assets · {stat(item, 'exposure_paths')} exposure paths ·{' '}
                        {stat(item, 'assets_created')} new assets · {stat(item, 'vulns_created')} new findings
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30 text-xs">
                          {stat(item, 'hosts_prevent')} hosts blocking
                        </Badge>
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30 text-xs">
                          {stat(item, 'hosts_detect_only')} detect-only
                        </Badge>
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          {stat(item, 'hosts_unprotected')} unprotected / unknown
                        </Badge>
                      </div>
                    </div>
                  )}
                  {item.last_error && item.last_sync_ok !== false && (
                    <p className="text-xs text-amber-400 mt-1">{item.last_error}</p>
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
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add CID</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Create a Falcon API client with Read on Exposure Management, Vulnerabilities, Hosts and Prevention policies.
            </p>
            <Button onClick={openCreate}><ShieldCheck className="h-4 w-4 mr-2" />Connect CrowdStrike</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit CrowdStrike connection' : 'Connect CrowdStrike'}</DialogTitle>
            <DialogDescription>
              Credentials are validated before saving and encrypted at rest. The integration never writes to Falcon.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input value={form.connection_name} placeholder="e.g. Production CID" onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Falcon cloud</label>
              <Select value={form.cloud} onValueChange={(value) => setForm({ ...form, cloud: value as FalconCloud })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{CLOUDS.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent>
              </Select>
              <a href="https://falcon.crowdstrike.com/api-clients-and-keys/clients" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Create an API client in Falcon <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Client ID {editing && '(optional)'}</label>
                <Input type="password" value={form.client_id} placeholder={editing ? 'Leave blank to keep existing' : 'API client ID'} onChange={(event) => setForm({ ...form, client_id: event.target.value })} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Client Secret {editing && '(optional)'}</label>
                <Input type="password" value={form.client_secret} placeholder={editing ? 'Leave blank to keep existing' : 'API client secret'} onChange={(event) => setForm({ ...form, client_secret: event.target.value })} />
              </div>
            </div>
            <details className="rounded-lg border border-border p-3">
              <summary className="text-sm font-medium cursor-pointer">Advanced</summary>
              <div className="grid grid-cols-1 gap-3 mt-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">Member CID (Flight Control child tenant)</label>
                  <Input value={form.member_cid} placeholder="Optional" onChange={(event) => setForm({ ...form, member_cid: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium">External-asset FQL filter</label>
                  <Input value={form.asset_filter} placeholder="e.g. criticality:'Critical'" onChange={(event) => setForm({ ...form, asset_filter: event.target.value })} />
                </div>
              </div>
            </details>
            <div className="space-y-2">
              {OPTIONS.map(({ id, title, description, key }) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox id={id} checked={form[key]} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })} className="mt-0.5" />
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
            <DialogTitle>Remove CrowdStrike connection?</DialogTitle>
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
