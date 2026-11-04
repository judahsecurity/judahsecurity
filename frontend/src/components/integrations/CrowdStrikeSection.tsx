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
  ShieldHalf,
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
  type CrowdStrikeRegion,
} from '@/lib/api';

type CrowdStrikeForm = {
  connection_name: string;
  cloud_region: CrowdStrikeRegion;
  client_id: string;
  client_secret: string;
  import_hosts: boolean;
  import_spotlight: boolean;
  spotlight_filter_mode: 'prioritized' | 'all';
  extra_cve_ids: string;
  host_lookback_days: number;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: CrowdStrikeForm = {
  connection_name: '',
  cloud_region: 'us-1',
  client_id: '',
  client_secret: '',
  import_hosts: true,
  import_spotlight: true,
  spotlight_filter_mode: 'prioritized',
  extra_cve_ids: '',
  host_lookback_days: 7,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const REGIONS: { value: CrowdStrikeRegion; label: string }[] = [
  { value: 'us-1', label: 'us-1 — api.crowdstrike.com' },
  { value: 'us-2', label: 'us-2 — api.us-2.crowdstrike.com' },
  { value: 'eu-1', label: 'eu-1 — api.eu-1.crowdstrike.com' },
  { value: 'us-gov-1', label: 'us-gov-1 — api.laggar.gcw.crowdstrike.com' },
];

const INTERVALS = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

function parseCves(value: string): string[] {
  return value.split(/[\s,]+/).map((item) => item.trim().toUpperCase()).filter(Boolean);
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
      cloud_region: item.cloud_region,
      client_id: '',
      client_secret: '',
      import_hosts: item.import_hosts,
      import_spotlight: item.import_spotlight,
      spotlight_filter_mode: item.spotlight_filter_mode,
      extra_cve_ids: (item.extra_cve_ids || []).join(', '),
      host_lookback_days: item.host_lookback_days,
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
    if (!form.import_hosts && !form.import_spotlight) {
      toast({ title: 'Enable at least one module.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    const common = {
      connection_name: form.connection_name,
      cloud_region: form.cloud_region,
      import_hosts: form.import_hosts,
      import_spotlight: form.import_spotlight,
      spotlight_filter_mode: form.spotlight_filter_mode,
      extra_cve_ids: parseCves(form.extra_cve_ids),
      host_lookback_days: form.host_lookback_days,
      continuous_sync_enabled: form.continuous_sync_enabled,
      sync_interval_minutes: form.sync_interval_minutes,
    };
    try {
      if (editing) {
        await api.updateCrowdStrikeIntegration(editing.id, {
          ...common,
          ...(form.client_id ? { client_id: form.client_id } : {}),
          ...(form.client_secret ? { client_secret: form.client_secret } : {}),
        });
      } else {
        await api.createCrowdStrikeIntegration({ ...common, client_id: form.client_id, client_secret: form.client_secret });
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

  const toggles: [string, string, string, keyof CrowdStrikeForm][] = [
    ['cs-hosts', 'Hosts (endpoint inventory)', 'Maps Falcon devices seen recently into internal assets and the graph: agent, internal IP, NAT egress IP, AD domain, OU, and site. Requires Hosts: Read.', 'import_hosts'],
    ['cs-spotlight', 'Spotlight (vulnerabilities)', 'Imports open CVEs onto the matching hosts by agent ID. Requires Vulnerabilities: Read and Hosts: Read.', 'import_spotlight'],
    ['cs-sync', 'Automatically re-sync', 'Keeps hosts and findings current; closures in Falcon resolve findings here.', 'continuous_sync_enabled'],
  ];

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-red-600/20 flex items-center justify-center shrink-0">
          <ShieldHalf className="w-5 h-5 text-red-400" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">CrowdStrike Falcon</CardTitle>
          <CardDescription>
            Bring Falcon-managed endpoints and Spotlight CVEs into internal attack-path mapping. Read-only.
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
            {integrations.map((item) => {
              const stats = item.last_sync_stats || {};
              return (
                <div key={item.id} className="rounded-lg border border-border p-3 space-y-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-medium text-sm">{item.connection_name}</p>
                      <Badge variant="outline" className="text-xs">{item.cloud_region}</Badge>
                      {item.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Access issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                      <span>{[item.import_hosts && 'Hosts', item.import_spotlight && 'Spotlight'].filter(Boolean).join(' + ')}</span>
                      {item.import_spotlight && (
                        <span>{item.spotlight_filter_mode === 'all' ? 'All open CVEs' : 'ExPRT High/Critical (network), KEV, attack-chain CVEs'}</span>
                      )}
                      <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                      {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                    </div>
                    {item.last_sync_ok && item.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {(stats.assets_created || 0) + (stats.assets_updated || 0)} hosts mapped ({stats.assets_created || 0} new
                        {stats.hosts_skipped ? `, ${stats.hosts_skipped} skipped: missing hostname or local IP` : ''}),{' '}
                        {stats.vulns_created || 0} new findings
                        {stats.findings_uncorrelated ? `, ${stats.findings_uncorrelated} not matched to a host` : ''}.
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
              );
            })}
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add tenant</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Create a read-only Falcon API client with Hosts: Read and Vulnerabilities: Read scopes.
            </p>
            <Button onClick={openCreate}><ShieldHalf className="h-4 w-4 mr-2" />Connect CrowdStrike</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit CrowdStrike connection' : 'Connect CrowdStrike Falcon'}</DialogTitle>
            <DialogDescription>
              Access to each enabled module is validated before saving. Credentials are encrypted at rest; the integration never writes to Falcon.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input value={form.connection_name} placeholder="e.g. Corporate tenant" onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Cloud region</label>
              <Select value={form.cloud_region} onValueChange={(value) => setForm({ ...form, cloud_region: value as CrowdStrikeRegion })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{REGIONS.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent>
              </Select>
              <a href="https://falcon.crowdstrike.com/api-clients-and-keys/clients" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Support &amp; Resources → API Clients &amp; Keys <ExternalLink className="h-3 w-3" />
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
            <div className="space-y-2">
              {toggles.map(([id, title, description, key]) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox id={id} checked={Boolean(form[key])} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })} className="mt-0.5" />
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
            <details className="rounded-lg border border-border p-3">
              <summary className="text-sm font-medium cursor-pointer">Filtering</summary>
              <div className="space-y-3 mt-3">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Spotlight findings to import</label>
                  <Select value={form.spotlight_filter_mode} onValueChange={(value) => setForm({ ...form, spotlight_filter_mode: value as 'prioritized' | 'all' })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="prioritized">Prioritized: ExPRT High/Critical with network vector, CISA KEV, or listed CVEs</SelectItem>
                      <SelectItem value="all">All open CVEs</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Attack-chain CVEs (always imported)</label>
                  <Input value={form.extra_cve_ids} placeholder="CVE-2024-3400, CVE-2023-4966" onChange={(event) => setForm({ ...form, extra_cve_ids: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Host last-seen window (days)</label>
                  <Input type="number" min={1} max={90} value={form.host_lookback_days} onChange={(event) => setForm({ ...form, host_lookback_days: Math.min(90, Math.max(1, Number(event.target.value) || 7)) })} />
                </div>
              </div>
            </details>
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
            <DialogDescription>Stored credentials will be deleted. Previously imported hosts and findings are retained.</DialogDescription>
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
