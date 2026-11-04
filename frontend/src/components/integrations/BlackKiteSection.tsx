'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Gauge,
  Loader2,
  RefreshCw,
  RotateCw,
  Settings2,
  Unplug,
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
import { api, getApiErrorMessage, type BlackKiteIntegration } from '@/lib/api';

type BlackKiteForm = {
  client_id: string;
  client_secret: string;
  ecosystem_names: string;
  company_domains: string;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: BlackKiteForm = {
  client_id: '',
  client_secret: '',
  ecosystem_names: '',
  company_domains: '',
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const INTERVALS = [
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
  { value: 10080, label: 'Every 7 days' },
];

function splitList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

export function BlackKiteSection() {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<BlackKiteIntegration | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<BlackKiteForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [disconnectOpen, setDisconnectOpen] = useState(false);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const items = await api.getBlackKiteIntegrations();
      setIntegration(items[0] ?? null);
    } catch {
      setIntegration(null);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(false);
    setForm(DEFAULT_FORM);
    setSetupOpen(true);
  }

  function openEdit() {
    if (!integration) return;
    setEditing(true);
    setForm({
      client_id: '',
      client_secret: '',
      ecosystem_names: integration.ecosystem_names.join(', '),
      company_domains: integration.company_domains.join(', '),
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function save() {
    const ecosystem_names = splitList(form.ecosystem_names);
    const company_domains = splitList(form.company_domains);
    if (!ecosystem_names.length && !company_domains.length) {
      toast({ title: 'Enter at least one ecosystem name or company domain.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.client_id.trim() || !form.client_secret.trim())) {
      toast({ title: 'Client ID and Client Secret are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      const common = {
        ecosystem_names,
        company_domains,
        continuous_sync_enabled: form.continuous_sync_enabled,
        sync_interval_minutes: form.sync_interval_minutes,
      };
      if (editing && integration) {
        await api.updateBlackKiteIntegration(integration.id, {
          ...common,
          ...(form.client_id ? { client_id: form.client_id } : {}),
          ...(form.client_secret ? { client_secret: form.client_secret } : {}),
        });
        toast({ title: 'Black Kite connection updated.' });
      } else {
        await api.createBlackKiteIntegration({
          ...common,
          client_id: form.client_id,
          client_secret: form.client_secret,
        });
        toast({ title: 'Black Kite connected.', description: 'The initial import has started.' });
      }
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save Black Kite connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    if (!integration) return;
    setBusy(true);
    try {
      const result = await api.testBlackKiteConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Connection test failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  }

  async function sync() {
    if (!integration) return;
    setBusy(true);
    try {
      const result = await api.syncBlackKiteIntegration(integration.id);
      toast({
        title: result.ok ? 'Black Kite sync complete' : 'Black Kite sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Black Kite sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    if (!integration) return;
    setBusy(true);
    try {
      await api.deleteBlackKiteIntegration(integration.id);
      setDisconnectOpen(false);
      toast({ title: 'Black Kite disconnected.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not disconnect Black Kite', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  }

  const stats = integration?.last_sync_stats;

  return (
    <Card className="border border-border" id="black-kite">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-slate-500/20 flex items-center justify-center shrink-0">
          <Gauge className="w-5 h-5 text-slate-300" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Black Kite</CardTitle>
          <CardDescription>
            Import your own companies&apos; active subdomains, vulnerability findings and fraudulent domains. Monitored third parties are not imported.
          </CardDescription>
        </div>
        {loading ? (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        ) : integration ? (
          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
            <CheckCircle2 className="h-3 w-3 mr-1" />Connected
          </Badge>
        ) : (
          <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {integration ? (
          <div className="space-y-3">
            <div className="space-y-1 text-xs text-muted-foreground">
              {integration.last_test_ok === false && (
                <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                  <AlertCircle className="h-3 w-3 mr-1" />Auth or scope issue
                </Badge>
              )}
              {integration.ecosystem_names.length > 0 && (
                <p>Ecosystems: <span className="text-foreground">{integration.ecosystem_names.join(', ')}</span></p>
              )}
              {integration.company_domains.length > 0 && (
                <p>Company domains: <span className="text-foreground">{integration.company_domains.join(', ')}</span></p>
              )}
              <p>
                In scope: {integration.matched_companies.length
                  ? integration.matched_companies.map((c) => c.name || c.domain || c.id).join(', ')
                  : 'no companies resolved yet'}
              </p>
              <div className="flex flex-wrap gap-x-3">
                <span>{integration.continuous_sync_enabled ? `Auto-sync ${intervalLabel(integration.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                {integration.last_sync_at && <span>Last sync: {new Date(integration.last_sync_at).toLocaleString()}</span>}
              </div>
              {stats && integration.last_sync_ok && (
                <p>
                  {stats.assets_created || 0} new assets, {stats.vulns_created || 0} new risks,{' '}
                  {stats.vulns_resolved || 0} resolved across {stats.companies_synced || 0} company(ies).
                </p>
              )}
              {integration.last_error && integration.last_sync_ok === false && (
                <p className="text-red-400">{integration.last_error}</p>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" onClick={sync} disabled={busy || !integration.is_active}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}Sync now
              </Button>
              <Button size="sm" variant="outline" onClick={test} disabled={busy}>
                <RefreshCw className="h-4 w-4 mr-2" />Test
              </Button>
              <Button size="sm" variant="outline" onClick={openEdit}>
                <Settings2 className="h-4 w-4 mr-2" />Edit
              </Button>
              <Button size="sm" variant="outline" className="border-red-600/30 text-red-400" onClick={() => setDisconnectOpen(true)}>
                <Unplug className="h-4 w-4 mr-2" />Disconnect
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Generate an OAuth2 client in Black Kite under Integrations &gt; Black Kite API, scoped to the tenant you want to import.
            </p>
            <Button onClick={openCreate} disabled={loading}><Gauge className="h-4 w-4 mr-2" />Connect Black Kite</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Black Kite connection' : 'Connect Black Kite'}</DialogTitle>
            <DialogDescription>
              Credentials are validated, and your ecosystem names or company domains must match at least one company in the tenant. Credentials are encrypted at rest; the integration never writes to Black Kite.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium" htmlFor="bk-client-id">Client ID {editing && '(optional)'}</label>
                <Input id="bk-client-id" type="password" autoComplete="off" value={form.client_id} placeholder={editing ? 'Leave blank to keep existing' : 'OAuth2 Client ID'} onChange={(event) => setForm({ ...form, client_id: event.target.value })} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium" htmlFor="bk-client-secret">Client Secret {editing && '(optional)'}</label>
                <Input id="bk-client-secret" type="password" autoComplete="off" value={form.client_secret} placeholder={editing ? 'Leave blank to keep existing' : 'OAuth2 Client Secret'} onChange={(event) => setForm({ ...form, client_secret: event.target.value })} />
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="bk-ecosystems">Ecosystem Name(s)</label>
              <Input id="bk-ecosystems" value={form.ecosystem_names} placeholder="e.g. Our Enterprise" onChange={(event) => setForm({ ...form, ecosystem_names: event.target.value })} />
              <p className="text-xs text-muted-foreground">Comma-separated. The Black Kite ecosystem(s) that group your own companies.</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="bk-domains">Company Domains</label>
              <Input id="bk-domains" value={form.company_domains} placeholder="e.g. example.com, example.co.uk" onChange={(event) => setForm({ ...form, company_domains: event.target.value })} />
              <p className="text-xs text-muted-foreground">Comma-separated. At least one ecosystem name or company domain is required.</p>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border p-3">
              <Checkbox id="bk-sync" checked={form.continuous_sync_enabled} onCheckedChange={(checked) => setForm({ ...form, continuous_sync_enabled: Boolean(checked) })} className="mt-0.5" />
              <label htmlFor="bk-sync" className="text-sm cursor-pointer">
                <span className="font-medium">Automatically re-sync</span>
                <p className="text-xs text-muted-foreground mt-0.5">Keeps Black Kite assets and risks current in the background.</p>
              </label>
            </div>
            {form.continuous_sync_enabled && (
              <Select value={String(form.sync_interval_minutes)} onValueChange={(value) => setForm({ ...form, sync_interval_minutes: Number(value) })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{INTERVALS.map((item) => <SelectItem key={item.value} value={String(item.value)}>{item.label}</SelectItem>)}</SelectContent>
              </Select>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={save} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RotateCw className="h-4 w-4 mr-2" />}{editing ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={disconnectOpen} onOpenChange={setDisconnectOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Disconnect Black Kite?</DialogTitle>
            <DialogDescription>Stored credentials will be deleted. Previously imported assets and risks are not deleted.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDisconnectOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={disconnect} disabled={busy}>Disconnect</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
