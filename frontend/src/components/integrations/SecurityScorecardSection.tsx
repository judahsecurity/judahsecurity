'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  Gauge,
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
import { api, getApiErrorMessage, type SecurityScorecardIntegration } from '@/lib/api';

type ScorecardForm = {
  connection_name: string;
  api_key: string;
  import_risks: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: ScorecardForm = {
  connection_name: 'SecurityScorecard',
  api_key: '',
  import_risks: true,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const INTERVALS = [
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
  { value: 10080, label: 'Every week' },
];

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

export function SecurityScorecardSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<SecurityScorecardIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<SecurityScorecardIntegration | null>(null);
  const [form, setForm] = useState<ScorecardForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SecurityScorecardIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getSecurityScorecardIntegrations());
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

  function openEdit(item: SecurityScorecardIntegration) {
    setEditing(item);
    setForm({
      connection_name: item.connection_name,
      api_key: '',
      import_risks: item.import_risks,
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
    if (!editing && !form.api_key.trim()) {
      toast({ title: 'API key is required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateSecurityScorecardIntegration(editing.id, {
          connection_name: form.connection_name,
          ...(form.api_key.trim() ? { api_key: form.api_key.trim() } : {}),
          import_risks: form.import_risks,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
      } else {
        await api.createSecurityScorecardIntegration({ ...form, api_key: form.api_key.trim() });
      }
      toast({ title: editing ? 'SecurityScorecard connection updated.' : 'SecurityScorecard connected.' });
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save SecurityScorecard connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: SecurityScorecardIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testSecurityScorecardConnection(item.id);
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

  async function sync(item: SecurityScorecardIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncSecurityScorecardIntegration(item.id);
      toast({
        title: result.ok ? 'SecurityScorecard sync complete' : 'SecurityScorecard sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'SecurityScorecard sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteSecurityScorecardIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'SecurityScorecard connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove SecurityScorecard connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-emerald-600/20 flex items-center justify-center shrink-0">
          <Gauge className="w-5 h-5 text-emerald-400" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">SecurityScorecard</CardTitle>
          <CardDescription>
            Import portfolio domains, their scores and grades, factor scores, score history, and active issues as risks. Read-only.
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
                  <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                    <span>{item.import_risks ? 'Domains, ratings and risks' : 'Domains and ratings only'}</span>
                    <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                    {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                  </div>
                  {item.last_sync_stats && item.last_sync_ok && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.last_sync_stats.companies_seen || 0} domains from {item.last_sync_stats.portfolios_seen || 0} portfolios;{' '}
                      {item.last_sync_stats.assets_created || 0} new assets, {item.last_sync_stats.risks_created || 0} new risks,{' '}
                      {item.last_sync_stats.risks_resolved || 0} resolved.
                      {item.last_sync_stats.companies_without_factors
                        ? ` ${item.last_sync_stats.companies_without_factors} domain(s) had no accessible factors.`
                        : ''}
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
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add account</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Requires a SecurityScorecard API token and at least one portfolio with companies.
            </p>
            <Button onClick={openCreate}><Gauge className="h-4 w-4 mr-2" />Connect SecurityScorecard</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit SecurityScorecard connection' : 'Connect SecurityScorecard'}</DialogTitle>
            <DialogDescription>
              The API key is validated against your portfolios before saving and encrypted at rest. Judah never writes to SecurityScorecard.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input value={form.connection_name} onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">API Key {editing && '(optional)'}</label>
              <Input
                type="password"
                autoComplete="off"
                value={form.api_key}
                placeholder={editing ? 'Leave blank to keep existing' : 'SecurityScorecard API token'}
                onChange={(event) => setForm({ ...form, api_key: event.target.value })}
              />
              <p className="text-xs text-muted-foreground">
                In SecurityScorecard: My Settings → API → Generate New API Token.
              </p>
              <a href="https://securityscorecard.readme.io/reference" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                SecurityScorecard API reference <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-2">
              {[
                ['ssc-risks', 'Import active issues as risks', 'Creates a finding per issue type on each domain, with mapped severity, the vendor definition, and per-instance evidence.', 'import_risks'],
                ['ssc-sync', 'Automatically re-sync', 'Keeps scores, grades, and issues current in the background.', 'continuous_sync_enabled'],
              ].map(([id, title, description, key]) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox id={id} checked={Boolean(form[key as keyof ScorecardForm])} onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })} className="mt-0.5" />
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
            <p className="text-xs text-muted-foreground">
              Portfolios often track vendors, so newly imported domains are added out of scanning scope until you confirm ownership.
            </p>
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
            <DialogTitle>Remove SecurityScorecard connection?</DialogTitle>
            <DialogDescription>The stored API key will be deleted. Previously imported domains and risks are retained.</DialogDescription>
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
