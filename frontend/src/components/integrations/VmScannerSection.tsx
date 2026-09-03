'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Loader2,
  CheckCircle2,
  Plug,
  Trash2,
  RefreshCw,
  ExternalLink,
  AlertCircle,
  Settings2,
  Plus,
  RotateCw,
  Download,
  ShieldAlert,
} from 'lucide-react';
import {
  api,
  getApiErrorMessage,
  type VmScannerIntegration,
  type VmScannerProvider,
  type VmScannerProviderInfo,
} from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface VmScannerFormState {
  provider: VmScannerProvider;
  connection_name: string;
  base_url: string;
  credentials: Record<string, string>;
  verify_ssl: boolean;
  import_vulnerabilities: boolean;
  import_assets: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultForm: VmScannerFormState = {
  provider: 'tenable',
  connection_name: '',
  base_url: '',
  credentials: {},
  verify_ssl: true,
  import_vulnerabilities: true,
  import_assets: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatInterval(minutes: number): string {
  const match = SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

export function VmScannerSection() {
  const { toast } = useToast();
  const [providers, setProviders] = useState<VmScannerProviderInfo[]>([]);
  const [integrations, setIntegrations] = useState<VmScannerIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<VmScannerIntegration | null>(null);
  const [form, setForm] = useState<VmScannerFormState>(defaultForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<VmScannerIntegration | null>(null);

  const providerMeta = providers.find(p => p.provider === form.provider);
  const providerLabel = (key: string) =>
    providers.find(p => p.provider === key)?.label ?? key;

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const [providerList, connections] = await Promise.all([
        api.getVmScannerProviders(),
        api.getVmScannerIntegrations(),
      ]);
      setProviders(providerList);
      setIntegrations(connections);
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultForm);
    setSetupOpen(true);
  }

  function openEdit(integration: VmScannerIntegration) {
    setEditing(integration);
    setForm({
      provider: integration.provider,
      connection_name: integration.connection_name,
      base_url: integration.base_url || '',
      credentials: {},
      verify_ssl: integration.verify_ssl,
      import_vulnerabilities: integration.import_vulnerabilities,
      import_assets: integration.import_assets,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  const credentialsEntered = Object.values(form.credentials).some(v => v.trim());

  async function handleSave() {
    if (!form.connection_name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (providerMeta?.base_url_required && !form.base_url.trim()) {
      toast({ title: `${providerMeta.label} requires an API base URL.`, variant: 'destructive' });
      return;
    }
    if (!editing) {
      const missing = (providerMeta?.credential_fields ?? []).filter(
        f => !(form.credentials[f.key] || '').trim()
      );
      if (missing.length > 0) {
        toast({
          title: `Missing: ${missing.map(f => f.label).join(', ')}.`,
          variant: 'destructive',
        });
        return;
      }
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateVmScannerIntegration(editing.id, {
          connection_name: form.connection_name,
          base_url: form.base_url,
          ...(credentialsEntered ? { credentials: form.credentials } : {}),
          verify_ssl: form.verify_ssl,
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'VM scanner connection updated.' });
      } else {
        await api.createVmScannerIntegration({
          provider: form.provider,
          connection_name: form.connection_name,
          base_url: form.base_url || undefined,
          credentials: form.credentials,
          verify_ssl: form.verify_ssl,
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'VM scanner connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: VmScannerIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testVmScannerConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: VmScannerIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncVmScannerIntegration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Sync failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteVmScannerIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'VM scanner connection removed.' });
      await load();
    } catch (err) {
      toast({ title: 'Failed to remove', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-[#1F2A0A] flex items-center justify-center shrink-0">
          <ShieldAlert className="w-5 h-5 text-[#A3C93A]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Vulnerability Management</CardTitle>
          <CardDescription className="text-sm">
            Import scanned hosts and detections from Tenable VM, Qualys VMDR, Rapid7 InsightVM, or Nessus. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} scanner{integrations.length > 1 ? 's' : ''}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {integrations.length > 0 ? (
          <div className="space-y-3">
            {integrations.map((c) => (
              <div key={c.id} className="rounded-lg border border-border p-3 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm truncate">{c.connection_name}</p>
                      <Badge variant="outline" className="text-xs">{providerLabel(c.provider)}</Badge>
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span>Import: {[c.import_assets && 'Assets', c.import_vulnerabilities && 'Vulnerabilities'].filter(Boolean).join(' + ') || 'Nothing'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatInterval(c.sync_interval_minutes).toLowerCase()}
                        </span>
                      ) : (
                        <span>Auto-sync off</span>
                      )}
                      {c.last_sync_at && (
                        <span>
                          Last sync: {new Date(c.last_sync_at).toLocaleString()}
                          {c.last_sync_ok === true && <span className="text-green-400"> — OK</span>}
                          {c.last_sync_ok === false && <span className="text-red-400"> — Failed</span>}
                        </span>
                      )}
                      {c.continuous_sync_enabled && c.next_sync_at && (
                        <span>Next: {new Date(c.next_sync_at).toLocaleString()}</span>
                      )}
                    </div>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.assets_created ?? 0} new assets, {c.last_sync_stats.vulns_created ?? 0} new findings imported.
                      </p>
                    )}
                    {c.last_sync_ok === false && c.last_error && (
                      <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={() => handleSync(c)} disabled={busyId === c.id || !c.is_active}>
                    {busyId === c.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                    Sync now
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => handleTest(c)} disabled={busyId === c.id}>
                    <RefreshCw className="h-4 w-4 mr-2" />Test
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openEdit(c)}>
                    <Settings2 className="h-4 w-4 mr-2" />Edit
                  </Button>
                  <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteTarget(c)}>
                    <Trash2 className="h-4 w-4 mr-2" />Remove
                  </Button>
                </div>
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-2" />Add another scanner
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a vulnerability management platform to ingest its scanned hosts and detections into your attack surface.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect a VM scanner
            </Button>
          </div>
        )}
      </CardContent>

      {/* Setup / Edit Dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-[#A3C93A]" />
              {editing ? 'Edit VM scanner connection' : 'Connect a VM scanner'}
            </DialogTitle>
            <DialogDescription>
              Connections are read-only: findings and hosts are pulled into the platform, nothing is written back.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Vendor</label>
              <Select
                value={form.provider}
                onValueChange={(v) => setForm(f => ({ ...f, provider: v as VmScannerProvider, credentials: {}, base_url: '' }))}
                disabled={!!editing}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {providers.map(p => (
                    <SelectItem key={p.provider} value={p.provider}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {editing && <p className="text-xs text-muted-foreground">The vendor cannot be changed after creation.</p>}
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. Corporate Qualys"
                value={form.connection_name}
                onChange={(e) => setForm(f => ({ ...f, connection_name: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">A label to identify this connection.</p>
            </div>

            {(providerMeta?.base_url_required || providerMeta?.base_url_hint) && (
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  API base URL{!providerMeta?.base_url_required && <span className="text-muted-foreground font-normal"> (optional)</span>}
                </label>
                <Input
                  placeholder={providerMeta?.base_url_hint || providerMeta?.default_base_url || 'https://...'}
                  value={form.base_url}
                  onChange={(e) => setForm(f => ({ ...f, base_url: e.target.value }))}
                />
                {providerMeta?.base_url_hint && (
                  <p className="text-xs text-muted-foreground">{providerMeta.base_url_hint}</p>
                )}
              </div>
            )}

            {(providerMeta?.credential_fields ?? []).map(field => (
              <div key={field.key} className="space-y-1.5">
                <label className="text-sm font-medium">
                  {field.label}
                  {editing && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
                </label>
                <Input
                  type={field.secret ? 'password' : 'text'}
                  placeholder={editing && field.secret ? '••••••••••••' : field.label}
                  value={form.credentials[field.key] || ''}
                  onChange={(e) => setForm(f => ({
                    ...f,
                    credentials: { ...f.credentials, [field.key]: e.target.value },
                  }))}
                />
              </div>
            ))}
            {providerMeta?.docs_url && (
              <a href={providerMeta.docs_url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                How to generate {providerMeta.label} API credentials <ExternalLink className="h-3 w-3" />
              </a>
            )}

            {providerMeta?.base_url_required && (
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="vm-verify-ssl"
                  checked={form.verify_ssl}
                  onCheckedChange={(v) => setForm(f => ({ ...f, verify_ssl: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="vm-verify-ssl" className="text-sm cursor-pointer">
                  <span className="font-medium">Verify TLS certificate</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Disable only for self-hosted scanners with self-signed certificates.</p>
                </label>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-sm font-medium">What to import</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="vm-assets"
                  checked={form.import_assets}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_assets: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="vm-assets" className="text-sm cursor-pointer">
                  <span className="font-medium">Import assets</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Hosts the scanner has assessed, added to your inventory.</p>
                </label>
              </div>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="vm-vulns"
                  checked={form.import_vulnerabilities}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_vulnerabilities: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="vm-vulns" className="text-sm cursor-pointer">
                  <span className="font-medium">Import vulnerabilities</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Open detections from the scanner, imported as findings.</p>
                </label>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="vm-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="vm-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps findings current by pulling new detections in the background.
                  </p>
                </label>
              </div>
              {form.continuous_sync_enabled && (
                <div className="space-y-1.5 pl-1">
                  <label className="text-sm font-medium">Sync frequency</label>
                  <Select
                    value={String(form.sync_interval_minutes)}
                    onValueChange={(v) => setForm(f => ({ ...f, sync_interval_minutes: Number(v) }))}
                  >
                    <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SYNC_INTERVALS.map(i => (
                        <SelectItem key={i.value} value={String(i.value)}>{i.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
          </div>

          <DialogFooter className="gap-2 pt-2 border-t border-border">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {editing ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes the stored credentials for <strong>{deleteTarget?.connection_name}</strong>. Assets and findings already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button
              variant="outline"
              className="border-red-600/30 hover:bg-red-600/20 text-red-400"
              onClick={handleDelete}
              disabled={busyId === deleteTarget?.id}
            >
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Trash2 className="h-4 w-4 mr-2" />}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
