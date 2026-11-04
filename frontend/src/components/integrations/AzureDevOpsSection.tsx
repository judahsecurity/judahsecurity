'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  GitBranch,
  KeyRound,
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
  type AzureDevOpsIntegration,
  type AzureDevOpsIntegrationPayload,
  type ScmAuthMethod,
} from '@/lib/api';

type AdoForm = {
  connection_name: string;
  scope_url: string;
  auth_method: ScmAuthMethod;
  personal_access_token: string;
  tenant_id: string;
  client_id: string;
  client_secret: string;
  secret_scanning_enabled: boolean;
  include_unverified_secrets: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
};

const DEFAULT_FORM: AdoForm = {
  connection_name: '',
  scope_url: '',
  auth_method: 'entra_id',
  personal_access_token: '',
  tenant_id: '',
  client_id: '',
  client_secret: '',
  secret_scanning_enabled: true,
  include_unverified_secrets: false,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const INTERVALS = [
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
  { value: 10080, label: 'Every 7 days' },
];

const SCOPE_URL_RE = /^https:\/\/dev\.azure\.com\/[A-Za-z0-9][A-Za-z0-9-]*(\/[^/?#]+)*\/?$/i;

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

function AzureDevOpsLogo() {
  return (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor" aria-hidden="true">
      <path d="M22 4.6v14.27l-5.86 4.8-9.08-3.3v3.27L1.92 16.9l15-1.17V3.13zM17 5.39 8.58.33v3.3L.85 5.91 0 7.06v6.5l3.3 1.45V6.69z" />
    </svg>
  );
}

export function AzureDevOpsSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<AzureDevOpsIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<AzureDevOpsIntegration | null>(null);
  const [form, setForm] = useState<AdoForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AzureDevOpsIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getAzureDevOpsIntegrations());
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

  function openEdit(item: AzureDevOpsIntegration) {
    setEditing(item);
    setForm({
      connection_name: item.connection_name,
      scope_url: item.scope_url,
      auth_method: item.auth_method,
      personal_access_token: '',
      tenant_id: item.tenant_id || '',
      client_id: item.client_id || '',
      client_secret: '',
      secret_scanning_enabled: item.secret_scanning_enabled,
      include_unverified_secrets: item.include_unverified_secrets,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  // Editing keeps stored secrets unless the method changes or a new value is typed.
  const keepsStoredSecret = Boolean(editing && editing.auth_method === form.auth_method);

  function validate(): string | null {
    if (!form.connection_name.trim()) return 'Connection name is required.';
    if (!SCOPE_URL_RE.test(form.scope_url.trim())) {
      return 'Enter a valid Azure DevOps organization or project URL (https://dev.azure.com/your-org).';
    }
    if (form.auth_method === 'pat' && !keepsStoredSecret && !form.personal_access_token.trim()) {
      return 'A Personal Access Token is required.';
    }
    if (form.auth_method === 'entra_id') {
      if (!form.tenant_id.trim() || !form.client_id.trim()) return 'Tenant ID and Application (client) ID are required.';
      if (!keepsStoredSecret && !form.client_secret.trim()) return 'A client secret is required.';
    }
    return null;
  }

  async function save() {
    const problem = validate();
    if (problem) {
      toast({ title: problem, variant: 'destructive' });
      return;
    }
    const payload: Partial<AzureDevOpsIntegrationPayload> = {
      connection_name: form.connection_name.trim(),
      scope_url: form.scope_url.trim(),
      auth_method: form.auth_method,
      secret_scanning_enabled: form.secret_scanning_enabled,
      include_unverified_secrets: form.include_unverified_secrets,
      continuous_sync_enabled: form.continuous_sync_enabled,
      sync_interval_minutes: form.sync_interval_minutes,
    };
    if (form.auth_method === 'pat') {
      if (form.personal_access_token.trim()) payload.personal_access_token = form.personal_access_token.trim();
    } else {
      payload.tenant_id = form.tenant_id.trim();
      payload.client_id = form.client_id.trim();
      if (form.client_secret.trim()) payload.client_secret = form.client_secret.trim();
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateAzureDevOpsIntegration(editing.id, payload);
      } else {
        await api.createAzureDevOpsIntegration(payload as AzureDevOpsIntegrationPayload);
      }
      toast({ title: editing ? 'Azure DevOps connection updated.' : 'Azure DevOps connected.' });
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save Azure DevOps connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: AzureDevOpsIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testAzureDevOpsConnection(item.id);
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

  async function sync(item: AzureDevOpsIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncAzureDevOpsIntegration(item.id);
      toast({
        title: result.ok ? 'Azure DevOps sync complete' : 'Azure DevOps sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Azure DevOps sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteAzureDevOpsIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Azure DevOps connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove Azure DevOps connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  const secretPlaceholder = keepsStoredSecret ? 'Leave blank to keep existing' : undefined;

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-sky-600/20 text-sky-400 flex items-center justify-center shrink-0">
          <AzureDevOpsLogo />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Azure DevOps</CardTitle>
          <CardDescription>
            Import active Git repositories from Azure DevOps Services and scan their code and commit history for secrets. Read-only.
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
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-medium text-sm">{item.connection_name}</p>
                    <Badge variant="outline" className="text-xs">
                      {item.scm_project ? 'Project' : 'Organization'}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {item.auth_method === 'entra_id' ? 'Entra ID' : 'PAT'}
                    </Badge>
                    {item.last_test_ok === false && (
                      <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                        <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                      </Badge>
                    )}
                  </div>
                  <a href={item.scope_url} target="_blank" rel="noopener noreferrer" className="text-xs text-muted-foreground hover:underline truncate inline-flex items-center gap-1 max-w-full">
                    <span className="truncate">{item.scope_url}</span><ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                  <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                    <span>{item.secret_scanning_enabled ? 'Secret scanning on' : 'Secret scanning off'}</span>
                    <span>{item.continuous_sync_enabled ? `Re-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                    {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                  </div>
                  {item.last_sync_stats && item.last_sync_ok && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.last_sync_stats.repositories_seen || 0} repositories across {item.last_sync_stats.projects_seen || 0} project(s)
                      {' '}({item.last_sync_stats.repositories_created || 0} new)
                      {(item.last_sync_stats.forks_skipped || item.last_sync_stats.disabled_skipped)
                        ? `; skipped ${item.last_sync_stats.forks_skipped || 0} fork(s), ${item.last_sync_stats.disabled_skipped || 0} disabled`
                        : ''}
                      .
                      {item.last_scan_id ? (
                        <> <Link href={`/scans/${item.last_scan_id}`} className="text-primary hover:underline">View secret scan</Link></>
                      ) : null}
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
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add organization or project</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect with an Entra ID service principal (recommended) or a PAT with Code (Read) and Project and Team (Read).
              The identity must be a member of every project you want scanned.
            </p>
            <Button onClick={openCreate}><GitBranch className="h-4 w-4 mr-2" />Connect Azure DevOps</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Azure DevOps connection' : 'Connect Azure DevOps'}</DialogTitle>
            <DialogDescription>
              Access is validated by listing projects before saving. Credentials are encrypted at rest, and the
              integration never pushes code, creates branches, or changes settings in Azure DevOps.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="ado-name">Connection name</label>
              <Input id="ado-name" value={form.connection_name} placeholder="e.g. Contoso engineering" onChange={(event) => setForm({ ...form, connection_name: event.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="ado-url">Azure DevOps organization or project URL</label>
              <Input id="ado-url" value={form.scope_url} placeholder="https://dev.azure.com/your-org" onChange={(event) => setForm({ ...form, scope_url: event.target.value })} />
              <p className="text-xs text-muted-foreground">
                An organization URL scans every project; a project URL scans only that project. A repository URL scans its
                whole project. Azure DevOps Server, TFS, and visualstudio.com URLs are not supported.
              </p>
            </div>

            {form.auth_method === 'entra_id' ? (
              <div className="space-y-3 rounded-lg border border-border p-3">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <ShieldCheck className="h-4 w-4 text-green-400" />Entra ID service principal
                  <Badge variant="outline" className="text-xs">Recommended</Badge>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium" htmlFor="ado-tenant">Directory (tenant) ID</label>
                    <Input id="ado-tenant" value={form.tenant_id} placeholder="00000000-0000-0000-0000-000000000000" onChange={(event) => setForm({ ...form, tenant_id: event.target.value })} />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium" htmlFor="ado-client">Application (client) ID</label>
                    <Input id="ado-client" value={form.client_id} placeholder="00000000-0000-0000-0000-000000000000" onChange={(event) => setForm({ ...form, client_id: event.target.value })} />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium" htmlFor="ado-secret">Client secret</label>
                  <Input id="ado-secret" type="password" value={form.client_secret} placeholder={secretPlaceholder || 'Service principal client secret'} onChange={(event) => setForm({ ...form, client_secret: event.target.value })} />
                </div>
                <p className="text-xs text-muted-foreground">
                  Add the application under <span className="font-medium">Organization Settings &gt; Users</span> with Basic access,
                  then use <span className="font-medium">Manage access</span> to add it to every project as a Project Reader.
                  Without project access, authentication succeeds but no repositories are visible.
                </p>
                <button type="button" className="text-xs text-primary hover:underline" onClick={() => setForm({ ...form, auth_method: 'pat' })}>
                  Use alternative authentication (Personal Access Token)
                </button>
              </div>
            ) : (
              <div className="space-y-3 rounded-lg border border-border p-3">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <KeyRound className="h-4 w-4 text-amber-400" />Personal Access Token
                </div>
                <Input type="password" aria-label="Personal Access Token" value={form.personal_access_token} placeholder={secretPlaceholder || 'PAT with Code (Read) and Project and Team (Read)'} onChange={(event) => setForm({ ...form, personal_access_token: event.target.value })} />
                <p className="text-xs text-muted-foreground">
                  PATs are long-lived and must be rotated by hand. Use a service account, set a short expiry, and make sure the
                  token owner is a member of every project to scan.{' '}
                  <a href="https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">
                    Creating a PAT <ExternalLink className="h-3 w-3" />
                  </a>
                </p>
                <button type="button" className="text-xs text-primary hover:underline" onClick={() => setForm({ ...form, auth_method: 'entra_id' })}>
                  Use Entra ID service principal instead
                </button>
              </div>
            )}

            <div className="space-y-2">
              {([
                ['ado-scan', 'Scan repositories for secrets', 'Clones each repository and scans current code and full commit history, so secrets that were committed and later removed are still found.', 'secret_scanning_enabled'],
                ['ado-unverified', 'Include unverified secrets', 'Also report credentials that match a detector but could not be verified live. Noisier.', 'include_unverified_secrets'],
                ['ado-sync', 'Automatically re-sync', 'Re-enumerates the scope on a schedule so new repositories are imported and scanned.', 'continuous_sync_enabled'],
              ] as const).map(([id, title, description, key]) => (
                <div key={id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox
                    id={id}
                    checked={Boolean(form[key])}
                    disabled={key === 'include_unverified_secrets' && !form.secret_scanning_enabled}
                    onCheckedChange={(checked) => setForm({ ...form, [key]: Boolean(checked) })}
                    className="mt-0.5"
                  />
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
            <DialogTitle>Remove Azure DevOps connection?</DialogTitle>
            <DialogDescription>Stored credentials will be deleted. Previously imported repositories and findings are retained.</DialogDescription>
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
