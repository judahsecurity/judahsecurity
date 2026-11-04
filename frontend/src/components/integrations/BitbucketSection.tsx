'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  GitBranch,
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
import { api, getApiErrorMessage, type BitbucketIntegration } from '@/lib/api';

type BitbucketForm = {
  workspace_url: string;
  access_token: string;
  scan_secrets: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  max_repo_size_mb: number;
};

const DEFAULT_FORM: BitbucketForm = {
  workspace_url: '',
  access_token: '',
  scan_secrets: true,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
  max_repo_size_mb: 500,
};

const INTERVALS = [
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
  { value: 10080, label: 'Every 7 days' },
];

const WORKSPACE_URL_RE = /^(https:\/\/)?(www\.)?bitbucket\.org\/[A-Za-z0-9][A-Za-z0-9_-]*\/?$/;

function intervalLabel(minutes: number) {
  return INTERVALS.find((item) => item.value === minutes)?.label || `Every ${minutes} minutes`;
}

export function BitbucketSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<BitbucketIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<BitbucketIntegration | null>(null);
  const [form, setForm] = useState<BitbucketForm>(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<BitbucketIntegration | null>(null);
  const [detailsTarget, setDetailsTarget] = useState<BitbucketIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getBitbucketIntegrations());
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

  function openEdit(item: BitbucketIntegration) {
    setEditing(item);
    setForm({
      workspace_url: item.workspace_url,
      access_token: '',
      scan_secrets: item.scan_secrets,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
      max_repo_size_mb: item.max_repo_size_mb,
    });
    setSetupOpen(true);
  }

  async function save() {
    if (!editing) {
      if (!WORKSPACE_URL_RE.test(form.workspace_url.trim())) {
        toast({
          title: 'Enter a valid Bitbucket workspace URL',
          description: 'Use the form https://bitbucket.org/your-workspace',
          variant: 'destructive',
        });
        return;
      }
      if (!form.access_token.trim()) {
        toast({ title: 'Workspace access token is required.', variant: 'destructive' });
        return;
      }
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateBitbucketIntegration(editing.id, {
          ...(form.access_token ? { access_token: form.access_token.trim() } : {}),
          scan_secrets: form.scan_secrets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
          max_repo_size_mb: form.max_repo_size_mb,
        });
        toast({ title: 'Bitbucket connection updated.' });
      } else {
        await api.createBitbucketIntegration({
          ...form,
          workspace_url: form.workspace_url.trim(),
          access_token: form.access_token.trim(),
        });
        toast({
          title: 'Bitbucket connected',
          description: 'Repositories are being imported in the background.',
        });
      }
      setSetupOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Could not save Bitbucket connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function test(item: BitbucketIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.testBitbucketConnection(item.id);
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

  async function sync(item: BitbucketIntegration) {
    setBusyId(item.id);
    try {
      const result = await api.syncBitbucketIntegration(item.id);
      toast({
        title: result.ok ? 'Bitbucket sync started' : 'Bitbucket sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
    } catch (error) {
      toast({ title: 'Bitbucket sync failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function toggleActive(item: BitbucketIntegration) {
    setBusyId(item.id);
    try {
      await api.updateBitbucketIntegration(item.id, { is_active: !item.is_active });
      await load();
    } catch (error) {
      toast({ title: 'Could not update connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteBitbucketIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Bitbucket connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove Bitbucket connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-sky-600/20 flex items-center justify-center shrink-0">
          <GitBranch className="w-5 h-5 text-sky-400" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Bitbucket</CardTitle>
          <CardDescription>
            Import a Bitbucket Cloud workspace&apos;s repositories as assets and scan them for exposed secrets. Read-only.
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
                      <p className="font-medium text-sm">{item.workspace}</p>
                      {!item.is_active && <Badge variant="outline" className="text-xs text-muted-foreground">Disabled</Badge>}
                      {item.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <a href={item.workspace_url} target="_blank" rel="noopener noreferrer" className="text-xs text-muted-foreground hover:underline truncate inline-flex items-center gap-1">
                      {item.workspace_url} <ExternalLink className="h-3 w-3" />
                    </a>
                    <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                      <span>{item.scan_secrets ? 'Secret scanning on' : 'Secret scanning off'}</span>
                      <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                      {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
                    </div>
                    {item.last_sync_ok && item.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.repos_seen || 0} repositories ({stats.assets_created || 0} new, {stats.repos_skipped_forks || 0} forks skipped)
                        {item.scan_secrets && <> · {stats.repos_scanned || 0} scanned, {stats.secrets_created || 0} new secrets, {stats.secrets_resolved || 0} resolved</>}
                        {(stats.repos_scan_failed || 0) > 0 && <span className="text-amber-400"> · {stats.repos_scan_failed} scan failures</span>}
                      </p>
                    )}
                    {!item.last_sync_at && item.is_active && (
                      <p className="text-xs text-muted-foreground mt-1">First import pending…</p>
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
                    <Button size="sm" variant="outline" onClick={() => setDetailsTarget(item)}>
                      Details
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => openEdit(item)}>
                      <Settings2 className="h-4 w-4 mr-2" />Edit
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => toggleActive(item)} disabled={busyId === item.id}>
                      {item.is_active ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" variant="outline" className="border-red-600/30 text-red-400" onClick={() => setDeleteTarget(item)}>
                      <Trash2 className="h-4 w-4 mr-2" />Remove
                    </Button>
                  </div>
                </div>
              );
            })}
            <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add workspace</Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Bitbucket Cloud only. Use a workspace access token with <span className="font-medium">Repository: Read</span>. Forks are skipped; public repositories are flagged.
            </p>
            <Button onClick={openCreate}><GitBranch className="h-4 w-4 mr-2" />Connect Bitbucket</Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(open) => { if (!saving) setSetupOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.workspace}` : 'Connect Bitbucket'}</DialogTitle>
            <DialogDescription>
              The token is validated against the workspace before saving and encrypted at rest. The integration only reads repositories.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {!editing && (
              <ol className="text-xs text-muted-foreground list-decimal pl-4 space-y-1 rounded-lg border border-border p-3">
                <li>In Bitbucket, open <span className="font-medium">Settings → Workspace settings → Security → Access tokens</span>.</li>
                <li>Create an access token named <span className="font-medium">Judah</span> with <span className="font-medium">Repository: Read</span> only.</li>
                <li>Copy the token now. Bitbucket will not show it again.</li>
              </ol>
            )}
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Bitbucket Workspace URL</label>
              <Input
                value={form.workspace_url}
                placeholder="https://bitbucket.org/your-workspace"
                disabled={Boolean(editing)}
                onChange={(event) => setForm({ ...form, workspace_url: event.target.value })}
              />
              {editing && <p className="text-xs text-muted-foreground">To connect a different workspace, add a new connection.</p>}
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Workspace Token {editing && '(optional)'}</label>
              <Input
                type="password"
                value={form.access_token}
                placeholder={editing ? 'Leave blank to keep existing' : 'Workspace access token'}
                onChange={(event) => setForm({ ...form, access_token: event.target.value })}
              />
              <a href="https://support.atlassian.com/bitbucket-cloud/docs/workspace-access-tokens/" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                About workspace access tokens <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-2">
              {([
                ['bb-secrets', 'Scan repositories for exposed secrets', 'Shallow-clones each repository’s main branch and runs Gitleaks. Secret values are redacted and never stored.', 'scan_secrets'],
                ['bb-sync', 'Automatically re-sync', 'Picks up new repositories and re-scans repositories that changed since the last scan.', 'continuous_sync_enabled'],
              ] as const).map(([id, title, description, key]) => (
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
              {form.scan_secrets && (
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Skip repositories larger than (MB)</label>
                  <Input
                    type="number"
                    min={1}
                    max={5000}
                    value={form.max_repo_size_mb}
                    onChange={(event) => setForm({ ...form, max_repo_size_mb: Math.max(1, Math.min(5000, Number(event.target.value) || 500)) })}
                  />
                </div>
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

      <Dialog open={Boolean(detailsTarget)} onOpenChange={(open) => { if (!open) setDetailsTarget(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{detailsTarget?.workspace}</DialogTitle>
            <DialogDescription>{detailsTarget?.workspace_url}</DialogDescription>
          </DialogHeader>
          {detailsTarget && (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted-foreground">Status</dt><dd>{detailsTarget.is_active ? 'Active' : 'Disabled'}</dd>
              <dt className="text-muted-foreground">Last test</dt>
              <dd>{detailsTarget.last_tested_at ? `${detailsTarget.last_test_ok ? 'OK' : 'Failed'} · ${new Date(detailsTarget.last_tested_at).toLocaleString()}` : '—'}</dd>
              <dt className="text-muted-foreground">Last sync</dt>
              <dd>{detailsTarget.last_sync_at ? `${detailsTarget.last_sync_ok ? 'OK' : 'Failed'} · ${new Date(detailsTarget.last_sync_at).toLocaleString()}` : '—'}</dd>
              <dt className="text-muted-foreground">Next sync</dt>
              <dd>{detailsTarget.next_sync_at ? new Date(detailsTarget.next_sync_at).toLocaleString() : '—'}</dd>
              {Object.entries(detailsTarget.last_sync_stats || {}).map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-muted-foreground">{key.replace(/_/g, ' ')}</dt><dd>{value}</dd>
                </div>
              ))}
            </dl>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetailsTarget(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove Bitbucket connection?</DialogTitle>
            <DialogDescription>The stored token will be deleted. Previously imported repositories and findings are kept.</DialogDescription>
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
