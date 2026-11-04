'use client';

import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Download,
  ExternalLink,
  Github,
  KeyRound,
  Loader2,
  RefreshCw,
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
import {
  api,
  getApiErrorMessage,
  type GitHubAppStatus,
  type GitHubConnectionOptions,
  type GitHubIntegration,
} from '@/lib/api';

type OptionsForm = GitHubConnectionOptions & { allow_fix_pull_requests: boolean };
type PatForm = OptionsForm & { token: string; organization_url: string };

const DEFAULT_OPTIONS: OptionsForm = {
  import_member_repos: true,
  scan_secrets: true,
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
  allow_fix_pull_requests: false,
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

function manageInstallationUrl(item: GitHubIntegration) {
  if (!item.installation_id) return item.account_url;
  return item.account_type === 'User'
    ? `https://github.com/settings/installations/${item.installation_id}`
    : `https://github.com/organizations/${item.account_login}/settings/installations/${item.installation_id}`;
}

function OptionToggles({
  form,
  onChange,
  showWrite,
  idPrefix,
}: {
  form: OptionsForm;
  onChange: (next: OptionsForm) => void;
  showWrite: boolean;
  idPrefix: string;
}) {
  const rows: [keyof OptionsForm, string, string][] = [
    ['import_member_repos', 'Import member-owned repositories', 'Adds public repositories owned by organization members with the status Pending, for review.'],
    ['scan_secrets', 'Scan repositories for secrets', 'Scans the default branch of each repository. Findings include the full matched value.'],
    ['continuous_sync_enabled', 'Automatically re-sync', 'Picks up new repositories and changes on a schedule. GitHub webhooks are not used.'],
  ];
  if (showWrite) {
    rows.push([
      'allow_fix_pull_requests',
      'Allow fix pull requests',
      'Lets the platform open pull requests with patches. Needs Contents and Pull requests write access (or the classic repo scope). Never merges.',
    ]);
  }
  return (
    <div className="space-y-2">
      {rows.map(([key, title, description]) => (
        <div key={key} className="space-y-2">
          <div className="flex items-start gap-3 rounded-lg border border-border p-3">
          <Checkbox
            id={`${idPrefix}-${key}`}
            checked={Boolean(form[key])}
            onCheckedChange={(checked) => onChange({ ...form, [key]: Boolean(checked) })}
            className="mt-0.5"
          />
          <label htmlFor={`${idPrefix}-${key}`} className="text-sm cursor-pointer">
            <span className="font-medium">{title}</span>
            <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
          </label>
          </div>
          {key === 'continuous_sync_enabled' && form.continuous_sync_enabled && (
            <Select
              value={String(form.sync_interval_minutes)}
              onValueChange={(value) => onChange({ ...form, sync_interval_minutes: Number(value) })}
            >
              <SelectTrigger aria-label="Sync interval"><SelectValue /></SelectTrigger>
              <SelectContent>
                {INTERVALS.map((item) => <SelectItem key={item.value} value={String(item.value)}>{item.label}</SelectItem>)}
              </SelectContent>
            </Select>
          )}
        </div>
      ))}
    </div>
  );
}

export function GitHubSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<GitHubIntegration[]>([]);
  const [appStatus, setAppStatus] = useState<GitHubAppStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [checking, setChecking] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  const [patOpen, setPatOpen] = useState(false);
  const [patForm, setPatForm] = useState<PatForm>({ ...DEFAULT_OPTIONS, token: '', organization_url: '' });
  const [savingPat, setSavingPat] = useState(false);

  const [editing, setEditing] = useState<GitHubIntegration | null>(null);
  const [editForm, setEditForm] = useState<OptionsForm & { token: string }>({ ...DEFAULT_OPTIONS, token: '' });
  const [savingEdit, setSavingEdit] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<GitHubIntegration | null>(null);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const [items, status] = await Promise.all([
        api.getGitHubIntegrations(),
        api.getGitHubAppStatus().catch(() => null),
      ]);
      setIntegrations(items);
      setAppStatus(status);
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  async function installApp() {
    setInstalling(true);
    try {
      const { install_url } = await api.startGitHubAppInstall({
        import_member_repos: DEFAULT_OPTIONS.import_member_repos,
        scan_secrets: DEFAULT_OPTIONS.scan_secrets,
        continuous_sync_enabled: DEFAULT_OPTIONS.continuous_sync_enabled,
        sync_interval_minutes: DEFAULT_OPTIONS.sync_interval_minutes,
      });
      window.location.assign(install_url);
    } catch (error) {
      toast({ title: 'Could not start the GitHub App install', description: getApiErrorMessage(error), variant: 'destructive' });
      setInstalling(false);
    }
  }

  async function checkRequests() {
    setChecking(true);
    try {
      const { linked } = await api.reconcileGitHubAppRequests();
      toast({
        title: linked ? 'GitHub connected' : 'Still waiting for approval',
        description: linked ? 'An owner approved the install request.' : 'No owner has approved the request yet.',
      });
      await load();
    } catch (error) {
      toast({ title: 'Could not check install requests', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setChecking(false);
    }
  }

  async function connectPat() {
    if (!patForm.token.trim() || !patForm.organization_url.trim()) {
      toast({ title: 'Token and GitHub organization are required.', variant: 'destructive' });
      return;
    }
    setSavingPat(true);
    try {
      await api.createGitHubPatIntegration(patForm);
      toast({ title: 'GitHub connected', description: 'Run a sync to import repositories now, or wait for the next scheduled sync.' });
      setPatOpen(false);
      setPatForm({ ...DEFAULT_OPTIONS, token: '', organization_url: '' });
      await load();
    } catch (error) {
      toast({ title: 'Could not connect GitHub', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSavingPat(false);
    }
  }

  function openEdit(item: GitHubIntegration) {
    setEditing(item);
    setEditForm({
      import_member_repos: item.import_member_repos,
      scan_secrets: item.scan_secrets,
      continuous_sync_enabled: item.continuous_sync_enabled,
      sync_interval_minutes: item.sync_interval_minutes,
      allow_fix_pull_requests: item.allow_fix_pull_requests,
      token: '',
    });
  }

  async function saveEdit() {
    if (!editing) return;
    setSavingEdit(true);
    try {
      const { token, allow_fix_pull_requests, ...options } = editForm;
      await api.updateGitHubIntegration(editing.id, {
        ...options,
        ...(editing.auth_method === 'pat' ? { allow_fix_pull_requests } : {}),
        ...(token.trim() ? { token: token.trim() } : {}),
      });
      toast({ title: 'GitHub connection updated.' });
      setEditing(null);
      await load();
    } catch (error) {
      toast({ title: 'Could not save GitHub connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSavingEdit(false);
    }
  }

  async function runAction(item: GitHubIntegration, action: 'sync' | 'test') {
    setBusyId(item.id);
    try {
      const result = action === 'sync'
        ? await api.syncGitHubIntegration(item.id)
        : await api.testGitHubIntegration(item.id);
      toast({
        title: result.ok ? (action === 'sync' ? 'GitHub sync complete' : 'Connection OK') : (action === 'sync' ? 'GitHub sync failed' : 'Connection failed'),
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: action === 'sync' ? 'GitHub sync failed' : 'Connection test failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteGitHubIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'GitHub connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Could not remove GitHub connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  const appConfigured = Boolean(appStatus?.app_configured);
  const pending = appStatus?.pending_requests || [];

  const installButton = (
    <Button onClick={installApp} disabled={!appConfigured || installing}>
      {installing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Github className="h-4 w-4 mr-2" />}
      Install GitHub App
    </Button>
  );
  const patButton = (
    <Button variant="outline" onClick={() => setPatOpen(true)}>
      <KeyRound className="h-4 w-4 mr-2" />Use alternative authentication
    </Button>
  );

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-zinc-500/20 flex items-center justify-center shrink-0">
          <Github className="w-5 h-5 text-zinc-200" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">GitHub</CardTitle>
          <CardDescription>
            Discover repositories as assets, scan them for secrets, and optionally open fix pull requests.
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
        {pending.map((request) => (
          <div key={request.id} className="flex flex-col sm:flex-row sm:items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <Clock className="h-4 w-4 text-amber-400 shrink-0" />
            <p className="text-sm flex-1">
              Install request{request.github_login ? <> from <span className="font-medium">@{request.github_login}</span></> : ''} is
              waiting for an organization owner to approve it in GitHub. It expires {new Date(request.expires_at).toLocaleDateString()}.
            </p>
            <Button size="sm" variant="outline" onClick={checkRequests} disabled={checking}>
              {checking ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}Check now
            </Button>
          </div>
        ))}

        {integrations.map((item) => (
          <div key={item.id} className="rounded-lg border border-border p-3 space-y-3">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <a href={item.account_url} target="_blank" rel="noopener noreferrer" className="font-medium text-sm hover:underline">
                  {item.account_login}
                </a>
                <Badge variant="outline" className="text-xs">{item.auth_method === 'app' ? 'GitHub App' : 'Personal access token'}</Badge>
                <Badge variant="outline" className="text-xs text-muted-foreground">{item.account_type}</Badge>
                {item.can_open_pull_requests && <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-400 border-amber-500/30">Can open PRs</Badge>}
                {!item.is_active && <Badge variant="outline" className="text-xs text-muted-foreground">Disabled</Badge>}
                {item.last_test_ok === false && (
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                    <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                  </Badge>
                )}
              </div>
              <div className="flex flex-wrap gap-x-3 mt-1 text-xs text-muted-foreground">
                {item.auth_method === 'app' && (
                  <span>{item.repository_selection === 'all' ? 'All repositories' : 'Selected repositories'}</span>
                )}
                <span>{item.scan_secrets ? 'Secret scanning on' : 'Secret scanning off'}</span>
                <span>{item.import_member_repos ? 'Member repos imported' : 'Member repos skipped'}</span>
                <span>{item.continuous_sync_enabled ? `Auto-sync ${intervalLabel(item.sync_interval_minutes).toLowerCase()}` : 'Auto-sync off'}</span>
                {item.last_sync_at && <span>Last sync: {new Date(item.last_sync_at).toLocaleString()}</span>}
              </div>
              {item.last_sync_stats && item.last_sync_ok && (
                <p className="text-xs text-muted-foreground mt-1">
                  {Number(item.last_sync_stats.repos_seen || 0)} repositories, {Number(item.last_sync_stats.member_repos_seen || 0)} member-owned,{' '}
                  {Number(item.last_sync_stats.secrets_created || 0)} new secrets.
                  {item.last_sync_stats.members_skipped ? ' Member repositories skipped: the credential can’t list members.' : ''}
                </p>
              )}
              {item.last_error && item.last_sync_ok === false && (
                <p className="text-xs text-red-400 mt-1">{item.last_error}</p>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" onClick={() => runAction(item, 'sync')} disabled={busyId === item.id || !item.is_active}>
                {busyId === item.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}Sync now
              </Button>
              <Button size="sm" variant="outline" onClick={() => runAction(item, 'test')} disabled={busyId === item.id}>
                <RefreshCw className="h-4 w-4 mr-2" />Test
              </Button>
              <Button size="sm" variant="outline" onClick={() => openEdit(item)}>
                <Settings2 className="h-4 w-4 mr-2" />Edit
              </Button>
              {item.auth_method === 'app' && (
                <a href={manageInstallationUrl(item)} target="_blank" rel="noopener noreferrer">
                  <Button size="sm" variant="outline"><ExternalLink className="h-4 w-4 mr-2" />Repository access</Button>
                </a>
              )}
              <Button size="sm" variant="outline" className="border-red-600/30 text-red-400" onClick={() => setDeleteTarget(item)}>
                <Trash2 className="h-4 w-4 mr-2" />Remove
              </Button>
            </div>
          </div>
        ))}

        {integrations.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {appConfigured && installButton}
            {patButton}
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Recommended: an organization owner installs the GitHub App and chooses which repositories are visible.
              No GitHub token is stored; the platform requests short-lived, read-only installation tokens.
            </p>
            <div className="flex flex-wrap gap-2">
              {installButton}
              {patButton}
            </div>
            {!loading && !appConfigured && (
              <p className="text-xs text-muted-foreground">
                The GitHub App isn&apos;t configured on this platform yet. Connect with a personal access token instead.
              </p>
            )}
          </div>
        )}

        {integrations.some((item) => item.scan_secrets) && (
          <div className="flex items-start gap-2 rounded-lg border border-border p-3 text-xs text-muted-foreground">
            <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400" />
            Secret findings show the matched value in full, and exports include it. Treat them as sensitive and rotate any exposed secret.
          </div>
        )}
      </CardContent>

      <Dialog open={patOpen} onOpenChange={(open) => { if (!savingPat) setPatOpen(open); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Connect with a personal access token</DialogTitle>
            <DialogDescription>
              Use this when you can&apos;t install the GitHub App, to import a personal account, or to let the platform open fix pull requests.
              The token is validated against the organization before saving and encrypted at rest.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="gh-pat">Personal Access Token (PAT)</label>
              <Input id="gh-pat" type="password" autoComplete="off" value={patForm.token} placeholder="github_pat_…" onChange={(event) => setPatForm({ ...patForm, token: event.target.value })} />
              <p className="text-xs text-muted-foreground">
                Read-only access is enough for discovery and scanning. To import member-owned repositories with a fine-grained token, grant the
                Members organization permission (read).
              </p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium" htmlFor="gh-org">GitHub Organization</label>
              <Input id="gh-org" value={patForm.organization_url} placeholder="github.com/<organization>" onChange={(event) => setPatForm({ ...patForm, organization_url: event.target.value })} />
            </div>
            <OptionToggles form={patForm} onChange={(next) => setPatForm({ ...patForm, ...next })} showWrite idPrefix="gh-pat" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPatOpen(false)} disabled={savingPat}>Cancel</Button>
            <Button onClick={connectPat} disabled={savingPat}>
              {savingPat && <Loader2 className="h-4 w-4 animate-spin mr-2" />}Connect
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(editing)} onOpenChange={(open) => { if (!open && !savingEdit) setEditing(null); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit GitHub connection — {editing?.account_login}</DialogTitle>
            <DialogDescription>
              {editing?.auth_method === 'app'
                ? 'The GitHub App is read-only, so it can’t open fix pull requests yet. Change which repositories it can see in your GitHub settings.'
                : 'Leave the token blank to keep the stored one.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {editing?.auth_method === 'pat' && (
              <div className="space-y-1.5">
                <label className="text-sm font-medium" htmlFor="gh-edit-token">Replace token (optional)</label>
                <Input id="gh-edit-token" type="password" autoComplete="off" value={editForm.token} placeholder="Leave blank to keep existing" onChange={(event) => setEditForm({ ...editForm, token: event.target.value })} />
              </div>
            )}
            <OptionToggles
              form={editForm}
              onChange={(next) => setEditForm({ ...editForm, ...next })}
              showWrite={editing?.auth_method === 'pat'}
              idPrefix="gh-edit"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)} disabled={savingEdit}>Cancel</Button>
            <Button onClick={saveEdit} disabled={savingEdit}>
              {savingEdit && <Loader2 className="h-4 w-4 animate-spin mr-2" />}Save changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove GitHub connection?</DialogTitle>
            <DialogDescription>
              {deleteTarget?.auth_method === 'app'
                ? 'The platform stops using this installation. To revoke access entirely, also uninstall the App in your GitHub settings.'
                : 'The stored token is deleted.'}{' '}
              Previously imported repositories and findings are retained.
            </DialogDescription>
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
