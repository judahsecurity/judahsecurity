'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
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
  XCircle,
  Plug,
  Trash2,
  RefreshCw,
  ExternalLink,
  AlertCircle,
  Settings2,
  Plus,
  X,
  ArrowRight,
  Zap,
  ArrowLeftRight,
  Radar,
  Download,
  RotateCw,
  Shield,
  Bug,
} from 'lucide-react';
import {
  api,
  getApiErrorMessage,
  type JiraIntegration,
  type CensysIntegration,
  type HackerOneIntegration,
  type AkamaiIntegration,
  type PanoramaIntegration,
  type F5Integration,
  type FortiGateIntegration,
  type CheckPointIntegration,
  type CloudflareIntegration,
} from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { JiraProjectPicker } from '@/components/integrations/JiraProjectPicker';
import { ServiceNowSection } from '@/components/integrations/ServiceNowSection';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

interface JiraFormState {
  hostname: string;
  email: string;
  api_token: string;
  default_project_key: string;
  default_issue_type: string;
  auto_create_enabled: boolean;
  auto_create_min_severity: string;
  open_to_close_transitions: string[];
  close_to_open_transitions: string[];
}

const defaultForm: JiraFormState = {
  hostname: '',
  email: '',
  api_token: '',
  default_project_key: '',
  default_issue_type: 'Bug',
  auto_create_enabled: false,
  auto_create_min_severity: 'high',
  open_to_close_transitions: [],
  close_to_open_transitions: [],
};

function TransitionListEditor({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const [input, setInput] = useState('');
  const add = () => {
    const trimmed = input.trim();
    if (trimmed && !value.includes(trimmed)) {
      onChange([...value, trimmed]);
    }
    setInput('');
  };
  const remove = (i: number) => onChange(value.filter((_, idx) => idx !== i));

  return (
    <div className="space-y-2">
      <label className="text-sm font-medium">{label}</label>
      <p className="text-xs text-muted-foreground">{hint}</p>
      <div className="space-y-1">
        {value.map((t, i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            {i > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
            {i === 0 && <span className="w-3 h-3 shrink-0" />}
            <span className="flex-1 bg-muted/50 rounded px-2 py-0.5 font-mono text-xs">{t}</span>
            <button onClick={() => remove(i)} className="text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <Input
          placeholder="Transition name, e.g. In Progress"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          className="text-sm h-8"
        />
        <Button size="sm" variant="outline" onClick={add} className="h-8 shrink-0">
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

interface CensysFormState {
  workspace_name: string;
  api_key: string;
  import_vulnerabilities: boolean;
  import_assets: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultCensysForm: CensysFormState = {
  workspace_name: '',
  api_key: '',
  import_vulnerabilities: true,
  import_assets: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const CENSYS_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatCensysInterval(minutes: number): string {
  const match = CENSYS_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function CensysSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<CensysIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<CensysIntegration | null>(null);
  const [form, setForm] = useState<CensysFormState>(defaultCensysForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CensysIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getCensysIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultCensysForm);
    setSetupOpen(true);
  }

  function openEdit(integration: CensysIntegration) {
    setEditing(integration);
    setForm({
      workspace_name: integration.workspace_name,
      api_key: '',
      import_vulnerabilities: integration.import_vulnerabilities,
      import_assets: integration.import_assets,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.workspace_name.trim()) {
      toast({ title: 'Workspace name is required.', variant: 'destructive' });
      return;
    }
    if (!editing && !form.api_key.trim()) {
      toast({ title: 'API key is required when adding a connection.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateCensysIntegration(editing.id, {
          workspace_name: form.workspace_name,
          ...(form.api_key ? { api_key: form.api_key } : {}),
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Censys ASM connection updated.' });
      } else {
        await api.createCensysIntegration({
          workspace_name: form.workspace_name,
          api_key: form.api_key,
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Censys ASM connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: CensysIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testCensysConnection(integration.id);
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

  async function handleSync(integration: CensysIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncCensysIntegration(integration.id);
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
      await api.deleteCensysIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Censys ASM connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#0A1F44] flex items-center justify-center shrink-0">
          <Radar className="w-5 h-5 text-[#4A90E2]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Censys ASM</CardTitle>
          <CardDescription className="text-sm">
            Import risks and assets that Censys Attack Surface Management has attributed to your organization. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} workspace{integrations.length > 1 ? 's' : ''}
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
                      <p className="font-medium text-sm truncate">{c.workspace_name}</p>
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
                          Auto-sync {formatCensysInterval(c.sync_interval_minutes).toLowerCase()}
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
                        {c.last_sync_stats.assets_created ?? 0} new assets, {c.last_sync_stats.vulns_created ?? 0} new risks imported.
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
              <Plus className="h-4 w-4 mr-2" />Add another workspace
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a Censys ASM workspace to ingest its discovered risks and assets into your attack surface.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Censys ASM
            </Button>
          </div>
        )}
      </CardContent>

      {/* Setup / Edit Dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5 text-[#4A90E2]" />
              {editing ? 'Edit Censys ASM connection' : 'Connect Censys ASM'}
            </DialogTitle>
            <DialogDescription>
              Each connection maps to one Censys ASM workspace. Generate a workspace-scoped API key from the Censys ASM Integrations page.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Workspace name</label>
              <Input
                placeholder="e.g. Production"
                value={form.workspace_name}
                onChange={(e) => setForm(f => ({ ...f, workspace_name: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">A label to identify this connection.</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                ASM API Key{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'Paste your workspace API key'}
                value={form.api_key}
                onChange={(e) => setForm(f => ({ ...f, api_key: e.target.value }))}
              />
              <a href="https://app.censys.io/integrations" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Get your ASM API key <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">What to import</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-assets"
                  checked={form.import_assets}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_assets: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-assets" className="text-sm cursor-pointer">
                  <span className="font-medium">Import assets</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Hosts, domains, subdomains, and certificates Censys attributes to you.</p>
                </label>
              </div>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-vulns"
                  checked={form.import_vulnerabilities}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_vulnerabilities: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-vulns" className="text-sm cursor-pointer">
                  <span className="font-medium">Import vulnerabilities</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Risks identified by Censys ASM, imported as findings.</p>
                </label>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps your inventory current by pulling new Censys risks and assets in the background.
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
                      {CENSYS_SYNC_INTERVALS.map(i => (
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
              This removes the stored API key for <strong>{deleteTarget?.workspace_name}</strong>. Assets and findings already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface HackerOneFormState {
  connection_name: string;
  api_identifier: string;
  api_token: string;
  import_vulnerabilities: boolean;
  import_scopes: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultHackerOneForm: HackerOneFormState = {
  connection_name: '',
  api_identifier: '',
  api_token: '',
  import_vulnerabilities: true,
  import_scopes: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const HACKERONE_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatHackerOneInterval(minutes: number): string {
  const match = HACKERONE_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function HackerOneSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<HackerOneIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<HackerOneIntegration | null>(null);
  const [form, setForm] = useState<HackerOneFormState>(defaultHackerOneForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<HackerOneIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getHackerOneIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultHackerOneForm);
    setSetupOpen(true);
  }

  function openEdit(integration: HackerOneIntegration) {
    setEditing(integration);
    setForm({
      connection_name: integration.connection_name,
      api_identifier: integration.api_identifier,
      api_token: '',
      import_vulnerabilities: integration.import_vulnerabilities,
      import_scopes: integration.import_scopes,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.connection_name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!form.api_identifier.trim()) {
      toast({ title: 'API Identifier is required.', variant: 'destructive' });
      return;
    }
    if (!editing && !form.api_token.trim()) {
      toast({ title: 'API Token is required when adding a connection.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateHackerOneIntegration(editing.id, {
          connection_name: form.connection_name,
          api_identifier: form.api_identifier,
          ...(form.api_token ? { api_token: form.api_token } : {}),
          import_vulnerabilities: form.import_vulnerabilities,
          import_scopes: form.import_scopes,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'HackerOne connection updated.' });
      } else {
        await api.createHackerOneIntegration({
          connection_name: form.connection_name,
          api_identifier: form.api_identifier,
          api_token: form.api_token,
          import_vulnerabilities: form.import_vulnerabilities,
          import_scopes: form.import_scopes,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'HackerOne connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: HackerOneIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testHackerOneConnection(integration.id);
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

  async function handleSync(integration: HackerOneIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncHackerOneIntegration(integration.id);
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
      await api.deleteHackerOneIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'HackerOne connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#494649] flex items-center justify-center shrink-0">
          <Bug className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">HackerOne</CardTitle>
          <CardDescription className="text-sm">
            Import bug bounty reports as findings and eligible program scopes as assets. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span>API ID: {c.api_identifier}</span>
                      <span>Import: {[c.import_scopes && 'Scopes', c.import_vulnerabilities && 'Reports'].filter(Boolean).join(' + ') || 'Nothing'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatHackerOneInterval(c.sync_interval_minutes).toLowerCase()}
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
                        {c.last_sync_stats.assets_created ?? 0} new assets, {c.last_sync_stats.vulns_created ?? 0} new reports
                        {typeof c.last_sync_stats.programs_seen === 'number' && (
                          <> across {c.last_sync_stats.programs_seen} program(s)</>
                        )}.
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect HackerOne to ingest researcher-reported vulnerabilities alongside the rest of your attack surface.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect HackerOne
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5" />
              {editing ? 'Edit HackerOne connection' : 'Connect HackerOne'}
            </DialogTitle>
            <DialogDescription>
              Create an API token in HackerOne Settings → API Tokens. Credentials are validated against your programs before saving.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. Production"
                value={form.connection_name}
                onChange={(e) => setForm(f => ({ ...f, connection_name: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">A label to identify this connection.</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">API Identifier</label>
              <Input
                placeholder="Your HackerOne API identifier"
                value={form.api_identifier}
                onChange={(e) => setForm(f => ({ ...f, api_identifier: e.target.value }))}
                autoComplete="username"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                API Token{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'Paste your API token'}
                value={form.api_token}
                onChange={(e) => setForm(f => ({ ...f, api_token: e.target.value }))}
                autoComplete="current-password"
              />
              <a href="https://hackerone.com/settings/api_token/edit" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Get your API token <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">What to import</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="h1-scopes"
                  checked={form.import_scopes}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_scopes: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="h1-scopes" className="text-sm cursor-pointer">
                  <span className="font-medium">Import program scopes</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Eligible URLs, domains, IPs, and CIDRs as in-scope assets.</p>
                </label>
              </div>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="h1-vulns"
                  checked={form.import_vulnerabilities}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_vulnerabilities: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="h1-vulns" className="text-sm cursor-pointer">
                  <span className="font-medium">Import vulnerability reports</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Bug bounty findings with severity, CWE, and status mapping.</p>
                </label>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="h1-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="h1-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps findings current by pulling new HackerOne reports and scopes in the background.
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
                      {HACKERONE_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes the stored HackerOne credentials for <strong>{deleteTarget?.connection_name}</strong>. Assets and findings already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface AkamaiFormState {
  connection_name: string;
  api_host: string;
  client_token: string;
  client_secret: string;
  access_token: string;
  import_configurations: boolean;
  import_hostnames: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultAkamaiForm: AkamaiFormState = {
  connection_name: '',
  api_host: '',
  client_token: '',
  client_secret: '',
  access_token: '',
  import_configurations: true,
  import_hostnames: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const AKAMAI_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatAkamaiInterval(minutes: number): string {
  const match = AKAMAI_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function AkamaiSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<AkamaiIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<AkamaiIntegration | null>(null);
  const [form, setForm] = useState<AkamaiFormState>(defaultAkamaiForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AkamaiIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getAkamaiIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultAkamaiForm);
    setSetupOpen(true);
  }

  function openEdit(integration: AkamaiIntegration) {
    setEditing(integration);
    setForm({
      connection_name: integration.connection_name,
      api_host: integration.api_host,
      client_token: '',
      client_secret: '',
      access_token: '',
      import_configurations: integration.import_configurations,
      import_hostnames: integration.import_hostnames,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.connection_name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!form.api_host.trim()) {
      toast({ title: 'API Host is required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.client_token.trim() || !form.client_secret.trim() || !form.access_token.trim())) {
      toast({ title: 'All EdgeGrid credential fields are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateAkamaiIntegration(editing.id, {
          connection_name: form.connection_name,
          api_host: form.api_host,
          ...(form.client_token ? { client_token: form.client_token } : {}),
          ...(form.client_secret ? { client_secret: form.client_secret } : {}),
          ...(form.access_token ? { access_token: form.access_token } : {}),
          import_configurations: form.import_configurations,
          import_hostnames: form.import_hostnames,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Akamai WAF connection updated.' });
      } else {
        await api.createAkamaiIntegration({
          connection_name: form.connection_name,
          api_host: form.api_host,
          client_token: form.client_token,
          client_secret: form.client_secret,
          access_token: form.access_token,
          import_configurations: form.import_configurations,
          import_hostnames: form.import_hostnames,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Akamai WAF connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: AkamaiIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testAkamaiConnection(integration.id);
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

  async function handleSync(integration: AkamaiIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncAkamaiIntegration(integration.id);
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
      await api.deleteAkamaiIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Akamai WAF connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#0096D6]/15 flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-[#0096D6]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Akamai WAF</CardTitle>
          <CardDescription className="text-sm">
            Import Application Security configurations, policies, and protected hostnames from Akamai. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono">{c.api_host}</span>
                      <span>Import: {[c.import_configurations && 'Configs', c.import_hostnames && 'Hostnames'].filter(Boolean).join(' + ') || 'Nothing'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatAkamaiInterval(c.sync_interval_minutes).toLowerCase()}
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
                        {c.last_sync_stats.assets_created ?? 0} new assets
                        {' · '}{c.last_sync_stats.configs_seen ?? 0} configs
                        {' · '}{c.last_sync_stats.policies_seen ?? 0} policies
                        {' · '}{c.last_sync_stats.hostnames_seen ?? 0} hostnames
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect Akamai Application Security (Kona / App &amp; API Protector) to inventory WAF configs and protected hostnames.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Akamai WAF
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-[#0096D6]" />
              {editing ? 'Edit Akamai WAF connection' : 'Connect Akamai WAF'}
            </DialogTitle>
            <DialogDescription>
              Enter EdgeGrid credentials with READ access to the Application Security API. Credentials are encrypted at rest and never written back to Akamai.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. Production"
                value={form.connection_name}
                onChange={(e) => setForm(f => ({ ...f, connection_name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">API Host</label>
              <Input
                placeholder="akab-xxxxx.luna.akamaiapis.net"
                value={form.api_host}
                onChange={(e) => setForm(f => ({ ...f, api_host: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">Hostname only — do not include https://</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                Client Token{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'EdgeGrid client token'}
                value={form.client_token}
                onChange={(e) => setForm(f => ({ ...f, client_token: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                Client Secret{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'EdgeGrid client secret'}
                value={form.client_secret}
                onChange={(e) => setForm(f => ({ ...f, client_secret: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                Access Token{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'EdgeGrid access token'}
                value={form.access_token}
                onChange={(e) => setForm(f => ({ ...f, access_token: e.target.value }))}
              />
              <a
                href="https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline inline-flex items-center gap-1"
              >
                Create EdgeGrid credentials <ExternalLink className="h-3 w-3" />
              </a>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">What to import</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="akamai-configs"
                  checked={form.import_configurations}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_configurations: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="akamai-configs" className="text-sm cursor-pointer">
                  <span className="font-medium">Import security configurations</span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Each AppSec config (with policies and mode) as a WAF configuration asset.
                  </p>
                </label>
              </div>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="akamai-hostnames"
                  checked={form.import_hostnames}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_hostnames: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="akamai-hostnames" className="text-sm cursor-pointer">
                  <span className="font-medium">Import protected hostnames</span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Hostnames covered by your WAF configs, imported as domain/subdomain assets.
                  </p>
                </label>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="akamai-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="akamai-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps WAF coverage and protected hostnames current in the background.
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
                      {AKAMAI_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes the stored EdgeGrid credentials for <strong>{deleteTarget?.connection_name}</strong>. Assets already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface PanoramaFormState {
  name: string;
  connection_mode: 'api' | 'config_export';
  panorama_host: string;
  api_key: string;
  device_group: string;
  api_version: string;
  verify_ssl: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultPanoramaForm: PanoramaFormState = {
  name: '',
  connection_mode: 'api',
  panorama_host: '',
  api_key: '',
  device_group: '',
  api_version: 'v11.1',
  verify_ssl: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const PANORAMA_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatPanoramaInterval(minutes: number): string {
  const match = PANORAMA_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function formatBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function PanoramaSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<PanoramaIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<PanoramaIntegration | null>(null);
  const [form, setForm] = useState<PanoramaFormState>(defaultPanoramaForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<PanoramaIntegration | null>(null);
  const [uploadTarget, setUploadTarget] = useState<PanoramaIntegration | null>(null);
  const [uploading, setUploading] = useState(false);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getPanoramaIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultPanoramaForm);
    setSetupOpen(true);
  }

  function openEdit(integration: PanoramaIntegration) {
    setEditing(integration);
    setForm({
      name: integration.name,
      connection_mode: integration.connection_mode || 'api',
      panorama_host: integration.panorama_host || '',
      api_key: '',
      device_group: integration.device_group || '',
      api_version: integration.api_version || 'v11.1',
      verify_ssl: integration.verify_ssl !== false,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (form.connection_mode === 'api') {
      if (!form.panorama_host.trim()) {
        toast({ title: 'Panorama host is required for API mode.', variant: 'destructive' });
        return;
      }
      if (!editing && !form.api_key.trim()) {
        toast({ title: 'API key is required for API mode.', variant: 'destructive' });
        return;
      }
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updatePanoramaIntegration(editing.id, {
          name: form.name.trim(),
          connection_mode: form.connection_mode,
          panorama_host: form.connection_mode === 'api' ? form.panorama_host.trim() : (form.panorama_host.trim() || null),
          ...(form.api_key ? { api_key: form.api_key } : {}),
          device_group: form.device_group.trim() || null,
          api_version: form.api_version.trim() || 'v11.1',
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Panorama connection updated.' });
      } else {
        const created = await api.createPanoramaIntegration({
          name: form.name.trim(),
          connection_mode: form.connection_mode,
          panorama_host: form.connection_mode === 'api' ? form.panorama_host.trim() : null,
          api_key: form.connection_mode === 'api' ? form.api_key : null,
          device_group: form.device_group.trim() || null,
          api_version: form.api_version.trim() || 'v11.1',
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({
          title: 'Panorama connection added.',
          description: form.connection_mode === 'config_export'
            ? 'Upload a configuration export next to import address objects.'
            : undefined,
        });
        setSetupOpen(false);
        await load();
        if (form.connection_mode === 'config_export') {
          setUploadTarget(created);
        }
        return;
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: PanoramaIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testPanoramaConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.ok && result.address_count != null
          ? `${result.message} (${result.address_count} address object(s) in scope)`
          : result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: PanoramaIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncPanoramaIntegration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Sync failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleUploadFile(file: File | null) {
    if (!uploadTarget || !file) return;
    setUploading(true);
    try {
      const result = await api.uploadPanoramaConfigExport(uploadTarget.id, file, true);
      toast({
        title: result.ok ? 'Export uploaded' : 'Upload failed',
        description: result.sync?.message || result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      setUploadTarget(null);
      await load();
    } catch (err) {
      toast({ title: 'Upload failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setUploading(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deletePanoramaIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Panorama connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#FA582D] flex items-center justify-center shrink-0">
          <svg viewBox="0 0 24 24" fill="white" className="w-5 h-5" aria-hidden="true">
            <path d="M12 2 3 6.5v5.2c0 5.4 3.7 10.4 9 11.8 5.3-1.4 9-6.4 9-11.8V6.5L12 2zm0 2.2 7 3.5v4.8c0 4.4-2.9 8.5-7 9.7-4.1-1.2-7-5.3-7-9.7V7.7l7-3.5z" />
            <path d="M11 8h2v5h-2V8zm0 7h2v2h-2v-2z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Palo Alto Networks Panorama</CardTitle>
          <CardDescription className="text-sm">
            Import firewall address objects via live REST API or air-gapped configuration exports. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {integrations.length > 0 ? (
          <div className="space-y-3">
            {integrations.map((c) => {
              const isExport = c.connection_mode === 'config_export';
              return (
                <div key={c.id} className="rounded-lg border border-border p-3 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="font-medium text-sm truncate">{c.name}</p>
                        <Badge variant="outline" className="text-xs">
                          {isExport ? 'Config export' : 'Live API'}
                        </Badge>
                        {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                        {c.last_test_ok === false && (
                          <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                            <AlertCircle className="h-3 w-3 mr-1" />{isExport ? 'Export issue' : 'Auth issue'}
                          </Badge>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                        {isExport ? (
                          <>
                            <span>
                              File: {c.export_filename
                                ? `${c.export_filename} (${formatBytes(c.export_file_size)})`
                                : 'No export uploaded yet'}
                            </span>
                            {c.export_uploaded_at && (
                              <span>Uploaded: {new Date(c.export_uploaded_at).toLocaleString()}</span>
                            )}
                          </>
                        ) : (
                          <>
                            <span className="font-mono truncate max-w-[240px]">{c.panorama_host}</span>
                            <span>API {c.api_version}</span>
                          </>
                        )}
                        <span>Scope: {c.device_group || (isExport ? 'all in file' : 'shared')}</span>
                        {c.continuous_sync_enabled ? (
                          <span className="inline-flex items-center gap-1 text-green-400">
                            <RotateCw className="h-3 w-3" />
                            Auto-sync {formatPanoramaInterval(c.sync_interval_minutes).toLowerCase()}
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
                      </div>
                      {c.last_sync_ok && c.last_sync_stats && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {c.last_sync_stats.assets_created ?? 0} new assets from {c.last_sync_stats.addresses_seen ?? 0} address object(s).
                        </p>
                      )}
                      {c.last_sync_ok === false && c.last_error && (
                        <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {isExport && (
                      <Button size="sm" variant="outline" onClick={() => setUploadTarget(c)} disabled={busyId === c.id}>
                        <Download className="h-4 w-4 mr-2" />Upload export
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleSync(c)}
                      disabled={busyId === c.id || !c.is_active || (isExport && !c.export_filename)}
                    >
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
              );
            })}
            <Button size="sm" variant="outline" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect Panorama over the network, or ingest scheduled configuration exports for air-gapped deployments.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Panorama
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {editing ? 'Edit Panorama connection' : 'Connect Palo Alto Panorama'}
            </DialogTitle>
            <DialogDescription>
              Choose live REST API access, or config-export mode for Panorama instances that are not reachable from ASM.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. HQ Panorama"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection mode</label>
              <Select
                value={form.connection_mode}
                onValueChange={(v: 'api' | 'config_export') => setForm(f => ({ ...f, connection_mode: v }))}
                disabled={!!editing}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="api">Live API (X-PAN-KEY)</SelectItem>
                  <SelectItem value="config_export">Config export (air-gapped)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {form.connection_mode === 'api'
                  ? 'ASM queries Panorama Objects/Addresses over HTTPS.'
                  : 'Upload scheduled Panorama .gz / .tgz / .xml exports. No network path to Panorama required.'}
              </p>
            </div>

            {form.connection_mode === 'api' ? (
              <>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Panorama host</label>
                  <Input
                    placeholder="https://panorama.example.com"
                    value={form.panorama_host}
                    onChange={(e) => setForm(f => ({ ...f, panorama_host: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">
                    API key{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
                  </label>
                  <Input
                    type="password"
                    placeholder={editing ? '••••••••••••' : 'Paste Panorama API key'}
                    value={form.api_key}
                    onChange={(e) => setForm(f => ({ ...f, api_key: e.target.value }))}
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Device group</label>
                    <Input
                      placeholder="Shared (blank)"
                      value={form.device_group}
                      onChange={(e) => setForm(f => ({ ...f, device_group: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">API version</label>
                    <Input
                      placeholder="v11.1"
                      value={form.api_version}
                      onChange={(e) => setForm(f => ({ ...f, api_version: e.target.value }))}
                    />
                  </div>
                </div>
                <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox
                    id="panorama-verify-ssl"
                    checked={form.verify_ssl}
                    onCheckedChange={(v) => setForm(f => ({ ...f, verify_ssl: !!v }))}
                    className="mt-0.5 shrink-0"
                  />
                  <label htmlFor="panorama-verify-ssl" className="text-sm cursor-pointer">
                    <span className="font-medium">Verify TLS certificate</span>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Turn off only for lab/self-signed Panorama instances.
                    </p>
                  </label>
                </div>
              </>
            ) : (
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Device group filter</label>
                <Input
                  placeholder="All scopes in file (blank)"
                  value={form.device_group}
                  onChange={(e) => setForm(f => ({ ...f, device_group: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground">
                  Optional. When set, imports that device group plus shared objects. Leave blank to import every address object found in the export.
                </p>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="panorama-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="panorama-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {form.connection_mode === 'config_export'
                      ? 'Re-parses the last uploaded export on a schedule. Prefer re-uploading after each Panorama export job.'
                      : 'Keeps firewall-managed inventory current in the background.'}
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
                      {PANORAMA_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!uploadTarget} onOpenChange={(v) => { if (!v && !uploading) setUploadTarget(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Upload Panorama config export</DialogTitle>
            <DialogDescription>
              Accepts <code className="text-xs">.gz</code>, <code className="text-xs">.tgz</code>, <code className="text-xs">.tar.gz</code>, or <code className="text-xs">.xml</code>.
              Address objects are imported immediately after a successful upload.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {uploadTarget?.export_filename && (
              <p className="text-xs text-muted-foreground">
                Current file: <span className="font-mono">{uploadTarget.export_filename}</span> ({formatBytes(uploadTarget.export_file_size)})
              </p>
            )}
            <Input
              type="file"
              accept=".gz,.tgz,.tar.gz,.xml,application/gzip,application/x-gzip,application/xml,text/xml"
              disabled={uploading}
              onChange={(e) => handleUploadFile(e.target.files?.[0] || null)}
            />
            {uploading && (
              <p className="text-xs text-muted-foreground inline-flex items-center gap-2">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Uploading and importing…
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadTarget(null)} disabled={uploading}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes credentials/export files for <strong>{deleteTarget?.name}</strong>. Assets already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface F5FormState {
  name: string;
  bigip_host: string;
  username: string;
  password: string;
  partition: string;
  verify_ssl: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultF5Form: F5FormState = {
  name: '',
  bigip_host: '',
  username: '',
  password: '',
  partition: '',
  verify_ssl: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const F5_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatF5Interval(minutes: number): string {
  const match = F5_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function F5Section() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<F5Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<F5Integration | null>(null);
  const [form, setForm] = useState<F5FormState>(defaultF5Form);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<F5Integration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getF5Integrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultF5Form);
    setSetupOpen(true);
  }

  function openEdit(integration: F5Integration) {
    setEditing(integration);
    setForm({
      name: integration.name,
      bigip_host: integration.bigip_host || '',
      username: '',
      password: '',
      partition: integration.partition || '',
      verify_ssl: integration.verify_ssl !== false,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!form.bigip_host.trim()) {
      toast({ title: 'BIG-IP host is required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.username.trim() || !form.password.trim())) {
      toast({ title: 'Username and password are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateF5Integration(editing.id, {
          name: form.name.trim(),
          bigip_host: form.bigip_host.trim(),
          ...(form.username ? { username: form.username } : {}),
          ...(form.password ? { password: form.password } : {}),
          partition: form.partition.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'F5 connection updated.' });
      } else {
        await api.createF5Integration({
          name: form.name.trim(),
          bigip_host: form.bigip_host.trim(),
          username: form.username.trim(),
          password: form.password,
          partition: form.partition.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'F5 connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: F5Integration) {
    setBusyId(integration.id);
    try {
      const result = await api.testF5Connection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.ok && result.virtual_count != null
          ? `${result.message} (${result.virtual_count} virtual server(s) in scope)`
          : result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: F5Integration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncF5Integration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
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
      await api.deleteF5Integration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'F5 connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#E4002B] flex items-center justify-center shrink-0">
          <svg viewBox="0 0 24 24" fill="white" className="w-5 h-5" aria-hidden="true">
            <path d="M4 6h16v2H4V6zm0 5h10v2H4v-2zm0 5h16v2H4v-2z" />
            <path d="M16 10h4v4h-4v-4z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">F5 BIG-IP</CardTitle>
          <CardDescription className="text-sm">
            Map internet-facing VIPs to internal pool members for reachability. Read-only iControl REST.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-medium text-sm truncate">{c.name}</p>
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono truncate max-w-[260px]">{c.bigip_host}</span>
                      <span>Partition: {c.partition || 'all'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatF5Interval(c.sync_interval_minutes).toLowerCase()}
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
                    </div>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.vips_imported ?? 0} VIP(s), {c.last_sync_stats.members_imported ?? 0} pool member(s)
                        {' '}from {c.last_sync_stats.virtuals_seen ?? 0} virtual(s).
                      </p>
                    )}
                    {c.last_sync_ok === false && c.last_error && (
                      <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleSync(c)}
                    disabled={busyId === c.id || !c.is_active}
                  >
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect BIG-IP to import VIP → pool-member mappings and see what is reachable from the internet.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect F5
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {editing ? 'Edit F5 connection' : 'Connect F5 BIG-IP'}
            </DialogTitle>
            <DialogDescription>
              Uses iControl REST to pull virtual servers and pool members. Credentials stay encrypted; ASM never writes back to BIG-IP.
              Prefer a least-privilege Auditor / Guest role that can read LTM virtuals and pools.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. DC1 BIG-IP"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">BIG-IP host</label>
              <Input
                placeholder="https://bigip.example.com"
                value={form.bigip_host}
                onChange={(e) => setForm(f => ({ ...f, bigip_host: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Username{editing && <span className="text-muted-foreground font-normal"> (optional)</span>}
                </label>
                <Input
                  placeholder={editing ? '••••••••' : 'admin'}
                  value={form.username}
                  onChange={(e) => setForm(f => ({ ...f, username: e.target.value }))}
                  autoComplete="username"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Password{editing && <span className="text-muted-foreground font-normal"> (optional)</span>}
                </label>
                <Input
                  type="password"
                  placeholder={editing ? '••••••••••••' : 'Management password'}
                  value={form.password}
                  onChange={(e) => setForm(f => ({ ...f, password: e.target.value }))}
                  autoComplete="current-password"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Partition</label>
              <Input
                placeholder="All partitions (blank) or Common"
                value={form.partition}
                onChange={(e) => setForm(f => ({ ...f, partition: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                Optional. Leave blank to import virtuals from every partition.
              </p>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border p-3">
              <Checkbox
                id="f5-verify-ssl"
                checked={form.verify_ssl}
                onCheckedChange={(v) => setForm(f => ({ ...f, verify_ssl: !!v }))}
                className="mt-0.5 shrink-0"
              />
              <label htmlFor="f5-verify-ssl" className="text-sm cursor-pointer">
                <span className="font-medium">Verify TLS certificate</span>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Turn off only for lab/self-signed BIG-IP management interfaces.
                </p>
              </label>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="f5-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="f5-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps VIP → internal reachability mappings current in the background.
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
                      {F5_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes credentials for <strong>{deleteTarget?.name}</strong>. Assets already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface FortiGateFormState {
  name: string;
  fortigate_host: string;
  api_token: string;
  vdom: string;
  verify_ssl: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultFortiGateForm: FortiGateFormState = {
  name: '',
  fortigate_host: '',
  api_token: '',
  vdom: '',
  verify_ssl: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const FORTIGATE_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatFortiGateInterval(minutes: number): string {
  const match = FORTIGATE_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function FortiGateSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<FortiGateIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<FortiGateIntegration | null>(null);
  const [form, setForm] = useState<FortiGateFormState>(defaultFortiGateForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<FortiGateIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getFortiGateIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultFortiGateForm);
    setSetupOpen(true);
  }

  function openEdit(integration: FortiGateIntegration) {
    setEditing(integration);
    setForm({
      name: integration.name,
      fortigate_host: integration.fortigate_host || '',
      api_token: '',
      vdom: integration.vdom || '',
      verify_ssl: integration.verify_ssl !== false,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!form.fortigate_host.trim()) {
      toast({ title: 'FortiGate host is required.', variant: 'destructive' });
      return;
    }
    if (!editing && !form.api_token.trim()) {
      toast({ title: 'A REST API token is required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateFortiGateIntegration(editing.id, {
          name: form.name.trim(),
          fortigate_host: form.fortigate_host.trim(),
          ...(form.api_token ? { api_token: form.api_token } : {}),
          vdom: form.vdom.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'FortiGate connection updated.' });
      } else {
        await api.createFortiGateIntegration({
          name: form.name.trim(),
          fortigate_host: form.fortigate_host.trim(),
          api_token: form.api_token,
          vdom: form.vdom.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'FortiGate connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: FortiGateIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testFortiGateConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.ok && result.address_count != null
          ? `${result.message} (${result.address_count} address object(s) in scope)`
          : result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: FortiGateIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncFortiGateIntegration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
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
      await api.deleteFortiGateIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'FortiGate connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#DA291C] flex items-center justify-center shrink-0">
          <svg viewBox="0 0 24 24" fill="white" className="w-5 h-5" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 8.6 8 11 4.6-2.4 8-6 8-11V5l-8-3zm0 2.2 6 2.2V11c0 3.9-2.5 6.9-6 8.9-3.5-2-6-5-6-8.9V6.4l6-2.2z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Fortinet FortiGate</CardTitle>
          <CardDescription className="text-sm">
            Import firewall address objects (subnets, ranges, FQDNs) as assets. Read-only FortiOS REST.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-medium text-sm truncate">{c.name}</p>
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono truncate max-w-[260px]">{c.fortigate_host}</span>
                      <span>VDOM: {c.vdom || 'root'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatFortiGateInterval(c.sync_interval_minutes).toLowerCase()}
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
                    </div>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.ips_imported ?? 0} IP(s), {c.last_sync_stats.cidrs_imported ?? 0} subnet(s), {c.last_sync_stats.fqdns_imported ?? 0} FQDN(s)
                        {' '}from {c.last_sync_stats.addresses_seen ?? 0} object(s).
                      </p>
                    )}
                    {c.last_sync_ok === false && c.last_error && (
                      <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleSync(c)}
                    disabled={busyId === c.id || !c.is_active}
                  >
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect FortiGate to import firewall-managed address objects and keep external inventory in sync.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect FortiGate
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {editing ? 'Edit FortiGate connection' : 'Connect Fortinet FortiGate'}
            </DialogTitle>
            <DialogDescription>
              Uses the FortiOS REST API to pull firewall address objects. The token stays encrypted; ASM never writes back to the FortiGate.
              Prefer a least-privilege REST API admin with read-only access to the address configuration.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. Perimeter FortiGate"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">FortiGate host</label>
              <Input
                placeholder="https://fortigate.example.com"
                value={form.fortigate_host}
                onChange={(e) => setForm(f => ({ ...f, fortigate_host: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                REST API token{editing && <span className="text-muted-foreground font-normal"> (optional)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'Paste FortiOS REST API token'}
                value={form.api_token}
                onChange={(e) => setForm(f => ({ ...f, api_token: e.target.value }))}
                autoComplete="off"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">VDOM</label>
              <Input
                placeholder="Management VDOM (blank) or root"
                value={form.vdom}
                onChange={(e) => setForm(f => ({ ...f, vdom: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                Optional. Leave blank to use the management VDOM.
              </p>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border p-3">
              <Checkbox
                id="fortigate-verify-ssl"
                checked={form.verify_ssl}
                onCheckedChange={(v) => setForm(f => ({ ...f, verify_ssl: !!v }))}
                className="mt-0.5 shrink-0"
              />
              <label htmlFor="fortigate-verify-ssl" className="text-sm cursor-pointer">
                <span className="font-medium">Verify TLS certificate</span>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Turn off only for lab/self-signed FortiGate management interfaces.
                </p>
              </label>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="fortigate-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="fortigate-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps firewall-managed inventory current in the background.
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
                      {FORTIGATE_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes credentials for <strong>{deleteTarget?.name}</strong>. Assets already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface CheckPointFormState {
  name: string;
  management_host: string;
  username: string;
  password: string;
  domain: string;
  verify_ssl: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultCheckPointForm: CheckPointFormState = {
  name: '',
  management_host: '',
  username: '',
  password: '',
  domain: '',
  verify_ssl: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const CHECKPOINT_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatCheckPointInterval(minutes: number): string {
  const match = CHECKPOINT_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function CheckPointSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<CheckPointIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<CheckPointIntegration | null>(null);
  const [form, setForm] = useState<CheckPointFormState>(defaultCheckPointForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CheckPointIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getCheckPointIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultCheckPointForm);
    setSetupOpen(true);
  }

  function openEdit(integration: CheckPointIntegration) {
    setEditing(integration);
    setForm({
      name: integration.name,
      management_host: integration.management_host || '',
      username: '',
      password: '',
      domain: integration.domain || '',
      verify_ssl: integration.verify_ssl !== false,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!form.management_host.trim()) {
      toast({ title: 'Management host is required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.username.trim() || !form.password.trim())) {
      toast({ title: 'Username and password are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateCheckPointIntegration(editing.id, {
          name: form.name.trim(),
          management_host: form.management_host.trim(),
          ...(form.username ? { username: form.username } : {}),
          ...(form.password ? { password: form.password } : {}),
          domain: form.domain.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Check Point connection updated.' });
      } else {
        await api.createCheckPointIntegration({
          name: form.name.trim(),
          management_host: form.management_host.trim(),
          username: form.username.trim(),
          password: form.password,
          domain: form.domain.trim() || null,
          verify_ssl: form.verify_ssl,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Check Point connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: CheckPointIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testCheckPointConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.ok && result.object_count != null
          ? `${result.message} (${result.object_count} host object(s) in scope)`
          : result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: CheckPointIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncCheckPointIntegration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
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
      await api.deleteCheckPointIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Check Point connection removed.' });
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
        <div className="w-10 h-10 rounded-lg bg-[#E6017C] flex items-center justify-center shrink-0">
          <svg viewBox="0 0 24 24" fill="white" className="w-5 h-5" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 8.6 8 11 4.6-2.4 8-6 8-11V5l-8-3zm0 2.2 6 2.2V11c0 3.9-2.5 6.9-6 8.9-3.5-2-6-5-6-8.9V6.4l6-2.2z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Check Point</CardTitle>
          <CardDescription className="text-sm">
            Import host, network, and address-range objects as assets. Read-only Management Web API.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-medium text-sm truncate">{c.name}</p>
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono truncate max-w-[260px]">{c.management_host}</span>
                      <span>Domain: {c.domain || 'SMS'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatCheckPointInterval(c.sync_interval_minutes).toLowerCase()}
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
                    </div>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.hosts_seen ?? 0} host(s), {c.last_sync_stats.networks_seen ?? 0} network(s), {c.last_sync_stats.ranges_seen ?? 0} range(s) imported.
                      </p>
                    )}
                    {c.last_sync_ok === false && c.last_error && (
                      <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleSync(c)}
                    disabled={busyId === c.id || !c.is_active}
                  >
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a Security Management Server to import managed network objects and keep external inventory in sync.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Check Point
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {editing ? 'Edit Check Point connection' : 'Connect Check Point'}
            </DialogTitle>
            <DialogDescription>
              Uses the Management Web API to read host, network, and address-range objects. Credentials stay encrypted and sessions are
              opened read-only; ASM never publishes changes to the management server.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. HQ Management"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Management host</label>
              <Input
                placeholder="https://mgmt.example.com"
                value={form.management_host}
                onChange={(e) => setForm(f => ({ ...f, management_host: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Username{editing && <span className="text-muted-foreground font-normal"> (optional)</span>}
                </label>
                <Input
                  placeholder={editing ? '••••••••' : 'api-reader'}
                  value={form.username}
                  onChange={(e) => setForm(f => ({ ...f, username: e.target.value }))}
                  autoComplete="username"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Password{editing && <span className="text-muted-foreground font-normal"> (optional)</span>}
                </label>
                <Input
                  type="password"
                  placeholder={editing ? '••••••••••••' : 'Management password'}
                  value={form.password}
                  onChange={(e) => setForm(f => ({ ...f, password: e.target.value }))}
                  autoComplete="current-password"
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Domain</label>
              <Input
                placeholder="Single-domain SMS (blank) or MDS domain name"
                value={form.domain}
                onChange={(e) => setForm(f => ({ ...f, domain: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                Optional. Set only for a Multi-Domain Server (MDS).
              </p>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border p-3">
              <Checkbox
                id="checkpoint-verify-ssl"
                checked={form.verify_ssl}
                onCheckedChange={(v) => setForm(f => ({ ...f, verify_ssl: !!v }))}
                className="mt-0.5 shrink-0"
              />
              <label htmlFor="checkpoint-verify-ssl" className="text-sm cursor-pointer">
                <span className="font-medium">Verify TLS certificate</span>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Turn off only for lab/self-signed management interfaces.
                </p>
              </label>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="checkpoint-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="checkpoint-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps firewall-managed inventory current in the background.
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
                      {CHECKPOINT_SYNC_INTERVALS.map(i => (
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes credentials for <strong>{deleteTarget?.name}</strong>. Assets already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

interface CloudflareFormState {
  connection_name: string;
  api_token: string;
  zones_text: string;
  scanner_ips_text: string;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultCloudflareForm: CloudflareFormState = {
  connection_name: '',
  api_token: '',
  zones_text: '',
  scanner_ips_text: '',
  continuous_sync_enabled: true,
  sync_interval_minutes: 1440,
};

const CLOUDFLARE_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatCloudflareInterval(minutes: number): string {
  const match = CLOUDFLARE_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function linesToList(text: string): string[] {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function CloudflareSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<CloudflareIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<CloudflareIntegration | null>(null);
  const [form, setForm] = useState<CloudflareFormState>(defaultCloudflareForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CloudflareIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getCloudflareIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultCloudflareForm);
    setSetupOpen(true);
  }

  function openEdit(integration: CloudflareIntegration) {
    setEditing(integration);
    setForm({
      connection_name: integration.connection_name,
      api_token: '',
      zones_text: (integration.zones || []).join('\n'),
      scanner_ips_text: (integration.scanner_ips || []).join('\n'),
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.connection_name.trim()) {
      toast({ title: 'Connection name is required.', variant: 'destructive' });
      return;
    }
    if (!editing && !form.api_token.trim()) {
      toast({ title: 'API token is required.', variant: 'destructive' });
      return;
    }

    setSaving(true);
    try {
      const zones = linesToList(form.zones_text);
      const scanner_ips = linesToList(form.scanner_ips_text);
      if (editing) {
        await api.updateCloudflareIntegration(editing.id, {
          connection_name: form.connection_name.trim(),
          ...(form.api_token.trim() ? { api_token: form.api_token.trim() } : {}),
          zones,
          scanner_ips,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Cloudflare WAF connection updated.' });
      } else {
        await api.createCloudflareIntegration({
          connection_name: form.connection_name.trim(),
          api_token: form.api_token.trim(),
          zones,
          scanner_ips,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Cloudflare WAF connected — whitelist sync started.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Save failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: CloudflareIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testCloudflareConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: CloudflareIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncCloudflareIntegration(integration.id);
      toast({
        title: result.ok ? 'Whitelist synced' : 'Sync failed',
        description: result.message,
        variant: result.ok ? 'default' : 'destructive',
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
      await api.deleteCloudflareIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({
        title: 'Cloudflare WAF connection removed.',
        description: 'Managed WAF rules were left in Cloudflare — delete “(Managed By Judah)” rules manually if desired.',
      });
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
        <div className="w-10 h-10 rounded-lg bg-[#F6821F]/15 flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-[#F6821F]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Cloudflare WAF</CardTitle>
          <CardDescription className="text-sm">
            Create a targeted WAF skip rule so Judah Security scanner traffic is not blocked. Syncs daily by default.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} connection{integrations.length > 1 ? 's' : ''}
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
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span>
                        Zones: {(c.zones || []).length > 0 ? (c.zones || []).join(', ') : 'All account zones'}
                      </span>
                      <span className="font-mono">{c.scan_header_name}</span>
                      <span className="font-mono truncate max-w-[220px]" title={c.scanner_user_agent}>
                        UA: {c.scanner_user_agent}
                      </span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatCloudflareInterval(c.sync_interval_minutes).toLowerCase()}
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
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      Scanner IPs: {(c.effective_scanner_ips || []).length > 0
                        ? (c.effective_scanner_ips || []).join(', ')
                        : 'None configured — set ASM_SCANNER_EGRESS_IPS or per-connection IPs'}
                    </p>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.zones_seen ?? 0} zones
                        {' · '}{c.last_sync_stats.rules_created ?? 0} created
                        {' · '}{c.last_sync_stats.rules_updated ?? 0} updated
                        {' · '}{c.last_sync_stats.rules_skipped ?? 0} unchanged
                        {(c.last_sync_stats.rules_failed ?? 0) > 0 && (
                          <span className="text-red-400"> · {c.last_sync_stats.rules_failed} failed</span>
                        )}
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
                    Sync whitelist
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
              <Plus className="h-4 w-4 mr-2" />Add another connection
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect Cloudflare so scans can bypass WAF / bot / rate-limit blocks via a managed custom rule labeled “(Managed By Judah)”.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Cloudflare WAF
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-[#F6821F]" />
              {editing ? 'Edit Cloudflare WAF connection' : 'Connect Cloudflare WAF'}
            </DialogTitle>
            <DialogDescription>
              Token needs Account Rulesets:Read, Zone WAF:Edit, and Zone Settings:Read. A unique scan header secret is generated automatically.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Connection name</label>
              <Input
                placeholder="e.g. Production"
                value={form.connection_name}
                onChange={(e) => setForm(f => ({ ...f, connection_name: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                API Token{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'Cloudflare API token'}
                value={form.api_token}
                onChange={(e) => setForm(f => ({ ...f, api_token: e.target.value }))}
              />
              <a
                href="https://dash.cloudflare.com/profile/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline inline-flex items-center gap-1"
              >
                Create API token <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Zones <span className="text-muted-foreground font-normal">(optional)</span></label>
              <textarea
                className="flex min-h-[88px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                placeholder={"example.com\napp.example.com"}
                value={form.zones_text}
                onChange={(e) => setForm(f => ({ ...f, zones_text: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">One zone per line. Leave blank to apply to all zones the token can see.</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Scanner IPs <span className="text-muted-foreground font-normal">(optional override)</span></label>
              <textarea
                className="flex min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                placeholder={"203.0.113.10\n198.51.100.0/24"}
                value={form.scanner_ips_text}
                onChange={(e) => setForm(f => ({ ...f, scanner_ips_text: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                Defaults to platform <code className="text-[11px]">ASM_SCANNER_EGRESS_IPS</code> when empty.
              </p>
            </div>
            <div className="flex items-start gap-3 rounded-lg border border-border p-3">
              <Checkbox
                id="cf-continuous"
                checked={form.continuous_sync_enabled}
                onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                className="mt-0.5 shrink-0"
              />
              <div className="flex-1 space-y-2">
                <label htmlFor="cf-continuous" className="text-sm cursor-pointer">
                  Keep whitelist rules synchronized
                </label>
                {form.continuous_sync_enabled && (
                  <Select
                    value={String(form.sync_interval_minutes)}
                    onValueChange={(v) => setForm(f => ({ ...f, sync_interval_minutes: Number(v) }))}
                  >
                    <SelectTrigger className="w-48 h-8"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {CLOUDFLARE_SYNC_INTERVALS.map(i => (
                        <SelectItem key={i.value} value={String(i.value)}>{i.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
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

      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes stored credentials for <strong>{deleteTarget?.connection_name}</strong>. Cloudflare WAF rules are not deleted automatically.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

export default function IntegrationsPage() {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<JiraIntegration | null>(null);
  const [loadingIntegration, setLoadingIntegration] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [form, setForm] = useState<JiraFormState>(defaultForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; display_name?: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [activeTab, setActiveTab] = useState<'auth' | 'auto' | 'transitions'>('auth');

  // Admin org-selector state
  const [currentUser, setCurrentUser] = useState<{ is_superuser?: boolean; organization_id?: number } | null>(null);
  const [organizations, setOrganizations] = useState<{ id: number; name: string }[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<number | undefined>(undefined);

  useEffect(() => {
    async function bootstrap() {
      try {
        const user = await api.getCurrentUser();
        setCurrentUser(user);
        if (user.is_superuser) {
          const orgs = await api.getOrganizations();
          const list = Array.isArray(orgs) ? orgs : orgs.items || [];
          setOrganizations(list);
        }
      } catch { /* ignore */ }
      loadIntegration();
    }
    bootstrap();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reload integration whenever the selected org changes
  useEffect(() => {
    loadIntegration();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId]);

  async function loadIntegration() {
    setLoadingIntegration(true);
    try {
      const data = await api.getJiraIntegration(selectedOrgId);
      setIntegration(data);
    } catch {
      setIntegration(null);
    } finally {
      setLoadingIntegration(false);
    }
  }

  function openSetup() {
    if (integration) {
      setForm({
        hostname: integration.hostname,
        email: integration.email,
        api_token: '',
        default_project_key: integration.default_project_key || '',
        default_issue_type: integration.default_issue_type || 'Bug',
        auto_create_enabled: integration.auto_create_enabled,
        auto_create_min_severity: integration.auto_create_min_severity || 'high',
        open_to_close_transitions: integration.open_to_close_transitions || [],
        close_to_open_transitions: integration.close_to_open_transitions || [],
      });
    } else {
      setForm(defaultForm);
    }
    setTestResult(null);
    setActiveTab('auth');
    setSetupOpen(true);
  }

  async function handleTest() {
    if (!integration) { toast({ title: 'Save the integration first to test it.', variant: 'destructive' }); return; }
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testJiraConnection(selectedOrgId);
      setTestResult(result);
      await loadIntegration();
    } catch (err) {
      setTestResult({ ok: false, message: getApiErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!form.hostname || !form.email) { toast({ title: 'Hostname and email are required.', variant: 'destructive' }); return; }
    if (!integration && !form.api_token) { toast({ title: 'API token is required when creating the integration.', variant: 'destructive' }); return; }
    setSaving(true);
    try {
      const payload = {
        hostname: form.hostname,
        email: form.email,
        ...(form.api_token ? { api_token: form.api_token } : {}),
        default_project_key: form.default_project_key || undefined,
        default_issue_type: form.default_issue_type || 'Bug',
        auto_create_enabled: form.auto_create_enabled,
        auto_create_min_severity: form.auto_create_min_severity,
        open_to_close_transitions: form.open_to_close_transitions,
        close_to_open_transitions: form.close_to_open_transitions,
      };
      if (integration) {
        await api.updateJiraIntegration(payload, selectedOrgId);
        toast({ title: 'Jira integration updated.' });
      } else {
        await api.createJiraIntegration({ ...payload, api_token: form.api_token }, selectedOrgId);
        toast({ title: 'Jira integration configured.' });
      }
      setSetupOpen(false);
      await loadIntegration();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await api.deleteJiraIntegration(selectedOrgId);
      setIntegration(null);
      setDeleteOpen(false);
      toast({ title: 'Jira integration removed.' });
    } catch (err) {
      toast({ title: 'Failed to remove', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setDeleting(false);
    }
  }

  const tabBtn = (id: typeof activeTab, label: string) => (
    <button
      onClick={() => setActiveTab(id)}
      className={cn(
        'px-3 py-1.5 text-sm rounded-md transition-colors',
        activeTab === id
          ? 'bg-primary/15 text-primary border border-primary/25'
          : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
      )}
    >
      {label}
    </button>
  );

  return (
    <MainLayout>
      <Header title="Integrations" subtitle="Connect ASM to third-party platforms to push findings and automate workflows." />
      <div className="p-6 space-y-6">

        {/* Admin org selector — only visible to superusers */}
        {currentUser?.is_superuser && organizations.length > 0 && (
          <Card className="border border-primary/20 bg-primary/5">
            <CardContent className="py-3 px-4 flex items-center gap-3">
              <Settings2 className="h-4 w-4 text-primary shrink-0" />
              <span className="text-sm font-medium text-primary">Admin view — configure for:</span>
              <Select
                value={selectedOrgId ? String(selectedOrgId) : '__own__'}
                onValueChange={(v) => {
                  setSelectedOrgId(v === '__own__' ? undefined : Number(v));
                  setIntegration(null);
                }}
              >
                <SelectTrigger className="h-8 w-56 text-sm border-primary/30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__own__">My organization</SelectItem>
                  {organizations.map((org) => (
                    <SelectItem key={org.id} value={String(org.id)}>
                      {org.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedOrgId && (
                <Badge variant="outline" className="text-primary border-primary/40 text-xs">
                  Org #{selectedOrgId}
                </Badge>
              )}
            </CardContent>
          </Card>
        )}
        <Card className="border border-border">
          <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
            <div className="w-10 h-10 rounded-lg bg-[#0052CC] flex items-center justify-center shrink-0">
              <svg viewBox="0 0 24 24" fill="white" className="w-6 h-6">
                <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <CardTitle className="text-base">Atlassian Jira</CardTitle>
              <CardDescription className="text-sm">
                Push vulnerability findings to Jira, sync status bidirectionally, and auto-create tickets on discovery.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {loadingIntegration ? (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              ) : integration ? (
                <Badge variant="outline" className={cn(
                  integration.is_active && integration.last_test_ok !== false
                    ? 'bg-green-500/10 text-green-400 border-green-500/30'
                    : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
                )}>
                  {integration.is_active && integration.last_test_ok !== false
                    ? <><CheckCircle2 className="h-3 w-3 mr-1" />Connected</>
                    : <><AlertCircle className="h-3 w-3 mr-1" />Check config</>}
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
              )}
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            {integration ? (
              <>
                {/* Summary grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Hostname</p>
                    <p className="font-mono text-xs">{integration.hostname}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auth email</p>
                    <p className="text-xs">{integration.email}</p>
                  </div>
                  {integration.default_project_key && (
                    <div>
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Default project</p>
                      <p className="font-mono text-xs">{integration.default_project_key}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auto-create</p>
                    <p className="text-xs">
                      {integration.auto_create_enabled
                        ? <span className="text-green-400">Enabled — {integration.auto_create_min_severity?.toUpperCase()}+</span>
                        : <span className="text-muted-foreground">Disabled</span>}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Status sync</p>
                    <p className="text-xs">
                      {(integration.open_to_close_transitions?.length || 0) > 0
                        ? <span className="text-green-400">
                            {integration.open_to_close_transitions.length} close + {integration.close_to_open_transitions.length} reopen transitions
                          </span>
                        : <span className="text-muted-foreground">Not configured</span>}
                    </p>
                  </div>
                </div>

                {integration.last_tested_at && (
                  <p className="text-xs text-muted-foreground">
                    Last tested: {new Date(integration.last_tested_at).toLocaleString()}{' '}
                    {integration.last_test_ok === true && <span className="text-green-400">— OK</span>}
                    {integration.last_test_ok === false && <span className="text-red-400">— Failed</span>}
                  </p>
                )}

                {testResult && (
                  <div className={cn(
                    'flex items-start gap-2 rounded-lg border p-3 text-sm',
                    testResult.ok ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300',
                  )}>
                    {testResult.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 shrink-0" />}
                    <span>{testResult.message}{testResult.display_name && ` (${testResult.display_name})`}</span>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
                    {testing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                    Test connection
                  </Button>
                  <Button size="sm" variant="outline" onClick={openSetup}>
                    <Settings2 className="h-4 w-4 mr-2" />Edit
                  </Button>
                  <a href={`https://${integration.hostname.replace(/^https?:\/\//, '')}`} target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="outline">
                      <ExternalLink className="h-4 w-4 mr-2" />Open Jira
                    </Button>
                  </a>
                  <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteOpen(true)}>
                    <Trash2 className="h-4 w-4 mr-2" />Remove
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                <p className="text-sm text-muted-foreground flex-1">
                  Connect your Jira workspace to create tickets, sync statuses, and auto-create issues from findings.
                </p>
                <Button onClick={openSetup}>
                  <Plug className="h-4 w-4 mr-2" />Set up Jira
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Censys ASM Integration Card */}
        <CensysSection />

        {/* HackerOne Bug Bounty Integration Card */}
        <HackerOneSection />

        {/* Akamai WAF Integration Card */}
        <AkamaiSection />

        {/* Palo Alto Panorama Integration Card */}
        <PanoramaSection />

        {/* F5 BIG-IP Reachability Integration Card */}
        <F5Section />

        {/* Fortinet FortiGate Firewall Integration Card */}
        <FortiGateSection />

        {/* Check Point Firewall Integration Card */}
        <CheckPointSection />

        {/* Cloudflare WAF Integration Card */}
        <CloudflareSection />

        {/* ServiceNow ITSM Integration Card */}
        <ServiceNowSection selectedOrgId={selectedOrgId} />

        {/* Placeholder integrations */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { name: 'Slack', desc: 'Send alerts to Slack channels on new critical findings.' },
            { name: 'PagerDuty', desc: 'Page on-call when P0/P1 findings are detected.' },
          ].map((item) => (
            <Card key={item.name} className="border border-border opacity-50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">{item.name}</CardTitle>
                <CardDescription className="text-xs">{item.desc}</CardDescription>
              </CardHeader>
              <CardContent>
                <Badge variant="outline" className="text-xs text-muted-foreground">Coming soon</Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Setup / Edit Dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#0052CC] flex items-center justify-center">
                <svg viewBox="0 0 24 24" fill="white" className="w-4 h-4">
                  <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
                </svg>
              </div>
              {integration ? 'Edit Jira Integration' : 'Connect Jira'}
            </DialogTitle>
            <DialogDescription>
              Configure authentication, auto-create behavior, and bidirectional status sync.
            </DialogDescription>
          </DialogHeader>

          {/* Tab navigation */}
          <div className="flex gap-1 border-b border-border pb-2">
            {tabBtn('auth', '1. Authentication')}
            {tabBtn('auto', '2. Auto-create')}
            {tabBtn('transitions', '3. Status Sync')}
          </div>

          <div className="space-y-4 py-2 min-h-[280px]">

            {/* ── Auth tab ── */}
            {activeTab === 'auth' && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Hostname</label>
                  <Input placeholder="myorg.atlassian.net" value={form.hostname} onChange={(e) => setForm(f => ({ ...f, hostname: e.target.value }))} />
                  <p className="text-xs text-muted-foreground">Your Jira Cloud instance URL (without https://)</p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Email</label>
                  <Input type="email" placeholder="admin@yourcompany.com" value={form.email} onChange={(e) => setForm(f => ({ ...f, email: e.target.value }))} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">
                    API Token{integration && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
                  </label>
                  <Input type="password" placeholder={integration ? '••••••••••••' : 'Paste your API token'} value={form.api_token} onChange={(e) => setForm(f => ({ ...f, api_token: e.target.value }))} />
                  <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                    Create API token <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Default project</label>
                  <JiraProjectPicker
                    orgId={selectedOrgId}
                    value={form.default_project_key}
                    enabled={!!integration}
                    onChange={(key) => setForm((f) => ({ ...f, default_project_key: key }))}
                    placeholder={integration ? 'Search e.g. ITVM or Vulnerability Management…' : 'Save credentials first to search projects'}
                  />
                  {!integration && (
                    <p className="text-xs text-muted-foreground">
                      Save hostname / email / API token first, then reopen to search and select the project (e.g. ITVM).
                    </p>
                  )}
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Default issue type</label>
                  <Select value={form.default_issue_type} onValueChange={(v) => setForm(f => ({ ...f, default_issue_type: v }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {['Bug', 'Task', 'Story', 'Epic', 'Vulnerability', 'Security'].map(t => (
                        <SelectItem key={t} value={t}>{t}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}

            {/* ── Auto-create tab ── */}
            {activeTab === 'auto' && (
              <div className="space-y-5">
                <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox
                    id="auto-create"
                    checked={form.auto_create_enabled}
                    onCheckedChange={(v) => setForm(f => ({ ...f, auto_create_enabled: !!v }))}
                    className="mt-0.5 shrink-0"
                  />
                  <div>
                    <label htmlFor="auto-create" className="text-sm font-medium cursor-pointer flex items-center gap-2">
                      <Zap className="h-4 w-4 text-yellow-400" />
                      Auto-create Jira tickets on discovery
                    </label>
                    <p className="text-xs text-muted-foreground mt-1">
                      When a new vulnerability is detected at or above the minimum severity, a Jira ticket is automatically created using the default project and issue type above.
                    </p>
                  </div>
                </div>

                {form.auto_create_enabled && (
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Minimum severity threshold</label>
                    <Select value={form.auto_create_min_severity} onValueChange={(v) => setForm(f => ({ ...f, auto_create_min_severity: v }))}>
                      <SelectTrigger className="w-48">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITIES.map(s => (
                          <SelectItem key={s} value={s}>
                            <span className={cn(
                              'capitalize font-medium',
                              s === 'critical' ? 'text-red-400' :
                              s === 'high' ? 'text-orange-400' :
                              s === 'medium' ? 'text-yellow-400' :
                              s === 'low' ? 'text-blue-400' : 'text-muted-foreground'
                            )}>{s.toUpperCase()} and above</span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      Requires a default project key to be set on the Authentication tab.
                    </p>
                  </div>
                )}

                {!form.auto_create_enabled && (
                  <p className="text-sm text-muted-foreground">
                    When disabled, tickets must be created manually from the Findings page.
                  </p>
                )}
              </div>
            )}

            {/* ── Transitions tab ── */}
            {activeTab === 'transitions' && (
              <div className="space-y-6">
                <div className="rounded-lg border border-border bg-muted/20 p-3 text-xs text-muted-foreground space-y-1">
                  <p className="flex items-center gap-2 text-foreground font-medium text-sm">
                    <ArrowLeftRight className="h-4 w-4" />
                    Bidirectional Status Sync
                  </p>
                  <p>When a vulnerability status changes in ASM, linked Jira tickets are automatically transitioned through your configured workflow sequences. Enter the <strong>exact transition names</strong> as they appear in your Jira project settings.</p>
                </div>

                <TransitionListEditor
                  label="Open → Close transitions"
                  hint="Executed when a finding is marked Resolved, Accepted, Mitigated, or False Positive. Example: In Progress → Done"
                  value={form.open_to_close_transitions}
                  onChange={(v) => setForm(f => ({ ...f, open_to_close_transitions: v }))}
                />

                <TransitionListEditor
                  label="Close → Open transitions"
                  hint="Executed when a resolved finding is reopened or redetected. Example: Reopen Issue"
                  value={form.close_to_open_transitions}
                  onChange={(v) => setForm(f => ({ ...f, close_to_open_transitions: v }))}
                />

                <div className="rounded-lg border border-border p-3 text-xs text-muted-foreground space-y-1">
                  <p className="font-medium text-foreground">Tip: finding your transition names</p>
                  <p>In Jira, go to <strong>Project settings → Workflows</strong> and click on your workflow to see all available transitions and their names.</p>
                  <p>After you connect an integration and have an active ticket, you can also click "Jira" on a finding and look at the available transitions displayed there.</p>
                </div>
              </div>
            )}
          </div>

          <DialogFooter className="gap-2 pt-2 border-t border-border">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {integration ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={deleteOpen} onOpenChange={(v) => { if (!deleting) setDeleteOpen(v); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove Jira integration
            </DialogTitle>
            <DialogDescription>
              This removes the stored credentials and disables all Jira features. Existing tickets in Jira will not be affected.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={deleting}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
