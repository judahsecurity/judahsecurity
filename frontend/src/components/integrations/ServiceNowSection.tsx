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
  XCircle,
  Plug,
  Trash2,
  RefreshCw,
  AlertCircle,
  Settings2,
  Shield,
  ArrowLeftRight,
  Download,
} from 'lucide-react';
import { api, getApiErrorMessage, type ServiceNowIntegration } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const ACCEPT_AS = [
  { value: 'resolved', label: 'Resolved' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'mitigated', label: 'Mitigated' },
  { value: 'accepted', label: 'Risk accepted' },
] as const;

interface ServiceNowFormState {
  webhook_url: string;
  username: string;
  password: string;
  auto_create_enabled: boolean;
  auto_create_min_severity: string;
  sync_enabled: boolean;
  table_name: string;
  close_state: string;
  reopen_state: string;
  remote_closed_states: string;
  validate_on_remote_close: boolean;
  accept_close_as: string;
}

const defaultForm: ServiceNowFormState = {
  webhook_url: '',
  username: '',
  password: '',
  auto_create_enabled: false,
  auto_create_min_severity: 'high',
  sync_enabled: false,
  table_name: 'incident',
  close_state: '6',
  reopen_state: '2',
  remote_closed_states: '6,7',
  validate_on_remote_close: true,
  accept_close_as: 'resolved',
};

function formFromIntegration(integration: ServiceNowIntegration): ServiceNowFormState {
  return {
    webhook_url: integration.webhook_url,
    username: integration.username || '',
    password: '',
    auto_create_enabled: integration.auto_create_enabled,
    auto_create_min_severity: integration.auto_create_min_severity || 'high',
    sync_enabled: integration.sync_enabled,
    table_name: integration.table_name || 'incident',
    close_state: integration.close_state || '6',
    reopen_state: integration.reopen_state || '2',
    remote_closed_states: (integration.remote_closed_states || ['6', '7']).join(','),
    validate_on_remote_close: integration.validate_on_remote_close,
    accept_close_as: integration.accept_close_as || 'resolved',
  };
}

export function ServiceNowSection({ selectedOrgId }: { selectedOrgId?: number }) {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<ServiceNowIntegration | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [form, setForm] = useState<ServiceNowFormState>(defaultForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [pulling, setPulling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; http_status?: number; table_api_ok?: boolean } | null>(null);
  const [activeTab, setActiveTab] = useState<'endpoint' | 'auto' | 'sync'>('endpoint');

  useEffect(() => {
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId]);

  async function load() {
    setLoading(true);
    try {
      setIntegration(await api.getServiceNowIntegration(selectedOrgId));
    } catch {
      setIntegration(null);
    } finally {
      setLoading(false);
    }
  }

  function openSetup() {
    setForm(integration ? formFromIntegration(integration) : defaultForm);
    setTestResult(null);
    setActiveTab('endpoint');
    setSetupOpen(true);
  }

  function buildPayload() {
    return {
      webhook_url: form.webhook_url.trim(),
      username: form.username.trim() || undefined,
      ...(form.password ? { password: form.password } : {}),
      auto_create_enabled: form.auto_create_enabled,
      auto_create_min_severity: form.auto_create_min_severity,
      sync_enabled: form.sync_enabled,
      table_name: form.table_name.trim() || 'incident',
      close_state: form.close_state.trim() || '6',
      reopen_state: form.reopen_state.trim() || '2',
      remote_closed_states: form.remote_closed_states
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      validate_on_remote_close: form.validate_on_remote_close,
      accept_close_as: form.accept_close_as,
    };
  }

  async function handleTest() {
    if (!integration) {
      toast({ title: 'Save the integration first to test it.', variant: 'destructive' });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testServiceNowConnection(selectedOrgId);
      setTestResult(result);
      await load();
    } catch (err) {
      setTestResult({ ok: false, message: getApiErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  }

  async function handlePull() {
    if (!integration?.sync_enabled) {
      toast({ title: 'Enable status sync first.', variant: 'destructive' });
      return;
    }
    setPulling(true);
    try {
      const result = await api.pullServiceNowDeliveries(selectedOrgId);
      toast({
        title: result.ok ? 'Pull complete' : 'Pull finished with errors',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Pull failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setPulling(false);
    }
  }

  async function handleSave() {
    if (!form.webhook_url.trim()) {
      toast({ title: 'Scripted REST API URL is required.', variant: 'destructive' });
      return;
    }
    if (!integration && form.username && !form.password) {
      toast({ title: 'Password is required when a username is set.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      const payload = buildPayload();
      if (integration) {
        await api.updateServiceNowIntegration(payload, selectedOrgId);
        toast({ title: 'ServiceNow integration updated.' });
      } else {
        await api.createServiceNowIntegration(payload, selectedOrgId);
        toast({ title: 'ServiceNow integration configured.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await api.deleteServiceNowIntegration(selectedOrgId);
      setIntegration(null);
      setDeleteOpen(false);
      toast({ title: 'ServiceNow integration removed.' });
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
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-[#81B5A1] flex items-center justify-center shrink-0">
          <Shield className="w-5 h-5 text-[#1B3C34]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">ServiceNow</CardTitle>
          <CardDescription className="text-sm">
            Push findings to Scripted REST, sync incident state via Table API, and validate close claims before accepting remediation.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
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
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div className="sm:col-span-2">
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Webhook URL</p>
                <p className="font-mono text-xs break-all">{integration.webhook_url}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auth</p>
                <p className="text-xs">
                  {integration.username
                    ? <>Basic — {integration.username}{integration.has_password ? '' : ' (no password saved)'}</>
                    : <span className="text-muted-foreground">None (open endpoint)</span>}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auto-push</p>
                <p className="text-xs">
                  {integration.auto_create_enabled
                    ? <span className="text-green-400">Enabled — {integration.auto_create_min_severity?.toUpperCase()}+</span>
                    : <span className="text-muted-foreground">Disabled</span>}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Status sync</p>
                <p className="text-xs">
                  {integration.sync_enabled
                    ? <span className="text-green-400 inline-flex items-center gap-1">
                        <ArrowLeftRight className="h-3 w-3" />
                        Bidirectional{integration.validate_on_remote_close ? ' + close validation' : ''}
                      </span>
                    : <span className="text-muted-foreground">Disabled</span>}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Table</p>
                <p className="font-mono text-xs">{integration.table_name || 'incident'}</p>
              </div>
            </div>

            {integration.last_tested_at && (
              <p className="text-xs text-muted-foreground">
                Last tested: {new Date(integration.last_tested_at).toLocaleString()}{' '}
                {integration.last_test_ok === true && <span className="text-green-400">— OK</span>}
                {integration.last_test_ok === false && <span className="text-red-400">— Failed</span>}
              </p>
            )}
            {integration.last_pull_at && (
              <p className="text-xs text-muted-foreground">
                Last pull: {new Date(integration.last_pull_at).toLocaleString()}
              </p>
            )}
            {integration.last_error && (
              <p className="text-xs text-red-400 truncate">{integration.last_error}</p>
            )}

            {testResult && (
              <div className={cn(
                'flex items-start gap-2 rounded-lg border p-3 text-sm',
                testResult.ok ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300',
              )}>
                {testResult.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 shrink-0" />}
                <span>{testResult.message}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-1">
              <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
                {testing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                Test connection
              </Button>
              {integration.sync_enabled && (
                <Button size="sm" variant="outline" onClick={handlePull} disabled={pulling}>
                  {pulling ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                  Pull statuses
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={openSetup}>
                <Settings2 className="h-4 w-4 mr-2" />Edit
              </Button>
              <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="h-4 w-4 mr-2" />Remove
              </Button>
            </div>
          </>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a ServiceNow Scripted REST endpoint and optionally enable Table API sync with close-claim validation.
            </p>
            <Button onClick={openSetup}>
              <Plug className="h-4 w-4 mr-2" />Set up ServiceNow
            </Button>
          </div>
        )}
      </CardContent>

      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#81B5A1] flex items-center justify-center">
                <Shield className="w-4 h-4 text-[#1B3C34]" />
              </div>
              {integration ? 'Edit ServiceNow Integration' : 'Connect ServiceNow'}
            </DialogTitle>
            <DialogDescription>
              Webhook for create, Table API for status sync, and Vanguard validation when ServiceNow claims a finding is closed.
            </DialogDescription>
          </DialogHeader>

          <div className="flex gap-1 border-b border-border pb-2 flex-wrap">
            {tabBtn('endpoint', '1. Endpoint')}
            {tabBtn('auto', '2. Auto-push')}
            {tabBtn('sync', '3. Status Sync')}
          </div>

          <div className="space-y-4 py-2 min-h-[240px]">
            {activeTab === 'endpoint' && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Scripted REST API URL</label>
                  <Input
                    placeholder="https://instance.service-now.com/api/.../notification"
                    value={form.webhook_url}
                    onChange={(e) => setForm((f) => ({ ...f, webhook_url: e.target.value }))}
                  />
                  <p className="text-xs text-muted-foreground">
                    Full URL including the resource path. Handlers should return <span className="font-mono">sys_id</span> / <span className="font-mono">number</span> for sync.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Username <span className="text-muted-foreground font-normal">(required for sync)</span></label>
                  <Input
                    placeholder="servicenow.service.account"
                    value={form.username}
                    onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">
                    Password{integration?.has_password && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
                  </label>
                  <Input
                    type="password"
                    placeholder={integration?.has_password ? '••••••••••••' : 'Service account password'}
                    value={form.password}
                    onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                  />
                </div>
              </div>
            )}

            {activeTab === 'auto' && (
              <div className="space-y-4">
                <label className="flex items-start gap-3 cursor-pointer">
                  <Checkbox
                    checked={form.auto_create_enabled}
                    onCheckedChange={(v) => setForm((f) => ({ ...f, auto_create_enabled: !!v }))}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="text-sm font-medium">Auto-push new findings</p>
                    <p className="text-xs text-muted-foreground">
                      Newly created vulnerabilities at or above the severity threshold are POSTed to ServiceNow automatically.
                    </p>
                  </div>
                </label>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Minimum severity</label>
                  <Select
                    value={form.auto_create_min_severity}
                    onValueChange={(v) => setForm((f) => ({ ...f, auto_create_min_severity: v }))}
                    disabled={!form.auto_create_enabled}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SEVERITIES.map((s) => (
                        <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}

            {activeTab === 'sync' && (
              <div className="space-y-4">
                <label className="flex items-start gap-3 cursor-pointer">
                  <Checkbox
                    checked={form.sync_enabled}
                    onCheckedChange={(v) => setForm((f) => ({ ...f, sync_enabled: !!v }))}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="text-sm font-medium">Enable bidirectional status sync</p>
                    <p className="text-xs text-muted-foreground">
                      Uses the Table API. ASM closes/reopens update ServiceNow; pulling ServiceNow closed states can trigger close-claim validation.
                    </p>
                  </div>
                </label>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Table</label>
                    <Input
                      value={form.table_name}
                      onChange={(e) => setForm((f) => ({ ...f, table_name: e.target.value }))}
                      disabled={!form.sync_enabled}
                      placeholder="incident"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Close state</label>
                    <Input
                      value={form.close_state}
                      onChange={(e) => setForm((f) => ({ ...f, close_state: e.target.value }))}
                      disabled={!form.sync_enabled}
                      placeholder="6"
                    />
                    <p className="text-[11px] text-muted-foreground">Default 6 = Resolved</p>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Reopen state</label>
                    <Input
                      value={form.reopen_state}
                      onChange={(e) => setForm((f) => ({ ...f, reopen_state: e.target.value }))}
                      disabled={!form.sync_enabled}
                      placeholder="2"
                    />
                    <p className="text-[11px] text-muted-foreground">Default 2 = In Progress</p>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Remote closed states</label>
                    <Input
                      value={form.remote_closed_states}
                      onChange={(e) => setForm((f) => ({ ...f, remote_closed_states: e.target.value }))}
                      disabled={!form.sync_enabled}
                      placeholder="6,7"
                    />
                    <p className="text-[11px] text-muted-foreground">Comma-separated</p>
                  </div>
                </div>

                <label className="flex items-start gap-3 cursor-pointer">
                  <Checkbox
                    checked={form.validate_on_remote_close}
                    onCheckedChange={(v) => setForm((f) => ({ ...f, validate_on_remote_close: !!v }))}
                    disabled={!form.sync_enabled}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="text-sm font-medium">Validate close claims</p>
                    <p className="text-xs text-muted-foreground">
                      When ServiceNow marks an incident closed, re-test with Vanguard before accepting. Confirmed still-open findings reject the close and reopen the incident.
                    </p>
                  </div>
                </label>

                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Accept verified close as</label>
                  <Select
                    value={form.accept_close_as}
                    onValueChange={(v) => setForm((f) => ({ ...f, accept_close_as: v }))}
                    disabled={!form.sync_enabled}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {ACCEPT_AS.map((o) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    False-positive verdicts always map to false positive regardless of this setting.
                  </p>
                </div>
              </div>
            )}
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {integration ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteOpen} onOpenChange={(v) => { if (!deleting) setDeleteOpen(v); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove ServiceNow
            </DialogTitle>
            <DialogDescription>
              This removes the stored webhook URL and credentials. Delivery history links in ASM are also removed; records already created in ServiceNow are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
