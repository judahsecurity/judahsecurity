'use client';

import { useEffect, useState, type ReactNode } from 'react';
import { CheckCircle2, Loader2, Network, Play, Plus, RefreshCw, Settings2, Trash2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage, type NetBrainIntegration } from '@/lib/api';

interface FormState {
  name: string;
  base_url: string;
  username: string;
  password: string;
  authentication_id: string;
  tenant_id: string;
  domain_id: string;
  verify_ssl: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
  max_config_age_hours: number;
  auto_mitigate_enabled: boolean;
}

const defaults: FormState = {
  name: '', base_url: '', username: '', password: '', authentication_id: '', tenant_id: '', domain_id: '',
  verify_ssl: true, continuous_sync_enabled: false, sync_interval_minutes: 360,
  max_config_age_hours: 24, auto_mitigate_enabled: false,
};

const intervals = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

export function NetBrainSection() {
  const { toast } = useToast();
  const [connections, setConnections] = useState<NetBrainIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<NetBrainIntegration | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<NetBrainIntegration | null>(null);
  const [form, setForm] = useState<FormState>(defaults);

  async function load() {
    setLoading(true);
    try { setConnections(await api.getNetBrainIntegrations()); }
    catch { setConnections([]); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  function openCreate() {
    setEditing(null);
    setForm(defaults);
    setDialogOpen(true);
  }

  function openEdit(connection: NetBrainIntegration) {
    setEditing(connection);
    setForm({
      name: connection.name, base_url: connection.base_url, username: '', password: '',
      authentication_id: connection.authentication_id || '', tenant_id: connection.tenant_id,
      domain_id: connection.domain_id, verify_ssl: connection.verify_ssl,
      continuous_sync_enabled: connection.continuous_sync_enabled,
      sync_interval_minutes: connection.sync_interval_minutes,
      max_config_age_hours: connection.max_config_age_hours,
      auto_mitigate_enabled: connection.auto_mitigate_enabled,
    });
    setDialogOpen(true);
  }

  async function save() {
    if (!form.name.trim() || !form.base_url.trim() || !form.tenant_id.trim() || !form.domain_id.trim()) {
      toast({ title: 'Name, URL, tenant ID, and domain ID are required.', variant: 'destructive' });
      return;
    }
    if (!editing && (!form.username.trim() || !form.password)) {
      toast({ title: 'Service-account credentials are required.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      const common = {
        name: form.name.trim(), base_url: form.base_url.trim(),
        authentication_id: form.authentication_id.trim() || null,
        tenant_id: form.tenant_id.trim(), domain_id: form.domain_id.trim(), verify_ssl: form.verify_ssl,
        continuous_sync_enabled: form.continuous_sync_enabled,
        sync_interval_minutes: form.sync_interval_minutes, max_config_age_hours: form.max_config_age_hours,
        auto_mitigate_enabled: form.auto_mitigate_enabled,
      };
      if (editing) {
        await api.updateNetBrainIntegration(editing.id, {
          ...common,
          ...(form.username.trim() ? { username: form.username.trim() } : {}),
          ...(form.password ? { password: form.password } : {}),
        });
        toast({ title: 'NetBrain connection updated.' });
      } else {
        await api.createNetBrainIntegration({ ...common, username: form.username.trim(), password: form.password });
        toast({ title: 'NetBrain connection added.' });
      }
      setDialogOpen(false);
      await load();
    } catch (error) {
      toast({ title: 'Unable to save NetBrain connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setSaving(false); }
  }

  async function test(connection: NetBrainIntegration) {
    setBusyId(connection.id);
    try {
      const result = await api.testNetBrainConnection(connection.id);
      toast({ title: result.ok ? 'Connection OK' : 'Connection failed', description: result.message,
        variant: result.ok ? 'default' : 'destructive' });
      await load();
    } catch (error) {
      toast({ title: 'Connection test failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  async function assess(connection: NetBrainIntegration) {
    setBusyId(connection.id);
    try {
      const result = await api.assessNetBrainFindings(connection.id);
      toast({
        title: result.ok ? 'Assessment complete' : 'Assessment failed',
        description: `${result.findings_assessed} assessed; ${result.findings_mitigated} mitigated; ${result.findings_reopened} reopened; ${result.unknown} unknown.`,
        variant: result.ok ? 'default' : 'destructive',
      });
      await load();
    } catch (error) {
      toast({ title: 'Assessment failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteNetBrainIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'NetBrain connection removed.' });
      await load();
    } catch (error) {
      toast({ title: 'Unable to remove connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center shrink-0">
          <Network className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">NetBrain</CardTitle>
          <CardDescription className="text-sm">
            Validate network-device exploit prerequisites from read-only configuration evidence.
          </CardDescription>
        </div>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : connections.length ? (
          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
            <CheckCircle2 className="h-3 w-3 mr-1" />{connections.length} connected
          </Badge>
        ) : <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>}
      </CardHeader>
      <CardContent className="space-y-4">
        {connections.length ? connections.map(connection => (
          <div key={connection.id} className="rounded-lg border border-border p-3 space-y-3">
            <div className="flex justify-between gap-3">
              <div className="min-w-0">
                <p className="font-medium text-sm">{connection.name}</p>
                <p className="font-mono text-xs text-muted-foreground truncate">{connection.base_url}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Evidence ≤ {connection.max_config_age_hours}h · {connection.auto_mitigate_enabled ? 'Automatic mitigation enabled' : 'Evidence only'}
                </p>
                {connection.last_sync_at && <p className="text-xs text-muted-foreground">
                  Last assessment: {new Date(connection.last_sync_at).toLocaleString()} {connection.last_sync_ok ? '— OK' : '— Failed'}
                </p>}
                {connection.last_error && <p className="text-xs text-red-400 truncate">{connection.last_error}</p>}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" onClick={() => assess(connection)} disabled={busyId === connection.id}>
                {busyId === connection.id ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}Assess findings
              </Button>
              <Button size="sm" variant="outline" onClick={() => test(connection)} disabled={busyId === connection.id}>
                <RefreshCw className="h-4 w-4 mr-2" />Test
              </Button>
              <Button size="sm" variant="outline" onClick={() => openEdit(connection)}><Settings2 className="h-4 w-4 mr-2" />Edit</Button>
              <Button size="sm" variant="outline" className="text-red-400 border-red-600/30" onClick={() => setDeleteTarget(connection)}>
                <Trash2 className="h-4 w-4 mr-2" />Remove
              </Button>
            </div>
          </div>
        )) : !loading && (
          <div className="flex flex-col sm:flex-row gap-4 sm:items-center">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a least-privilege NetBrain account to assess Cisco configuration prerequisites and retain evidence on findings.
            </p>
            <Button onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Connect NetBrain</Button>
          </div>
        )}
        {connections.length > 0 && <Button size="sm" variant="outline" onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add connection</Button>}
      </CardContent>

      <Dialog open={dialogOpen} onOpenChange={value => { if (!saving) setDialogOpen(value); }}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit NetBrain connection' : 'Connect NetBrain'}</DialogTitle>
            <DialogDescription>
              Judah uses this account only to look up devices and retrieve configuration evidence. Use a dedicated account with domain access and no change privileges.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2 max-h-[65vh] overflow-y-auto pr-1">
            <div className="grid sm:grid-cols-2 gap-3">
              <Field label="Connection name"><Input value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} placeholder="Production NetBrain" /></Field>
              <Field label="NetBrain URL"><Input value={form.base_url} onChange={event => setForm({ ...form, base_url: event.target.value })} placeholder="https://netbrain.example.com" /></Field>
              <Field label={`Username${editing ? ' (optional)' : ''}`}><Input value={form.username} onChange={event => setForm({ ...form, username: event.target.value })} autoComplete="username" /></Field>
              <Field label={`Password${editing ? ' (optional)' : ''}`}><Input type="password" value={form.password} onChange={event => setForm({ ...form, password: event.target.value })} autoComplete="current-password" /></Field>
              <Field label="Tenant ID"><Input value={form.tenant_id} onChange={event => setForm({ ...form, tenant_id: event.target.value })} /></Field>
              <Field label="Domain ID"><Input value={form.domain_id} onChange={event => setForm({ ...form, domain_id: event.target.value })} /></Field>
              <Field label="External authentication ID (optional)"><Input value={form.authentication_id} onChange={event => setForm({ ...form, authentication_id: event.target.value })} placeholder="LDAP/AD provider name" /></Field>
              <Field label="Maximum configuration age"><Input type="number" min={1} max={720} value={form.max_config_age_hours} onChange={event => setForm({ ...form, max_config_age_hours: Number(event.target.value) })} /></Field>
            </div>
            <Check label="Verify TLS certificates" checked={form.verify_ssl} onChange={value => setForm({ ...form, verify_ssl: value })} />
            <Check label="Automatically mark supported findings Mitigated when the required exploit path is absent" checked={form.auto_mitigate_enabled} onChange={value => setForm({ ...form, auto_mitigate_enabled: value })} />
            <Check label="Continuously reassess and reopen findings after configuration drift or stale evidence" checked={form.continuous_sync_enabled} onChange={value => setForm({ ...form, continuous_sync_enabled: value })} />
            {form.continuous_sync_enabled && <Field label="Assessment frequency">
              <Select value={String(form.sync_interval_minutes)} onValueChange={value => setForm({ ...form, sync_interval_minutes: Number(value) })}>
                <SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{intervals.map(item => <SelectItem key={item.value} value={String(item.value)}>{item.label}</SelectItem>)}</SelectContent>
              </Select>
            </Field>}
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button><Button onClick={save} disabled={saving}>{saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}{editing ? 'Save changes' : 'Connect'}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={value => { if (!value) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm"><DialogHeader><DialogTitle>Remove NetBrain connection</DialogTitle><DialogDescription>Stored credentials will be deleted. Existing evidence remains on findings.</DialogDescription></DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button><Button variant="destructive" onClick={remove}>Remove</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div className="space-y-1.5"><label className="text-sm font-medium">{label}</label>{children}</div>;
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  const id = `netbrain-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  return <div className="flex items-start gap-3 rounded-lg border border-border p-3"><Checkbox id={id} checked={checked} onCheckedChange={value => onChange(!!value)} className="mt-0.5" /><label htmlFor={id} className="text-sm cursor-pointer">{label}</label></div>;
}
