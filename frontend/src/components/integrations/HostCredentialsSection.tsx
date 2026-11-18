'use client';

import { useEffect, useMemo, useState } from 'react';
import { AlertCircle, CheckCircle2, KeyRound, Loader2, Plus, LockKeyhole, RefreshCw, Server, Settings2, Trash2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import {
  api, getApiErrorMessage,
  type HostCredentialProfile, type HostCredentialProfileInput, type HostSecretStore, type SecretStoreProvider,
} from '@/lib/api';

const PROVIDERS: Record<SecretStoreProvider, string> = {
  hashicorp_vault: 'HashiCorp Vault',
  aws_secrets_manager: 'AWS Secrets Manager',
  cyberark_ccp: 'CyberArk Central Credential Provider',
};

// Fields each provider's connection takes (secret handled separately).
const STORE_FIELDS: Record<SecretStoreProvider, { key: string; label: string; placeholder?: string; multiline?: boolean }[]> = {
  hashicorp_vault: [
    { key: 'address', label: 'Vault address', placeholder: 'https://vault.corp.example:8200' },
    { key: 'namespace', label: 'Namespace (Vault Enterprise, optional)' },
    { key: 'kv_mount', label: 'KV mount', placeholder: 'secret' },
    { key: 'role_id', label: 'AppRole role ID (AppRole only)' },
    { key: 'approle_mount', label: 'AppRole mount', placeholder: 'approle' },
    { key: 'ca_cert', label: 'CA certificate (PEM, optional)', multiline: true },
  ],
  aws_secrets_manager: [
    { key: 'region', label: 'Region', placeholder: 'us-east-1' },
    { key: 'role_arn', label: 'Role to assume (optional)', placeholder: 'arn:aws:iam::123456789012:role/judah-secrets-read' },
    { key: 'external_id', label: 'External ID (optional)' },
  ],
  cyberark_ccp: [
    { key: 'url', label: 'CCP URL', placeholder: 'https://ccp.corp.example' },
    { key: 'app_id', label: 'Application ID', placeholder: 'Judah' },
    { key: 'ca_cert', label: 'CA certificate (PEM, optional)', multiline: true },
    { key: 'client_cert', label: 'Client certificate (PEM, optional)', multiline: true },
  ],
};

const SECRET_REF_FIELDS: Record<SecretStoreProvider, { key: string; label: string; placeholder?: string }[]> = {
  hashicorp_vault: [
    { key: 'path', label: 'Secret path', placeholder: 'judah/linux-prod' },
    { key: 'key', label: 'Field', placeholder: 'private_key or password' },
  ],
  aws_secrets_manager: [
    { key: 'secret_id', label: 'Secret name or ARN', placeholder: 'judah/windows-prod' },
    { key: 'key', label: 'JSON field (if the secret is JSON)', placeholder: 'password' },
    { key: 'version_stage', label: 'Version stage (optional)', placeholder: 'AWSCURRENT' },
  ],
  cyberark_ccp: [
    { key: 'safe', label: 'Safe', placeholder: 'Linux-Servers' },
    { key: 'object', label: 'Account object', placeholder: 'judah-probe' },
  ],
};

type StoreForm = { name: string; provider: SecretStoreProvider; config: Record<string, string>; secret: string; is_active: boolean };
const EMPTY_STORE: StoreForm = { name: '', provider: 'hashicorp_vault', config: { auth_method: 'token', kv_version: '2' }, secret: '', is_active: true };

type ProfileForm = {
  name: string; kind: 'ssh' | 'winrm'; username: string; secret_source: 'stored' | 'store'; secret: string;
  secret_store_id: number | null; secret_ref: Record<string, string>; targets: string; priority: number; is_active: boolean;
  auth: 'key' | 'password'; port: string; sudo: boolean; trust_on_first_use: boolean; known_hosts: string;
  transport: 'ntlm' | 'kerberos'; https: boolean; ca_cert: string;
};
const EMPTY_PROFILE: ProfileForm = {
  name: '', kind: 'ssh', username: '', secret_source: 'stored', secret: '', secret_store_id: null, secret_ref: {},
  targets: '', priority: 100, is_active: true, auth: 'key', port: '', sudo: true, trust_on_first_use: false, known_hosts: '',
  transport: 'ntlm', https: true, ca_cert: '',
};

function statusBadge(ok?: boolean | null, error?: string | null) {
  if (ok === true) return <Badge variant="outline" className="text-green-400 border-green-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />Test passed</Badge>;
  if (ok === false) return <Badge variant="outline" className="text-red-400" title={error || undefined}><AlertCircle className="h-3 w-3 mr-1" />Test failed</Badge>;
  return null;
}

function profileOptions(form: ProfileForm): Record<string, string | number | boolean> {
  const port = form.port.trim() ? Number(form.port) : undefined;
  if (form.kind === 'ssh') {
    return { auth: form.auth, sudo: form.sudo, trust_on_first_use: form.trust_on_first_use,
      ...(form.known_hosts.trim() ? { known_hosts: form.known_hosts } : {}), ...(port ? { port } : {}) };
  }
  return { transport: form.transport, https: form.https, ...(form.ca_cert.trim() ? { ca_cert: form.ca_cert } : {}), ...(port ? { port } : {}) };
}

export function HostCredentialsSection() {
  const { toast } = useToast();
  const [stores, setStores] = useState<HostSecretStore[]>([]);
  const [profiles, setProfiles] = useState<HostCredentialProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const [storeOpen, setStoreOpen] = useState(false);
  const [editingStore, setEditingStore] = useState<HostSecretStore | null>(null);
  const [storeForm, setStoreForm] = useState<StoreForm>(EMPTY_STORE);

  const [profileOpen, setProfileOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState<HostCredentialProfile | null>(null);
  const [profileForm, setProfileForm] = useState<ProfileForm>(EMPTY_PROFILE);

  const [loginTest, setLoginTest] = useState<HostCredentialProfile | null>(null);
  const [loginAssetId, setLoginAssetId] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<{ type: 'store' | 'profile'; id: number; name: string } | null>(null);

  const selectedStore = useMemo(() => stores.find((s) => s.id === profileForm.secret_store_id) || null, [stores, profileForm.secret_store_id]);

  useEffect(() => { void load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const data = await api.getHostCredentials();
      setStores(data.stores); setProfiles(data.profiles);
    } catch { setStores([]); setProfiles([]); }
    finally { setLoading(false); }
  }

  function editStore(store: HostSecretStore | null) {
    setEditingStore(store);
    setStoreForm(store ? { name: store.name, provider: store.provider, config: { ...store.config }, secret: '', is_active: store.is_active } : EMPTY_STORE);
    setStoreOpen(true);
  }

  function editProfile(p: HostCredentialProfile | null) {
    setEditingProfile(p);
    setProfileForm(p ? {
      ...EMPTY_PROFILE, name: p.name, kind: p.kind, username: p.username, secret_source: p.secret_source,
      secret_store_id: p.secret_store_id ?? null, secret_ref: { ...p.secret_ref }, targets: p.targets.join('\n'),
      priority: p.priority, is_active: p.is_active,
      auth: (p.options.auth as 'key' | 'password') || 'key', port: p.options.port ? String(p.options.port) : '',
      sudo: p.options.sudo !== false, trust_on_first_use: Boolean(p.options.trust_on_first_use),
      known_hosts: String(p.options.known_hosts || ''), transport: (p.options.transport as 'ntlm' | 'kerberos') || 'ntlm',
      https: p.options.https !== false, ca_cert: String(p.options.ca_cert || ''),
    } : { ...EMPTY_PROFILE, secret_store_id: stores[0]?.id ?? null });
    setProfileOpen(true);
  }

  async function saveStore() {
    if (!storeForm.name.trim()) { toast({ title: 'Name the vault connection.', variant: 'destructive' }); return; }
    setBusy('store-save');
    try {
      const config = Object.fromEntries(Object.entries(storeForm.config).filter(([, v]) => String(v).trim() !== ''));
      if (editingStore) {
        await api.updateHostSecretStore(editingStore.id, { name: storeForm.name, config, is_active: storeForm.is_active,
          ...(storeForm.secret ? { secret: storeForm.secret } : {}) });
      } else {
        await api.createHostSecretStore({ ...storeForm, config, ...(storeForm.secret ? { secret: storeForm.secret } : { secret: undefined }) });
      }
      toast({ title: editingStore ? 'Vault connection updated.' : 'Vault connection added.' });
      setStoreOpen(false); await load();
    } catch (error) {
      toast({ title: 'Could not save the vault connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusy(null); }
  }

  async function saveProfile() {
    const targets = profileForm.targets.split(/[\n,]/).map((t) => t.trim()).filter(Boolean);
    if (!profileForm.name.trim() || !targets.length) {
      toast({ title: 'A name and at least one target are required.', variant: 'destructive' }); return;
    }
    const payload: HostCredentialProfileInput = {
      name: profileForm.name.trim(), kind: profileForm.kind, username: profileForm.username.trim(),
      secret_source: profileForm.secret_source, targets, priority: Number(profileForm.priority) || 0,
      is_active: profileForm.is_active, options: profileOptions(profileForm),
      secret_store_id: profileForm.secret_source === 'store' ? profileForm.secret_store_id : null,
      secret_ref: profileForm.secret_source === 'store'
        ? Object.fromEntries(Object.entries(profileForm.secret_ref).filter(([, v]) => v.trim() !== '')) : {},
      ...(profileForm.secret_source === 'stored' && profileForm.secret ? { secret: profileForm.secret } : {}),
    };
    setBusy('profile-save');
    try {
      if (editingProfile) {
        const { kind: _kind, ...update } = payload;
        await api.updateHostCredentialProfile(editingProfile.id, update);
      } else {
        await api.createHostCredentialProfile(payload);
      }
      toast({ title: editingProfile ? 'Credential profile updated.' : 'Credential profile added.' });
      setProfileOpen(false); await load();
    } catch (error) {
      toast({ title: 'Could not save the credential profile', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusy(null); }
  }

  async function test(kind: 'store' | 'profile', id: number, assetId?: number) {
    setBusy(`${kind}-${id}`);
    try {
      const result = kind === 'store' ? await api.testHostSecretStore(id) : await api.testHostCredentialProfile(id, assetId);
      toast({ title: result.ok ? 'Test passed' : 'Test failed', description: result.message, variant: result.ok ? undefined : 'destructive' });
      await load();
    } catch (error) {
      toast({ title: 'Test failed', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusy(null); }
  }

  async function remove() {
    if (!deleteTarget) return;
    setBusy(`delete-${deleteTarget.id}`);
    try {
      if (deleteTarget.type === 'store') await api.deleteHostSecretStore(deleteTarget.id);
      else await api.deleteHostCredentialProfile(deleteTarget.id);
      toast({ title: `${deleteTarget.name} removed.` });
      setDeleteTarget(null); await load();
    } catch (error) {
      toast({ title: 'Could not remove it', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusy(null); }
  }

  const sf = storeForm;
  const pf = profileForm;
  const storeSecretLabel = sf.provider === 'hashicorp_vault'
    ? (sf.config.auth_method === 'approle' ? 'AppRole secret ID' : 'Vault token')
    : sf.provider === 'cyberark_ccp' ? 'Client private key (PEM, with the client certificate)' : '';

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Host credentials for agentless checks</CardTitle>
          <CardDescription>
            Logins Judah uses to check servers that can&apos;t run an agent: SSH for Linux and macOS, WinRM for Windows.
            Only servers matching a profile&apos;s targets are contacted, and only a fixed list of read-only commands runs.
          </CardDescription>
        </div>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : profiles.length ? (
          <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />{profiles.length} profile{profiles.length === 1 ? '' : 's'}</Badge>
        ) : <Badge variant="outline">Not configured</Badge>}
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium flex items-center gap-2"><Server className="h-4 w-4" />Credential profiles</h3>
              <p className="text-xs text-muted-foreground">A server uses the first profile, lowest priority number first, whose targets match it.</p>
            </div>
            <Button size="sm" onClick={() => editProfile(null)}><Plus className="h-4 w-4 mr-2" />Add profile</Button>
          </div>
          {!loading && !profiles.length && <p className="text-sm text-muted-foreground">No profiles yet.</p>}
          {profiles.map((p) => (
            <div key={p.id} className="rounded-lg border border-border p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium text-sm">{p.name}</p>
                <Badge variant="outline">{p.kind === 'ssh' ? 'SSH · Linux/macOS' : 'WinRM · Windows'}</Badge>
                <Badge variant="outline">Priority {p.priority}</Badge>
                {!p.is_active && <Badge variant="outline" className="text-muted-foreground">Disabled</Badge>}
                {statusBadge(p.last_test_ok, p.last_error)}
              </div>
              <p className="text-xs text-muted-foreground">
                {p.username || '(username from vault)'} · {p.secret_source === 'stored' ? 'secret stored in Judah' : `secret from ${p.secret_store_name || 'a vault'}`}
                {' · '}{p.targets.slice(0, 3).join(', ')}{p.targets.length > 3 ? ` +${p.targets.length - 3} more` : ''}
              </p>
              {p.last_test_ok === false && p.last_error && <p className="text-xs text-red-400">{p.last_error}</p>}
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={busy === `profile-${p.id}`} onClick={() => void test('profile', p.id)}><KeyRound className="h-4 w-4 mr-2" />Test credential</Button>
                <Button size="sm" variant="outline" disabled={busy === `profile-${p.id}`} onClick={() => { setLoginTest(p); setLoginAssetId(''); }}><RefreshCw className="h-4 w-4 mr-2" />Test login</Button>
                <Button size="sm" variant="outline" onClick={() => editProfile(p)}><Settings2 className="h-4 w-4 mr-2" />Edit</Button>
                <Button size="sm" variant="outline" className="text-red-400" onClick={() => setDeleteTarget({ type: 'profile', id: p.id, name: p.name })}><Trash2 className="h-4 w-4 mr-2" />Remove</Button>
              </div>
            </div>
          ))}
        </section>

        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium flex items-center gap-2"><LockKeyhole className="h-4 w-4" />Password vaults</h3>
              <p className="text-xs text-muted-foreground">Keep server credentials in your vault. Judah fetches a profile&apos;s secret when a check runs and doesn&apos;t store it.</p>
            </div>
            <Button size="sm" variant="outline" onClick={() => editStore(null)}><Plus className="h-4 w-4 mr-2" />Add vault</Button>
          </div>
          {!loading && !stores.length && <p className="text-sm text-muted-foreground">No vaults connected. Profiles can store their secret in Judah (encrypted) instead.</p>}
          {stores.map((s) => (
            <div key={s.id} className="rounded-lg border border-border p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium text-sm">{s.name}</p>
                <Badge variant="outline">{PROVIDERS[s.provider]}</Badge>
                {!s.is_active && <Badge variant="outline" className="text-muted-foreground">Disabled</Badge>}
                {statusBadge(s.last_test_ok, s.last_error)}
              </div>
              <p className="text-xs text-muted-foreground">
                {s.config.address || s.config.url || s.config.region}{s.config.role_arn ? ` · assumes ${s.config.role_arn}` : ''}
                {' · '}used by {s.in_use} profile{s.in_use === 1 ? '' : 's'}
              </p>
              {s.last_test_ok === false && s.last_error && <p className="text-xs text-red-400">{s.last_error}</p>}
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={busy === `store-${s.id}`} onClick={() => void test('store', s.id)}><RefreshCw className="h-4 w-4 mr-2" />Test</Button>
                <Button size="sm" variant="outline" onClick={() => editStore(s)}><Settings2 className="h-4 w-4 mr-2" />Edit</Button>
                <Button size="sm" variant="outline" className="text-red-400" disabled={s.in_use > 0} title={s.in_use ? 'Change the profiles that use it first' : undefined} onClick={() => setDeleteTarget({ type: 'store', id: s.id, name: s.name })}><Trash2 className="h-4 w-4 mr-2" />Remove</Button>
              </div>
            </div>
          ))}
        </section>
      </CardContent>

      {/* Vault connection */}
      <Dialog open={storeOpen} onOpenChange={setStoreOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingStore ? 'Edit vault connection' : 'Connect a password vault'}</DialogTitle>
            <DialogDescription>Judah only reads from the vault. Give it an identity that can read just the host-check secrets.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <label htmlFor="store-name" className="text-xs text-muted-foreground">Name</label>
              <Input id="store-name" placeholder="corp-vault" value={sf.name} onChange={(e) => setStoreForm({ ...sf, name: e.target.value })} />
            </div>
            <Select value={sf.provider} disabled={Boolean(editingStore)} onValueChange={(v) => setStoreForm({ ...sf, provider: v as SecretStoreProvider, config: v === 'hashicorp_vault' ? { auth_method: 'token', kv_version: '2' } : {} })}>
              <SelectTrigger aria-label="Vault type"><SelectValue /></SelectTrigger>
              <SelectContent>{Object.entries(PROVIDERS).map(([k, label]) => <SelectItem key={k} value={k}>{label}</SelectItem>)}</SelectContent>
            </Select>
            {sf.provider === 'hashicorp_vault' && (
              <div className="grid grid-cols-2 gap-3">
                <Select value={sf.config.auth_method || 'token'} onValueChange={(v) => setStoreForm({ ...sf, config: { ...sf.config, auth_method: v } })}>
                  <SelectTrigger aria-label="Auth method"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="token">Token</SelectItem><SelectItem value="approle">AppRole</SelectItem></SelectContent>
                </Select>
                <Select value={sf.config.kv_version || '2'} onValueChange={(v) => setStoreForm({ ...sf, config: { ...sf.config, kv_version: v } })}>
                  <SelectTrigger aria-label="KV version"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="2">KV v2</SelectItem><SelectItem value="1">KV v1</SelectItem></SelectContent>
                </Select>
              </div>
            )}
            {STORE_FIELDS[sf.provider].filter((f) => sf.provider !== 'hashicorp_vault' || sf.config.auth_method === 'approle' || !['role_id', 'approle_mount'].includes(f.key)).map((f) => (
              <div key={f.key} className="space-y-1">
                <label className="text-xs text-muted-foreground">{f.label}</label>
                {f.multiline
                  ? <Textarea rows={3} className="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" value={sf.config[f.key] || ''} onChange={(e) => setStoreForm({ ...sf, config: { ...sf.config, [f.key]: e.target.value } })} />
                  : <Input placeholder={f.placeholder} value={sf.config[f.key] || ''} onChange={(e) => setStoreForm({ ...sf, config: { ...sf.config, [f.key]: e.target.value } })} />}
              </div>
            ))}
            {sf.provider === 'aws_secrets_manager' && <p className="text-xs text-muted-foreground">Judah uses its own AWS identity (for example the EC2 instance role) and, if set, assumes your role. No access keys are stored.</p>}
            {storeSecretLabel && (
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">{storeSecretLabel}{editingStore?.has_secret ? ' — leave blank to keep the current one' : ''}</label>
                {sf.provider === 'cyberark_ccp'
                  ? <Textarea rows={3} className="font-mono text-xs" value={sf.secret} onChange={(e) => setStoreForm({ ...sf, secret: e.target.value })} />
                  : <Input type="password" autoComplete="off" value={sf.secret} onChange={(e) => setStoreForm({ ...sf, secret: e.target.value })} />}
              </div>
            )}
            <div className="flex items-center gap-3">
              <Checkbox id="store-active" checked={sf.is_active} onCheckedChange={(c) => setStoreForm({ ...sf, is_active: Boolean(c) })} />
              <label htmlFor="store-active" className="text-sm cursor-pointer">Enabled</label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setStoreOpen(false)} disabled={busy === 'store-save'}>Cancel</Button>
            <Button onClick={() => void saveStore()} disabled={busy === 'store-save'}>{busy === 'store-save' && <Loader2 className="h-4 w-4 animate-spin mr-2" />}{editingStore ? 'Save changes' : 'Add vault'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Credential profile */}
      <Dialog open={profileOpen} onOpenChange={setProfileOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingProfile ? 'Edit credential profile' : 'Add a credential profile'}</DialogTitle>
            <DialogDescription>Use a dedicated low-privilege account. See docs/HOST_EVIDENCE_COLLECTION.md for the minimum rights per OS.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label htmlFor="p-name" className="text-xs text-muted-foreground">Name</label>
                <Input id="p-name" placeholder="windows-prod" value={pf.name} onChange={(e) => setProfileForm({ ...pf, name: e.target.value })} />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Protocol</label>
                <Select value={pf.kind} disabled={Boolean(editingProfile)} onValueChange={(v) => setProfileForm({ ...pf, kind: v as 'ssh' | 'winrm', port: '' })}>
                  <SelectTrigger aria-label="Protocol"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="ssh">SSH (Linux, macOS)</SelectItem><SelectItem value="winrm">WinRM (Windows)</SelectItem></SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Targets — CIDRs or hostname patterns, one per line. Only these servers are contacted.</label>
              <Textarea rows={3} className="font-mono text-xs" placeholder={'10.40.0.0/16\n*.prod.corp.example'} value={pf.targets} onChange={(e) => setProfileForm({ ...pf, targets: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label htmlFor="p-username" className="text-xs text-muted-foreground">Username</label>
                <Input id="p-username" placeholder={pf.kind === 'winrm' ? 'CORP\\svc-judah' : 'judah-probe'} value={pf.username} onChange={(e) => setProfileForm({ ...pf, username: e.target.value })} />
              </div>
              <div className="space-y-1">
                <label htmlFor="p-priority" className="text-xs text-muted-foreground">Priority (lower is tried first)</label>
                <Input id="p-priority" type="number" min={0} max={1000} value={pf.priority} onChange={(e) => setProfileForm({ ...pf, priority: Number(e.target.value) })} />
              </div>
            </div>
            <Select value={pf.secret_source} onValueChange={(v) => setProfileForm({ ...pf, secret_source: v as 'stored' | 'store' })}>
              <SelectTrigger aria-label="Secret source"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="stored">Store the secret in Judah (encrypted)</SelectItem>
                <SelectItem value="store" disabled={!stores.length}>Fetch the secret from a vault{stores.length ? '' : ' (connect one first)'}</SelectItem>
              </SelectContent>
            </Select>
            {pf.secret_source === 'stored' ? (
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  {pf.kind === 'ssh' && pf.auth === 'key' ? 'Private key (unencrypted ed25519, ECDSA or RSA)' : 'Password'}
                  {editingProfile?.has_secret && editingProfile.secret_source === 'stored' ? ' — leave blank to keep the current one' : ''}
                </label>
                {pf.kind === 'ssh' && pf.auth === 'key'
                  ? <Textarea rows={3} className="font-mono text-xs" value={pf.secret} onChange={(e) => setProfileForm({ ...pf, secret: e.target.value })} />
                  : <Input type="password" autoComplete="off" value={pf.secret} onChange={(e) => setProfileForm({ ...pf, secret: e.target.value })} />}
              </div>
            ) : (
              <div className="space-y-3 rounded-md border border-border p-3">
                <Select value={pf.secret_store_id ? String(pf.secret_store_id) : ''} onValueChange={(v) => setProfileForm({ ...pf, secret_store_id: Number(v), secret_ref: {} })}>
                  <SelectTrigger aria-label="Vault"><SelectValue placeholder="Choose a vault" /></SelectTrigger>
                  <SelectContent>{stores.map((s) => <SelectItem key={s.id} value={String(s.id)}>{s.name} · {PROVIDERS[s.provider]}</SelectItem>)}</SelectContent>
                </Select>
                {selectedStore && SECRET_REF_FIELDS[selectedStore.provider].map((f) => (
                  <div key={f.key} className="space-y-1">
                    <label htmlFor={`p-ref-${f.key}`} className="text-xs text-muted-foreground">{f.label}</label>
                    <Input id={`p-ref-${f.key}`} placeholder={f.placeholder} value={pf.secret_ref[f.key] || ''}
                      onChange={(e) => setProfileForm({ ...pf, secret_ref: { ...pf.secret_ref, [f.key]: e.target.value } })} />
                  </div>
                ))}
                {selectedStore?.provider === 'cyberark_ccp' && <p className="text-xs text-muted-foreground">Leave the username blank to use the account name CyberArk returns.</p>}
              </div>
            )}
            {pf.kind === 'ssh' ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <Select value={pf.auth} onValueChange={(v) => setProfileForm({ ...pf, auth: v as 'key' | 'password' })}>
                    <SelectTrigger aria-label="SSH auth"><SelectValue /></SelectTrigger>
                    <SelectContent><SelectItem value="key">Private key</SelectItem><SelectItem value="password">Password</SelectItem></SelectContent>
                  </Select>
                  <Input aria-label="Port" placeholder="Port 22" value={pf.port} onChange={(e) => setProfileForm({ ...pf, port: e.target.value.replace(/\D/g, '') })} />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Known host keys (ssh-keyscan output)</label>
                  <Textarea rows={3} className="font-mono text-xs" value={pf.known_hosts} onChange={(e) => setProfileForm({ ...pf, known_hosts: e.target.value })} />
                </div>
                <div className="flex items-start gap-3">
                  <Checkbox id="p-sudo" className="mt-0.5" checked={pf.sudo} onCheckedChange={(c) => setProfileForm({ ...pf, sudo: Boolean(c) })} />
                  <label htmlFor="p-sudo" className="text-sm cursor-pointer">Use <code>sudo -n sshd -T</code> for the effective sshd config (needs one sudoers line)</label>
                </div>
                <div className="flex items-start gap-3">
                  <Checkbox id="p-tofu" className="mt-0.5" checked={pf.trust_on_first_use} onCheckedChange={(c) => setProfileForm({ ...pf, trust_on_first_use: Boolean(c) })} />
                  <label htmlFor="p-tofu" className="text-sm cursor-pointer">Trust a server&apos;s host key on first connection and pin it (when it isn&apos;t listed above)</label>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <Select value={pf.transport} onValueChange={(v) => setProfileForm({ ...pf, transport: v as 'ntlm' | 'kerberos' })}>
                    <SelectTrigger aria-label="WinRM auth"><SelectValue /></SelectTrigger>
                    <SelectContent><SelectItem value="ntlm">NTLM</SelectItem><SelectItem value="kerberos">Kerberos</SelectItem></SelectContent>
                  </Select>
                  <Input aria-label="Port" placeholder={pf.https ? 'Port 5986' : 'Port 5985'} value={pf.port} onChange={(e) => setProfileForm({ ...pf, port: e.target.value.replace(/\D/g, '') })} />
                </div>
                <div className="flex items-start gap-3">
                  <Checkbox id="p-https" className="mt-0.5" checked={pf.https} onCheckedChange={(c) => setProfileForm({ ...pf, https: Boolean(c) })} />
                  <label htmlFor="p-https" className="text-sm cursor-pointer">HTTPS with certificate validation (recommended). Without it, NTLM/Kerberos message encryption is forced on.</label>
                </div>
                {pf.https && (
                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">CA certificate for the WinRM listener (PEM, if it isn&apos;t publicly trusted)</label>
                    <Textarea rows={3} className="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" value={pf.ca_cert} onChange={(e) => setProfileForm({ ...pf, ca_cert: e.target.value })} />
                  </div>
                )}
              </div>
            )}
            <div className="flex items-center gap-3">
              <Checkbox id="p-active" checked={pf.is_active} onCheckedChange={(c) => setProfileForm({ ...pf, is_active: Boolean(c) })} />
              <label htmlFor="p-active" className="text-sm cursor-pointer">Enabled</label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setProfileOpen(false)} disabled={busy === 'profile-save'}>Cancel</Button>
            <Button onClick={() => void saveProfile()} disabled={busy === 'profile-save'}>{busy === 'profile-save' && <Loader2 className="h-4 w-4 animate-spin mr-2" />}{editingProfile ? 'Save changes' : 'Add profile'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Login test */}
      <Dialog open={Boolean(loginTest)} onOpenChange={(v) => { if (!v) setLoginTest(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Test login</DialogTitle>
            <DialogDescription>Fetches the credential, then logs in to one asset and logs straight out. No checks run. The asset must match the profile&apos;s targets.</DialogDescription>
          </DialogHeader>
          <Input aria-label="Asset ID" placeholder="Asset ID" value={loginAssetId} onChange={(e) => setLoginAssetId(e.target.value.replace(/\D/g, ''))} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setLoginTest(null)}>Cancel</Button>
            <Button disabled={!loginAssetId || busy === `profile-${loginTest?.id}`} onClick={() => { if (loginTest) { void test('profile', loginTest.id, Number(loginAssetId)); setLoginTest(null); } }}>Test login</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Remove {deleteTarget?.name}?</DialogTitle>
            <DialogDescription>{deleteTarget?.type === 'store'
              ? 'The connection and its stored token or key are deleted. Nothing in the vault changes.'
              : 'The profile and any secret stored in Judah are deleted. Servers it covered are no longer checked with it.'}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" disabled={busy === `delete-${deleteTarget?.id}`} onClick={() => void remove()}>Remove</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
