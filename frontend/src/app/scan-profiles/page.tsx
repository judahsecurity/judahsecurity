'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { ScanNavTabs } from '@/components/scanning/ScanNavTabs';
import { api, getApiErrorMessage, ScanProfile, ScanProfileCreateInput, ScanProfileType } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Pencil, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';

type ProfileForm = {
  name: string;
  description: string;
  profile_type: ScanProfileType;
  severity: string;
  tags: string;
  exclude_tags: string;
  rate_limit: string;
  bulk_size: string;
  concurrency: string;
  timeout: string;
  max_hosts: string;
  requests_per_second: string;
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_http_probe: boolean;
  enable_technology_detection: boolean;
  enable_vulnerability_scan: boolean;
  is_default: boolean;
};

const EMPTY_FORM: ProfileForm = {
  name: '',
  description: '',
  profile_type: 'nuclei',
  severity: 'critical, high',
  tags: '',
  exclude_tags: '',
  rate_limit: '150',
  bulk_size: '25',
  concurrency: '25',
  timeout: '10',
  max_hosts: '50',
  requests_per_second: '100',
  enable_subdomain_enum: true,
  enable_port_scan: true,
  enable_http_probe: true,
  enable_technology_detection: true,
  enable_vulnerability_scan: true,
  is_default: false,
};

const csv = (value: string) => value.split(',').map((item) => item.trim()).filter(Boolean);

function formFromProfile(profile: ScanProfile): ProfileForm {
  return {
    name: profile.name,
    description: profile.description || '',
    profile_type: profile.profile_type,
    severity: profile.nuclei_severity.join(', '),
    tags: profile.nuclei_tags.join(', '),
    exclude_tags: profile.nuclei_exclude_tags.join(', '),
    rate_limit: String(profile.nuclei_rate_limit),
    bulk_size: String(profile.nuclei_bulk_size),
    concurrency: String(profile.nuclei_concurrency),
    timeout: String(profile.nuclei_timeout),
    max_hosts: String(profile.max_concurrent_hosts),
    requests_per_second: String(profile.requests_per_second),
    enable_subdomain_enum: profile.enable_subdomain_enum,
    enable_port_scan: profile.enable_port_scan,
    enable_http_probe: profile.enable_http_probe,
    enable_technology_detection: profile.enable_technology_detection,
    enable_vulnerability_scan: profile.enable_vulnerability_scan,
    is_default: profile.is_default,
  };
}

export default function ScanProfilesPage() {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [organizations, setOrganizations] = useState<Array<{ id: number; name: string }>>([]);
  const [organizationId, setOrganizationId] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<ScanProfile | null>(null);
  const [deleting, setDeleting] = useState<ScanProfile | null>(null);
  const [form, setForm] = useState<ProfileForm>(EMPTY_FORM);
  const { toast } = useToast();

  const loadOrganizations = async () => {
    const data = await api.getOrganizations();
    setOrganizations(data || []);
    if (data?.length) setOrganizationId((current) => current || String(data[0].id));
  };

  const loadProfiles = async () => {
    setLoading(true);
    try {
      const selected = organizationId ? parseInt(organizationId, 10) : undefined;
      setProfiles(await api.getScanProfiles(selected ? { organization_id: selected } : undefined));
    } catch (error) {
      toast({ title: 'Unable to load profiles', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOrganizations().catch((error) => {
      toast({ title: 'Unable to load organizations', description: getApiErrorMessage(error), variant: 'destructive' });
    });
  }, []);

  useEffect(() => { loadProfiles(); }, [organizationId]);

  const openCreate = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setDialogOpen(true);
  };

  const openEdit = (profile: ScanProfile) => {
    setEditing(profile);
    setForm(formFromProfile(profile));
    setDialogOpen(true);
  };

  const submit = async () => {
    if (!form.name.trim()) {
      toast({ title: 'Profile name is required', variant: 'destructive' });
      return;
    }
    if (!editing && !organizationId) {
      toast({ title: 'Select an organization first', variant: 'destructive' });
      return;
    }
    const payload: ScanProfileCreateInput = {
      name: form.name.trim(),
      description: form.description.trim() || null,
      profile_type: form.profile_type,
      organization_id: organizationId ? parseInt(organizationId, 10) : undefined,
      nuclei_severity: csv(form.severity),
      nuclei_tags: csv(form.tags),
      nuclei_exclude_tags: csv(form.exclude_tags),
      nuclei_rate_limit: parseInt(form.rate_limit, 10),
      nuclei_bulk_size: parseInt(form.bulk_size, 10),
      nuclei_concurrency: parseInt(form.concurrency, 10),
      nuclei_timeout: parseInt(form.timeout, 10),
      max_concurrent_hosts: parseInt(form.max_hosts, 10),
      requests_per_second: parseInt(form.requests_per_second, 10),
      enable_subdomain_enum: form.enable_subdomain_enum,
      enable_port_scan: form.enable_port_scan,
      enable_http_probe: form.enable_http_probe,
      enable_technology_detection: form.enable_technology_detection,
      enable_vulnerability_scan: form.enable_vulnerability_scan,
      is_default: form.is_default,
    };
    setSaving(true);
    try {
      if (editing) {
        const { organization_id: _organizationId, ...changes } = payload;
        await api.updateScanProfile(editing.id, changes);
      } else {
        await api.createScanProfile(payload);
      }
      toast({ title: editing ? 'Profile updated' : 'Profile created' });
      setDialogOpen(false);
      await loadProfiles();
    } catch (error) {
      toast({ title: 'Unable to save profile', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setSaving(true);
    try {
      await api.deleteScanProfile(deleting.id);
      toast({ title: 'Profile deleted' });
      setDeleting(null);
      await loadProfiles();
    } catch (error) {
      toast({ title: 'Unable to delete profile', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const toggle = (field: keyof ProfileForm, label: string) => (
    <div className="flex items-center justify-between rounded-md border p-3">
      <Label htmlFor={String(field)}>{label}</Label>
      <Switch id={String(field)} checked={Boolean(form[field])} onCheckedChange={(checked) => setForm({ ...form, [field]: checked })} />
    </div>
  );

  return (
    <MainLayout>
      <Header title="Scan Profiles" subtitle="Reusable, organization-scoped scanning policies" />
      <ScanNavTabs />
      <div className="p-6 space-y-6">
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-4">
            <div>
              <CardTitle>Profiles</CardTitle>
              <CardDescription>Built-ins are read-only. Custom profiles are isolated to the selected organization.</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {organizations.length > 0 && (
                <Select value={organizationId} onValueChange={setOrganizationId}>
                  <SelectTrigger className="w-56"><SelectValue placeholder="Select organization" /></SelectTrigger>
                  <SelectContent>{organizations.map((org) => <SelectItem key={org.id} value={String(org.id)}>{org.name}</SelectItem>)}</SelectContent>
                </Select>
              )}
              <Button variant="outline" size="icon" onClick={loadProfiles} aria-label="Refresh profiles"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /></Button>
              <Button onClick={openCreate} disabled={!organizationId}><Plus className="mr-2 h-4 w-4" />New Profile</Button>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Coverage</TableHead><TableHead>Limits</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader>
              <TableBody>
                {profiles.map((profile) => {
                  const builtIn = profile.organization_id == null;
                  return (
                    <TableRow key={profile.id}>
                      <TableCell><div className="font-medium flex items-center gap-2">{profile.name}{builtIn && <ShieldCheck className="h-4 w-4 text-primary" />}{profile.is_default && <Badge variant="secondary">Default</Badge>}</div><div className="text-xs text-muted-foreground max-w-xl">{profile.description || 'No description'}</div></TableCell>
                      <TableCell><Badge variant="outline">{profile.profile_type}</Badge></TableCell>
                      <TableCell className="text-sm">{profile.nuclei_severity.join(', ') || 'Discovery settings'}</TableCell>
                      <TableCell className="text-sm">{profile.nuclei_rate_limit} req/s · {profile.nuclei_concurrency} concurrent</TableCell>
                      <TableCell className="text-right">
                        {builtIn ? <span className="text-xs text-muted-foreground">Built-in</span> : <div className="flex justify-end gap-1"><Button variant="ghost" size="icon" onClick={() => openEdit(profile)} aria-label={`Edit ${profile.name}`}><Pencil className="h-4 w-4" /></Button><Button variant="ghost" size="icon" onClick={() => setDeleting(profile)} aria-label={`Delete ${profile.name}`}><Trash2 className="h-4 w-4 text-destructive" /></Button></div>}
                      </TableCell>
                    </TableRow>
                  );
                })}
                {!loading && profiles.length === 0 && <TableRow><TableCell colSpan={5} className="py-10 text-center text-muted-foreground">No profiles are available.</TableCell></TableRow>}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader><DialogTitle>{editing ? 'Edit scan profile' : 'Create scan profile'}</DialogTitle><DialogDescription>Set safe reusable defaults. A scan may still provide explicit per-run overrides.</DialogDescription></DialogHeader>
          <div className="grid gap-4 py-2 md:grid-cols-2">
            <div className="space-y-2"><Label>Name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div className="space-y-2"><Label>Profile type</Label><Select value={form.profile_type} onValueChange={(value: ScanProfileType) => setForm({ ...form, profile_type: value })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="nuclei">Nuclei</SelectItem><SelectItem value="discovery">Discovery</SelectItem><SelectItem value="full">Full</SelectItem><SelectItem value="custom">Custom</SelectItem></SelectContent></Select></div>
            <div className="space-y-2 md:col-span-2"><Label>Description</Label><Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
            <div className="space-y-2"><Label>Severities (comma-separated)</Label><Input value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} /></div>
            <div className="space-y-2"><Label>Include tags (comma-separated)</Label><Input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} /></div>
            <div className="space-y-2 md:col-span-2"><Label>Exclude tags (comma-separated)</Label><Input value={form.exclude_tags} onChange={(e) => setForm({ ...form, exclude_tags: e.target.value })} /></div>
            {[['rate_limit', 'Nuclei rate / sec'], ['bulk_size', 'Bulk hosts'], ['concurrency', 'Template concurrency'], ['timeout', 'Timeout (seconds)'], ['max_hosts', 'Maximum concurrent hosts'], ['requests_per_second', 'Overall requests / sec']].map(([field, label]) => <div className="space-y-2" key={field}><Label>{label}</Label><Input type="number" min="1" value={String(form[field as keyof ProfileForm])} onChange={(e) => setForm({ ...form, [field]: e.target.value })} /></div>)}
            <div className="grid gap-2 md:col-span-2 md:grid-cols-2">{toggle('enable_subdomain_enum', 'Subdomain enumeration')}{toggle('enable_port_scan', 'Port scanning')}{toggle('enable_http_probe', 'HTTP probing')}{toggle('enable_technology_detection', 'Technology detection')}{toggle('enable_vulnerability_scan', 'Vulnerability scanning')}{toggle('is_default', 'Default for this profile type')}</div>
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button><Button onClick={submit} disabled={saving}>{saving ? 'Saving…' : 'Save profile'}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleting)} onOpenChange={(open) => !open && setDeleting(null)}>
        <DialogContent><DialogHeader><DialogTitle>Delete scan profile?</DialogTitle><DialogDescription>This permanently removes “{deleting?.name}”. Existing scans retain the settings copied into them.</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => setDeleting(null)}>Cancel</Button><Button variant="destructive" onClick={remove} disabled={saving}>{saving ? 'Deleting…' : 'Delete'}</Button></DialogFooter></DialogContent>
      </Dialog>
    </MainLayout>
  );
}
