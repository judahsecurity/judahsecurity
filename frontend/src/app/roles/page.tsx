'use client';

import { useCallback, useEffect, useState } from 'react';
import { Loader2, Plus, Save, Trash2 } from 'lucide-react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { api, getApiErrorMessage, type RoleCatalog, type CustomRole } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

type Draft = { id?: number; name: string; description: string; permissions: string[] };
type OrgUser = { id: number; email: string; username: string; role: string; custom_role_id?: number | null };

const EMPTY: Draft = { name: '', description: '', permissions: [] };

export default function RolesPage() {
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<RoleCatalog | null>(null);
  const [users, setUsers] = useState<OrgUser[]>([]);
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [roles, people] = await Promise.all([api.getRoles(), api.getUsers()]);
      setCatalog(roles);
      setUsers(Array.isArray(people) ? people : people?.items || []);
    } catch (error) {
      toast({ title: 'Could not load roles', description: getApiErrorMessage(error, 'Admin access required'), variant: 'destructive' });
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const toggle = (perm: string) => setDraft((d) => ({
    ...d,
    permissions: d.permissions.includes(perm) ? d.permissions.filter((p) => p !== perm) : [...d.permissions, perm],
  }));

  const save = async () => {
    setBusy(true);
    try {
      const body = { name: draft.name.trim(), description: draft.description, permissions: draft.permissions };
      if (draft.id) await api.updateRole(draft.id, body);
      else await api.createRole(body);
      toast({ title: 'Saved', description: `Role "${body.name}" saved` });
      setDraft(EMPTY);
      await load();
    } catch (error) {
      toast({ title: 'Save failed', description: getApiErrorMessage(error, 'Could not save role'), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (role: CustomRole) => {
    if (!window.confirm(`Delete role "${role.name}"? ${role.members} user(s) fall back to their built-in role.`)) return;
    try {
      await api.deleteRole(role.id);
      if (draft.id === role.id) setDraft(EMPTY);
      await load();
    } catch (error) {
      toast({ title: 'Delete failed', description: getApiErrorMessage(error, 'Could not delete role'), variant: 'destructive' });
    }
  };

  const assign = async (userId: number, value: string) => {
    try {
      await api.assignRole(userId, value === 'none' ? null : Number(value));
      await load();
    } catch (error) {
      toast({ title: 'Assignment failed', description: getApiErrorMessage(error, 'Could not assign role'), variant: 'destructive' });
    }
  };

  return (
    <MainLayout>
      <Header title="Roles" subtitle="Custom roles narrow what a user's built-in role (admin, analyst, viewer) can do" />
      <div className="p-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{draft.id ? 'Edit role' : 'New role'}</CardTitle>
            <CardDescription>
              A custom role can only take access away: a user gets a permission only if both their
              built-in role and the custom role include it.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="role-name">Name</Label>
              <Input id="role-name" value={draft.name} maxLength={80}
                     onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="e.g. Recon only" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="role-desc">Description</Label>
              <Input id="role-desc" value={draft.description} maxLength={300}
                     onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
            </div>
            <div className="space-y-2">
              {(catalog?.permissions || []).map((p) => (
                <label key={p.name} className="flex items-start gap-3 text-sm cursor-pointer">
                  <Checkbox checked={draft.permissions.includes(p.name)} onCheckedChange={() => toggle(p.name)} />
                  <span><span className="font-mono text-xs">{p.name}</span><br />
                    <span className="text-muted-foreground">{p.description}</span></span>
                </label>
              ))}
            </div>
            <div className="flex gap-2">
              <Button onClick={save} disabled={busy || draft.name.trim().length < 2}>
                {busy ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                Save role
              </Button>
              {draft.id && <Button variant="outline" onClick={() => setDraft(EMPTY)}><Plus className="h-4 w-4 mr-2" />New role</Button>}
            </div>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader><CardTitle>Custom roles</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {!catalog?.roles.length && <p className="text-sm text-muted-foreground">No custom roles yet.</p>}
              {catalog?.roles.map((role) => (
                <div key={role.id} className="flex items-center justify-between border rounded-md px-3 py-2">
                  <button type="button" className="text-left" onClick={() => setDraft({ ...role })}>
                    <p className="font-medium">{role.name}</p>
                    <p className="text-xs text-muted-foreground">{role.permissions.length} permissions · {role.members} member(s)</p>
                  </button>
                  <Button variant="ghost" size="icon" aria-label={`Delete ${role.name}`} onClick={() => remove(role)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Assignments</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {users.map((u) => (
                <div key={u.id} className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm truncate">{u.email || u.username}</p>
                    <p className="text-xs text-muted-foreground capitalize">Built-in: {u.role}</p>
                  </div>
                  <Select value={u.custom_role_id ? String(u.custom_role_id) : 'none'} onValueChange={(v) => assign(u.id, v)}>
                    <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">No custom role</SelectItem>
                      {catalog?.roles.map((r) => <SelectItem key={r.id} value={String(r.id)}>{r.name}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
