'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Plus, RefreshCw, Workflow, Library } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import type { WorkflowSummary } from '@/components/workflows/types';

export default function WorkflowsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<{ id: number; name: string }[]>([]);
  const [orgId, setOrgId] = useState<number | null>(null);
  const [workflows, setWorkflows] = useState<WorkflowSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'workflow' | 'module'>('workflow');
  const [creating, setCreating] = useState(false);

  const load = async (organizationId: number) => {
    setLoading(true);
    try {
      const rows = await api.getWorkflows({
        organization_id: organizationId,
        seed_library: true,
      });
      setWorkflows(rows || []);
    } catch (e: any) {
      toast({ title: 'Failed to load workflows', description: e?.message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const list = await api.getOrganizations();
        setOrgs(list || []);
        if (list?.length) {
          setOrgId(list[0].id);
          await load(list[0].id);
        } else {
          setLoading(false);
        }
      } catch {
        setLoading(false);
      }
    })();
  }, []);

  const create = async () => {
    if (!orgId || !name.trim()) return;
    setCreating(true);
    try {
      const wf = await api.createWorkflow({
        name: name.trim(),
        kind,
        organization_id: orgId,
        graph: { nodes: [], edges: [], viewport: { x: 0, y: 0, zoom: 1 } },
      });
      toast({ title: 'Workflow created' });
      setCreateOpen(false);
      setName('');
      router.push(`/workflows/${wf.id}`);
    } catch (e: any) {
      toast({ title: 'Create failed', description: e?.message, variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  const seed = async () => {
    if (!orgId) return;
    try {
      await api.seedWorkflowLibrary(orgId);
      await load(orgId);
      toast({ title: 'Library templates ready' });
    } catch (e: any) {
      toast({ title: 'Seed failed', description: e?.message, variant: 'destructive' });
    }
  };

  return (
    <MainLayout>
      <Header title="Workflows" subtitle="Design and run Trickest-style recon DAGs" />
      <div className="p-6 space-y-4">
        <div className="flex flex-wrap items-center gap-3 justify-between">
          <div className="flex items-center gap-3">
            <Select
              value={orgId ? String(orgId) : undefined}
              onValueChange={(v) => {
                const id = parseInt(v, 10);
                setOrgId(id);
                load(id);
              }}
            >
              <SelectTrigger className="w-56">
                <SelectValue placeholder="Organization" />
              </SelectTrigger>
              <SelectContent>
                {orgs.map((o) => (
                  <SelectItem key={o.id} value={String(o.id)}>
                    {o.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => orgId && load(orgId)}>
              <RefreshCw className="h-4 w-4 mr-1" /> Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={seed}>
              <Library className="h-4 w-4 mr-1" /> Seed library
            </Button>
          </div>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-1" /> New workflow
          </Button>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" /> Loading…
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {workflows.map((wf) => (
              <Card
                key={wf.id}
                className="cursor-pointer hover:border-primary/40 transition-colors"
                onClick={() => router.push(`/workflows/${wf.id}`)}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Workflow className="h-4 w-4 text-primary" />
                      {wf.name}
                    </CardTitle>
                    <div className="flex gap-1">
                      {wf.is_library && <Badge variant="secondary">Library</Badge>}
                      <Badge variant="outline" className="capitalize">
                        {wf.kind}
                      </Badge>
                    </div>
                  </div>
                  <CardDescription className="line-clamp-2">
                    {wf.description || 'No description'}
                  </CardDescription>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground">
                  Updated {wf.updated_at ? new Date(wf.updated_at).toLocaleString() : '—'}
                </CardContent>
              </Card>
            ))}
            {workflows.length === 0 && (
              <div className="col-span-full text-center text-muted-foreground py-16">
                No workflows yet. Create one or seed the library.
              </div>
            )}
          </div>
        )}
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create workflow</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="External recon" />
            </div>
            <div className="space-y-1">
              <Label>Kind</Label>
              <Select value={kind} onValueChange={(v) => setKind(v as any)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="workflow">Workflow</SelectItem>
                  <SelectItem value="module">Module</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={create} disabled={creating || !name.trim()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
