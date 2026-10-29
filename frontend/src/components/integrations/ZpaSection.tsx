'use client';

import { useEffect, useState } from 'react';
import { Loader2, Plus, RefreshCw, RotateCw } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { api, getApiErrorMessage, type ZpaIntegration, type ZpaIntegrationSecret } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

export function ZpaSection() {
  const { toast } = useToast();
  const [connections, setConnections] = useState<ZpaIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [secret, setSecret] = useState<ZpaIntegrationSecret | null>(null);

  async function load() {
    try { setConnections(await api.getZpaIntegrations()); }
    catch (error) { toast({ title: 'Unable to load ZPA connections', description: getApiErrorMessage(error), variant: 'destructive' }); }
    finally { setLoading(false); }
  }

  useEffect(() => { void load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function create() {
    if (!name.trim()) return;
    setBusyId(-1);
    try {
      const created = await api.createZpaIntegration(name.trim());
      setSecret(created);
      setCreateOpen(false);
      setName('');
      await load();
    } catch (error) {
      toast({ title: 'Unable to create ZPA connection', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  async function toggle(connection: ZpaIntegration) {
    setBusyId(connection.id);
    try { await api.updateZpaIntegration(connection.id, !connection.is_active); await load(); }
    catch (error) { toast({ title: 'Unable to update ZPA connection', description: getApiErrorMessage(error), variant: 'destructive' }); }
    finally { setBusyId(null); }
  }

  async function rotate(connection: ZpaIntegration) {
    setBusyId(connection.id);
    try { setSecret(await api.rotateZpaToken(connection.id)); }
    catch (error) { toast({ title: 'Unable to rotate ZPA token', description: getApiErrorMessage(error), variant: 'destructive' }); }
    finally { setBusyId(null); }
  }

  async function project(connection: ZpaIntegration) {
    setBusyId(connection.id);
    try {
      const result = await api.projectZpaIntegration(connection.id);
      toast({ title: result.ok ? 'ZPA graph refreshed' : 'ZPA graph unavailable',
        description: result.ok ? `${result.assets ?? 0} candidates, ${result.edges ?? 0} observation edges` : result.error,
        variant: result.ok ? 'default' : 'destructive' });
    } catch (error) {
      toast({ title: 'Unable to refresh ZPA graph', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusyId(null); }
  }

  return <>
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="text-base">Zscaler ZPA</CardTitle>
          <CardDescription>Discover candidate destinations from ZPA User Activity and Microsegmentation LSS logs.</CardDescription>
        </div>
        <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-4 w-4 mr-1" />Add connection</Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : connections.length === 0 ?
          <p className="text-sm text-muted-foreground">Create a connection, then configure your LSS collector to forward JSON events to Judah.</p> :
          connections.map(connection => <div key={connection.id} className="rounded-md border p-3 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <div className="font-medium text-sm">{connection.name}</div>
              <Badge variant={connection.is_active ? 'default' : 'secondary'}>{connection.is_active ? 'Active' : 'Disabled'}</Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              Ingest path: <code>/api/v1/integrations/zpa/{connection.id}/events</code><br />
              Last event: {connection.last_ingest_at ? new Date(connection.last_ingest_at).toLocaleString() : 'Never'}
            </p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={busyId === connection.id} onClick={() => void toggle(connection)}>
                {connection.is_active ? 'Disable' : 'Enable'}
              </Button>
              <Button size="sm" variant="outline" disabled={busyId === connection.id} onClick={() => void rotate(connection)}>
                <RotateCw className="h-3.5 w-3.5 mr-1" />Rotate token
              </Button>
              <Button size="sm" variant="outline" disabled={busyId === connection.id} onClick={() => void project(connection)}>
                <RefreshCw className="h-3.5 w-3.5 mr-1" />Refresh graph
              </Button>
            </div>
          </div>)}
        <p className="text-xs text-muted-foreground">Destinations are unverified candidates. Successful flows and blocked or unknown-status events get separate graph edges. ZPA private-app logs do not cover general Internet egress.</p>
      </CardContent>
    </Card>

    <Dialog open={createOpen} onOpenChange={setCreateOpen}>
      <DialogContent>
        <DialogHeader><DialogTitle>Add ZPA connection</DialogTitle><DialogDescription>Name this LSS feed. Judah will issue a collector token when you create it.</DialogDescription></DialogHeader>
        <Input aria-label="Connection name" placeholder="Production ZPA" value={name} onChange={event => setName(event.target.value)} />
        <DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button disabled={!name.trim() || busyId === -1} onClick={() => void create()}>Create</Button></DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog open={secret !== null} onOpenChange={open => { if (!open) setSecret(null); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Save the ZPA ingest token</DialogTitle><DialogDescription>This token is shown once. Put it in your LSS collector and send it in the X-ZPA-Ingest-Token header. Rotation invalidates the previous token.</DialogDescription></DialogHeader>
        <Input aria-label="ZPA ingest token" readOnly value={secret?.ingest_token ?? ''} className="font-mono text-xs" />
        <p className="text-xs text-muted-foreground">POST JSON or NDJSON to <code>/api/v1/integrations/zpa/{secret?.id}/events</code>. See the ZPA integration guide for supported fields.</p>
        <DialogFooter><Button onClick={() => setSecret(null)}>Done</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  </>;
}
