'use client';

import { useEffect, useState } from 'react';
import { Loader2, RefreshCw } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage, type NetBrainPath } from '@/lib/api';

type Gateway = { ip: string; device: string; interface: string };

export function NetBrainPathPanel({ integrationId }: { integrationId: number }) {
  const { toast } = useToast();
  const [paths, setPaths] = useState<NetBrainPath[]>([]);
  const [busy, setBusy] = useState(false);
  const [sourceId, setSourceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [targetIp, setTargetIp] = useState('');
  const [destinationPort, setDestinationPort] = useState('0');
  const [protocol, setProtocol] = useState('4');
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [selectedGateway, setSelectedGateway] = useState('');
  const [selectionMessage, setSelectionMessage] = useState('');

  useEffect(() => {
    let active = true;
    api.getNetBrainPaths(integrationId).then(rows => { if (active) setPaths(rows); })
      .catch(() => { if (active) setPaths([]); });
    return () => { active = false; };
  }, [integrationId]);

  async function calculate() {
    const source = Number(sourceId);
    const target = Number(targetId);
    const port = Number(destinationPort);
    if (!Number.isInteger(source) || source <= 0 || !Number.isInteger(target) || target <= 0 ||
        !Number.isInteger(port) || port < 0 || port > 65535) {
      setSelectionMessage('Enter two valid asset IDs and a port between 0 and 65535.');
      return;
    }
    const gateway = selectedGateway ? gateways[Number(selectedGateway)] : undefined;
    setBusy(true);
    setSelectionMessage('');
    try {
      const path = await api.calculateNetBrainPath(integrationId, {
        source_asset_id: source, target_asset_id: target,
        ...(sourceIp.trim() ? { source_ip: sourceIp.trim() } : {}),
        ...(targetIp.trim() ? { target_ip: targetIp.trim() } : {}),
        ...(gateway ? { gateway_ip: gateway.ip, gateway_device: gateway.device,
          gateway_interface: gateway.interface } : {}),
        protocol: Number(protocol), destination_port: port,
      });
      setPaths(rows => [path, ...rows]);
      setGateways([]);
      setSelectedGateway('');
      toast({ title: 'Route calculation started', description: 'Refresh the row to import its hops into the graph.' });
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
        setSelectionMessage(detail.message || 'Choose a more specific route context.');
        const choices = Array.isArray(detail.options) ? detail.options : [];
        if (choices.some((item: Gateway) => item.device && item.interface)) {
          setGateways(choices);
          setSelectedGateway('');
        } else if (choices.length) {
          setSelectionMessage(`${detail.message} Available addresses: ${choices.map((item: { ip: string }) => item.ip).join(', ')}`);
        }
      } else {
        setSelectionMessage(getApiErrorMessage(error));
      }
    } finally { setBusy(false); }
  }

  async function refresh(pathId: number) {
    setBusy(true);
    try {
      const updated = await api.refreshNetBrainPath(integrationId, pathId);
      setPaths(rows => rows.map(row => row.id === pathId ? updated : row));
      if (updated.status === 'succeeded') toast({ title: 'Calculated route stored', description: updated.graph_projected_at
        ? `${updated.hop_list.length} hops projected into the graph.`
        : `${updated.hop_list.length} hops stored; Neo4j is unavailable. Refresh again to project.` });
    } catch (error) {
      toast({ title: 'Could not refresh route', description: getApiErrorMessage(error), variant: 'destructive' });
    } finally { setBusy(false); }
  }

  return <div className="border-t border-border pt-3 space-y-3">
    <div>
      <p className="text-sm font-medium">Calculated internal routes</p>
      <p className="text-xs text-muted-foreground">Choose exact Judah assets. A calculated route shows NetBrain topology; it does not prove traffic is allowed.</p>
    </div>
    <div className="grid sm:grid-cols-2 gap-2">
      <Input aria-label="Source asset ID" type="number" min={1} placeholder="Source asset ID" value={sourceId} onChange={e => setSourceId(e.target.value)} />
      <Input aria-label="Target asset ID" type="number" min={1} placeholder="Target asset ID" value={targetId} onChange={e => setTargetId(e.target.value)} />
      <Input aria-label="Source IP" placeholder="Source IPv4, if asset has several" value={sourceIp} onChange={e => setSourceIp(e.target.value)} />
      <Input aria-label="Target IP" placeholder="Target IPv4, if asset has several" value={targetIp} onChange={e => setTargetIp(e.target.value)} />
      <Select value={protocol} onValueChange={value => { setProtocol(value); if (value === '4') setDestinationPort('0'); }}><SelectTrigger aria-label="Protocol"><SelectValue /></SelectTrigger><SelectContent>
        <SelectItem value="4">IPv4 route</SelectItem><SelectItem value="6">TCP</SelectItem>
      </SelectContent></Select>
      <Input aria-label="Destination port" type="number" min={0} max={65535} placeholder="Destination port" value={destinationPort} onChange={e => setDestinationPort(e.target.value)} disabled={protocol === '4'} />
    </div>
    {gateways.length > 0 && <Select value={selectedGateway} onValueChange={setSelectedGateway}>
      <SelectTrigger aria-label="Source gateway"><SelectValue placeholder="Select source gateway" /></SelectTrigger>
      <SelectContent>{gateways.map((gateway, index) => <SelectItem key={`${gateway.ip}-${gateway.device}-${gateway.interface}`} value={String(index)}>{gateway.device} · {gateway.ip} · {gateway.interface}</SelectItem>)}</SelectContent>
    </Select>}
    {selectionMessage && <p role="alert" className="text-xs text-amber-400">{selectionMessage}</p>}
    <Button size="sm" variant="outline" onClick={calculate} disabled={busy || !sourceId || !targetId}>
      {busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}Calculate route
    </Button>
    {paths.map(path => <div key={path.id} className="rounded border border-border p-2 text-xs space-y-1">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium">#{path.source_asset_id} {path.source_ip} → #{path.target_asset_id} {path.target_ip}</span>
        <Button size="sm" variant="ghost" onClick={() => refresh(path.id)} disabled={busy} aria-label={`Refresh route ${path.id}`}><RefreshCw className="h-3.5 w-3.5" /></Button>
      </div>
      <p className="text-muted-foreground">{path.status} · {path.hop_list.length} hops · {path.graph_projected_at ? 'in graph' : 'graph pending'} · gateway {path.gateway_device} · {path.protocol === 6 ? 'TCP' : 'IPv4'} {path.destination_port || ''}</p>
      {path.hop_list.length > 0 && <details><summary className="cursor-pointer">View hops</summary><ol className="mt-1 space-y-1 list-decimal pl-5">
        {path.hop_list.map(hop => <li key={hop.hop_id}>{hop.source_device || 'Unknown'} → {hop.target_device || 'Unknown'} ({hop.outbound_interface || 'interface unknown'})</li>)}
      </ol></details>}
    </div>)}
  </div>;
}
