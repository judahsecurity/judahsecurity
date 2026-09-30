'use client';

import { useEffect, useState, useMemo } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Network, Search, Download, Loader2, Filter, AlertTriangle, MoreVertical, Bug, Flag, ExternalLink, Shield, CheckCircle2, ScanLine, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Link from 'next/link';

interface PortResult {
  id: number;
  asset_id: number;
  hostname: string | null;
  ip_address: string | null;
  asset_value: string | null;
  scanned_ip?: string;  // Actual IP where port was found
  port: number;
  protocol: string;
  service_name?: string;
  service_product?: string;
  service_version?: string;
  state: string;
  banner?: string;
  is_risky: boolean;
  risk_reason?: string;
  discovered_by?: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  finding_id?: number;  // Link to associated finding
  // Nmap verification fields
  verified: boolean;
  verified_at?: string;
  verified_state?: string;  // open, filtered, closed from nmap
  verification_scanner?: string;
}

interface PortChartData {
  name: string;
  count: number;
  color: string;
}

const nonOpenStates = ['filtered', 'closed', 'open|filtered', 'closed|filtered'];

const effectivePortState = (port: PortResult) =>
  port.verified && nonOpenStates.includes(port.verified_state?.toLowerCase() || '')
    ? port.verified_state || port.state
    : port.state;

const isNonExposedPort = (port: PortResult) =>
  nonOpenStates.includes(effectivePortState(port)?.toLowerCase() || '');

// Color palette for charts
const CHART_COLORS = [
  '#3b82f6', // blue
  '#22c55e', // green
  '#f59e0b', // amber
  '#ef4444', // red
  '#8b5cf6', // purple
  '#06b6d4', // cyan
  '#ec4899', // pink
  '#f97316', // orange
  '#84cc16', // lime
  '#6366f1', // indigo
];

export default function PortsPage() {
  const [ports, setPorts] = useState<PortResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const [riskyFilter, setRiskyFilter] = useState<string>('all');
  const [verifyingPorts, setVerifyingPorts] = useState<Set<number>>(new Set());
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [portsData, orgsData] = await Promise.all([
        api.getPorts({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          is_risky: riskyFilter === 'risky' ? true : riskyFilter === 'safe' ? false : undefined,
          limit: 200,
        }),
        api.getOrganizations(),
      ]);

      setPorts(portsData.items || portsData || []);
      setOrganizations(orgsData);
    } catch (error) {
      console.error('Failed to fetch ports:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch port data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [orgFilter, riskyFilter]);

  const handleCreateFinding = async (portId: number, severity: string) => {
    try {
      const response = await api.request(`/ports/${portId}/create-finding?severity=${severity}`, {
        method: 'POST',
      });
      if (response.success) {
        toast({
          title: 'Finding Created',
          description: response.message,
        });
        fetchData(); // Refresh to show updated risky status
      } else {
        toast({
          title: 'Finding Exists',
          description: response.message,
          variant: 'default',
        });
      }
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create finding',
        variant: 'destructive',
      });
    }
  };

  const handleMarkRisky = async (portId: number) => {
    const reason = prompt('Enter reason why this port is risky:');
    if (!reason) return;
    
    try {
      await api.request(`/ports/${portId}/mark-risky?reason=${encodeURIComponent(reason)}`, {
        method: 'POST',
      });
      toast({
        title: 'Port Marked as Risky',
        description: 'The port has been flagged for attention.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to mark port as risky',
        variant: 'destructive',
      });
    }
  };

  const handleVerifyPort = async (portId: number) => {
    setVerifyingPorts((prev: Set<number>) => new Set(Array.from(prev).concat(portId)));
    
    try {
      const response = await api.request(`/ports/${portId}/verify`, {
        method: 'POST',
      });
      
      toast({
        title: 'Port Verified',
        description: `Port ${response.port} is ${response.state.toUpperCase()}${response.service ? ` (${response.service})` : ''}`,
        variant: response.state === 'open' ? 'default' : 'destructive',
      });
      
      // Refresh to show updated verification status
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Verification Failed',
        description: error.response?.data?.detail || 'Failed to verify port with nmap',
        variant: 'destructive',
      });
    } finally {
      setVerifyingPorts((prev: Set<number>) => {
        const next = new Set(prev);
        next.delete(portId);
        return next;
      });
    }
  };

  const handleBulkVerify = async () => {
    const unverifiedPorts = filteredPorts.filter(p => !p.verified && p.state?.toLowerCase() === 'open');
    
    if (unverifiedPorts.length === 0) {
      toast({
        title: 'No Ports to Verify',
        description: 'All displayed open ports have been verified.',
      });
      return;
    }
    
    if (unverifiedPorts.length > 100) {
      toast({
        title: 'Too Many Ports',
        description: `Can only verify up to 100 ports at once. Found ${unverifiedPorts.length} unverified ports.`,
        variant: 'destructive',
      });
      return;
    }
    
    try {
      const response = await api.request('/ports/verify-bulk', {
        method: 'POST',
        body: JSON.stringify(unverifiedPorts.map(p => p.id)),
      });
      
      toast({
        title: 'Bulk Verification Queued',
        description: `Verification queued for ${response.ports_queued} ports. Scan ID: ${response.scan_id}`,
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to queue bulk verification',
        variant: 'destructive',
      });
    }
  };

  const handleBackgroundVerify = async () => {
    // Get the first organization from the list (or use the filtered one)
    const orgId = orgFilter !== 'all' ? parseInt(orgFilter) : organizations[0]?.id;
    if (!orgId) {
      toast({
        title: 'Error',
        description: 'Please select an organization first',
        variant: 'destructive',
      });
      return;
    }

    try {
      const response = await api.request(`/scans/port-verify/${orgId}?max_ports=500`, {
        method: 'POST',
      });
      
      if (response.unverified_count === 0) {
        toast({
          title: 'No Ports to Verify',
          description: 'All ports have already been verified.',
        });
      } else {
        toast({
          title: 'Background Verification Started',
          description: `Scan ${response.scan_id} queued to verify ${response.ports_to_verify} ports. Check Scans page for progress.`,
        });
      }
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to start background verification',
        variant: 'destructive',
      });
    }
  };

  const handleServiceDetection = async () => {
    // Get the first organization from the list (or use the filtered one)
    const orgId = orgFilter !== 'all' ? parseInt(orgFilter) : organizations[0]?.id;
    if (!orgId) {
      toast({
        title: 'Error',
        description: 'Please select an organization first',
        variant: 'destructive',
      });
      return;
    }

    try {
      const response = await api.request(`/scans/service-detect/${orgId}?max_ports=200&intensity=7`, {
        method: 'POST',
      });
      
      if (response.unknown_count === 0) {
        toast({
          title: 'No Unknown Services',
          description: 'All services have already been identified.',
        });
      } else {
        toast({
          title: 'Service Detection Started',
          description: `Scan ${response.scan_id} queued to identify ${response.ports_to_scan} unknown services. Check Scans page for progress.`,
        });
      }
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to start service detection',
        variant: 'destructive',
      });
    }
  };

  const handleExport = () => {
    downloadCSV(
      ports.map((p) => ({
        hostname: p.hostname || p.asset_value || '',
        ip_address: p.ip_address || p.asset_value || '',
        port: p.port,
        protocol: p.protocol,
        service: p.service_name || '',
        product: p.service_product || '',
        version: p.service_version || '',
        state: effectivePortState(p),
        is_risky: p.is_risky ? 'Yes' : 'No',
        risk_reason: p.risk_reason || '',
        discovered_by: p.discovered_by || '',
        last_seen: p.last_seen,
      })),
      'ports'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  const filteredPorts = ports.filter(
    (p) =>
      (p.hostname?.toLowerCase() || '').includes(search.toLowerCase()) ||
      (p.ip_address || '').includes(search) ||
      (p.asset_value || '').toLowerCase().includes(search.toLowerCase()) ||
      p.port?.toString().includes(search) ||
      (p.service_name?.toLowerCase() || '').includes(search.toLowerCase())
  );

  // Compute top ports chart data
  const topPortsData = useMemo((): PortChartData[] => {
    const portCounts: Record<number, number> = {};
    ports.forEach((p) => {
      portCounts[p.port] = (portCounts[p.port] || 0) + 1;
    });
    
    return Object.entries(portCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([port, count], index) => ({
        name: port,
        count,
        color: CHART_COLORS[index % CHART_COLORS.length],
      }));
  }, [ports]);

  // Compute top services chart data
  const topServicesData = useMemo((): PortChartData[] => {
    const serviceCounts: Record<string, number> = {};
    ports.forEach((p) => {
      const service = p.service_name || 'unknown';
      serviceCounts[service] = (serviceCounts[service] || 0) + 1;
    });
    
    return Object.entries(serviceCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([service, count], index) => ({
        name: service,
        count,
        color: CHART_COLORS[index % CHART_COLORS.length],
      }));
  }, [ports]);

  const getStateColor = (state: string) => {
    switch (state?.toLowerCase()) {
      case 'open':
        return 'bg-green-500/20 text-green-400';
      case 'closed':
        return 'bg-red-500/20 text-red-400';
      case 'filtered':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getServiceColor = (port: number) => {
    const criticalPorts = [21, 22, 23, 25, 53, 110, 143, 445, 3389, 5900];
    const webPorts = [80, 443, 8080, 8443];
    const dbPorts = [3306, 5432, 27017, 6379, 1433];

    if (criticalPorts.includes(port)) return 'border-red-500/30 bg-red-500/10';
    if (webPorts.includes(port)) return 'border-blue-500/30 bg-blue-500/10';
    if (dbPorts.includes(port)) return 'border-yellow-500/30 bg-yellow-500/10';
    return '';
  };

  return (
    <MainLayout>
      <Header title="Ports" subtitle="Open ports and services discovered across assets" />

      <div className="p-6">
        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 mb-6 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by host, IP, port, or service..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="flex items-center gap-2">
            <Select value={orgFilter} onValueChange={setOrgFilter}>
              <SelectTrigger className="w-[200px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Organization" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Organizations</SelectItem>
                {organizations.map((org) => (
                  <SelectItem key={org.id} value={org.id.toString()}>
                    {org.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <ScanLine className="h-4 w-4 mr-2" />
                  Nmap Scans
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={handleBackgroundVerify}>
                  <CheckCircle2 className="h-4 w-4 mr-2 text-green-500" />
                  Verify All Ports (Background)
                  <span className="ml-2 text-xs text-muted-foreground">Confirm open/filtered</span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleServiceDetection}>
                  <Search className="h-4 w-4 mr-2 text-blue-500" />
                  Detect Unknown Services
                  <span className="ml-2 text-xs text-muted-foreground">Identify service versions</span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={handleBulkVerify}>
                  <RefreshCw className="h-4 w-4 mr-2 text-yellow-500" />
                  Quick Verify (Displayed)
                  <span className="ml-2 text-xs text-muted-foreground">Max 100 ports</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Port Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Network className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{ports.filter((p) => effectivePortState(p)?.toLowerCase() === 'open').length}</p>
                <p className="text-sm text-muted-foreground">Open Ports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{ports.filter((p) => effectivePortState(p)?.toLowerCase() === 'filtered').length}</p>
                <p className="text-sm text-muted-foreground">Filtered Ports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Network className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {new Set(ports.map((p) => p.asset_value || p.hostname || p.ip_address)).size}
                </p>
                <p className="text-sm text-muted-foreground">Unique Hosts</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Network className="h-5 w-5 text-yellow-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {new Set(ports.map((p) => p.service_name).filter(Boolean)).size}
                </p>
                <p className="text-sm text-muted-foreground">Services</p>
              </div>
            </div>
          </Card>
          <Card 
            className={`p-4 cursor-pointer hover:border-red-500/40 transition-colors ${riskyFilter === 'risky' ? 'ring-2 ring-red-500' : ''}`}
            onClick={() => setRiskyFilter(riskyFilter === 'risky' ? 'all' : 'risky')}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <AlertTriangle className="h-5 w-5 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => p.is_risky && !isNonExposedPort(p)).length}
                </p>
                <p className="text-sm text-muted-foreground">Risky Ports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Network className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => !isNonExposedPort(p) && [21, 22, 23, 3389, 5900, 3306, 5432, 27017, 6379].includes(p.port)).length}
                </p>
                <p className="text-sm text-muted-foreground">Critical Ports</p>
              </div>
            </div>
          </Card>
          <Card 
            className="p-4 cursor-pointer hover:border-blue-500/40 transition-colors"
            onClick={handleBackgroundVerify}
            title="Click to start background verification scan"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <ScanLine className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => !p.verified && p.state?.toLowerCase() === 'open').length}
                </p>
                <p className="text-sm text-muted-foreground">Unverified Ports</p>
              </div>
            </div>
          </Card>
          <Card 
            className="p-4 cursor-pointer hover:border-orange-500/40 transition-colors"
            onClick={handleServiceDetection}
            title="Click to start service detection scan"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Search className="h-5 w-5 text-orange-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => !p.service_name || p.service_name === 'unknown').length}
                </p>
                <p className="text-sm text-muted-foreground">Unknown Services</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Bar Charts - Top Ports and Top Services */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Top Ports Chart */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base font-medium flex items-center gap-2">
                <Network className="h-4 w-4 text-blue-500" />
                Top Ports
              </CardTitle>
            </CardHeader>
            <CardContent>
              {topPortsData.length > 0 ? (
                <div className="h-[250px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={topPortsData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                      <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        tick={{ fill: '#9ca3af', fontSize: 12 }} 
                        width={50}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#f3f4f6'
                        }}
                        formatter={(value: number) => [`${value} hosts`, 'Count']}
                        labelFormatter={(label) => `Port ${label}`}
                      />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                        {topPortsData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-[250px] flex items-center justify-center text-muted-foreground">
                  No port data available
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top Services Chart */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base font-medium flex items-center gap-2">
                <Shield className="h-4 w-4 text-green-500" />
                Top Services
              </CardTitle>
            </CardHeader>
            <CardContent>
              {topServicesData.length > 0 ? (
                <div className="h-[250px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={topServicesData} layout="vertical" margin={{ top: 5, right: 30, left: 70, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
                      <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        tick={{ fill: '#9ca3af', fontSize: 12 }} 
                        width={65}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#f3f4f6'
                        }}
                        formatter={(value: number) => [`${value} instances`, 'Count']}
                        labelFormatter={(label) => `Service: ${label}`}
                      />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                        {topServicesData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-[250px] flex items-center justify-center text-muted-foreground">
                  No service data available
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Ports Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Product / Version</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Verified</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead className="w-[60px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : filteredPorts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8 text-muted-foreground">
                    No port scan results found. Run a port scan to discover services.
                  </TableCell>
                </TableRow>
              ) : (
                filteredPorts.map((port) => (
                  <TableRow key={port.id} className={getServiceColor(port.port)}>
                    <TableCell className="font-medium">
                      <div className="flex flex-col">
                        <span>{port.hostname || port.asset_value || port.ip_address || '-'}</span>
                        {port.hostname && port.ip_address && port.hostname !== port.ip_address && (
                          <span className="text-xs text-muted-foreground font-mono">{port.ip_address}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {port.port}
                      </Badge>
                    </TableCell>
                    <TableCell className="uppercase text-xs">{port.protocol}</TableCell>
                    <TableCell>{port.service_name || '-'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                      {port.service_product || port.service_version 
                        ? `${port.service_product || ''} ${port.service_version || ''}`.trim()
                        : '-'}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStateColor(effectivePortState(port))}>{effectivePortState(port)}</Badge>
                    </TableCell>
                    <TableCell>
                      {verifyingPorts.has(port.id) ? (
                        <div className="flex items-center gap-1 text-blue-400">
                          <RefreshCw className="h-3 w-3 animate-spin" />
                          <span className="text-xs">Verifying...</span>
                        </div>
                      ) : port.verified ? (
                        <div 
                          className="flex items-center gap-1"
                          title={`Verified: ${port.verified_state?.toUpperCase() || 'unknown'} at ${port.verified_at ? new Date(port.verified_at).toLocaleString() : 'unknown time'}`}
                        >
                          <CheckCircle2 className={`h-4 w-4 ${
                            port.verified_state === 'open' ? 'text-green-500' : 
                            port.verified_state === 'filtered' ? 'text-yellow-500' : 
                            port.verified_state === 'closed' ? 'text-red-500' : 
                            'text-gray-500'
                          }`} />
                          <Badge 
                            variant="outline" 
                            className={`text-xs ${
                              port.verified_state === 'open' ? 'border-green-500/50 text-green-400' : 
                              port.verified_state === 'filtered' ? 'border-yellow-500/50 text-yellow-400' : 
                              port.verified_state === 'closed' ? 'border-red-500/50 text-red-400' : 
                              'border-gray-500/50 text-gray-400'
                            }`}
                          >
                            {port.verified_state || 'verified'}
                          </Badge>
                        </div>
                      ) : (
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          className="h-6 px-2 text-xs text-muted-foreground hover:text-primary"
                          onClick={() => handleVerifyPort(port.id)}
                          title="Run nmap verification scan"
                        >
                          <ScanLine className="h-3 w-3 mr-1" />
                          Verify
                        </Button>
                      )}
                    </TableCell>
                    <TableCell>
                      {effectivePortState(port)?.toLowerCase() === 'filtered' ? (
                        <Badge className="bg-yellow-500/20 text-yellow-400" title="Port is filtered - may be behind firewall">
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          Filtered
                        </Badge>
                      ) : port.is_risky ? (
                        <Badge className="bg-red-500/20 text-red-400" title={port.risk_reason}>
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          Risky
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {isNonExposedPort(port) ? (
                        <span className="text-muted-foreground text-xs">-</span>
                      ) : port.finding_id ? (
                        <Link 
                          href={`/findings?id=${port.finding_id}`}
                          className="inline-flex items-center gap-1 text-primary hover:underline text-sm"
                        >
                          <Shield className="h-3 w-3" />
                          View
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      ) : port.is_risky ? (
                        <Link 
                          href={`/findings?search=port+${port.port}`}
                          className="inline-flex items-center gap-1 text-orange-400 hover:underline text-sm"
                          title="Search for related findings"
                        >
                          <Bug className="h-3 w-3" />
                          Search
                        </Link>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(port.last_seen)}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem 
                            onClick={() => handleVerifyPort(port.id)}
                            disabled={verifyingPorts.has(port.id)}
                          >
                            <ScanLine className="h-4 w-4 mr-2 text-blue-500" />
                            {port.verified ? 'Re-verify with Nmap' : 'Verify with Nmap'}
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'critical')}>
                            <Bug className="h-4 w-4 mr-2 text-red-500" />
                            Create Critical Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'high')}>
                            <Bug className="h-4 w-4 mr-2 text-orange-500" />
                            Create High Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'medium')}>
                            <Bug className="h-4 w-4 mr-2 text-yellow-500" />
                            Create Medium Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleMarkRisky(port.id)}>
                            <Flag className="h-4 w-4 mr-2 text-red-500" />
                            Mark as Risky
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
          <span>Showing {filteredPorts.length} ports</span>
        </div>
      </div>
    </MainLayout>
  );
}







