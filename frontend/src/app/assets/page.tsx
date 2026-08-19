'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TableCustomization, Column, FilterOption } from '@/components/table/TableCustomization';
import {
  Globe,
  Server,
  Network,
  Lock,
  Layers,
  Award,
  ImageOff,
  Wifi,
  Hash,
  Tag,
  X,
  Plus,
  ArrowUpDown,
  Loader2,
  ExternalLink,
  MoreHorizontal,
  Camera,
  Shield,
  Eye,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  MapPin,
  Code,
  Zap,
  KeyRound,
  Trash2,
  Check,
  Square,
  CheckSquare,
  MinusSquare,
  Radar,
} from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';
import Link from 'next/link';

interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  ip_address?: string;
  ip_addresses?: string[];  // All resolved IPs (multi-value for load balancers, CDNs)
  asset_type: string;
  type?: string;
  status: string;
  organization_id: number;
  organization_name?: string;
  http_status?: number;
  http_title?: string;
  live_url?: string;
  technologies?: Array<{ name: string; slug: string; categories: string[] }>;
  tags?: string[];
  findingsCount?: number;
  screenshotUrl?: string;
  geoLocation?: GeoLocation;
  created_at: string;
  lastSeen?: Date;
  // Screenshots from API
  screenshots?: Array<{ id: number; image_path: string; thumbnail_path?: string }>;
  // Attack surface data
  is_live?: boolean;
  open_ports_count?: number;
  risky_ports_count?: number;
  port_services?: Array<{ port: number; protocol: string; service?: string; is_risky?: boolean; state?: string; verified_state?: string }>;
  endpoints?: string[];
  parameters?: string[];
  js_files?: string[];
  discovery_source?: string;
  risk_score?: number;
  in_scope?: boolean;
  asn?: string;
  country?: string;
  city?: string;
  has_login_portal?: boolean;
  login_portals?: Array<{ url: string; type: string; status?: number; title?: string }>;
}

// Asset type icons - matching AssetType enum values
const assetIcons: Record<string, typeof Globe> = {
  domain: Globe,
  subdomain: Globe,
  ip_address: Server,
  ip: Server,  // alias
  url: ExternalLink,
  port: Network,
  service: Layers,
  certificate: Lock,
  cloud_resource: Server,
  api_endpoint: Layers,
  email: Globe,
  other: Globe,
};

// Asset type colors - matching AssetType enum values
const assetColors: Record<string, string> = {
  domain: 'text-primary',
  subdomain: 'text-blue-400',
  ip_address: 'text-orange-400',
  ip: 'text-orange-400',  // alias
  url: 'text-cyan-400',
  port: 'text-purple-400',
  service: 'text-green-400',
  certificate: 'text-gray-400',
  cloud_resource: 'text-yellow-400',
  api_endpoint: 'text-pink-400',
  email: 'text-teal-400',
  other: 'text-gray-400',
};

const PAGE_SIZE = 100; // Assets per page

/** Extract host for grouping: from URL value (hostname) or asset value/name. */
function getHost(asset: Asset): string {
  const type = (asset.asset_type || asset.type || '').toLowerCase();
  const value = (asset.value || asset.name || '').trim();
  if (type === 'url' && value) {
    try {
      const u = value.startsWith('http') ? new URL(value) : new URL(`https://${value}`);
      return u.hostname;
    } catch {
      return value;
    }
  }
  return value || '';
}

/** Row can be a single asset or a group of assets by host (for consolidated view). */
type AssetRow = Asset | { _group: true; host: string; assets: Asset[]; representative: Asset };

export default function AssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [liveFilter, setLiveFilter] = useState<string>('live'); // Default to live assets
  const [viewMode, setViewMode] = useState<'all' | 'by_host'>('by_host'); // Consolidated by host by default
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [sortColumn, setSortColumn] = useState<string>('');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [selectedScreenshot, setSelectedScreenshot] = useState<{ url: string; asset: string } | null>(null);
  const [editingLabels, setEditingLabels] = useState<Asset | null>(null);
  const [newLabel, setNewLabel] = useState('');
  const { toast } = useToast();
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalAssets, setTotalAssets] = useState(0);
  
  // Multi-select state
  const [selectedAssets, setSelectedAssets] = useState<Set<number>>(new Set());

  const [columns, setColumns] = useState<Column[]>([
    { key: 'screenshot', label: 'Screenshot', visible: true },
    { key: 'type', label: 'Type', visible: true },
    { key: 'hostname', label: 'Host', visible: true },
    { key: 'is_live', label: 'Live', visible: true },
    { key: 'has_login_portal', label: 'Login', visible: true },
    { key: 'http_status', label: 'HTTP', visible: true },
    { key: 'ip_address', label: 'IP Address', visible: true },
    { key: 'ports', label: 'Ports', visible: true },
    { key: 'technologies', label: 'Technologies', visible: true },
    { key: 'labels', label: 'Labels', visible: false },
    { key: 'status', label: 'Status', visible: false },
    { key: 'findings', label: 'Findings', visible: true },
    { key: 'endpoints', label: 'Endpoints', visible: false },
    { key: 'source', label: 'Source', visible: false },
    { key: 'location', label: 'Location', visible: false },
    { key: 'organization', label: 'Organization', visible: true },
    { key: 'created_at', label: 'Last Seen', visible: true },
  ]);

  const [serverStats, setServerStats] = useState<any>(null);
  const [geoStats, setGeoStats] = useState<any>(null);
  const [probingLive, setProbingLive] = useState(false);
  const [enrichingGeo, setEnrichingGeo] = useState(false);

  const handleEnrichGeo = async () => {
    try {
      setEnrichingGeo(true);
      const params: { force: boolean; organization_id?: number } = { force: false };
      if (orgFilter !== 'all') {
        params.organization_id = parseInt(orgFilter);
      }
      const response = await api.request('/assets/enrich-from-netblocks', {
        method: 'POST',
        params,
      });
      toast({
        title: 'Geo Enrichment Complete',
        description: `Enriched ${(response.enriched_from_netblock_link || 0) + (response.enriched_from_cidr_match || 0)} assets from netblock data.`,
      });
      fetchData();
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      const isOrgRequired = typeof detail === 'string' && detail.toLowerCase().includes('organization');
      toast({
        title: 'Error',
        description: isOrgRequired
          ? 'Select an organization from the filter above (next to Search), then click Enrich Geo to run for that org\'s assets.'
          : detail || 'Failed to enrich assets',
        variant: 'destructive',
      });
    } finally {
      setEnrichingGeo(false);
    }
  };

  const handleProbeLive = async () => {
    try {
      setProbingLive(true);
      const orgId = orgFilter !== 'all' ? parseInt(orgFilter) : 1;
      const response = await api.post(`/assets/probe-live?organization_id=${orgId}&limit=500`);
      
      if (response.data) {
        toast({
          title: 'Live Probe Complete',
          description: `Probed ${response.data.probed ?? 0} assets. ${response.data.live ?? 0} are live.`,
        });
        fetchData();
      }
    } catch (error: any) {
      console.error('Error probing assets:', error);
      toast({
        title: 'Error',
        description: error?.response?.data?.detail || 'Failed to probe assets',
        variant: 'destructive',
      });
    } finally {
      setProbingLive(false);
    }
  };
  
  const fetchData = async (page: number = currentPage) => {
    setLoading(true);
    try {
      const skip = (page - 1) * PAGE_SIZE;
      const [assetsData, orgsData, summaryData, geoData] = await Promise.all([
        api.getAssets({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          asset_type: typeFilter !== 'all' ? typeFilter : undefined,
          status: statusFilter !== 'all' ? statusFilter : undefined,
          is_live: liveFilter === 'live' ? true : liveFilter === 'not_live' ? false : undefined,
          search: search || undefined,
          limit: PAGE_SIZE,
          skip: skip,
        }),
        api.getOrganizations(),
        api.getAssetsSummary(orgFilter !== 'all' ? parseInt(orgFilter) : undefined),
        api.request('/assets/geo-stats', {
          params: { organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined }
        }).catch(() => null),
      ]);
      
      // Store server-side stats for accurate counts
      setServerStats(summaryData);
      setGeoStats(geoData);
      
      // Get total count from response
      const total = assetsData.total || assetsData.items?.length || assetsData.length || 0;
      setTotalAssets(total);

      // Transform assets to include derived properties
      // NOTE: Removed screenshot fetching here - it was causing 50+ API calls per page load
      // Screenshots are now lazy-loaded via the screenshot_id field from the backend
      const assetsList = assetsData.items || assetsData || [];
      
      const transformedAssets = assetsList.map((a: any) => ({
        ...a,
        name: a.name || a.value,
        value: a.value || a.name,
        type: a.asset_type || 'subdomain',
        findingsCount: a.vulnerability_count || 0,
        tags: a.tags || [],
        lastSeen: new Date(a.updated_at || a.created_at),
        // Use screenshot_id from backend if available (cached from last screenshot capture)
        screenshotUrl: a.screenshot_id ? api.getScreenshotImageUrl(a.screenshot_id) : null,
        screenshotId: a.screenshot_id || null,
      }));

      setAssets(transformedAssets);
      setOrganizations(orgsData);
    } catch (error: any) {
      console.error('Failed to fetch assets:', error);
      // Extract meaningful error message
      let errorMessage = 'Failed to fetch assets';
      const detail = error?.response?.data?.detail;
      if (typeof detail === 'string') {
        errorMessage = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        errorMessage = detail.map((e: any) => e.msg || e.message || String(e)).join(', ');
      } else if (error?.message) {
        errorMessage = error.message;
      }
      toast({
        title: 'Error',
        description: errorMessage,
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCurrentPage(1);
    fetchData(1);
  }, [orgFilter, typeFilter, statusFilter, liveFilter]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (search !== '') {
        setCurrentPage(1);
        fetchData(1);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [search]);
  
  // Initial load
  useEffect(() => {
    fetchData(1);
  }, []);

  // Filter and sort assets; optionally group by host for consolidated view
  const displayedAssets = useMemo((): AssetRow[] => {
    let filtered = assets.filter(asset => {
      const matchesType = typeFilter === 'all' || asset.asset_type === typeFilter || asset.type === typeFilter;
      const matchesStatus = statusFilter === 'all' || asset.status === statusFilter;
      const matchesSearch = search === '' || 
        asset.name?.toLowerCase().includes(search.toLowerCase()) ||
        asset.value?.toLowerCase().includes(search.toLowerCase()) ||
        asset.ip_address?.toLowerCase().includes(search.toLowerCase()) ||
        asset.tags?.some(tag => tag.toLowerCase().includes(search.toLowerCase()));
      return matchesType && matchesStatus && matchesSearch;
    });

    // Sort assets
    if (sortColumn) {
      filtered = [...filtered].sort((a, b) => {
        const aVal: any = a[sortColumn as keyof Asset];
        const bVal: any = b[sortColumn as keyof Asset];
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }

    if (viewMode !== 'by_host') return filtered;

    // Group by host for consolidated view: one row per host; URL assets grouped under host
    const byHost = new Map<string, Asset[]>();
    for (const asset of filtered) {
      const host = getHost(asset);
      if (!host) continue;
      const key = host.toLowerCase();
      if (!byHost.has(key)) byHost.set(key, []);
      byHost.get(key)!.push(asset);
    }

    const rows: AssetRow[] = [];
    byHost.forEach((groupAssets, hostKey) => {
      const first = groupAssets[0];
      if (groupAssets.length === 1) {
        rows.push(first);
      } else {
        // Multiple assets for same host: show one consolidated row per host
        const representative = groupAssets[0];
        const hostDisplay = first.value?.startsWith('http') ? (() => { try { return new URL(first.value).hostname; } catch { return first.value || hostKey; } })() : (first.value || first.name || hostKey);
        rows.push({ _group: true, host: hostDisplay, assets: groupAssets, representative });
      }
    });

    // Sort rows by host when in by_host view
    rows.sort((a, b) => {
      const aHost = '_group' in a ? a.host : getHost(a);
      const bHost = '_group' in b ? b.host : getHost(b);
      if (sortColumn === 'hostname' || sortColumn === '') {
        return sortDirection === 'asc' ? aHost.localeCompare(bHost) : bHost.localeCompare(aHost);
      }
      return 0;
    });
    return rows;
  }, [assets, typeFilter, statusFilter, search, sortColumn, sortDirection, viewMode]);

  const handleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const handleExport = () => {
    const rowToAsset = (row: AssetRow): Asset =>
      '_group' in row ? row.representative : row;
    const csv = [
      ['Type', 'Host', 'IP Address', 'Labels', 'Status', 'Findings', 'Last Seen'],
      ...displayedAssets.map((row: AssetRow) => {
        const a = rowToAsset(row);
        return [
          a.type ?? a.asset_type ?? '',
          a.name || a.value,
          a.ip_address || '',
          a.tags?.join('; ') || '',
          a.status,
          (a.findingsCount || 0).toString(),
          a.created_at,
        ];
      }),
    ].map(r => r.join(',')).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `assets-${new Date().toISOString()}.csv`;
    link.click();
    
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  // Multi-select handlers
  const toggleAssetSelection = (assetId: number) => {
    setSelectedAssets(prev => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  };

  const toggleGroupSelection = (groupRow: { assets: Asset[] }) => {
    const ids = groupRow.assets.map((a) => a.id);
    const allSelected = ids.every((id) => selectedAssets.has(id));
    setSelectedAssets(prev => {
      const next = new Set(prev);
      if (allSelected) ids.forEach((id) => next.delete(id));
      else ids.forEach((id) => next.add(id));
      return next;
    });
  };

  const selectAll = () => {
    const ids = displayedAssets.flatMap((row) => '_group' in row ? row.assets.map((a) => a.id) : [row.id]);
    setSelectedAssets(new Set(ids));
  };

  const deselectAll = () => {
    setSelectedAssets(new Set());
  };

  const displayedAssetIds = useMemo(
    () => displayedAssets.flatMap((row) => ('_group' in row ? row.assets.map((a) => a.id) : [row.id])),
    [displayedAssets]
  );
  const isAllSelected = displayedAssetIds.length > 0 && displayedAssetIds.every((id) => selectedAssets.has(id));
  const isSomeSelected = selectedAssets.size > 0 && !isAllSelected;

  const handleBulkDelete = async () => {
    if (selectedAssets.size === 0) return;
    
    if (confirm(`Delete ${selectedAssets.size} selected assets? This cannot be undone.`)) {
      try {
        const result = await api.bulkDeleteAssets(Array.from(selectedAssets));
        toast({
          title: 'Assets Deleted',
          description: `Deleted ${result.deleted} assets.`,
        });
        setSelectedAssets(new Set());
        fetchData();
      } catch (error) {
        toast({
          title: 'Error',
          description: 'Failed to delete assets',
          variant: 'destructive',
        });
      }
    }
  };

  const handleBulkUpdateScope = async (inScope: boolean) => {
    if (selectedAssets.size === 0) return;
    
    try {
      // Update each selected asset's scope
      const promises = Array.from(selectedAssets).map(id =>
        api.updateAsset(id, { in_scope: inScope })
      );
      await Promise.all(promises);
      
      toast({
        title: 'Scope Updated',
        description: `Updated ${selectedAssets.size} assets to ${inScope ? 'in scope' : 'out of scope'}.`,
      });
      setSelectedAssets(new Set());
      fetchData();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update asset scope',
        variant: 'destructive',
      });
    }
  };

  const handleAddLabel = async () => {
    if (!editingLabels || !newLabel.trim()) return;
    // In production, this would call an API to update the asset
    const updatedTags = [...(editingLabels.tags || []), newLabel.trim()];
    setAssets(assets.map(a => 
      a.id === editingLabels.id ? { ...a, tags: updatedTags } : a
    ));
    setNewLabel('');
    toast({
      title: 'Label Added',
      description: `Added label "${newLabel.trim()}" to ${editingLabels.name || editingLabels.value}`,
    });
  };

  const handleRemoveLabel = (label: string) => {
    if (!editingLabels) return;
    const updatedTags = (editingLabels.tags || []).filter(t => t !== label);
    setAssets(assets.map(a => 
      a.id === editingLabels.id ? { ...a, tags: updatedTags } : a
    ));
    setEditingLabels({ ...editingLabels, tags: updatedTags });
  };

  const handleFilterChange = (key: string, value: string) => {
    if (key === 'view') setViewMode(value as 'all' | 'by_host');
    if (key === 'type') setTypeFilter(value);
    if (key === 'status') setStatusFilter(value);
    if (key === 'organization') setOrgFilter(value);
    if (key === 'live') setLiveFilter(value);
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      // AssetStatus enum values
      case 'discovered':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'verified':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'unverified':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'inactive':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      case 'archived':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
      // Legacy/scan status values (for backward compatibility)
      case 'active':
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'pending':
      case 'running':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'error':
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const filters: FilterOption[] = [
    {
      key: 'view',
      label: 'View',
      options: [
        { label: 'By host (consolidated)', value: 'by_host' },
        { label: 'All assets', value: 'all' },
      ],
    },
    {
      key: 'organization',
      label: 'Organization',
      options: organizations.map((org: { id: number; name: string }) => ({ label: org.name, value: String(org.id) })),
    },
    {
      key: 'live',
      label: 'Live Status',
      options: [
        { label: 'All', value: 'all' },
        { label: 'Live', value: 'live' },
        { label: 'Not Live', value: 'not_live' },
      ],
    },
    {
      key: 'type',
      label: 'Type',
      options: [
        { label: 'Domain', value: 'domain' },
        { label: 'Subdomain', value: 'subdomain' },
        { label: 'IP Address', value: 'ip_address' },
        { label: 'URL', value: 'url' },
        { label: 'Port', value: 'port' },
        { label: 'Service', value: 'service' },
        { label: 'Certificate', value: 'certificate' },
        { label: 'API Endpoint', value: 'api_endpoint' },
      ],
    },
    {
      key: 'status',
      label: 'Status',
      options: [
        { label: 'Discovered', value: 'discovered' },
        { label: 'Verified', value: 'verified' },
        { label: 'Unverified', value: 'unverified' },
        { label: 'Inactive', value: 'inactive' },
        { label: 'Archived', value: 'archived' },
      ],
    },
  ];

  const visibleColumns = columns.filter(c => c.visible);

  // Calculate attack surface stats - use server stats for accurate totals
  const attackSurfaceStats = useMemo(() => {
    // Use server-side stats for accurate counts across all assets
    if (serverStats) {
      const total = serverStats.total || totalAssets;
      const live = serverStats.live?.live || 0;
      return {
        total,
        live,
        notLive: serverStats.live?.not_live || (total - live),
        notProbed: serverStats.live?.not_probed || 0,
        loginPortals: serverStats.login_portals || 0,
        outOfScope: serverStats.scope?.out_of_scope || 0,
        totalPorts: serverStats.ports?.open_ports || 0,
        riskyPorts: serverStats.ports?.risky_ports || 0,
        withTech: 0, // Not in server stats yet
        uniqueTech: 0, // Not in server stats yet
        withEndpoints: 0, // Not in server stats yet
        withFindings: 0, // Not in server stats yet
      };
    }
    
    // Fallback to page-level stats
    const liveAssets = assets.filter(a => a.is_live).length;
    const notLiveAssets = assets.filter(a => a.is_live === false).length;
    const loginPortals = assets.filter(a => a.has_login_portal).length;
    const outOfScope = assets.filter(a => !a.in_scope).length;
    const totalPorts = assets.reduce((sum, a) => sum + (a.open_ports_count || 0), 0);
    const riskyPorts = assets.reduce((sum, a) => sum + (a.risky_ports_count || 0), 0);
    const withTech = assets.filter(a => a.technologies && a.technologies.length > 0).length;
    const withEndpoints = assets.filter(a => a.endpoints && a.endpoints.length > 0).length;
    const withFindings = assets.filter(a => (a.findingsCount || 0) > 0).length;
    
    // Count unique technologies
    const techSet = new Set<string>();
    assets.forEach(a => {
      a.technologies?.forEach(t => techSet.add(typeof t === 'string' ? t : t.name));
    });
    
    return {
      total: totalAssets, // Use server's total count, not just current page
      live: liveAssets,
      notLive: notLiveAssets,
      notProbed: 0,
      loginPortals,
      outOfScope,
      totalPorts,
      riskyPorts,
      withTech,
      uniqueTech: techSet.size,
      withEndpoints,
      withFindings,
    };
  }, [assets, totalAssets, serverStats]);

  return (
    <MainLayout>
      <Header title="Attack Surface" subtitle="Discovered hosts, domains, and services across your organization" />

      <div className="p-6 space-y-6">
        {/* Attack Surface Overview Stats */}
        {!loading && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <Card 
              className={`p-4 bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20 cursor-pointer hover:border-blue-500/40 transition-colors ${liveFilter === 'all' ? 'ring-2 ring-blue-500' : ''}`}
              onClick={() => setLiveFilter('all')}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/20">
                  <Globe className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.total}</p>
                  <p className="text-xs text-muted-foreground">Total Assets</p>
                </div>
              </div>
            </Card>
            
            <Card 
              className={`p-4 bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20 cursor-pointer hover:border-green-500/40 transition-colors ${liveFilter === 'live' ? 'ring-2 ring-green-500' : ''}`}
              onClick={() => setLiveFilter('live')}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-500/20">
                  <Activity className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.live}</p>
                  <p className="text-xs text-muted-foreground">Live Assets</p>
                </div>
              </div>
            </Card>

            <Card 
              className={`p-4 bg-gradient-to-br from-gray-500/10 to-gray-600/5 border-gray-500/20 cursor-pointer hover:border-gray-500/40 transition-colors ${liveFilter === 'not_live' ? 'ring-2 ring-gray-500' : ''}`}
              onClick={() => setLiveFilter('not_live')}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-gray-500/20">
                  <XCircle className="h-5 w-5 text-gray-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.notLive}</p>
                  <p className="text-xs text-muted-foreground">Not Live</p>
                </div>
              </div>
            </Card>

            <Card 
              className={`p-4 bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20 cursor-pointer hover:border-purple-500/40 transition-colors ${probingLive ? 'opacity-50' : ''}`}
              onClick={!probingLive ? handleProbeLive : undefined}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  {probingLive ? (
                    <Loader2 className="h-5 w-5 text-purple-400 animate-spin" />
                  ) : (
                    <Radar className="h-5 w-5 text-purple-400" />
                  )}
                </div>
                <div>
                  <p className="text-sm font-bold text-foreground">{probingLive ? 'Probing...' : 'Probe Live'}</p>
                  <p className="text-xs text-muted-foreground">Check HTTP status</p>
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.loginPortals > 0 && (
              <Card className="p-4 bg-gradient-to-br from-amber-500/10 to-amber-600/5 border-amber-500/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-500/20">
                    <KeyRound className="h-5 w-5 text-amber-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.loginPortals}</p>
                    <p className="text-xs text-muted-foreground">Login Portals</p>
                  </div>
                </div>
              </Card>
            )}
            
            {/* Geo Coverage Card */}
            <Card 
              className={`p-4 bg-gradient-to-br from-teal-500/10 to-teal-600/5 border-teal-500/20 cursor-pointer hover:border-teal-500/40 transition-colors ${enrichingGeo ? 'opacity-50' : ''}`}
              onClick={!enrichingGeo ? handleEnrichGeo : undefined}
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-teal-500/20">
                  {enrichingGeo ? (
                    <Loader2 className="h-5 w-5 text-teal-400 animate-spin" />
                  ) : (
                    <MapPin className="h-5 w-5 text-teal-400" />
                  )}
                </div>
                <div>
                  {geoStats ? (
                    <>
                      <p className="text-2xl font-bold text-foreground">{geoStats.with_geo || 0}</p>
                      <p className="text-xs text-muted-foreground">
                        {geoStats.coverage_percent || 0}% geo coverage ({Object.keys(geoStats.by_country || {}).length} countries)
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-sm font-bold text-foreground">{enrichingGeo ? 'Enriching...' : 'Enrich Geo'}</p>
                      <p className="text-xs text-muted-foreground">Add country data</p>
                    </>
                  )}
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.outOfScope > 0 && (
              <Card 
                className="p-4 bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/20 cursor-pointer hover:border-red-500/40 transition-colors"
                onClick={async () => {
                  if (confirm(`Delete ${attackSurfaceStats.outOfScope} out-of-scope assets? This cannot be undone.`)) {
                    try {
                      const outOfScopeIds = assets.filter(a => !a.in_scope).map(a => a.id);
                      const result = await api.bulkDeleteAssets(outOfScopeIds);
                      toast({
                        title: 'Assets Deleted',
                        description: `Deleted ${result.deleted} out-of-scope assets.`,
                      });
                      fetchData();
                    } catch (error) {
                      toast({
                        title: 'Error',
                        description: 'Failed to delete assets',
                        variant: 'destructive',
                      });
                    }
                  }
                }}
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-500/20">
                    <Trash2 className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.outOfScope}</p>
                    <p className="text-xs text-muted-foreground">Out of Scope (click to delete)</p>
                  </div>
                </div>
              </Card>
            )}
            
            <Card className="p-4 bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 border-cyan-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/20">
                  <Network className="h-5 w-5 text-cyan-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.totalPorts}</p>
                  <p className="text-xs text-muted-foreground">Open Ports</p>
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.riskyPorts > 0 && (
              <Card className="p-4 bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-500/20">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.riskyPorts}</p>
                    <p className="text-xs text-muted-foreground">Risky Ports</p>
                  </div>
                </div>
              </Card>
            )}
            
            <Card className="p-4 bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  <Zap className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.uniqueTech}</p>
                  <p className="text-xs text-muted-foreground">Technologies</p>
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.withFindings > 0 && (
              <Card className="p-4 bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-orange-500/20">
                    <Shield className="h-5 w-5 text-orange-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.withFindings}</p>
                    <p className="text-xs text-muted-foreground">With Findings</p>
                  </div>
                </div>
              </Card>
            )}
          </div>
        )}

        {/* Bulk Action Bar */}
        {selectedAssets.size > 0 && (
          <Card className="p-4 bg-primary/5 border-primary/20">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium">
                  {selectedAssets.size} asset{selectedAssets.size !== 1 ? 's' : ''} selected
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleBulkUpdateScope(true)}
                  >
                    <Check className="h-4 w-4 mr-1" />
                    Add to Scope
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleBulkUpdateScope(false)}
                  >
                    <X className="h-4 w-4 mr-1" />
                    Remove from Scope
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-red-500 border-red-500/50 hover:bg-red-500/10"
                    onClick={handleBulkDelete}
                  >
                    <Trash2 className="h-4 w-4 mr-1" />
                    Delete Selected
                  </Button>
                </div>
              </div>
              <Button size="sm" variant="ghost" onClick={deselectAll}>
                Clear Selection
              </Button>
            </div>
          </Card>
        )}

        {/* Table with Customization */}
        <TableCustomization
          columns={columns}
          onColumnVisibilityChange={setColumns}
          onExport={handleExport}
          onSort={handleSort}
          onSearch={setSearch}
          onRefresh={fetchData}
          isLoading={loading}
          filters={filters}
          filterValues={{ view: viewMode, organization: orgFilter, live: liveFilter, type: typeFilter, status: statusFilter }}
          onFilterChange={handleFilterChange}
        >
          <Card className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  {/* Checkbox column */}
                  <TableHead className="w-[50px]">
                    <Checkbox
                      checked={isAllSelected}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          selectAll();
                        } else {
                          deselectAll();
                        }
                      }}
                      aria-label="Select all"
                      className={isSomeSelected ? 'opacity-50' : ''}
                    />
                  </TableHead>
                  {visibleColumns.map(col => (
                    <TableHead 
                      key={col.key} 
                      className="text-muted-foreground cursor-pointer"
                      onClick={() => col.key !== 'screenshot' && handleSort(col.key)}
                    >
                      <div className="flex items-center gap-1">
                        {col.label}
                        {col.key !== 'screenshot' && col.key !== 'labels' && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </div>
                    </TableHead>
                  ))}
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={visibleColumns.length + 2} className="text-center py-8">
                      <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                    </TableCell>
                  </TableRow>
                ) : displayedAssets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={visibleColumns.length + 2} className="text-center py-8 text-muted-foreground">
                      No assets found. Run a discovery scan to find assets.
                    </TableCell>
                  </TableRow>
                ) : (
                  displayedAssets.map((row) => {
                    const isGroup = '_group' in row;
                    const asset: Asset = isGroup ? row.representative : row;
                    const assetType = asset.type || asset.asset_type || 'domain';
                    const Icon = assetIcons[assetType] || Globe;
                    const isSelected = selectedAssets.has(asset.id);
                    const groupCount = isGroup ? row.assets.length : 0;

                    return (
                      <TableRow 
                        key={isGroup ? `host-${row.host}` : asset.id} 
                        className={`border-border cursor-pointer transition-colors hover:bg-secondary/50 ${isSelected ? 'bg-primary/5' : ''}`}
                        onClick={() => router.push(`/assets/${asset.id}`)}
                      >
                        {/* Checkbox */}
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={isGroup ? row.assets.every((a) => selectedAssets.has(a.id)) : isSelected}
                            onCheckedChange={() => (isGroup ? toggleGroupSelection(row) : toggleAssetSelection(asset.id))}
                            aria-label={isGroup ? `Select ${row.host}` : `Select ${asset.value}`}
                          />
                        </TableCell>
                        {/* Screenshot */}
                        {columns.find(c => c.key === 'screenshot')?.visible && (
                          <TableCell>
                            {asset.screenshotUrl ? (
                                <div
                                  className="relative w-16 h-12 rounded overflow-hidden border border-border cursor-pointer hover:border-primary transition-colors group"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedScreenshot({ url: asset.screenshotUrl!, asset: asset.name || asset.value });
                                  }}
                                >
                                  <img
                                    src={asset.screenshotUrl}
                                    alt={`Screenshot of ${asset.name || asset.value}`}
                                    className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                                  />
                                <div className="absolute inset-0 bg-primary/0 group-hover:bg-primary/10 transition-colors flex items-center justify-center">
                                  <Eye className="h-4 w-4 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
                                </div>
                              </div>
                            ) : (
                              <div className="w-16 h-12 rounded border border-border/50 bg-secondary/30 flex items-center justify-center">
                                <ImageOff className="h-4 w-4 text-muted-foreground/50" />
                              </div>
                            )}
                          </TableCell>
                        )}

                        {/* Type */}
                        {columns.find(c => c.key === 'type')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Icon className={`h-4 w-4 ${assetColors[assetType] || 'text-muted-foreground'}`} />
                              <span className="text-xs font-medium uppercase text-muted-foreground">
                                {assetType}
                              </span>
                            </div>
                          </TableCell>
                        )}

                        {/* Value/Name (host; for groups show host + N URLs) */}
                        {columns.find(c => c.key === 'hostname')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {(() => {
                                if (isGroup) {
                                  const host = row.host;
                                  const href = `https://${host}`;
                                  return (
                                    <a
                                      href={href}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="font-mono text-sm text-foreground hover:text-primary flex items-center gap-2"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      {host}
                                      <span className="text-xs text-muted-foreground font-normal">({groupCount} URL{groupCount !== 1 ? 's' : ''})</span>
                                      <ExternalLink className="h-3 w-3" />
                                    </a>
                                  );
                                }
                                const value = asset.value || asset.name;
                                let href = value;
                                if (value && !value.startsWith('http://') && !value.startsWith('https://')) {
                                  href = `https://${value}`;
                                }
                                return (
                                  <a
                                    href={href}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-mono text-sm text-foreground hover:text-primary flex items-center gap-1"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {asset.name || asset.value}
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                );
                              })()}
                            </div>
                          </TableCell>
                        )}

                        {/* Live Status */}
                        {columns.find(c => c.key === 'is_live')?.visible && (
                          <TableCell>
                            {asset.is_live ? (
                              <div className="flex items-center gap-1">
                                <CheckCircle2 className="h-4 w-4 text-green-500" />
                                <span className="text-xs text-green-500 font-medium">Live</span>
                              </div>
                            ) : (
                              <div className="flex items-center gap-1">
                                <XCircle className="h-4 w-4 text-muted-foreground/50" />
                                <span className="text-xs text-muted-foreground">—</span>
                              </div>
                            )}
                          </TableCell>
                        )}

                        {/* Login Portal Flag */}
                        {columns.find(c => c.key === 'has_login_portal')?.visible && (
                          <TableCell>
                            {asset.has_login_portal ? (
                              <div className="flex items-center gap-1">
                                <KeyRound className="h-4 w-4 text-amber-500" />
                                <span className="text-xs text-amber-500 font-medium">
                                  {asset.login_portals?.length || 1}
                                </span>
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* HTTP Status - must come right after Live to match column order */}
                        {columns.find(c => c.key === 'http_status')?.visible && (
                          <TableCell>
                            {asset.http_status ? (
                              <Badge
                                variant="outline"
                                className={
                                  asset.http_status >= 200 && asset.http_status < 300
                                    ? 'text-green-400'
                                    : asset.http_status >= 400
                                    ? 'text-red-400'
                                    : 'text-yellow-400'
                                }
                              >
                                {asset.http_status}
                              </Badge>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* IP Address - must come after HTTP to match column order */}
                        {columns.find(c => c.key === 'ip_address')?.visible && (
                          <TableCell className="font-mono text-sm">
                            {(() => {
                              // For IP_ADDRESS type assets, the IP is in the value field
                              const assetType = (asset.asset_type || asset.type || '').toLowerCase();
                              const isIpAsset = assetType === 'ip_address' || assetType === 'ip';
                              const displayIp = asset.ip_address || (isIpAsset ? asset.value : null);
                              
                              if (displayIp) {
                                return (
                                  <div className="flex flex-col gap-0.5">
                                    <span className="text-foreground">{displayIp}</span>
                                    {asset.ip_addresses && asset.ip_addresses.length > 1 && (
                                      <span className="text-xs text-muted-foreground">
                                        +{asset.ip_addresses.length - 1} more
                                      </span>
                                    )}
                                  </div>
                                );
                              }
                              return <span className="text-muted-foreground">—</span>;
                            })()}
                          </TableCell>
                        )}

                        {/* Ports */}
                        {columns.find(c => c.key === 'ports')?.visible && (
                          <TableCell>
                            {asset.port_services && asset.port_services.length > 0 ? (
                              <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                                {asset.port_services.slice(0, 5).map((port, i) => {
                                  // Determine color based on state: filtered=yellow, risky=red, open=blue
                                  const isFiltered = port.state?.toLowerCase() === 'filtered' || port.verified_state?.toLowerCase() === 'filtered';
                                  const colorClass = isFiltered
                                    ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                                    : port.is_risky 
                                      ? 'bg-red-500/10 text-red-400 border-red-500/30' 
                                      : 'bg-blue-500/10 text-blue-400 border-blue-500/30';
                                  return (
                                    <Badge
                                      key={i}
                                      variant="outline"
                                      className={`text-[10px] px-1.5 py-0 h-5 font-mono ${colorClass}`}
                                    >
                                      {port.port}
                                      {port.service && <span className="text-muted-foreground">/{port.service}</span>}
                                    </Badge>
                                  );
                                })}
                                {asset.port_services.length > 5 && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 h-5">
                                    +{asset.port_services.length - 5}
                                  </Badge>
                                )}
                              </div>
                            ) : (asset.open_ports_count || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Network className="h-4 w-4 text-blue-400" />
                                <span className="font-mono text-sm text-blue-400">
                                  {asset.open_ports_count}
                                </span>
                                {(asset.risky_ports_count || 0) > 0 && (
                                  <Badge variant="destructive" className="text-[10px] px-1 py-0 h-4">
                                    {asset.risky_ports_count} risky
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Technologies */}
                        {columns.find(c => c.key === 'technologies')?.visible && (
                          <TableCell>
                            {asset.technologies && asset.technologies.length > 0 ? (
                              <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                                {asset.technologies.slice(0, 3).map((tech, i) => (
                                  <Badge 
                                    key={i} 
                                    variant="outline" 
                                    className="text-[10px] px-1.5 py-0 h-5 bg-purple-500/10 text-purple-400 border-purple-500/30"
                                  >
                                    {typeof tech === 'string' ? tech : tech.name}
                                  </Badge>
                                ))}
                                {asset.technologies.length > 3 && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 h-5">
                                    +{asset.technologies.length - 3}
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Labels */}
                        {columns.find(c => c.key === 'labels')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-1 flex-wrap">
                              {asset.tags && asset.tags.length > 0 ? (
                                <>
                                  {asset.tags.slice(0, 2).map((tag) => (
                                    <Badge key={tag} variant="secondary" className="text-xs">
                                      {tag}
                                    </Badge>
                                  ))}
                                  {asset.tags.length > 2 && (
                                    <Badge variant="secondary" className="text-xs">
                                      +{asset.tags.length - 2}
                                    </Badge>
                                  )}
                                </>
                              ) : (
                                <span className="text-muted-foreground text-xs">—</span>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 w-6 p-0"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setEditingLabels(asset);
                                }}
                              >
                                <Tag className="h-3 w-3" />
                              </Button>
                            </div>
                          </TableCell>
                        )}

                        {/* Status */}
                        {columns.find(c => c.key === 'status')?.visible && (
                          <TableCell>
                            <Badge className={getStatusColor(asset.status)}>
                              {asset.status}
                            </Badge>
                          </TableCell>
                        )}

                        {/* Findings */}
                        {columns.find(c => c.key === 'findings')?.visible && (
                          <TableCell>
                            {(asset.findingsCount || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Award className="h-4 w-4 text-orange-400" />
                                <span className="font-mono text-orange-400">
                                  {asset.findingsCount}
                                </span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Endpoints */}
                        {columns.find(c => c.key === 'endpoints')?.visible && (
                          <TableCell>
                            {(asset.endpoints?.length || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Code className="h-4 w-4 text-cyan-400" />
                                <span className="font-mono text-sm text-cyan-400">
                                  {asset.endpoints!.length}
                                </span>
                                {(asset.parameters?.length || 0) > 0 && (
                                  <span className="text-xs text-muted-foreground">
                                    ({asset.parameters!.length} params)
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Discovery Source */}
                        {columns.find(c => c.key === 'source')?.visible && (
                          <TableCell>
                            {asset.discovery_source ? (
                              <Badge variant="outline" className="text-xs">
                                {asset.discovery_source}
                              </Badge>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Location */}
                        {columns.find(c => c.key === 'location')?.visible && (
                          <TableCell>
                            {asset.country ? (
                              <div className="flex items-center gap-1">
                                <MapPin className="h-3 w-3 text-muted-foreground" />
                                <span className="text-xs">
                                  {asset.city ? `${asset.city}, ` : ''}{asset.country}
                                </span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Organization */}
                        {columns.find(c => c.key === 'organization')?.visible && (
                          <TableCell className="text-muted-foreground">
                            {asset.organization_name || '—'}
                          </TableCell>
                        )}

                        {/* Last Seen */}
                        {columns.find(c => c.key === 'created_at')?.visible && (
                          <TableCell className="text-muted-foreground text-sm">
                            {formatDate(asset.created_at)}
                          </TableCell>
                        )}

                        {/* Actions */}
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" onClick={(e) => e.stopPropagation()}>
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem asChild>
                                <Link href={`/assets/${asset.id}`}>View Details</Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem>
                                <Camera className="h-4 w-4 mr-2" />
                                Capture Screenshot
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={(e) => {
                                  e.stopPropagation();
                                  const targetEnc = encodeURIComponent(asset.value);
                                  router.push(`/agent?target=${targetEnc}&playbook=vuln_scan&mode=agent&autostart=1`);
                                }}
                              >
                                <Shield className="h-4 w-4 mr-2" />
                                Run Vulnerability Scan
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => setEditingLabels(asset)}>
                                <Tag className="h-4 w-4 mr-2" />
                                Manage Labels
                              </DropdownMenuItem>
                              <DropdownMenuItem 
                                className="text-red-500 focus:text-red-500"
                                onClick={async (e) => {
                                  e.stopPropagation();
                                  if (confirm(`Delete asset "${asset.value}"? This cannot be undone.`)) {
                                    try {
                                      await api.deleteAsset(asset.id);
                                      toast({
                                        title: 'Asset Deleted',
                                        description: `${asset.value} has been deleted.`,
                                      });
                                      fetchData();
                                    } catch (error) {
                                      toast({
                                        title: 'Error',
                                        description: 'Failed to delete asset',
                                        variant: 'destructive',
                                      });
                                    }
                                  }
                                }}
                              >
                                <Trash2 className="h-4 w-4 mr-2" />
                                Delete Asset
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </TableCustomization>

        {/* Pagination controls */}
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {((currentPage - 1) * PAGE_SIZE) + 1} - {Math.min(currentPage * PAGE_SIZE, totalAssets)} of {totalAssets} assets
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const newPage = currentPage - 1;
                setCurrentPage(newPage);
                fetchData(newPage);
              }}
              disabled={currentPage === 1 || loading}
            >
              Previous
            </Button>
            <div className="flex items-center gap-1 text-sm">
              <span>Page</span>
              <span className="font-medium">{currentPage}</span>
              <span>of</span>
              <span className="font-medium">{Math.ceil(totalAssets / PAGE_SIZE) || 1}</span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const newPage = currentPage + 1;
                setCurrentPage(newPage);
                fetchData(newPage);
              }}
              disabled={currentPage >= Math.ceil(totalAssets / PAGE_SIZE) || loading}
            >
              Next
            </Button>
          </div>
        </div>
      </div>

      {/* Screenshot Preview Dialog */}
      <Dialog open={!!selectedScreenshot} onOpenChange={() => setSelectedScreenshot(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm">{selectedScreenshot?.asset}</DialogTitle>
          </DialogHeader>
          {selectedScreenshot && (
            <div className="rounded-lg overflow-hidden border border-border">
              <img
                src={selectedScreenshot.url}
                alt={`Screenshot of ${selectedScreenshot.asset}`}
                className="w-full h-auto"
              />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Label Management Dialog */}
      <Dialog open={!!editingLabels} onOpenChange={() => setEditingLabels(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Labels</DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {editingLabels?.name || editingLabels?.value}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Current Labels</Label>
              <div className="flex flex-wrap gap-2 min-h-[40px] p-2 border border-border rounded-md">
                {editingLabels?.tags && editingLabels.tags.length > 0 ? (
                  editingLabels.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="gap-1">
                      {tag}
                      <button
                        onClick={() => handleRemoveLabel(tag)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground text-sm">No labels</span>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Add New Label</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., wordpress, drupal, citrix-netscaler"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      handleAddLabel();
                    }
                  }}
                />
                <Button onClick={handleAddLabel} size="sm" disabled={!newLabel.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Common labels: wordpress, drupal, citrix-netscaler, salesforce, joomla, magento
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
