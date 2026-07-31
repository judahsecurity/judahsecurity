'use client';

import React, { useEffect, useState, useCallback, useMemo } from 'react';


import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
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
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import {
  Globe,
  Search,
  RefreshCw,
  Plus,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Eye,
  Loader2,
  ExternalLink,
  Filter,
  Download,
  Upload,
  Trash2,
  Check,
  X,
  Database,
  Mail,
  Server,
  Radar,
  Cloud,
  Lock,
  FileText,
  Building,
  MoreHorizontal,
  ChevronDown,
  Zap,
  Code,
  Link2,
  Hash,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Domain {
  id: number;
  value: string;
  asset_type: string;
  discovery_source: string;
  association_reason: string;
  in_scope: boolean;
  is_live: boolean;
  http_status: number | null;
  created_at: string;
  ip_address?: string;
  metadata_: {
    suspicion_score?: number;
    suspicion_reasons?: string[];
    is_parked?: boolean;
    is_private?: boolean;
    validation_recommendation?: string;
    validated_at?: string;
    dns_records?: {
      A?: { address: string; ttl: number }[];
      AAAA?: { address: string; ttl: number }[];
      MX?: { target: string; priority: number; ttl: number }[];
      NS?: { target: string; ttl: number }[];
      TXT?: { value: string; ttl: number }[];
      SOA?: { admin: string; host: string; serial: number };
    };
    dns_summary?: {
      has_mail?: boolean;
      mail_providers?: string[];
      nameservers?: string[];
      ip_addresses?: string[];
      txt_verifications?: string[];
    };
    dns_analysis?: {
      is_active?: boolean;
      has_email?: boolean;
      uses_cdn?: string;
      security_features?: string[];
    };
    dns_fetched_at?: string;
    whois?: {
      registrant_name?: string;
      registrant_org?: string;
      registrant_email?: string;
      registrant_country?: string;
      registrar?: string;
      creation_date?: string;
      expiry_date?: string;
      is_private?: boolean;
      ownership_status?: string;
    };
    whois_fetched_at?: string;
  };
  // Web crawl results from Katana/ParamSpider
  endpoints?: string[];
  parameters?: string[];
  js_files?: string[];
}

interface Stats {
  total: number;
  domains: number;
  subdomains: number;
  in_scope: number;
  out_of_scope: number;
  validated: number;
  suspicious: number;
  parked: number;
  dns_enriched: number;
  whois_enriched: number;
  has_mail: number;
  live: number;
  not_probed: number;
  with_ip: number;
  no_ip: number;
}

export default function DomainsContent() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState(false);
  const [enrichingDns, setEnrichingDns] = useState(false);
  const [enrichingWhois, setEnrichingWhois] = useState(false);
  const [probingLive, setProbingLive] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [scopeFilter, setScopeFilter] = useState<string>('all');
  const [suspicionFilter, setSuspicionFilter] = useState<string>('all');
  const [liveFilter, setLiveFilter] = useState<string>('all');
  const [stats, setStats] = useState<Stats>({
    total: 0,
    domains: 0,
    subdomains: 0,
    in_scope: 0,
    out_of_scope: 0,
    validated: 0,
    suspicious: 0,
    parked: 0,
    dns_enriched: 0,
    whois_enriched: 0,
    has_mail: 0,
    live: 0,
    not_probed: 0,
    with_ip: 0,
    no_ip: 0,
  });
  const [selectedDomains, setSelectedDomains] = useState<Set<number>>(new Set());
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  const [addDomainDialogOpen, setAddDomainDialogOpen] = useState(false);
  const [addingDomains, setAddingDomains] = useState(false);
  const [newDomainsInput, setNewDomainsInput] = useState('');
  const [expandedDomains, setExpandedDomains] = useState<Set<number>>(new Set());
  const { toast } = useToast();

  // Toggle expanded state for a domain row
  const toggleExpandDomain = (domainId: number) => {
    setExpandedDomains(prev => {
      const next = new Set(prev);
      if (next.has(domainId)) {
        next.delete(domainId);
      } else {
        next.add(domainId);
      }
      return next;
    });
  };

  // Debounce search input - waits 300ms after user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchTerm);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const fetchDomains = useCallback(async (search?: string) => {
    try {
      setLoading(true);
      // Build params - use server-side search for efficiency
      const baseParams = {
        organization_id: 1,
        limit: 50000,
        ...(search ? { search } : {}),
      };
      
      // Fetch both domains and subdomains - handle each independently
      // Fetch all assets to show complete attack surface
      const [domainsResult, subdomainsResult] = await Promise.allSettled([
        api.getAssets({ ...baseParams, asset_type: 'domain' }),
        api.getAssets({ ...baseParams, asset_type: 'subdomain' })
      ]);
      
      // Extract successful results, use empty arrays for failures
      const domainsResponse = domainsResult.status === 'fulfilled' ? domainsResult.value : { items: [] };
      const subdomainsResponse = subdomainsResult.status === 'fulfilled' ? subdomainsResult.value : { items: [] };
      
      // Log any failures for debugging
      if (domainsResult.status === 'rejected') {
        console.error('Failed to fetch domains:', domainsResult.reason);
      }
      if (subdomainsResult.status === 'rejected') {
        console.error('Failed to fetch subdomains:', subdomainsResult.reason);
      }
      
      const domainAssets = domainsResponse.items || domainsResponse || [];
      const subdomainAssets = subdomainsResponse.items || subdomainsResponse || [];
      const allAssets = [...domainAssets, ...subdomainAssets];
      setDomains(allAssets);
      
      // Calculate stats
      const hasIp = (d: Domain) => d.ip_address || (d.metadata_?.dns_summary?.ip_addresses?.length ?? 0) > 0;
      const newStats: Stats = {
        total: allAssets.length,
        domains: domainAssets.length,
        subdomains: subdomainAssets.length,
        in_scope: allAssets.filter((d: Domain) => d.in_scope).length,
        out_of_scope: allAssets.filter((d: Domain) => !d.in_scope).length,
        validated: allAssets.filter((d: Domain) => d.metadata_?.validated_at).length,
        suspicious: allAssets.filter((d: Domain) => (d.metadata_?.suspicion_score || 0) >= 50).length,
        parked: allAssets.filter((d: Domain) => d.metadata_?.is_parked).length,
        dns_enriched: allAssets.filter((d: Domain) => d.metadata_?.dns_fetched_at).length,
        whois_enriched: allAssets.filter((d: Domain) => d.metadata_?.whois_fetched_at).length,
        has_mail: allAssets.filter((d: Domain) => d.metadata_?.dns_summary?.has_mail).length,
        live: allAssets.filter((d: Domain) => d.is_live).length,
        not_probed: allAssets.filter((d: Domain) => d.is_live === undefined || d.is_live === null).length,
        with_ip: allAssets.filter((d: Domain) => hasIp(d)).length,
        no_ip: allAssets.filter((d: Domain) => !hasIp(d)).length,
      };
      setStats(newStats);
      
      // Show warning if any request failed but we still have some data
      const failedRequests = [];
      if (domainsResult.status === 'rejected') failedRequests.push('domains');
      if (subdomainsResult.status === 'rejected') failedRequests.push('subdomains');
      
      if (failedRequests.length > 0 && allAssets.length > 0) {
        toast({
          title: 'Partial Load',
          description: `Some data couldn't be loaded: ${failedRequests.join(', ')}. Database may need migration.`,
          variant: 'default',
        });
      } else if (failedRequests.length > 0 && allAssets.length === 0) {
        toast({
          title: 'Error',
          description: 'Failed to fetch domains. Check backend logs for details.',
          variant: 'destructive',
        });
      }
      
    } catch (error) {
      console.error('Error fetching domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch domains',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  // Refetch when debounced search changes (server-side search)
  useEffect(() => {
    fetchDomains(debouncedSearch || undefined);
  }, [debouncedSearch, fetchDomains]);

  const handleValidateAll = async () => {
    try {
      setValidating(true);
      const response = await api.post('/external-discovery/validate-domains', {
        organization_id: 1,
        validate_all_whoxy: true,
        limit: 100,
      });
      
      toast({
        title: 'Validation Complete',
        description: `Validated ${response.data?.total ?? 0} domains. ${response.data?.suspicious ?? 0} suspicious, ${response.data?.auto_removed ?? 0} auto-removed.`,
      });
      
      fetchDomains(debouncedSearch || undefined);
    } catch (error) {
      console.error('Error validating domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to validate domains',
        variant: 'destructive',
      });
    } finally {
      setValidating(false);
    }
  };

  // DNS resolution is now automated - direct users to scan schedules
  const handleResolveDns = () => {
    toast({
      title: 'DNS Resolution',
      description: 'DNS resolution runs automatically via scheduled scans. Go to Scans > Schedules to configure.',
    });
  };

  const handleEnrichDns = async () => {
    try {
      setEnrichingDns(true);
      const response = await api.enrichDomainsDns({
        organizationId: 1,
        limit: 50,
      });
      
      if (response) {
        toast({
          title: 'DNS Enrichment Complete',
          description: `Enriched ${response.enriched ?? 0} of ${response.total_domains ?? 0} domains with DNS records.`,
        });
        fetchDomains(debouncedSearch || undefined);
      } else {
        toast({
          title: 'Warning',
          description: 'DNS enrichment completed but returned no data.',
        });
      }
    } catch (error: any) {
      console.error('Error enriching DNS:', error);
      const message = error?.response?.data?.detail || error?.message || 'Failed to enrich DNS records';
      toast({
        title: 'Error',
        description: message,
        variant: 'destructive',
      });
    } finally {
      setEnrichingDns(false);
    }
  };

  const handleEnrichWhois = async () => {
    try {
      setEnrichingWhois(true);
      const response = await api.enrichDomainsWhois({
        organizationId: 1,
        limit: 50,
      });

      if (response) {
        toast({
          title: 'WHOIS Enrichment Complete',
          description: `Enriched ${response.enriched ?? 0} of ${response.total_domains ?? 0} domains. ${response.ownership_matches ?? 0} ownership matches, ${response.privacy_protected ?? 0} privacy protected.`,
        });
        fetchDomains(debouncedSearch || undefined);
      } else {
        toast({
          title: 'Warning',
          description: 'WHOIS enrichment completed but returned no data.',
        });
      }
    } catch (error: any) {
      console.error('Error enriching WHOIS:', error);
      const message = error?.response?.data?.detail || error?.message || 'Failed to enrich WHOIS records';
      toast({
        title: 'Error',
        description: message,
        variant: 'destructive',
      });
    } finally {
      setEnrichingWhois(false);
    }
  };

  const handleProbeLive = async () => {
    try {
      setProbingLive(true);
      // Probe assets to check if they're live (HTTP/HTTPS responding)
      const response = await api.post('/assets/probe-live?organization_id=1&limit=500');
      
      if (response.data) {
        toast({
          title: 'Live Probe Complete',
          description: `Probed ${response.data.probed ?? 0} assets. ${response.data.live ?? 0} are live.`,
        });
        fetchDomains(debouncedSearch || undefined); // Refresh to show updated is_live status
      }
    } catch (error: any) {
      console.error('Error probing assets:', error);
      const message = error?.response?.data?.detail || error?.message || 'Failed to probe assets';
      toast({
        title: 'Error',
        description: message,
        variant: 'destructive',
      });
    } finally {
      setProbingLive(false);
    }
  };

  const handleAddDomains = async () => {
    if (!newDomainsInput.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter at least one domain',
        variant: 'destructive',
      });
      return;
    }

    try {
      setAddingDomains(true);
      
      // Parse domains - split by newlines, commas, or spaces
      const domainsToAdd = newDomainsInput
        .split(/[\n,\s]+/)
        .map((d: string) => d.trim().toLowerCase())
        .filter((d: string) => d.length > 0 && d.includes('.'));
      
      if (domainsToAdd.length === 0) {
        toast({
          title: 'Error',
          description: 'No valid domains found. Domains should contain a period (e.g., example.com)',
          variant: 'destructive',
        });
        return;
      }
      
      // Create assets for each domain
      const assets = domainsToAdd.map((domain: string) => ({
        organization_id: 1,
        name: domain,
        value: domain,
        asset_type: domain.split('.').length > 2 ? 'SUBDOMAIN' : 'DOMAIN',
        in_scope: true,
        discovery_source: 'manual',
        association_reason: 'Manually added',
      }));
      
      if (assets.length === 1) {
        await api.createAsset(assets[0]);
      } else {
        await api.createAssetsBulk(assets);
      }
      
      toast({
        title: 'Success',
        description: `Added ${assets.length} domain(s) to inventory`,
      });
      
      setAddDomainDialogOpen(false);
      setNewDomainsInput('');
      fetchDomains(debouncedSearch || undefined);
    } catch (error: any) {
      console.error('Error adding domains:', error);
      toast({
        title: 'Error',
        description: error?.response?.data?.detail || 'Failed to add domains',
        variant: 'destructive',
      });
    } finally {
      setAddingDomains(false);
    }
  };

  const handleToggleScope = async (domain: Domain) => {
    try {
      // Use cascade endpoint - when a domain is removed from scope, 
      // its subdomains should also be removed from scope
      const result = await api.setAssetScopeWithCascade(domain.id, !domain.in_scope, true);
      
      // Refetch to get updated state including cascaded subdomains
      fetchDomains(debouncedSearch || undefined);
      
      const cascadeMsg = result.subdomains_updated > 0 
        ? ` (and ${result.subdomains_updated} subdomains)` 
        : '';
      
      toast({
        title: domain.in_scope ? 'Removed from Scope' : 'Added to Scope',
        description: `${domain.value}${cascadeMsg} is now ${domain.in_scope ? 'out of' : 'in'} scope`,
      });
    } catch (error) {
      console.error('Error updating domain:', error);
      toast({
        title: 'Error',
        description: 'Failed to update domain scope',
        variant: 'destructive',
      });
    }
  };

  const handleBulkScope = async (inScope: boolean) => {
    if (selectedDomains.size === 0) return;
    
    try {
      const domainIds: number[] = Array.from(selectedDomains);
      // Use bulk cascade endpoint for efficiency
      const result = await api.bulkSetScopeWithCascade(domainIds, inScope, true);
      
      const cascadeMsg = result.cascaded_subdomains > 0 
        ? ` and ${result.cascaded_subdomains} subdomains` 
        : '';
      
      toast({
        title: 'Bulk Update Complete',
        description: `Updated ${result.updated} domains${cascadeMsg} to ${inScope ? 'in' : 'out of'} scope`,
      });
      
      setSelectedDomains(new Set());
      fetchDomains(debouncedSearch || undefined);
    } catch (error) {
      console.error('Error bulk updating domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to update domains',
        variant: 'destructive',
      });
    }
  };

  const toggleSelectDomain = (domainId: number) => {
    const newSelected = new Set(selectedDomains);
    if (newSelected.has(domainId)) {
      newSelected.delete(domainId);
    } else {
      newSelected.add(domainId);
    }
    setSelectedDomains(newSelected);
  };

  const selectAllVisible = () => {
    const visibleIds = filteredDomains.map((d: Domain) => d.id);
    setSelectedDomains(new Set(visibleIds));
  };

  const deselectAll = () => {
    setSelectedDomains(new Set());
  };

  // Filter domains - search is now server-side, other filters remain client-side
  const filteredDomains = useMemo(() => {
    return domains.filter((domain: Domain) => {
      // Note: Search is now done server-side for efficiency across all records
      
      // Type filter (domain vs subdomain) - handle both uppercase and lowercase
      if (typeFilter !== 'all') {
        const assetType = domain.asset_type?.toLowerCase();
        if (typeFilter === 'domain' && assetType !== 'domain') return false;
        if (typeFilter === 'subdomain' && assetType !== 'subdomain') return false;
      }
      
      // Source filter
      if (sourceFilter !== 'all') {
        const src = domain.discovery_source?.toLowerCase() || '';
        if (sourceFilter === 'whoxy' && !src.includes('whoxy')) return false;
        if (sourceFilter === 'commoncrawl' && !src.includes('commoncrawl')) return false;
        if (sourceFilter === 'sni' && !src.includes('sni')) return false;
        if (
          sourceFilter === 'crtsh' &&
          !src.includes('crtsh') &&
          !src.includes('crt_name') &&
          !src.includes('shodan_ctl')
        ) return false;
        if (sourceFilter === 'virustotal' && !src.includes('virustotal')) return false;
        if (sourceFilter === 'wayback' && !src.includes('wayback')) return false;
        if (sourceFilter === 'rapiddns' && !src.includes('rapiddns')) return false;
        if (sourceFilter === 'subfinder' && !src.includes('subfinder')) return false;
        if (sourceFilter === 'm365' && !src.includes('m365')) return false;
        if (sourceFilter === 'whoisxml' && !src.includes('whoisxml')) return false;
        if (sourceFilter === 'manual' && !src.includes('manual') && !src.includes('seed')) return false;
      }
      
      // Scope filter
      if (scopeFilter === 'in_scope' && !domain.in_scope) return false;
      if (scopeFilter === 'out_of_scope' && domain.in_scope) return false;
      
      // Suspicion filter
      if (suspicionFilter === 'suspicious' && (domain.metadata_?.suspicion_score || 0) < 50) return false;
      if (suspicionFilter === 'clean' && (domain.metadata_?.suspicion_score || 0) >= 50) return false;
      if (suspicionFilter === 'parked' && !domain.metadata_?.is_parked) return false;
      if (suspicionFilter === 'unvalidated' && domain.metadata_?.validated_at) return false;
      
      // Live status filter
      if (liveFilter === 'live' && !domain.is_live) return false;
      if (liveFilter === 'not_live' && domain.is_live) return false;
      if (liveFilter === 'not_probed' && domain.is_live !== undefined && domain.is_live !== null) return false;
      
      return true;
    });
  }, [domains, typeFilter, sourceFilter, scopeFilter, suspicionFilter, liveFilter]);

  const getSuspicionBadge = (domain: Domain) => {
    const score = domain.metadata_?.suspicion_score || 0;
    const isParked = domain.metadata_?.is_parked;
    
    if (isParked) {
      return <Badge variant="destructive" className="gap-1"><AlertTriangle className="h-3 w-3" /> Parked</Badge>;
    }
    if (score >= 75) {
      return <Badge variant="destructive" className="gap-1"><XCircle className="h-3 w-3" /> High Risk</Badge>;
    }
    if (score >= 50) {
      return <Badge variant="secondary" className="gap-1 bg-yellow-500/20 text-yellow-700"><AlertTriangle className="h-3 w-3" /> Suspicious</Badge>;
    }
    if (domain.metadata_?.validated_at) {
      return <Badge variant="secondary" className="gap-1 bg-green-500/20 text-green-700"><CheckCircle className="h-3 w-3" /> Verified</Badge>;
    }
    return <Badge variant="outline" className="gap-1"><Eye className="h-3 w-3" /> Not Validated</Badge>;
  };

  // Source badge styling
  const getSourceBadge = (source: string | undefined) => {
    const s = source?.toLowerCase() || 'unknown';
    
    const sourceConfig: Record<string, { icon: React.ComponentType<{className?: string}>, label: string, className: string }> = {
      whoxy: { icon: Mail, label: 'Whoxy', className: 'bg-purple-500/20 text-purple-700 border-purple-500/30' },
      commoncrawl: { icon: Database, label: 'Common Crawl', className: 'bg-yellow-500/20 text-yellow-700 border-yellow-500/30' },
      commoncrawl_comprehensive: { icon: Database, label: 'Common Crawl', className: 'bg-yellow-500/20 text-yellow-700 border-yellow-500/30' },
      sni_ip_ranges: { icon: Cloud, label: 'SNI/Cloud', className: 'bg-pink-500/20 text-pink-700 border-pink-500/30' },
      crtsh: { icon: Lock, label: 'Cert Trans', className: 'bg-green-500/20 text-green-700 border-green-500/30' },
      crt_name: { icon: Lock, label: 'crt.name', className: 'bg-green-500/20 text-green-700 border-green-500/30' },
      shodan_ctl: { icon: Lock, label: 'Shodan CTL', className: 'bg-green-500/20 text-green-700 border-green-500/30' },
      subfaster: { icon: Radar, label: 'Subfaster', className: 'bg-indigo-500/20 text-indigo-700 border-indigo-500/30' },
      virustotal: { icon: Shield, label: 'VirusTotal', className: 'bg-red-500/20 text-red-700 border-red-500/30' },
      wayback: { icon: FileText, label: 'Wayback', className: 'bg-amber-500/20 text-amber-700 border-amber-500/30' },
      rapiddns: { icon: Radar, label: 'RapidDNS', className: 'bg-cyan-500/20 text-cyan-700 border-cyan-500/30' },
      subfinder: { icon: Radar, label: 'Subfinder', className: 'bg-indigo-500/20 text-indigo-700 border-indigo-500/30' },
      m365: { icon: Building, label: 'M365', className: 'bg-blue-500/20 text-blue-700 border-blue-500/30' },
      whoisxml: { icon: Building, label: 'WhoisXML', className: 'bg-violet-500/20 text-violet-700 border-violet-500/30' },
      manual: { icon: Globe, label: 'Manual', className: 'bg-gray-500/20 text-gray-700 border-gray-500/30' },
      seed: { icon: Globe, label: 'Seed', className: 'bg-blue-500/20 text-blue-700 border-blue-500/30' },
    };

    // Try to match source
    let config = sourceConfig[s];
    if (!config) {
      // Try partial matches
      for (const [key, val] of Object.entries(sourceConfig)) {
        if (s.includes(key)) {
          config = val;
          break;
        }
      }
    }
    
    if (!config) {
      config = { icon: Search, label: source || 'Unknown', className: 'bg-gray-500/20 text-gray-600 border-gray-500/30' };
    }

    const Icon = config.icon;
    return (
      <Badge variant="outline" className={`gap-1 text-xs ${config.className}`}>
        <Icon className="h-3 w-3" />
        {config.label}
      </Badge>
    );
  };

  return (
    <>
      <div className="p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{stats.total}</div>
              <div className="text-xs text-muted-foreground">Total</div>
            </CardContent>
          </Card>
          <Card className="cursor-pointer hover:bg-muted/50" onClick={() => setTypeFilter('domain')}>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-blue-600">{stats.domains}</div>
              <div className="text-xs text-muted-foreground">Domains</div>
            </CardContent>
          </Card>
          <Card className="cursor-pointer hover:bg-muted/50" onClick={() => setTypeFilter('subdomain')}>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-indigo-600">{stats.subdomains}</div>
              <div className="text-xs text-muted-foreground">Subdomains</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-green-600">{stats.in_scope}</div>
              <div className="text-xs text-muted-foreground">In Scope</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-gray-500">{stats.out_of_scope}</div>
              <div className="text-xs text-muted-foreground">Out of Scope</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-blue-600">{stats.validated}</div>
              <div className="text-xs text-muted-foreground">Validated</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-yellow-600">{stats.suspicious}</div>
              <div className="text-xs text-muted-foreground">Suspicious</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-red-600">{stats.parked}</div>
              <div className="text-xs text-muted-foreground">Parked</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-green-600">{stats.with_ip}</div>
              <div className="text-xs text-muted-foreground">Has IP</div>
            </CardContent>
          </Card>
          <Card className={stats.no_ip > 0 ? "cursor-pointer hover:bg-muted/50 border-yellow-500/50" : ""} onClick={stats.no_ip > 0 ? handleResolveDns : undefined}>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-yellow-600">{stats.no_ip}</div>
              <div className="text-xs text-muted-foreground">{stats.no_ip > 0 ? 'No IP (auto-resolved)' : 'No IP'}</div>
            </CardContent>
          </Card>
        </div>

        {/* Filters and Actions */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex flex-col gap-3">
              {/* Row 1: Search, Key Filters, Actions */}
              <div className="flex flex-wrap items-center gap-2 justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  {/* Search */}
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search domains..."
                      value={searchTerm}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchTerm(e.target.value)}
                      className="pl-9 w-56"
                    />
                  </div>
                  
                  {/* Key Filters */}
                  <Select value={typeFilter} onValueChange={setTypeFilter}>
                    <SelectTrigger className="w-32">
                      <SelectValue placeholder="Type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="domain">Domains</SelectItem>
                      <SelectItem value="subdomain">Subdomains</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  <Select value={scopeFilter} onValueChange={setScopeFilter}>
                    <SelectTrigger className="w-32">
                      <SelectValue placeholder="Scope" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="in_scope">In Scope</SelectItem>
                      <SelectItem value="out_of_scope">Out of Scope</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  <Select value={liveFilter} onValueChange={setLiveFilter}>
                    <SelectTrigger className="w-28">
                      <SelectValue placeholder="Live" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="live">Live</SelectItem>
                      <SelectItem value="not_live">Not Live</SelectItem>
                      <SelectItem value="not_probed">Not Probed</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  {/* More Filters Toggle */}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowMoreFilters(!showMoreFilters)}
                    className="text-muted-foreground"
                  >
                    <Filter className="h-4 w-4 mr-1" />
                    {showMoreFilters ? 'Less' : 'More'}
                    <ChevronDown className={`h-3 w-3 ml-1 transition-transform ${showMoreFilters ? 'rotate-180' : ''}`} />
                  </Button>
                </div>
                
                {/* Actions */}
                <div className="flex items-center gap-2">
                  <Button size="sm" onClick={() => setAddDomainDialogOpen(true)}>
                    <Plus className="h-4 w-4 mr-1" />
                    Add Domain
                  </Button>
                  
                  <Button variant="outline" size="sm" onClick={() => fetchDomains(debouncedSearch || undefined)} disabled={loading}>
                    <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                  </Button>
                  
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm">
                        <Zap className="h-4 w-4 mr-1" />
                        Actions
                        <ChevronDown className="h-3 w-3 ml-1" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem onClick={handleProbeLive} disabled={probingLive}>
                        <Radar className="h-4 w-4 mr-2" />
                        {probingLive ? 'Probing...' : 'Probe Live Status'}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={handleEnrichDns} disabled={enrichingDns}>
                        <Database className="h-4 w-4 mr-2" />
                        {enrichingDns ? 'Enriching...' : 'Enrich DNS Records'}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={handleEnrichWhois} disabled={enrichingWhois}>
                        <FileText className="h-4 w-4 mr-2" />
                        {enrichingWhois ? 'Enriching...' : 'Enrich WHOIS'}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={handleValidateAll} disabled={validating}>
                        <Shield className="h-4 w-4 mr-2" />
                        {validating ? 'Validating...' : 'Validate Ownership'}
                      </DropdownMenuItem>
                      {stats.out_of_scope > 0 && (
                        <>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem 
                            className="text-red-600"
                            onClick={async () => {
                              if (confirm(`Delete ${stats.out_of_scope} out-of-scope domains? This cannot be undone.`)) {
                                try {
                                  const outOfScopeIds = domains.filter((d: Domain) => !d.in_scope).map((d: Domain) => d.id);
                                  const result = await api.bulkDeleteAssets(outOfScopeIds);
                                  toast({
                                    title: 'Deleted',
                                    description: `Deleted ${result.deleted} out-of-scope domains.`,
                                  });
                                  fetchDomains(debouncedSearch || undefined);
                                } catch (error) {
                                  toast({
                                    title: 'Error',
                                    description: 'Failed to delete domains',
                                    variant: 'destructive',
                                  });
                                }
                              }
                            }}
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete Out of Scope ({stats.out_of_scope})
                          </DropdownMenuItem>
                        </>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
              
              {/* Row 2: More Filters (collapsible) */}
              {showMoreFilters && (
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t">
                  <Select value={sourceFilter} onValueChange={setSourceFilter}>
                    <SelectTrigger className="w-40">
                      <SelectValue placeholder="Source" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Sources</SelectItem>
                      <SelectItem value="whoxy">Whoxy (WHOIS)</SelectItem>
                      <SelectItem value="commoncrawl">Common Crawl</SelectItem>
                      <SelectItem value="sni">SNI/Cloud IP</SelectItem>
                      <SelectItem value="crtsh">Cert Transparency</SelectItem>
                      <SelectItem value="virustotal">VirusTotal</SelectItem>
                      <SelectItem value="wayback">Wayback Machine</SelectItem>
                      <SelectItem value="rapiddns">RapidDNS</SelectItem>
                      <SelectItem value="subfinder">Subfinder</SelectItem>
                      <SelectItem value="m365">Microsoft 365</SelectItem>
                      <SelectItem value="whoisxml">WhoisXML</SelectItem>
                      <SelectItem value="manual">Manual/Seed</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  <Select value={suspicionFilter} onValueChange={setSuspicionFilter}>
                    <SelectTrigger className="w-36">
                      <SelectValue placeholder="Validation" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Status</SelectItem>
                      <SelectItem value="suspicious">Suspicious</SelectItem>
                      <SelectItem value="parked">Parked</SelectItem>
                      <SelectItem value="clean">Clean</SelectItem>
                      <SelectItem value="unvalidated">Not Validated</SelectItem>
                    </SelectContent>
                  </Select>
                  
                  {/* Clear Filters */}
                  {(sourceFilter !== 'all' || suspicionFilter !== 'all' || typeFilter !== 'all' || scopeFilter !== 'all' || liveFilter !== 'all') && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setTypeFilter('all');
                        setScopeFilter('all');
                        setLiveFilter('all');
                        setSourceFilter('all');
                        setSuspicionFilter('all');
                      }}
                      className="text-muted-foreground"
                    >
                      <X className="h-3 w-3 mr-1" />
                      Clear filters
                    </Button>
                  )}
                </div>
              )}
            </div>
          </CardHeader>
          
          {/* Bulk Actions */}
          {selectedDomains.size > 0 && (
            <div className="px-6 pb-4 flex items-center gap-4 bg-muted/50 mx-6 rounded-lg py-3">
              <span className="text-sm font-medium">{selectedDomains.size} selected</span>
              <Button size="sm" variant="outline" onClick={() => handleBulkScope(true)}>
                <Check className="h-4 w-4 mr-1" /> Add to Scope
              </Button>
              <Button size="sm" variant="outline" onClick={() => handleBulkScope(false)}>
                <X className="h-4 w-4 mr-1" /> Remove from Scope
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                className="text-red-500 border-red-500/50 hover:bg-red-500/10"
                onClick={async () => {
                  if (confirm(`Delete ${selectedDomains.size} selected domains? This cannot be undone.`)) {
                    try {
                      const result = await api.bulkDeleteAssets(Array.from(selectedDomains));
                      toast({
                        title: 'Domains Deleted',
                        description: `Deleted ${result.deleted} domains.`,
                      });
                      setSelectedDomains(new Set());
                      fetchDomains(debouncedSearch || undefined);
                    } catch (error) {
                      toast({
                        title: 'Error',
                        description: 'Failed to delete domains',
                        variant: 'destructive',
                      });
                    }
                  }
                }}
              >
                <Trash2 className="h-4 w-4 mr-1" /> Delete Selected
              </Button>
              <Button size="sm" variant="ghost" onClick={deselectAll}>
                Clear Selection
              </Button>
            </div>
          )}
          
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : filteredDomains.length === 0 ? (
              <div className="text-center py-12">
                <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No domains found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Run an External Discovery with Whoxy to discover domains
                </p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">
                        <input
                          type="checkbox"
                          checked={selectedDomains.size === filteredDomains.length && filteredDomains.length > 0}
                          onChange={(e: React.ChangeEvent<HTMLInputElement>) => e.target.checked ? selectAllVisible() : deselectAll()}
                          className="rounded"
                        />
                      </TableHead>
                      <TableHead>Domain</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Registrant</TableHead>
                      <TableHead>IP / DNS</TableHead>
                      <TableHead>Mail / Security</TableHead>
                      <TableHead>Web Crawl</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredDomains.map((domain: Domain) => (
                      <React.Fragment key={domain.id}>
                      <TableRow className={!domain.in_scope ? 'opacity-60' : ''}>
                        <TableCell>
                          <input
                            type="checkbox"
                            checked={selectedDomains.has(domain.id)}
                            onChange={() => toggleSelectDomain(domain.id)}
                            className="rounded"
                          />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {domain.asset_type?.toLowerCase() === 'subdomain' ? (
                              <Radar className="h-4 w-4 text-indigo-500" />
                            ) : (
                              <Globe className="h-4 w-4 text-blue-500" />
                            )}
                            <div className="flex flex-col">
                              <a 
                                href={`https://${domain.value}`} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="font-mono text-sm hover:underline flex items-center gap-1"
                              >
                                {domain.value}
                                <ExternalLink className="h-3 w-3" />
                              </a>
                              <span className="text-[10px] text-muted-foreground">
                                {domain.asset_type?.toLowerCase() === 'subdomain' ? 'Subdomain' : 'Root Domain'}
                              </span>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          {getSourceBadge(domain.discovery_source)}
                        </TableCell>
                        <TableCell>
                          {domain.asset_type?.toLowerCase() === 'domain' ? (
                            domain.metadata_?.whois ? (
                              <div className="flex flex-col gap-0.5">
                                <span className="text-xs font-medium truncate max-w-32" title={domain.metadata_?.whois?.registrant_org || domain.metadata_?.whois?.registrant_name || ''}>
                                  {domain.metadata_?.whois?.registrant_org || domain.metadata_?.whois?.registrant_name || 'Unknown'}
                                </span>
                                {domain.metadata_?.whois?.is_private && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 w-fit bg-gray-500/20 text-gray-600">
                                    Private
                                  </Badge>
                                )}
                                {domain.metadata_?.whois?.ownership_status === 'confirmed' && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 w-fit bg-green-500/20 text-green-700">
                                    <CheckCircle className="h-2.5 w-2.5 mr-0.5" /> Confirmed
                                  </Badge>
                                )}
                                {domain.metadata_?.whois?.ownership_status === 'mismatch' && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 w-fit bg-red-500/20 text-red-700">
                                    <AlertTriangle className="h-2.5 w-2.5 mr-0.5" /> Mismatch
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">Not enriched</span>
                            )
                          ) : (
                            <span className="text-xs text-muted-foreground">N/A</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            {domain.ip_address || (domain.metadata_?.dns_summary?.ip_addresses?.length ?? 0) > 0 ? (
                              <>
                                <div className="flex items-center gap-1">
                                  <CheckCircle className="h-3 w-3 text-green-500" />
                                  <span className="font-mono text-xs">
                                    {domain.ip_address || domain.metadata_?.dns_summary?.ip_addresses?.[0]}
                                  </span>
                                </div>
                                {domain.metadata_?.dns_fetched_at && (
                                  <span className="text-[10px] text-muted-foreground">
                                    {formatDate(domain.metadata_.dns_fetched_at)}
                                  </span>
                                )}
                              </>
                            ) : domain.metadata_?.dns_fetched_at ? (
                              <div className="flex items-center gap-1">
                                <XCircle className="h-3 w-3 text-red-500" />
                                <span className="text-xs text-red-500">No A record</span>
                              </div>
                            ) : (
                              <div className="flex items-center gap-1">
                                <AlertTriangle className="h-3 w-3 text-yellow-500" />
                                <span className="text-xs text-yellow-600">Not resolved</span>
                              </div>
                            )}
                            {(domain.metadata_?.dns_summary?.nameservers?.length ?? 0) > 0 && (
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <Server className="h-3 w-3" />
                                {domain.metadata_?.dns_summary?.nameservers?.[0]?.split('.').slice(-2).join('.') || 'NS'}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            {domain.metadata_?.dns_summary?.has_mail ? (
                              <span className="text-xs flex items-center gap-1 text-green-600">
                                <Mail className="h-3 w-3" />
                                {(domain.metadata_?.dns_summary?.mail_providers?.length ?? 0) > 0 
                                  ? domain.metadata_?.dns_summary?.mail_providers?.[0]
                                  : 'Email'}
                              </span>
                            ) : domain.metadata_?.dns_fetched_at ? (
                              <span className="text-xs text-muted-foreground">No email</span>
                            ) : null}
                            {(domain.metadata_?.dns_analysis?.security_features?.length ?? 0) > 0 && (
                              <div className="flex gap-1 flex-wrap">
                                {domain.metadata_!.dns_analysis!.security_features!.map((f: string) => (
                                  <Badge key={f} variant="outline" className="text-[10px] px-1 py-0">
                                    {f}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          {/* Web Crawl Results - Endpoints, Params, JS - Clickable to expand */}
                          {((domain.endpoints?.length ?? 0) > 0 || 
                            (domain.parameters?.length ?? 0) > 0 || 
                            (domain.js_files?.length ?? 0) > 0) ? (
                            <button
                              onClick={() => toggleExpandDomain(domain.id)}
                              className="flex flex-col gap-1 hover:bg-muted/50 rounded p-1 -m-1 transition-colors text-left"
                            >
                              <div className="flex items-center gap-1">
                                <ChevronDown className={`h-3 w-3 transition-transform ${expandedDomains.has(domain.id) ? '' : '-rotate-90'}`} />
                                <span className="text-xs font-medium">View Details</span>
                              </div>
                              {(domain.endpoints?.length ?? 0) > 0 && (
                                <span className="text-xs flex items-center gap-1 text-blue-600 ml-4">
                                  <Link2 className="h-3 w-3" />
                                  {domain.endpoints!.length} endpoints
                                </span>
                              )}
                              {(domain.parameters?.length ?? 0) > 0 && (
                                <span className="text-xs flex items-center gap-1 text-orange-600 ml-4">
                                  <Hash className="h-3 w-3" />
                                  {domain.parameters!.length} params
                                </span>
                              )}
                              {(domain.js_files?.length ?? 0) > 0 && (
                                <span className="text-xs flex items-center gap-1 text-yellow-600 ml-4">
                                  <Code className="h-3 w-3" />
                                  {domain.js_files!.length} JS files
                                </span>
                              )}
                            </button>
                          ) : (
                            <span className="text-xs text-muted-foreground">Not crawled</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {getSuspicionBadge(domain)}
                        </TableCell>
                        <TableCell>
                          {domain.in_scope ? (
                            <Badge className="bg-green-500/20 text-green-700 hover:bg-green-500/30">
                              <CheckCircle className="h-3 w-3 mr-1" /> In Scope
                            </Badge>
                          ) : (
                            <Badge variant="secondary">
                              <XCircle className="h-3 w-3 mr-1" /> Out
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant={domain.in_scope ? "destructive" : "default"}
                              onClick={() => handleToggleScope(domain)}
                            >
                              {domain.in_scope ? (
                                <>
                                  <XCircle className="h-4 w-4 mr-1" /> Remove
                                </>
                              ) : (
                                <>
                                  <CheckCircle className="h-4 w-4 mr-1" /> Add
                                </>
                              )}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => window.open(`/assets/${domain.id}`, '_blank')}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                      {/* Expandable Web Crawl Details Row */}
                      {expandedDomains.has(domain.id) && (
                        <TableRow className="bg-muted/30 hover:bg-muted/40">
                          <TableCell colSpan={10} className="p-4">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                              {/* Endpoints */}
                              {domain.endpoints && domain.endpoints.length > 0 && (
                                <div className="bg-background rounded-lg p-3 border">
                                  <div className="flex items-center gap-2 mb-2">
                                    <Link2 className="h-4 w-4 text-blue-500" />
                                    <h4 className="text-sm font-medium">Endpoints ({domain.endpoints.length})</h4>
                                  </div>
                                  <div className="max-h-48 overflow-y-auto space-y-1">
                                    {domain.endpoints.slice(0, 25).map((endpoint, idx) => (
                                      <a
                                        key={idx}
                                        href={endpoint.startsWith('http') ? endpoint : `https://${domain.value}${endpoint}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="block font-mono text-xs text-muted-foreground hover:text-blue-500 transition-colors truncate"
                                        title={endpoint}
                                      >
                                        {endpoint}
                                      </a>
                                    ))}
                                    {domain.endpoints.length > 25 && (
                                      <div className="text-xs text-muted-foreground pt-2 border-t mt-2">
                                        +{domain.endpoints.length - 25} more
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* Parameters */}
                              {domain.parameters && domain.parameters.length > 0 && (
                                <div className="bg-background rounded-lg p-3 border">
                                  <div className="flex items-center gap-2 mb-2">
                                    <Hash className="h-4 w-4 text-orange-500" />
                                    <h4 className="text-sm font-medium">Parameters ({domain.parameters.length})</h4>
                                  </div>
                                  <div className="flex flex-wrap gap-1 max-h-48 overflow-y-auto">
                                    {domain.parameters.slice(0, 50).map((param, idx) => (
                                      <Badge 
                                        key={idx} 
                                        variant="outline" 
                                        className="font-mono text-[10px] bg-orange-500/10 text-orange-600 border-orange-500/30"
                                      >
                                        {param}
                                      </Badge>
                                    ))}
                                    {domain.parameters.length > 50 && (
                                      <Badge variant="outline" className="text-[10px]">
                                        +{domain.parameters.length - 50} more
                                      </Badge>
                                    )}
                                  </div>
                                  <p className="text-[10px] text-muted-foreground mt-2">
                                    May be vulnerable to XSS, SQLi, SSRF
                                  </p>
                                </div>
                              )}

                              {/* JavaScript Files */}
                              {domain.js_files && domain.js_files.length > 0 && (
                                <div className="bg-background rounded-lg p-3 border">
                                  <div className="flex items-center gap-2 mb-2">
                                    <Code className="h-4 w-4 text-yellow-500" />
                                    <h4 className="text-sm font-medium">JavaScript Files ({domain.js_files.length})</h4>
                                  </div>
                                  <div className="max-h-48 overflow-y-auto space-y-1">
                                    {domain.js_files.slice(0, 25).map((jsFile, idx) => (
                                      <a
                                        key={idx}
                                        href={jsFile.startsWith('http') ? jsFile : `https://${domain.value}${jsFile}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="block font-mono text-xs text-muted-foreground hover:text-yellow-500 transition-colors truncate"
                                        title={jsFile}
                                      >
                                        {jsFile}
                                      </a>
                                    ))}
                                    {domain.js_files.length > 25 && (
                                      <div className="text-xs text-muted-foreground pt-2 border-t mt-2">
                                        +{domain.js_files.length - 25} more JS files
                                      </div>
                                    )}
                                  </div>
                                  <p className="text-[10px] text-muted-foreground mt-2">
                                    May contain API endpoints or secrets
                                  </p>
                                </div>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                      </React.Fragment>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Add Domain Dialog */}
      <Dialog open={addDomainDialogOpen} onOpenChange={setAddDomainDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Domains</DialogTitle>
            <DialogDescription>
              Add domains or subdomains to your inventory. Enter one per line or separate with commas.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div>
              <Label htmlFor="domains">Domains</Label>
              <textarea
                id="domains"
                value={newDomainsInput}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setNewDomainsInput(e.target.value)}
                placeholder={"example.com\nsubdomain.example.com\nanother-domain.net"}
                rows={6}
                className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 font-mono"
              />
              <p className="text-xs text-muted-foreground mt-2">
                Enter domains one per line, or separate with commas or spaces.
                Subdomains (e.g., app.example.com) are automatically detected.
              </p>
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddDomainDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleAddDomains} disabled={addingDomains}>
              {addingDomains ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Adding...
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Domains
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
