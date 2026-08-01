'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Search,
  Globe,
  Loader2,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  RefreshCw,
  Key,
  Shield,
  Server,
  Network,
  Plus,
  X,
  Building2,
  Mail,
  Settings,
  ChevronDown,
  ChevronUp,
  History,
  AlertTriangle,
  FileWarning,
  FileText,
  ExternalLink,
  Link,
  Radar,
  Camera,
  Cloud,
  FolderTree,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import dynamic from 'next/dynamic';

const AppStructureContent = dynamic(() => import('./AppStructureContent'), {
  loading: () => <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>,
});

// Types for External Discovery
interface SourceResult {
  source: string;
  success: boolean;
  domains_found: number;
  subdomains_found: number;
  ips_found: number;
  cidrs_found: number;
  elapsed_time: number;
  error?: string;
}

interface DiscoveryResult {
  domain: string;
  organization_id: number;
  total_domains: number;
  total_subdomains: number;
  total_ips: number;
  total_cidrs: number;
  source_results: SourceResult[];
  domains: string[];
  subdomains: string[];
  ip_addresses: string[];
  ip_ranges: string[];
  assets_created: number;
  assets_skipped: number;
  total_elapsed_time: number;
}

// Types for Wayback URLs
interface DomainResult {
  domain: string;
  success: boolean;
  url_count: number;
  interesting_count: number;
  elapsed_time: number;
  error?: string;
}

interface WaybackResult {
  domain?: string;
  domains_scanned?: number;
  total_urls: number;
  total_interesting?: number;
  interesting_count?: number;
  url_count?: number;
  unique_paths_count?: number;
  file_extensions: Record<string, number>;
  urls: string[];
  interesting_urls: string[];
  unique_paths?: string[];
  domain_results?: DomainResult[];
  elapsed_time?: number;
}

// Types for Reverse-lookup pivot preview
interface PivotHost {
  host: string;
  seen_on_assets: number;
  sources: string[];
}

interface WhoisPreviewTerm {
  term: string;
  would_return_domains: number;
}

interface ReversePivotPlan {
  organization_id: number;
  primary_domain?: string | null;
  sampled_assets: number;
  min_shared_threshold: number;
  providers_available: string[];
  nameserver_pivots: PivotHost[];
  mailserver_pivots: PivotHost[];
  reverse_whois_preview: WhoisPreviewTerm[];
  note: string;
}

interface ReverseRunResult {
  organization_id: number;
  success: boolean;
  domains: string[];
  domains_by_nameserver: Record<string, string[]>;
  domains_by_mailserver: Record<string, string[]>;
  pivoted_nameservers: string[];
  pivoted_mailservers: string[];
  providers: string[];
  total_domains_found: number;
  assets_created: number;
  subdomains_enumerated: number;
  subdomain_assets_created: number;
  error?: string | null;
  elapsed_time: number;
}

// Wrapper component to handle Suspense for useSearchParams
export default function DiscoveryPage() {
  return (
    <Suspense fallback={
      <MainLayout>
        <div className="p-6 flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </MainLayout>
    }>
      <DiscoveryPageContent />
    </Suspense>
  );
}

function DiscoveryPageContent() {
  const searchParams = useSearchParams();
  
  // Common state
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [domain, setDomain] = useState('');
  const { toast } = useToast();
  
  // Main tab (external | wayback | app-structure) — supports deep-linking via ?tab=
  const [activeMainTab, setActiveMainTab] = useState<string>('external');

  // Pre-fill from URL params (when coming from Organization page)
  useEffect(() => {
    const orgId = searchParams?.get('org');
    const domainParam = searchParams?.get('domain');
    const tabParam = searchParams?.get('tab');
    
    if (orgId) {
      setSelectedOrg(orgId);
    }
    if (domainParam) {
      setDomain(domainParam);
    }
    if (tabParam && ['external', 'wayback', 'app-structure'].includes(tabParam)) {
      setActiveMainTab(tabParam);
    }
  }, [searchParams]);

  // External Discovery state
  const [discoveryRunning, setDiscoveryRunning] = useState(false);
  const [discoveryResults, setDiscoveryResults] = useState<DiscoveryResult | null>(null);
  const [discoveryActiveTab, setDiscoveryActiveTab] = useState<'subdomains' | 'ips' | 'domains' | 'ranges'>('subdomains');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [includePaid, setIncludePaid] = useState(true);
  const [includeFree, setIncludeFree] = useState(true);
  const [createAssets, setCreateAssets] = useState(true);
  const [enumerateDiscoveredDomains, setEnumerateDiscoveredDomains] = useState(true);
  const [maxDomainsToEnumerate, setMaxDomainsToEnumerate] = useState(50);
  const [orgNames, setOrgNames] = useState<string[]>([]);
  const [newOrgName, setNewOrgName] = useState('');
  const [regEmails, setRegEmails] = useState<string[]>([]);
  const [newRegEmail, setNewRegEmail] = useState('');
  
  // Common Crawl comprehensive search options
  const [ccOrgName, setCcOrgName] = useState('');
  const [ccKeywords, setCcKeywords] = useState<string[]>([]);
  const [newCcKeyword, setNewCcKeyword] = useState('');
  
  // Technology scanning options
  const [runTechScan, setRunTechScan] = useState(true);
  const [maxTechScan, setMaxTechScan] = useState(500);
  
  // Screenshot capture options
  const [runScreenshots, setRunScreenshots] = useState(true);
  const [maxScreenshots, setMaxScreenshots] = useState(200);
  const [screenshotTimeout, setScreenshotTimeout] = useState(30);
  
  // SNI IP Ranges - Cloud asset discovery
  const [includeSniDiscovery, setIncludeSniDiscovery] = useState(true);
  const [sniKeywords, setSniKeywords] = useState<string[]>([]);
  const [newSniKeyword, setNewSniKeyword] = useState('');

  // Reverse-lookup pivot preview (credit-free plan of NS/MX/WHOIS pivots)
  const [reversePivots, setReversePivots] = useState<ReversePivotPlan | null>(null);
  const [reversePivotsLoading, setReversePivotsLoading] = useState(false);
  // Which pivot hosts are selected to actually run on (default: all)
  const [selectedNsPivots, setSelectedNsPivots] = useState<Set<string>>(new Set());
  const [selectedMxPivots, setSelectedMxPivots] = useState<Set<string>>(new Set());
  const [reverseRunning, setReverseRunning] = useState(false);
  const [reverseRunResult, setReverseRunResult] = useState<ReverseRunResult | null>(null);
  const [reverseEnumerate, setReverseEnumerate] = useState(true);

  // Wayback URLs state
  const [waybackRunning, setWaybackRunning] = useState(false);
  const [waybackResults, setWaybackResults] = useState<WaybackResult | null>(null);
  const [waybackMode, setWaybackMode] = useState<'single' | 'organization'>('single');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [waybackActiveTab, setWaybackActiveTab] = useState<'interesting' | 'all'>('interesting');

  const fetchData = async () => {
    setLoading(true);
    try {
      const orgsData = await api.getOrganizations();
      setOrganizations(orgsData || []);
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
      toast({
        title: 'Error',
        description: 'Failed to load organizations. Please check your connection.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  // Load saved discovery settings when organization is selected
  const loadDiscoverySettings = async (orgId: string) => {
    try {
      const settings = await api.getDiscoverySettings(parseInt(orgId));
      if (settings) {
        // Pre-fill Common Crawl settings
        if (settings.commoncrawl_org_name) {
          setCcOrgName(settings.commoncrawl_org_name);
        }
        if (settings.commoncrawl_keywords && settings.commoncrawl_keywords.length > 0) {
          setCcKeywords(settings.commoncrawl_keywords);
        }
        // Pre-fill SNI settings
        if (settings.sni_keywords && settings.sni_keywords.length > 0) {
          setSniKeywords(settings.sni_keywords);
        }
        console.log('Loaded saved discovery settings:', settings);
      }
    } catch (error) {
      // Settings not found is fine - just use empty defaults
      console.log('No saved discovery settings found for organization');
    }
  };

  // Load settings when organization changes
  useEffect(() => {
    if (selectedOrg) {
      loadDiscoverySettings(selectedOrg);
    }
  }, [selectedOrg]);

  useEffect(() => {
    fetchData();
  }, []);

  // External Discovery handlers
  const handleRunDiscovery = async () => {
    if (!selectedOrg || !domain) {
      toast({
        title: 'Error',
        description: 'Please select an organization and enter a domain',
        variant: 'destructive',
      });
      return;
    }

    setDiscoveryRunning(true);
    setDiscoveryResults(null);
    try {
      const result = await api.runExternalDiscovery({
        organization_id: parseInt(selectedOrg),
        domain,
        include_paid_sources: includePaid,
        include_free_sources: includeFree,
        create_assets: createAssets,
        skip_existing: true,
        enumerate_discovered_domains: enumerateDiscoveredDomains,
        max_domains_to_enumerate: maxDomainsToEnumerate,
        organization_names: orgNames.length > 0 ? orgNames : undefined,
        registration_emails: regEmails.length > 0 ? regEmails : undefined,
        commoncrawl_org_name: ccOrgName || undefined,
        commoncrawl_keywords: ccKeywords.length > 0 ? ccKeywords : undefined,
        include_sni_discovery: includeSniDiscovery,
        sni_keywords: sniKeywords.length > 0 ? sniKeywords : undefined,
        run_technology_scan: runTechScan,
        max_technology_scan: maxTechScan,
        run_screenshots: runScreenshots,
        max_screenshots: maxScreenshots,
        screenshot_timeout: screenshotTimeout,
      });

      setDiscoveryResults(result);
      toast({
        title: 'Discovery Complete',
        description: `Found ${result.total_subdomains} subdomains, ${result.total_ips} IPs. Created ${result.assets_created} new assets.`,
      });
    } catch (error: any) {
      console.error('Discovery error:', error);
      toast({
        title: 'Discovery Failed',
        description: error.response?.data?.detail || error.message || 'Failed to run discovery. Check API keys in Settings.',
        variant: 'destructive',
      });
    } finally {
      setDiscoveryRunning(false);
    }
  };

  const downloadDiscoveryResults = () => {
    if (!discoveryResults) return;
    
    const data = {
      domain: discoveryResults.domain,
      timestamp: new Date().toISOString(),
      subdomains: discoveryResults.subdomains,
      domains: discoveryResults.domains,
      ip_addresses: discoveryResults.ip_addresses,
      ip_ranges: discoveryResults.ip_ranges,
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `discovery-${discoveryResults.domain}-${Date.now()}.json`;
    a.click();
  };

  const addOrgName = () => {
    if (newOrgName && !orgNames.includes(newOrgName)) {
      setOrgNames([...orgNames, newOrgName]);
      setNewOrgName('');
    }
  };

  const removeOrgName = (name: string) => {
    setOrgNames(orgNames.filter(n => n !== name));
  };

  const addRegEmail = () => {
    if (newRegEmail && !regEmails.includes(newRegEmail)) {
      setRegEmails([...regEmails, newRegEmail]);
      setNewRegEmail('');
    }
  };

  const removeRegEmail = (email: string) => {
    setRegEmails(regEmails.filter(e => e !== email));
  };

  const addCcKeyword = () => {
    if (newCcKeyword && !ccKeywords.includes(newCcKeyword)) {
      setCcKeywords([...ccKeywords, newCcKeyword]);
      setNewCcKeyword('');
    }
  };

  const removeCcKeyword = (keyword: string) => {
    setCcKeywords(ccKeywords.filter(k => k !== keyword));
  };

  const addSniKeyword = () => {
    if (newSniKeyword && !sniKeywords.includes(newSniKeyword)) {
      setSniKeywords([...sniKeywords, newSniKeyword]);
      setNewSniKeyword('');
    }
  };

  const removeSniKeyword = (keyword: string) => {
    setSniKeywords(sniKeywords.filter(k => k !== keyword));
  };

  // Load the credit-free reverse-lookup pivot plan for the selected org.
  const handleLoadReversePivots = async () => {
    if (!selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please select an organization first',
        variant: 'destructive',
      });
      return;
    }

    setReversePivotsLoading(true);
    setReverseRunResult(null);
    try {
      const plan = await api.getReversePivots(parseInt(selectedOrg), domain || undefined);
      setReversePivots(plan);
      // Select all discovered pivots by default so a run works out of the box.
      setSelectedNsPivots(new Set((plan.nameserver_pivots || []).map((p: PivotHost) => p.host)));
      setSelectedMxPivots(new Set((plan.mailserver_pivots || []).map((p: PivotHost) => p.host)));
      const pivotCount = (plan.nameserver_pivots?.length || 0) + (plan.mailserver_pivots?.length || 0);
      toast({
        title: 'Pivot Preview Ready',
        description: `${pivotCount} infrastructure pivot${pivotCount === 1 ? '' : 's'} found. No credits were spent.`,
      });
    } catch (error: any) {
      console.error('Reverse pivot preview error:', error);
      toast({
        title: 'Preview Failed',
        description: error.response?.data?.detail || error.message || 'Failed to load reverse-lookup pivots.',
        variant: 'destructive',
      });
    } finally {
      setReversePivotsLoading(false);
    }
  };

  const toggleNsPivot = (host: string) => {
    setSelectedNsPivots((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host); else next.add(host);
      return next;
    });
  };

  const toggleMxPivot = (host: string) => {
    setSelectedMxPivots((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host); else next.add(host);
      return next;
    });
  };

  // Run reverse discovery on exactly the pivots the user left selected.
  const handleRunReverseDiscovery = async () => {
    if (!selectedOrg) return;
    const nameservers = Array.from(selectedNsPivots);
    const mailservers = Array.from(selectedMxPivots);
    if (nameservers.length === 0 && mailservers.length === 0) {
      toast({
        title: 'No pivots selected',
        description: 'Select at least one nameserver or mailserver to run on.',
        variant: 'destructive',
      });
      return;
    }

    setReverseRunning(true);
    setReverseRunResult(null);
    try {
      const result = await api.runReverseDiscovery({
        organization_id: parseInt(selectedOrg),
        domain: domain || undefined,
        nameservers,
        mailservers,
        create_assets: createAssets,
        enumerate_discovered_domains: reverseEnumerate,
        max_domains_to_enumerate: maxDomainsToEnumerate,
      });
      setReverseRunResult(result);
      const enumNote = reverseEnumerate && result.subdomains_enumerated > 0
        ? ` +${result.subdomains_enumerated} subdomains enumerated.`
        : '';
      toast({
        title: 'Reverse Discovery Complete',
        description: `Found ${result.total_domains_found} domain${result.total_domains_found === 1 ? '' : 's'}. Created ${result.assets_created} new asset${result.assets_created === 1 ? '' : 's'}.${enumNote}`,
      });
    } catch (error: any) {
      console.error('Reverse discovery run error:', error);
      toast({
        title: 'Reverse Discovery Failed',
        description: error.response?.data?.detail || error.message || 'Failed to run reverse discovery.',
        variant: 'destructive',
      });
    } finally {
      setReverseRunning(false);
    }
  };

  // Wayback URLs handlers
  const handleRunWayback = async () => {
    if (waybackMode === 'single' && !domain) {
      toast({
        title: 'Error',
        description: 'Please enter a domain',
        variant: 'destructive',
      });
      return;
    }

    if (waybackMode === 'organization' && !selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please select an organization',
        variant: 'destructive',
      });
      return;
    }

    setWaybackRunning(true);
    setWaybackResults(null);
    try {
      let result;
      if (waybackMode === 'single') {
        const response = await api.post('/waybackurls/fetch', {
          domain,
          no_subs: !includeSubdomains,
          timeout: 120
        });
        result = response.data;
      } else {
        const response = await api.post('/waybackurls/fetch/organization', {
          organization_id: parseInt(selectedOrg),
          include_subdomains: includeSubdomains,
          timeout_per_domain: 120,
          max_concurrent: 3
        });
        result = response.data;
      }

      setWaybackResults(result);
      
      const totalUrls = result.total_urls || result.url_count || 0;
      const interestingCount = result.total_interesting || result.interesting_count || 0;
      
      toast({
        title: 'Wayback Scan Complete',
        description: `Found ${totalUrls} URLs, ${interestingCount} potentially interesting`,
      });
    } catch (error: any) {
      console.error('Wayback error:', error);
      toast({
        title: 'Wayback Scan Failed',
        description: error.response?.data?.detail || error.message || 'Failed to run wayback scan',
        variant: 'destructive',
      });
    } finally {
      setWaybackRunning(false);
    }
  };

  const downloadWaybackResults = () => {
    if (!waybackResults) return;
    
    const data = {
      timestamp: new Date().toISOString(),
      mode: waybackMode,
      ...waybackResults
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wayback-${waybackMode === 'single' ? domain : `org-${selectedOrg}`}-${Date.now()}.json`;
    a.click();
  };

  const discoveryMethods = [
    { name: 'Certificate Transparency (crt.sh)', key: 'crtsh', description: 'SSL/TLS certificate logs', icon: '🔐', free: true },
    { name: 'crt.name Index', key: 'crt_name', description: 'Aggregated CT/DNS subdomain index + first-seen', icon: '📇', free: true },
    { name: 'Shodan CTL', key: 'shodan_ctl', description: 'Shodan CT hostname mirror', icon: '🛰️', free: true },
    { name: 'Wayback Machine', key: 'wayback', description: 'Historical web archives', icon: '📜', free: true },
    { name: 'RapidDNS', key: 'rapiddns', description: 'DNS enumeration', icon: '🌐', free: true },
    { name: 'Microsoft 365', key: 'm365', description: 'Federated tenant domains', icon: '☁️', free: true },
    { name: 'AlienVault OTX', key: 'otx', description: 'Threat intelligence DNS', icon: '👽', free: true },
    { name: 'VirusTotal', key: 'virustotal', description: 'VT subdomain database', icon: '🦠', free: false },
    { name: 'WhoisXML API', key: 'whoisxml', description: 'IP ranges by org name', icon: '📋', free: false },
    { name: 'Whoxy', key: 'whoxy', description: 'Reverse WHOIS by email', icon: '🔍', free: false },
    { name: 'Chained Subdomain Enum', key: 'chained', description: 'Auto-enum on discovered domains', icon: '🔄', free: true },
  ];

  const getSourceStatus = (sourceKey: string) => {
    if (!discoveryResults) return null;
    return discoveryResults.source_results.find(s => s.source.toLowerCase().includes(sourceKey));
  };

  const totalWaybackUrls = waybackResults?.total_urls || waybackResults?.url_count || 0;
  const interestingCount = waybackResults?.total_interesting || waybackResults?.interesting_count || 0;

  return (
    <MainLayout>
      <Header title="Asset Discovery" subtitle="Discover subdomains, IPs, historical URLs, and more from multiple sources" />

      <div className="p-6 space-y-6">
        {/* Organization & Domain Selection - Shared */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5" />
              Discovery Configuration
            </CardTitle>
            <CardDescription>
              Select an organization and target domain to begin discovery
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Organization *</Label>
                <Select value={selectedOrg} onValueChange={setSelectedOrg}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select organization" />
                  </SelectTrigger>
                  <SelectContent>
                    {organizations.map((org) => (
                      <SelectItem key={org.id} value={org.id.toString()}>
                        {org.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Target Domain *</Label>
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Main Tabs */}
        <Tabs value={activeMainTab} onValueChange={setActiveMainTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-3 lg:w-[600px]">
            <TabsTrigger value="external" className="flex items-center gap-2">
              <Search className="h-4 w-4" />
              External Discovery
            </TabsTrigger>
            <TabsTrigger value="wayback" className="flex items-center gap-2">
              <History className="h-4 w-4" />
              Wayback URLs
            </TabsTrigger>
            <TabsTrigger value="app-structure" className="flex items-center gap-2">
              <FolderTree className="h-4 w-4" />
              App Structure
            </TabsTrigger>
          </TabsList>

          {/* External Discovery Tab */}
          <TabsContent value="external" className="space-y-6">
            {/* Run Discovery Card */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  External Asset Discovery
                </CardTitle>
                <CardDescription>
                  Discover subdomains, IPs, and related domains using certificate transparency, DNS, and threat intelligence sources
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Button
                    onClick={handleRunDiscovery}
                    disabled={discoveryRunning || !selectedOrg || !domain}
                    className="flex-1 md:flex-none"
                  >
                    {discoveryRunning ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Discovering...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Discovery
                      </>
                    )}
                  </Button>
                </div>

                {/* Advanced Options Toggle */}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="text-muted-foreground"
                >
                  {showAdvanced ? <ChevronUp className="h-4 w-4 mr-2" /> : <ChevronDown className="h-4 w-4 mr-2" />}
                  Advanced Options
                </Button>

                {showAdvanced && (
                  <div className="space-y-4 p-4 bg-muted/50 rounded-lg">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div className="flex items-center gap-2">
                        <Switch checked={includeFree} onCheckedChange={setIncludeFree} />
                        <Label>Free Sources</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={includePaid} onCheckedChange={setIncludePaid} />
                        <Label>Paid Sources</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={createAssets} onCheckedChange={setCreateAssets} />
                        <Label>Create Assets</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={enumerateDiscoveredDomains} onCheckedChange={setEnumerateDiscoveredDomains} />
                        <Label>Auto-Enumerate Subdomains</Label>
                      </div>
                    </div>
                    
                    {enumerateDiscoveredDomains && (
                      <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                        <p className="text-sm text-green-400 font-medium">🔄 Chained Subdomain Enumeration Enabled</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          When domains are discovered via Whoxy or other sources, subdomain enumeration (crt.sh, brute-force) 
                          will automatically run on up to {maxDomainsToEnumerate} discovered domains.
                        </p>
                      </div>
                    )}

                    <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg mb-4">
                      <p className="text-xs text-blue-400">
                        These settings override your organization defaults from <a href="/settings" className="underline">Settings</a>. 
                        Leave empty to use saved defaults.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label className="flex items-center gap-2">
                        <Building2 className="h-4 w-4" />
                        Organization Names (WhoisXML IP Range Discovery)
                      </Label>
                      <div className="flex gap-2">
                        <Input
                          placeholder="e.g., Acme Corporation (leave empty to use defaults)"
                          value={newOrgName}
                          onChange={(e) => setNewOrgName(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && addOrgName()}
                        />
                        <Button onClick={addOrgName} variant="outline" size="icon">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {orgNames.map((name) => (
                          <Badge key={name} variant="secondary" className="flex items-center gap-1">
                            {name}
                            <button onClick={() => removeOrgName(name)} className="ml-1 hover:text-destructive">
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label className="flex items-center gap-2">
                        <Mail className="h-4 w-4" />
                        Registration Emails (Whoxy Reverse WHOIS)
                      </Label>
                      <div className="flex gap-2">
                        <Input
                          placeholder="e.g., domains@company.com (leave empty to use defaults)"
                          value={newRegEmail}
                          onChange={(e) => setNewRegEmail(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && addRegEmail()}
                        />
                        <Button onClick={addRegEmail} variant="outline" size="icon">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {regEmails.map((email) => (
                          <Badge key={email} variant="secondary" className="flex items-center gap-1">
                            {email}
                            <button onClick={() => removeRegEmail(email)} className="ml-1 hover:text-destructive">
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* Technology Fingerprinting */}
                    <div className="border-t pt-4 mt-4">
                      <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
                        <Settings className="h-4 w-4" />
                        Technology Fingerprinting (Wappalyzer)
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Automatically scan all discovered domains and subdomains to identify web technologies (CMS, frameworks, servers, etc.) and add technology tags.
                      </p>
                      
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Switch 
                              checked={runTechScan} 
                              onCheckedChange={setRunTechScan} 
                              id="tech-scan"
                            />
                            <Label htmlFor="tech-scan">Run Technology Scan on All Hosts</Label>
                          </div>
                        </div>
                        
                        {runTechScan && (
                          <div className="space-y-2">
                            <Label>Maximum Hosts to Scan</Label>
                            <Input
                              type="number"
                              value={maxTechScan}
                              onChange={(e) => setMaxTechScan(parseInt(e.target.value) || 500)}
                              min={1}
                              max={2000}
                            />
                            <p className="text-xs text-muted-foreground">
                              Hosts are scanned in batches in the background. Each host is probed for technologies like WordPress, Nginx, React, etc.
                            </p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Screenshot Capture */}
                    <div className="border-t pt-4 mt-4">
                      <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
                        <Camera className="h-4 w-4" />
                        Screenshot Capture (EyeWitness)
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Automatically capture screenshots of all discovered domains and subdomains for visual monitoring and change detection.
                      </p>
                      
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Switch 
                              checked={runScreenshots} 
                              onCheckedChange={setRunScreenshots} 
                              id="screenshots"
                            />
                            <Label htmlFor="screenshots">Capture Screenshots on All Hosts</Label>
                          </div>
                        </div>
                        
                        {runScreenshots && (
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <Label>Maximum Hosts to Screenshot</Label>
                              <Input
                                type="number"
                                value={maxScreenshots}
                                onChange={(e) => setMaxScreenshots(parseInt(e.target.value) || 200)}
                                min={1}
                                max={1000}
                              />
                            </div>
                            <div className="space-y-2">
                              <Label>Screenshot Timeout (seconds)</Label>
                              <Input
                                type="number"
                                value={screenshotTimeout}
                                onChange={(e) => setScreenshotTimeout(parseInt(e.target.value) || 30)}
                                min={5}
                                max={120}
                              />
                              <p className="text-xs text-muted-foreground">
                                Screenshots are captured in batches in the background. View results on the Screenshots page.
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Common Crawl Comprehensive Search */}
                    <div className="border-t pt-4 mt-4">
                      <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
                        <Radar className="h-4 w-4" />
                        Common Crawl Deep Search
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Search Common Crawl's billions of URLs for organization-related domains.
                        Use this to find domains like org.*, *org*, and keyword matches like *rockwell*.
                      </p>
                      <div className="p-2 bg-green-500/10 border border-green-500/30 rounded-lg mb-3">
                        <p className="text-xs text-green-400">
                          ✓ Keywords are automatically saved when you run discovery and will be pre-filled next time.
                        </p>
                      </div>
                      
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label>Organization Name (for TLD search)</Label>
                          <Input
                            placeholder="e.g., rockwellautomation (finds rockwellautomation.net, .io, .cloud...)"
                            value={ccOrgName}
                            onChange={(e) => setCcOrgName(e.target.value)}
                          />
                          <p className="text-xs text-muted-foreground">
                            Searches for <code>{ccOrgName || 'orgname'}.*</code> across all TLDs
                          </p>
                        </div>
                        
                        <div className="space-y-2">
                          <Label>Keywords (for wildcard search)</Label>
                          <div className="flex gap-2">
                            <Input
                              placeholder="e.g., rockwell (finds *rockwell* domains)"
                              value={newCcKeyword}
                              onChange={(e) => setNewCcKeyword(e.target.value)}
                              onKeyDown={(e) => e.key === 'Enter' && addCcKeyword()}
                            />
                            <Button onClick={addCcKeyword} variant="outline" size="icon">
                              <Plus className="h-4 w-4" />
                            </Button>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Each keyword searches for <code>*keyword*</code> pattern in domain names
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {ccKeywords.map((keyword) => (
                              <Badge key={keyword} variant="secondary" className="flex items-center gap-1">
                                *{keyword}*
                                <button onClick={() => removeCcKeyword(keyword)} className="ml-1 hover:text-destructive">
                                  <X className="h-3 w-3" />
                                </button>
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* SNI IP Ranges - Cloud Asset Discovery */}
                    <div className="p-4 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 rounded-lg border border-cyan-500/20">
                      <h4 className="text-sm font-medium flex items-center gap-2 mb-2">
                        <Cloud className="h-4 w-4 text-cyan-500" />
                        SNI IP Ranges - Cloud Asset Discovery
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Discover cloud-hosted assets by searching SSL/TLS certificate data from AWS, GCP, Azure, Oracle, and DigitalOcean IP ranges.
                        Source: <a href="https://kaeferjaeger.gay/?dir=sni-ip-ranges" target="_blank" rel="noopener" className="text-primary underline">kaeferjaeger.gay</a>
                      </p>
                      <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg mb-3">
                        <p className="text-xs text-cyan-400">
                          ✓ SNI keywords are automatically saved when you run discovery and will be pre-filled next time.
                        </p>
                      </div>
                      
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <Label htmlFor="sni-discovery" className="text-sm font-medium">Enable Cloud Asset Discovery</Label>
                            <p className="text-xs text-muted-foreground">
                              Searches cloud provider IP ranges for your organization's SSL certificates
                            </p>
                          </div>
                          <Switch
                            checked={includeSniDiscovery}
                            onCheckedChange={setIncludeSniDiscovery}
                            id="sni-discovery"
                          />
                        </div>
                        
                        {includeSniDiscovery && (
                          <div className="space-y-2">
                            <Label>Additional Keywords (optional)</Label>
                            <div className="flex gap-2">
                              <Input
                                placeholder="e.g., rockwell, allen-bradley (finds additional cloud assets)"
                                value={newSniKeyword}
                                onChange={(e) => setNewSniKeyword(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && addSniKeyword()}
                              />
                              <Button onClick={addSniKeyword} variant="outline" size="icon">
                                <Plus className="h-4 w-4" />
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Keywords to search in addition to the organization name and primary domain
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {sniKeywords.map((keyword) => (
                                <Badge key={keyword} variant="secondary" className="flex items-center gap-1 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300">
                                  {keyword}
                                  <button onClick={() => removeSniKeyword(keyword)} className="ml-1 hover:text-destructive">
                                    <X className="h-3 w-3" />
                                  </button>
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-muted-foreground">
                      💡 Configure API keys and default org names/emails in <a href="/settings" className="text-primary underline">Settings</a>. 
                      Discovery may take several minutes when using Common Crawl or SNI scanning.
                    </p>
                  </div>
                )}

                {discoveryRunning && (
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-3">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                      <div>
                        <p className="font-medium">Discovery in progress...</p>
                        <p className="text-sm text-muted-foreground">
                          Querying crt.sh, Wayback, RapidDNS, OTX, and other sources...
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          This may take 1-5 minutes depending on enabled sources. Do not close this page.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Reverse-Lookup Pivots Preview (credit-free) */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Reverse-Lookup Pivots
                  <Badge variant="secondary" className="text-xs font-normal">Preview · no credits</Badge>
                </CardTitle>
                <CardDescription>
                  See exactly which nameservers, mail servers, and WHOIS terms reverse discovery
                  would pivot on for this organization — <span className="font-medium">before</span> any run
                  spends provider credits.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="outline"
                    onClick={handleLoadReversePivots}
                    disabled={reversePivotsLoading || !selectedOrg}
                  >
                    {reversePivotsLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Building plan...
                      </>
                    ) : (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2" />
                        {reversePivots ? 'Refresh Pivot Plan' : 'Preview Pivots'}
                      </>
                    )}
                  </Button>
                  {reversePivots && (
                    <span className="text-xs text-muted-foreground">
                      Sampled {reversePivots.sampled_assets} in-scope asset{reversePivots.sampled_assets === 1 ? '' : 's'} ·
                      recurrence threshold {reversePivots.min_shared_threshold}
                    </span>
                  )}
                </div>

                {reversePivots && (
                  <div className="space-y-5">
                    {/* Providers available */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm text-muted-foreground">Providers:</span>
                      {reversePivots.providers_available.length > 0 ? (
                        reversePivots.providers_available.map((p) => (
                          <Badge key={p} variant="default" className="bg-green-600 text-xs">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            {p}
                          </Badge>
                        ))
                      ) : (
                        <Badge variant="destructive" className="text-xs">
                          <XCircle className="h-3 w-3 mr-1" />
                          None configured — add keys in Settings
                        </Badge>
                      )}
                      {reversePivots.primary_domain && (
                        <Badge variant="outline" className="text-xs">
                          apex: {reversePivots.primary_domain}
                        </Badge>
                      )}
                    </div>

                    {/* Nameserver + Mailserver pivots (selectable) */}
                    {(reversePivots.nameserver_pivots.length > 0 || reversePivots.mailserver_pivots.length > 0) && (
                      <p className="text-xs text-muted-foreground -mb-2">
                        Check the pivots you trust, then run reverse discovery on the selection below.
                      </p>
                    )}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                          <Server className="h-4 w-4" />
                          Nameserver Pivots ({selectedNsPivots.size}/{reversePivots.nameserver_pivots.length})
                        </h4>
                        {reversePivots.nameserver_pivots.length > 0 ? (
                          <div className="space-y-1 max-h-64 overflow-y-auto">
                            {reversePivots.nameserver_pivots.map((p) => (
                              <label
                                key={p.host}
                                className="flex items-center justify-between gap-2 p-2 bg-muted/50 rounded text-sm cursor-pointer hover:bg-muted"
                              >
                                <div className="flex items-center gap-2 min-w-0">
                                  <Checkbox
                                    checked={selectedNsPivots.has(p.host)}
                                    onCheckedChange={() => toggleNsPivot(p.host)}
                                  />
                                  <span className="font-mono truncate" title={p.host}>{p.host}</span>
                                </div>
                                <div className="flex items-center gap-1 flex-shrink-0">
                                  <Badge variant="secondary" className="text-xs">{p.seen_on_assets} assets</Badge>
                                  {p.sources.map((s) => (
                                    <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
                                  ))}
                                </div>
                              </label>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground">No org-specific nameserver pivots detected.</p>
                        )}
                      </div>

                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                          <Mail className="h-4 w-4" />
                          Mailserver Pivots ({selectedMxPivots.size}/{reversePivots.mailserver_pivots.length})
                        </h4>
                        {reversePivots.mailserver_pivots.length > 0 ? (
                          <div className="space-y-1 max-h-64 overflow-y-auto">
                            {reversePivots.mailserver_pivots.map((p) => (
                              <label
                                key={p.host}
                                className="flex items-center justify-between gap-2 p-2 bg-muted/50 rounded text-sm cursor-pointer hover:bg-muted"
                              >
                                <div className="flex items-center gap-2 min-w-0">
                                  <Checkbox
                                    checked={selectedMxPivots.has(p.host)}
                                    onCheckedChange={() => toggleMxPivot(p.host)}
                                  />
                                  <span className="font-mono truncate" title={p.host}>{p.host}</span>
                                </div>
                                <div className="flex items-center gap-1 flex-shrink-0">
                                  <Badge variant="secondary" className="text-xs">{p.seen_on_assets} assets</Badge>
                                  {p.sources.map((s) => (
                                    <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
                                  ))}
                                </div>
                              </label>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground">No org-specific mailserver pivots detected.</p>
                        )}
                      </div>
                    </div>

                    {/* Run on selected pivots (spends credits) */}
                    {(reversePivots.nameserver_pivots.length > 0 || reversePivots.mailserver_pivots.length > 0) && (
                      <div className="flex flex-wrap items-center gap-3 border-t pt-4">
                        <Button
                          onClick={handleRunReverseDiscovery}
                          disabled={
                            reverseRunning ||
                            reversePivots.providers_available.length === 0 ||
                            (selectedNsPivots.size === 0 && selectedMxPivots.size === 0)
                          }
                        >
                          {reverseRunning ? (
                            <>
                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              Running reverse discovery...
                            </>
                          ) : (
                            <>
                              <Play className="h-4 w-4 mr-2" />
                              Run on {selectedNsPivots.size + selectedMxPivots.size} Selected Pivot{selectedNsPivots.size + selectedMxPivots.size === 1 ? '' : 's'}
                            </>
                          )}
                        </Button>
                        <div className="flex items-center gap-2">
                          <Switch checked={reverseEnumerate} onCheckedChange={setReverseEnumerate} id="reverse-enumerate" />
                          <Label htmlFor="reverse-enumerate" className="text-sm">Auto-enumerate subdomains</Label>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {createAssets
                            ? 'Discovered domains are created as assets'
                            : 'Preview only — enable "Create Assets" in Advanced Options to import'}
                          {reverseEnumerate ? `, then subdomains are enumerated (up to ${maxDomainsToEnumerate} domains)` : ''}
                          . This step spends provider credits.
                        </span>
                      </div>
                    )}

                    {/* Reverse run results */}
                    {reverseRunResult && (
                      <div className="border-t pt-4 space-y-3">
                        <h4 className="font-medium text-sm flex items-center gap-2">
                          <CheckCircle className="h-4 w-4 text-green-500" />
                          Reverse Discovery Results
                        </h4>
                        <div className="flex flex-wrap gap-2 text-sm">
                          <Badge variant="secondary">{reverseRunResult.total_domains_found} domains found</Badge>
                          <Badge variant="default" className="bg-green-600">{reverseRunResult.assets_created} domain assets</Badge>
                          {reverseRunResult.subdomains_enumerated > 0 && (
                            <Badge variant="default" className="bg-blue-600">
                              {reverseRunResult.subdomains_enumerated} subdomains ({reverseRunResult.subdomain_assets_created} new)
                            </Badge>
                          )}
                          {reverseRunResult.providers.map((p) => (
                            <Badge key={p} variant="outline">{p}</Badge>
                          ))}
                          <Badge variant="outline">{reverseRunResult.elapsed_time.toFixed(1)}s</Badge>
                        </div>
                        {reverseRunResult.domains.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto">
                            {reverseRunResult.domains.slice(0, 150).map((d) => (
                              <div key={d} className="p-2 bg-muted rounded text-sm font-mono truncate" title={d}>{d}</div>
                            ))}
                            {reverseRunResult.domains.length > 150 && (
                              <div className="p-2 text-muted-foreground text-sm col-span-full">
                                ...and {reverseRunResult.domains.length - 150} more
                              </div>
                            )}
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground">
                            No domains returned for the selected pivots.
                            {reverseRunResult.error ? ` (${reverseRunResult.error})` : ''}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Reverse-WHOIS preview */}
                    {reversePivots.reverse_whois_preview.length > 0 && (
                      <div>
                        <h4 className="font-medium text-sm mb-2 flex items-center gap-2">
                          <Building2 className="h-4 w-4" />
                          Reverse-WHOIS Estimates
                        </h4>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Search Term</TableHead>
                              <TableHead className="text-right">Est. Domains Returned</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {reversePivots.reverse_whois_preview.map((w) => (
                              <TableRow key={w.term}>
                                <TableCell className="font-mono text-sm">{w.term}</TableCell>
                                <TableCell className="text-right">
                                  {w.would_return_domains < 0 ? (
                                    <Badge variant="outline" className="text-xs">unknown</Badge>
                                  ) : (
                                    <Badge
                                      variant={w.would_return_domains > 5000 ? 'destructive' : 'secondary'}
                                      className="text-xs"
                                    >
                                      {w.would_return_domains.toLocaleString()}
                                    </Badge>
                                  )}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                        <p className="text-xs text-muted-foreground mt-2">
                          Estimates come from the provider&apos;s free preview mode. High counts (&gt;5,000)
                          usually mean a shared/registrar term that will pull in unrelated domains — refine before running.
                        </p>
                      </div>
                    )}

                    {reversePivots.note && (
                      <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                        <p className="text-xs text-blue-400">{reversePivots.note}</p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Discovery Results */}
            {discoveryResults && (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-8 w-8 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_subdomains}</p>
                          <p className="text-sm text-muted-foreground">Subdomains</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Server className="h-8 w-8 text-green-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_ips}</p>
                          <p className="text-sm text-muted-foreground">IP Addresses</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Network className="h-8 w-8 text-purple-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_cidrs}</p>
                          <p className="text-sm text-muted-foreground">IP Ranges</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Shield className="h-8 w-8 text-orange-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.assets_created}</p>
                          <p className="text-sm text-muted-foreground">Assets Created</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Clock className="h-8 w-8 text-gray-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_elapsed_time.toFixed(1)}s</p>
                          <p className="text-sm text-muted-foreground">Total Time</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Source Results */}
                <Card>
                  <CardHeader>
                    <div className="flex justify-between items-center">
                      <CardTitle>Source Results</CardTitle>
                      <Button variant="outline" size="sm" onClick={downloadDiscoveryResults}>
                        <Download className="h-4 w-4 mr-2" />
                        Export JSON
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Source</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Subdomains</TableHead>
                          <TableHead className="text-right">IPs</TableHead>
                          <TableHead className="text-right">CIDRs</TableHead>
                          <TableHead className="text-right">Time</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {discoveryResults.source_results.map((source) => (
                          <TableRow key={source.source}>
                            <TableCell className="font-medium">{source.source}</TableCell>
                            <TableCell>
                              {source.success ? (
                                <Badge variant="default" className="bg-green-600">
                                  <CheckCircle className="h-3 w-3 mr-1" />
                                  Success
                                </Badge>
                              ) : (
                                <Badge variant="destructive">
                                  <XCircle className="h-3 w-3 mr-1" />
                                  {source.error?.substring(0, 30) || 'Failed'}
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-right">{source.subdomains_found}</TableCell>
                            <TableCell className="text-right">{source.ips_found}</TableCell>
                            <TableCell className="text-right">{source.cidrs_found}</TableCell>
                            <TableCell className="text-right">{source.elapsed_time.toFixed(2)}s</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Discovered Assets */}
                <Card>
                  <CardHeader>
                    <CardTitle>Discovered Assets</CardTitle>
                    <div className="flex gap-2 mt-2">
                      <Button variant={discoveryActiveTab === 'subdomains' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('subdomains')}>
                        Subdomains ({discoveryResults.subdomains.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'ips' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('ips')}>
                        IPs ({discoveryResults.ip_addresses.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'domains' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('domains')}>
                        Domains ({discoveryResults.domains.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'ranges' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('ranges')}>
                        Ranges ({discoveryResults.ip_ranges.length})
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-96 overflow-y-auto">
                      {discoveryActiveTab === 'subdomains' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                          {discoveryResults.subdomains.slice(0, 100).map((subdomain) => (
                            <div key={subdomain} className="p-2 bg-muted rounded text-sm font-mono">{subdomain}</div>
                          ))}
                          {discoveryResults.subdomains.length > 100 && (
                            <div className="p-2 text-muted-foreground text-sm col-span-full">
                              ...and {discoveryResults.subdomains.length - 100} more
                            </div>
                          )}
                        </div>
                      )}
                      {discoveryActiveTab === 'ips' && (
                        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-2">
                          {discoveryResults.ip_addresses.slice(0, 100).map((ip) => (
                            <div key={ip} className="p-2 bg-muted rounded text-sm font-mono">{ip}</div>
                          ))}
                          {discoveryResults.ip_addresses.length > 100 && (
                            <div className="p-2 text-muted-foreground text-sm col-span-full">
                              ...and {discoveryResults.ip_addresses.length - 100} more
                            </div>
                          )}
                        </div>
                      )}
                      {discoveryActiveTab === 'domains' && (
                        discoveryResults.domains.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {discoveryResults.domains.map((d) => (
                              <div key={d} className="p-2 bg-muted rounded text-sm font-mono">{d}</div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-muted-foreground">No additional domains discovered</p>
                        )
                      )}
                      {discoveryActiveTab === 'ranges' && (
                        discoveryResults.ip_ranges.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {discoveryResults.ip_ranges.map((range) => (
                              <div key={range} className="p-2 bg-muted rounded text-sm font-mono">{range}</div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-muted-foreground">No IP ranges discovered (requires WhoisXML API key + organization names)</p>
                        )
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Discovery Sources Grid */}
            <div>
              <h2 className="text-lg font-semibold mb-4">Available Discovery Sources</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {discoveryMethods.map((method) => {
                  const status = getSourceStatus(method.key);
                  return (
                    <Card key={method.name} className="hover:border-primary/50 transition-colors">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="text-2xl mb-2">{method.icon}</div>
                          <div className="flex gap-1">
                            {status && (
                              status.success ? (
                                <Badge variant="default" className="bg-green-600 text-xs">
                                  ✓ {status.subdomains_found + status.ips_found + status.cidrs_found}
                                </Badge>
                              ) : (
                                <Badge variant="destructive" className="text-xs">✗</Badge>
                              )
                            )}
                            <Badge variant={method.free ? 'secondary' : 'outline'} className="text-xs">
                              {method.free ? 'Free' : <Key className="h-3 w-3" />}
                            </Badge>
                          </div>
                        </div>
                        <h3 className="font-medium text-sm">{method.name}</h3>
                        <p className="text-xs text-muted-foreground mt-1">{method.description}</p>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </div>
          </TabsContent>

          {/* Wayback URLs Tab */}
          <TabsContent value="wayback" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="h-5 w-5" />
                  Wayback URL Scanner
                </CardTitle>
                <CardDescription>
                  Fetch all historical URLs from the Wayback Machine to find old endpoints, APIs, and sensitive files
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Button variant={waybackMode === 'single' ? 'default' : 'outline'} onClick={() => setWaybackMode('single')}>
                    Single Domain
                  </Button>
                  <Button variant={waybackMode === 'organization' ? 'default' : 'outline'} onClick={() => setWaybackMode('organization')}>
                    Organization Assets
                  </Button>
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <Switch checked={includeSubdomains} onCheckedChange={setIncludeSubdomains} />
                    <Label>Include Subdomains</Label>
                  </div>

                  <Button
                    onClick={handleRunWayback}
                    disabled={waybackRunning || (waybackMode === 'single' ? !domain : !selectedOrg)}
                  >
                    {waybackRunning ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Fetching...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Fetch URLs
                      </>
                    )}
                  </Button>
                </div>

                {waybackRunning && (
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-3">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                      <div>
                        <p className="font-medium">Fetching historical URLs...</p>
                        <p className="text-sm text-muted-foreground">This may take a while for domains with many URLs.</p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Wayback Results */}
            {waybackResults && (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Link className="h-8 w-8 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{totalWaybackUrls.toLocaleString()}</p>
                          <p className="text-sm text-muted-foreground">Total URLs</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <FileWarning className="h-8 w-8 text-orange-500" />
                        <div>
                          <p className="text-2xl font-bold">{interestingCount.toLocaleString()}</p>
                          <p className="text-sm text-muted-foreground">Interesting</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <FileText className="h-8 w-8 text-green-500" />
                        <div>
                          <p className="text-2xl font-bold">{(waybackResults.unique_paths_count || waybackResults.unique_paths?.length || 0).toLocaleString()}</p>
                          <p className="text-sm text-muted-foreground">Unique Paths</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Clock className="h-8 w-8 text-gray-500" />
                        <div>
                          <p className="text-2xl font-bold">{(waybackResults.elapsed_time || 0).toFixed(1)}s</p>
                          <p className="text-sm text-muted-foreground">Elapsed</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Domain Results (organization mode) */}
                {waybackResults.domain_results && waybackResults.domain_results.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Domain Results</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Domain</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead className="text-right">URLs</TableHead>
                            <TableHead className="text-right">Interesting</TableHead>
                            <TableHead className="text-right">Time</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {waybackResults.domain_results.map((dr) => (
                            <TableRow key={dr.domain}>
                              <TableCell className="font-mono text-sm">{dr.domain}</TableCell>
                              <TableCell>
                                {dr.success ? (
                                  <Badge variant="default" className="bg-green-600">
                                    <CheckCircle className="h-3 w-3 mr-1" />
                                    Success
                                  </Badge>
                                ) : (
                                  <Badge variant="destructive">
                                    <XCircle className="h-3 w-3 mr-1" />
                                    {dr.error?.substring(0, 20) || 'Failed'}
                                  </Badge>
                                )}
                              </TableCell>
                              <TableCell className="text-right">{dr.url_count}</TableCell>
                              <TableCell className="text-right">{dr.interesting_count}</TableCell>
                              <TableCell className="text-right">{dr.elapsed_time.toFixed(1)}s</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                )}

                {/* File Extensions */}
                {Object.keys(waybackResults.file_extensions || {}).length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>File Extensions Found</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(waybackResults.file_extensions).slice(0, 30).map(([ext, count]) => (
                          <Badge key={ext} variant="secondary" className="flex items-center gap-1">
                            {ext}
                            <span className="text-xs bg-muted px-1 rounded">{count}</span>
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* URLs */}
                <Card>
                  <CardHeader>
                    <div className="flex justify-between items-center">
                      <CardTitle>Discovered URLs</CardTitle>
                      <Button variant="outline" size="sm" onClick={downloadWaybackResults}>
                        <Download className="h-4 w-4 mr-2" />
                        Export JSON
                      </Button>
                    </div>
                    <div className="flex gap-2 mt-2">
                      <Button variant={waybackActiveTab === 'interesting' ? 'default' : 'outline'} size="sm" onClick={() => setWaybackActiveTab('interesting')}>
                        <AlertTriangle className="h-4 w-4 mr-1" />
                        Interesting ({waybackResults.interesting_urls?.length || 0})
                      </Button>
                      <Button variant={waybackActiveTab === 'all' ? 'default' : 'outline'} size="sm" onClick={() => setWaybackActiveTab('all')}>
                        All URLs ({waybackResults.urls?.length || 0})
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-96 overflow-y-auto space-y-1">
                      {waybackActiveTab === 'interesting' && (
                        waybackResults.interesting_urls?.length > 0 ? (
                          waybackResults.interesting_urls.slice(0, 200).map((url, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                              <a href={url} target="_blank" rel="noopener noreferrer" className="flex-1 truncate text-primary hover:underline">
                                {url}
                              </a>
                              <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            </div>
                          ))
                        ) : (
                          <p className="text-muted-foreground">No interesting URLs found</p>
                        )
                      )}
                      {waybackActiveTab === 'all' && (
                        waybackResults.urls?.length > 0 ? (
                          waybackResults.urls.slice(0, 500).map((url, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                              <a href={url} target="_blank" rel="noopener noreferrer" className="flex-1 truncate text-primary hover:underline">
                                {url}
                              </a>
                              <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            </div>
                          ))
                        ) : (
                          <p className="text-muted-foreground">No URLs found</p>
                        )
                      )}
                      {((waybackActiveTab === 'interesting' && (waybackResults.interesting_urls?.length || 0) > 200) ||
                        (waybackActiveTab === 'all' && (waybackResults.urls?.length || 0) > 500)) && (
                        <p className="text-sm text-muted-foreground p-2">
                          Showing first {waybackActiveTab === 'interesting' ? 200 : 500} URLs. Export JSON for full list.
                        </p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Help Section */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">About Wayback URLs</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground space-y-2">
                <p>
                  <strong>What is waybackurls?</strong> Fetches all URLs the Wayback Machine has archived for a domain.
                </p>
                <p>
                  <strong>Why is this useful?</strong> Historical URLs can reveal:
                </p>
                <ul className="list-disc pl-6 space-y-1">
                  <li>Old/forgotten endpoints that may still be accessible</li>
                  <li>API endpoints with parameters</li>
                  <li>Backup files, config files, and sensitive data</li>
                  <li>Admin panels and login pages</li>
                </ul>
                <p>
                  <strong>Interesting patterns:</strong> URLs containing admin, api, backup, config, .sql, .bak, .env are highlighted.
                </p>
              </CardContent>
            </Card>
          </TabsContent>

          {/* App Structure Tab */}
          <TabsContent value="app-structure" className="space-y-6">
            <AppStructureContent />
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}
