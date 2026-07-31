'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
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
  ArrowLeft,
  RefreshCw,
  Loader2,
  Globe,
  Server,
  Shield,
  AlertTriangle,
  MapPin,
  Network,
  Clock,
  Eye,
  EyeOff,
  Lock,
  ExternalLink,
  Copy,
  CheckCircle,
  Cpu,
  AlertCircle,
  Tag,
  Camera,
  ImageIcon,
  Activity,
  FileText,
  Settings,
  Monitor,
  Wifi,
  Database,
  Calendar,
  Hash,
  Mail,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Search,
  Code,
  Link2,
  FolderSearch,
  ScanLine,
  CheckCircle2,
  MessageSquare,
  ChevronDown,
  Plus,
  FileDown,
  Radar,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import { ApplicationMap } from '@/components/assets/ApplicationMap';
import { DiscoveryPath } from '@/components/assets/DiscoveryPath';
import { AddFindingDialog } from '@/components/findings/AddFindingDialog';

interface Technology {
  name: string;
  slug: string;
  categories: string[];
  version?: string;
}

interface PortService {
  id: number;
  port: number;
  protocol: string;
  service?: string;
  product?: string;
  version?: string;
  state: string;
  is_ssl: boolean;
  is_risky: boolean;
  port_string: string;
  scanned_ip?: string;  // IP address where port was found
  // Nmap verification fields
  verified?: boolean;
  verified_at?: string;
  verified_state?: string;  // open, filtered, closed from nmap
  verification_scanner?: string;
}

interface DiscoveryStep {
  step: number;
  source: string;
  match_type?: string;
  match_value?: string;
  query_domain?: string;
  timestamp?: string;
  confidence?: number;
}

interface Screenshot {
  id: number;
  url: string;
  status: string;
  file_path?: string;
  thumbnail_path?: string;
  http_status?: number;
  page_title?: string;
  captured_at: string;
  has_changed?: boolean;
  change_percentage?: number;
}

interface Vulnerability {
  id: number;
  title: string;
  name?: string;
  description?: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  references?: string[];
  asset_id: number;
  scan_id?: number;
  detected_by?: string;
  template_id?: string;
  matcher_name?: string;
  status: string;
  assigned_to?: string;
  evidence?: string;
  proof_of_concept?: string;
  remediation?: string;
  remediation_deadline?: string;
  first_detected: string;
  last_detected: string;
  resolved_at?: string;
  tags?: string[];
  host?: string;
  matched_at?: string;
}

interface Asset {
  id: number;
  name: string;
  asset_type: string;
  value: string;
  root_domain?: string;
  live_url?: string;
  organization_id: number;
  parent_id?: number;
  status: string;
  description?: string;
  tags: string[];
  metadata_: Record<string, any>;
  discovery_source?: string;
  discovery_chain?: DiscoveryStep[];
  association_reason?: string;
  association_confidence?: number;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  criticality: string;
  is_monitored: boolean;
  is_live?: boolean;
  http_status?: number;
  http_title?: string;
  dns_records: Record<string, any>;
  ip_address?: string;
  ip_addresses?: string[];
  ip_history?: Array<{ip: string; first_seen: string; last_seen: string; removed_at?: string}>;
  latitude?: string;
  longitude?: string;
  city?: string;
  country?: string;
  country_code?: string;
  region?: string;
  isp?: string;
  in_scope: boolean;
  is_owned: boolean;
  netblock_id?: number;
  asn?: string;
  // Hosting classification (for IP assets)
  hosting_type?: string;  // owned, cloud, cdn, third_party, unknown
  hosting_provider?: string;  // azure, aws, gcp, cloudflare, etc.
  is_ephemeral_ip?: boolean;  // True if IP could change
  resolved_from?: string;  // Domain this IP was resolved from
  technologies: Technology[];
  port_services: PortService[];
  open_ports_count: number;
  risky_ports_count: number;
  created_at: string;
  updated_at: string;
  // Risk and Criticality scores
  acs_score?: number;
  acs_drivers?: Record<string, any>;
  ars_score?: number;
  system_type?: string;
  operating_system?: string;
  device_class?: string;
  device_subclass?: string;
  is_public?: boolean;
  is_licensed?: boolean;
  last_scan_id?: string;
  last_scan_name?: string;
  last_scan_date?: string;
  last_scan_target?: string;
  last_authenticated_scan_status?: string;
  vulnerability_count?: number;
  critical_vuln_count?: number;
  high_vuln_count?: number;
  medium_vuln_count?: number;
  low_vuln_count?: number;
  // Discovered endpoints and parameters (from Katana, ParamSpider)
  endpoints?: string[];
  parameters?: string[];
  js_files?: string[];
  // Login portals / discovered paths on this host (from login portal scan)
  login_portals?: Array<{ url: string; type?: string; status?: number; title?: string; verified?: boolean }>;
}

const assetTypeIcons: Record<string, any> = {
  domain: Globe,
  subdomain: Globe,
  ip_address: Server,
  url: ExternalLink,
  port: Network,
  service: Cpu,
  certificate: Lock,
  api_endpoint: Database,
};

const TABS = [
  { id: 'details', label: 'Details', icon: FileText },
  { id: 'discovery', label: 'Discovery', icon: Radar },
  { id: 'app-structure', label: 'App Structure', icon: FolderSearch },
  { id: 'findings', label: 'Findings', icon: Shield },
  { id: 'ports', label: 'Open Ports', icon: Network },
  { id: 'activity', label: 'Activity', icon: Activity },
  { id: 'mitigations', label: 'Mitigations', icon: Settings },
];

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;
  const [asset, setAsset] = useState<Asset | null>(null);
  const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [activeTab, setActiveTab] = useState('details');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [capturingScreenshot, setCapturingScreenshot] = useState(false);
  const [lookingUpVT, setLookingUpVT] = useState(false);
  const [acsDialogOpen, setAcsDialogOpen] = useState(false);
  const [editingAcs, setEditingAcs] = useState(5);
  const [savingAcs, setSavingAcs] = useState(false);
  const [appStructure, setAppStructure] = useState<{
    summary: { total_paths: number; total_urls: number; total_parameters: number; total_js_files: number; total_api_endpoints: number; total_interesting_urls: number; scans_included: number };
    paths: string[];
    urls: string[];
    parameters: string[];
    js_files: string[];
    api_endpoints: string[];
    interesting_urls: string[];
    source_breakdown: Record<string, Record<string, number>>;
  } | null>(null);
  const [addFindingDialogOpen, setAddFindingDialogOpen] = useState(false);
  const [exportingReport, setExportingReport] = useState(false);
  const [appStructureLoading, setAppStructureLoading] = useState(false);
  const [verifyingPorts, setVerifyingPorts] = useState<Set<number>>(new Set());
  const { toast } = useToast();

  // Handle port verification with nmap
  const handleVerifyPort = async (portId: number) => {
    setVerifyingPorts((prev: Set<number>) => new Set(Array.from(prev).concat(portId)));
    
    try {
      const response = await api.request(`/ports/${portId}/verify`, {
        method: 'POST',
      });
      
      toast({
        title: 'Port Verified',
        description: `Port ${response.port} is ${response.state?.toUpperCase() || 'UNKNOWN'}${response.service ? ` (${response.service})` : ''}`,
        variant: response.state === 'open' ? 'default' : 'destructive',
      });
      
      // Refresh asset data to show updated verification status
      fetchAsset();
    } catch (error: any) {
      toast({
        title: 'Verification Failed',
        description: error?.response?.data?.detail || 'Failed to verify port with nmap',
        variant: 'destructive',
      });
    } finally {
      setVerifyingPorts((prev: Set<number>) => {
        const newSet = new Set(prev);
        newSet.delete(portId);
        return newSet;
      });
    }
  };

  // Handle verifying all ports on this asset
  const handleVerifyAllPorts = async () => {
    if (!asset?.port_services?.length) return;
    
    const unverifiedPorts = asset.port_services.filter(p => !p.verified && p.state?.toLowerCase() === 'open');
    
    if (unverifiedPorts.length === 0) {
      toast({
        title: 'All Ports Verified',
        description: 'All open ports on this asset have already been verified.',
      });
      return;
    }
    
    if (unverifiedPorts.length > 20) {
      // For many ports, use bulk verify
      try {
        const response = await api.request('/ports/verify-bulk', {
          method: 'POST',
          body: JSON.stringify(unverifiedPorts.map(p => p.id)),
        });
        
        toast({
          title: 'Bulk Verification Queued',
          description: `Background scan created to verify ${unverifiedPorts.length} ports. Check Scans page for progress.`,
        });
      } catch (error: any) {
        toast({
          title: 'Bulk Verification Failed',
          description: error?.response?.data?.detail || 'Failed to queue bulk verification',
          variant: 'destructive',
        });
      }
    } else {
      // Verify ports one by one for smaller counts
      for (const port of unverifiedPorts) {
        await handleVerifyPort(port.id);
      }
    }
  };

  const handleVirusTotalLookup = async () => {
    if (!asset) return;
    
    setLookingUpVT(true);
    try {
      const result = await api.lookupVirusTotal(asset.id);
      toast({ 
        title: 'VirusTotal Lookup Complete',
        description: result.message || 'Reputation data retrieved'
      });
      fetchAsset(); // Refresh to show new VT data
    } catch (error: any) {
      toast({
        title: 'VirusTotal Lookup Failed',
        description: error?.response?.data?.detail || 'Failed to lookup reputation',
        variant: 'destructive',
      });
    } finally {
      setLookingUpVT(false);
    }
  };

  const fetchAsset = async () => {
    try {
      const [assetData, screenshotData, vulnData] = await Promise.all([
        api.getAsset(parseInt(assetId)),
        api.getAssetScreenshots(parseInt(assetId)).catch(() => ({ screenshots: [] })),
        api.getVulnerabilitiesForAsset(parseInt(assetId), { limit: 50 }).catch(() => [])
      ]);
      setAsset(assetData);
      setScreenshots(screenshotData.screenshots || []);
      
      // Sort vulnerabilities by severity: critical, high, medium, low, info
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const sortedVulns = (Array.isArray(vulnData) ? vulnData : []).sort((a: Vulnerability, b: Vulnerability) => {
        const orderA = severityOrder[a.severity?.toLowerCase()] ?? 5;
        const orderB = severityOrder[b.severity?.toLowerCase()] ?? 5;
        return orderA - orderB;
      });
      setVulnerabilities(sortedVulns);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch asset details',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchAppStructure = async () => {
    if (appStructureLoading || appStructure) return;
    
    setAppStructureLoading(true);
    try {
      const data = await api.getAppStructureByAsset(parseInt(assetId));
      setAppStructure(data);
    } catch (error) {
      console.error('Failed to fetch app structure:', error);
      // Set empty structure if API fails
      setAppStructure({
        summary: { total_paths: 0, total_urls: 0, total_parameters: 0, total_js_files: 0, total_api_endpoints: 0, total_interesting_urls: 0, scans_included: 0 },
        paths: [],
        urls: [],
        parameters: [],
        js_files: [],
        api_endpoints: [],
        interesting_urls: [],
        source_breakdown: {}
      });
    } finally {
      setAppStructureLoading(false);
    }
  };

  const handleCaptureScreenshot = async () => {
    if (!asset) return;
    
    setCapturingScreenshot(true);
    try {
      await api.captureScreenshot(asset.id);
      toast({ title: 'Screenshot captured successfully' });
      fetchAsset();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to capture screenshot',
        variant: 'destructive',
      });
    } finally {
      setCapturingScreenshot(false);
    }
  };

  const handleOpenAcsDialog = () => {
    if (asset) {
      setEditingAcs(asset.acs_score || 5);
      setAcsDialogOpen(true);
    }
  };

  const handleSaveAcs = async () => {
    if (!asset) return;
    
    setSavingAcs(true);
    try {
      await api.updateAsset(asset.id, { acs_score: editingAcs } as any);
      toast({ title: 'ACS score updated successfully' });
      setAcsDialogOpen(false);
      fetchAsset();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update ACS score',
        variant: 'destructive',
      });
    } finally {
      setSavingAcs(false);
    }
  };

  const handleCalculateRiskDrivers = async () => {
    if (!asset) return;
    
    setSavingAcs(true);
    try {
      const result = await api.post(`/assets/${asset.id}/calculate-risk-drivers`);
      toast({ 
        title: 'Risk drivers calculated',
        description: `Risk level: ${result.data?.risk_drivers?.overall_risk?.level || 'unknown'}`
      });
      setAcsDialogOpen(false);
      fetchAsset();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to calculate risk drivers',
        variant: 'destructive',
      });
    } finally {
      setSavingAcs(false);
    }
  };

  useEffect(() => {
    fetchAsset();
  }, [assetId]);

  // Fetch app structure when tab is selected
  useEffect(() => {
    if (activeTab === 'app-structure' && !appStructure && !appStructureLoading) {
      fetchAppStructure();
    }
  }, [activeTab]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAsset();
  };

  const handleExportReport = async () => {
    if (!asset) return;
    
    setExportingReport(true);
    try {
      const response = await api.generateAssetReport(parseInt(assetId), { format: 'pdf', include_info: false });
      
      const blob = new Blob([response], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings_report_${asset.value.replace(/[^a-zA-Z0-9.-]/g, '_')}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast({
        title: 'Report Downloaded',
        description: 'PDF report has been downloaded successfully.',
      });
    } catch (error) {
      toast({
        title: 'Export Failed',
        description: getApiErrorMessage(error, 'Failed to generate PDF report'),
        variant: 'destructive',
      });
    } finally {
      setExportingReport(false);
    }
  };

  const handleFindingAdded = () => {
    fetchAsset();
  };

  const handleCopyValue = (value: string) => {
    navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({ title: 'Copied to clipboard' });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-green-500 text-white';
      case 'info': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getVulnStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'open': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'in_progress': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'resolved': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const formatVulnAge = (firstDetected: string) => {
    const start = new Date(firstDetected);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return '1 day';
    if (diffDays < 30) return `${diffDays} days`;
    return `${Math.floor(diffDays / 30)} months`;
  };

  const getACSColor = (score: number) => {
    if (score >= 8) return 'text-red-500';
    if (score >= 6) return 'text-orange-500';
    if (score >= 4) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getARSColor = (score: number) => {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    if (score >= 20) return 'text-blue-500';
    return 'text-green-500';
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-96">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </MainLayout>
    );
  }

  if (!asset) {
    return (
      <MainLayout>
        <div className="flex flex-col items-center justify-center h-96 gap-4">
          <AlertTriangle className="h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">Asset not found</p>
          <Button variant="outline" onClick={() => router.push('/assets')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Assets
          </Button>
        </div>
      </MainLayout>
    );
  }

  const AssetIcon = assetTypeIcons[asset.asset_type] || Monitor;
  const acsScore = asset.acs_score || 5;
  const arsScore = asset.ars_score || asset.risk_score || 0;
  const vulnCount = asset.vulnerability_count || vulnerabilities.length;

  return (
    <MainLayout>
      {/* Header with Asset Name and ID */}
      <div className="border-b bg-card">
        <div className="p-6">
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="icon" onClick={() => router.push('/assets')}>
                <ArrowLeft className="h-5 w-5" />
          </Button>
              <div className="flex items-center gap-3">
                <AssetIcon className="h-8 w-8 text-primary" />
                <div>
                  <h1 className="text-2xl font-bold font-mono">{asset.value}</h1>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <span>Asset ID: {asset.id}</span>
                    <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => handleCopyValue(String(asset.id))}>
                      <Copy className="h-3 w-3" />
            </Button>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="gap-1">
                <Database className="h-3 w-3" />
                Data Sources
              </Badge>
              <Button
                variant="default"
                onClick={() => {
                  const targetEnc = encodeURIComponent(asset.value);
                  const questionEnc = encodeURIComponent(
                    `Perform a security assessment on ${asset.value}. Use create_finding for any vulnerabilities you find so they appear in Findings.`
                  );
                  router.push(`/agent?target=${targetEnc}&playbook=vuln_scan&question=${questionEnc}`);
                }}
              >
                <MessageSquare className="h-4 w-4 mr-2" />
                Run agent assessment
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    Run scan
                    <ChevronDown className="h-4 w-4 ml-2" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem
                    onClick={async () => {
                      try {
                        await api.createScan({
                          name: `Login portal - ${asset.value}`,
                          organization_id: asset.organization_id,
                          scan_type: 'login_portal',
                          targets: [asset.value],
                        });
                        toast({ title: 'Scan started', description: 'Login portal scan queued. Results will populate this asset when complete.' });
                      } catch (e: unknown) {
                        toast({ variant: 'destructive', title: 'Failed to start scan', description: getApiErrorMessage(e) });
                      }
                    }}
                  >
                    Login portal
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={async () => {
                      try {
                        await api.createScan({
                          name: `Technology - ${asset.value}`,
                          organization_id: asset.organization_id,
                          scan_type: 'technology',
                          targets: [asset.value],
                        });
                        toast({ title: 'Scan started', description: 'Technology scan queued. Results will populate this asset when complete.' });
                      } catch (e: unknown) {
                        toast({ variant: 'destructive', title: 'Failed to start scan', description: getApiErrorMessage(e) });
                      }
                    }}
                  >
                    Technology
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={async () => {
                      try {
                        await api.createScan({
                          name: `Port scan - ${asset.value}`,
                          organization_id: asset.organization_id,
                          scan_type: 'port_scan',
                          targets: [asset.value],
                        });
                        toast({ title: 'Scan started', description: 'Port scan queued. Results will populate this asset when complete.' });
                      } catch (e: unknown) {
                        toast({ variant: 'destructive', title: 'Failed to start scan', description: getApiErrorMessage(e) });
                      }
                    }}
                  >
                    Port scan
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            <Button variant="outline" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

          {/* Score Cards */}
          <div className="grid grid-cols-4 gap-4 mt-6">
            {/* ARS Score - Asset Risk Score */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="text-sm text-muted-foreground mb-1">ARS</div>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-bold ${getARSColor(arsScore)}`}>
                    {arsScore}
                  </span>
                  <span className="text-muted-foreground">/100</span>
              </div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div 
                    className={`h-full rounded-full ${arsScore >= 80 ? 'bg-red-500' : arsScore >= 60 ? 'bg-orange-500' : arsScore >= 40 ? 'bg-yellow-500' : arsScore >= 20 ? 'bg-blue-500' : 'bg-green-500'}`}
                    style={{ width: `${arsScore}%` }}
                  />
            </div>
          </CardContent>
        </Card>

            {/* ACS Score - Asset Criticality Score */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-muted-foreground">ACS</span>
                  <Button variant="ghost" size="icon" className="h-5 w-5" onClick={handleOpenAcsDialog} title="Edit ACS Score">
                    <Settings className="h-3 w-3" />
                  </Button>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-bold ${getACSColor(acsScore)}`}>{acsScore}</span>
                  <span className="text-muted-foreground">/10</span>
                </div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div 
                    className={`h-full rounded-full ${acsScore >= 8 ? 'bg-red-500' : acsScore >= 6 ? 'bg-orange-500' : acsScore >= 4 ? 'bg-yellow-500' : 'bg-green-500'}`}
                    style={{ width: `${(acsScore / 10) * 100}%` }}
                  />
              </div>
            </CardContent>
          </Card>

            {/* Risk Drivers */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="text-sm text-muted-foreground mb-2">Risk Drivers</div>
                <div className="flex flex-wrap gap-1">
                  {/* System type profile — data sensitivity classification */}
                  {asset.acs_drivers?.system_type_profile && (
                    <Badge
                      className={`text-xs ${
                        asset.acs_drivers.system_type_profile.risk === 'critical'
                          ? 'bg-purple-600/20 text-purple-300 border-purple-600/40'
                          : 'bg-orange-500/20 text-orange-300 border-orange-500/40'
                      }`}
                      title={[
                        asset.acs_drivers.system_type_profile.reason,
                        asset.acs_drivers.system_type_profile.data_labels?.join(', '),
                        `ACS floor: ${asset.acs_drivers.system_type_profile.acs_floor}`,
                      ].join(' · ')}
                    >
                      {asset.acs_drivers.system_type_profile.system_type?.replace(/_/g, ' ')}
                    </Badge>
                  )}
                  {/* Login Portal */}
                  {asset.acs_drivers?.login_portal && (
                    <Badge className="text-xs bg-red-500/20 text-red-400 border-red-500/30">
                      Login Portal
                    </Badge>
                  )}
                  {/* High-risk Technologies */}
                  {asset.acs_drivers?.technologies?.count > 0 && (
                    <Badge className={`text-xs ${
                      asset.acs_drivers?.technologies?.risk === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      asset.acs_drivers?.technologies?.risk === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                    }`}>
                      {asset.acs_drivers?.technologies?.items?.[0]?.reason || 'High-risk Tech'}
                    </Badge>
                  )}
                  {/* Risky Ports */}
                  {asset.acs_drivers?.risky_ports?.count > 0 && (
                    <Badge className={`text-xs ${
                      asset.acs_drivers?.risky_ports?.risk === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      'bg-orange-500/20 text-orange-400 border-orange-500/30'
                    }`}>
                      {asset.acs_drivers?.risky_ports?.count} Risky Port(s)
                    </Badge>
                  )}
                  {/* Vulnerabilities */}
                  {asset.acs_drivers?.vulnerabilities?.critical > 0 && (
                    <Badge className="text-xs bg-red-500/20 text-red-400 border-red-500/30">
                      {asset.acs_drivers?.vulnerabilities?.critical} Critical Vuln(s)
                    </Badge>
                  )}
                  {/* Public Facing */}
                  {asset.acs_drivers?.public_facing && (
                    <Badge variant="secondary" className="text-xs">
                      Public
                    </Badge>
                  )}
                  {/* Owned Infrastructure */}
                  {asset.acs_drivers?.owned_infrastructure && (
                    <Badge variant="secondary" className="text-xs">
                      Owned Infra
                    </Badge>
                  )}
                  {/* Device Class fallback if no drivers */}
                  {(!asset.acs_drivers || Object.keys(asset.acs_drivers).length === 0) && asset.device_class && (
                    <Badge variant="secondary" className="text-xs">{asset.device_class}</Badge>
                  )}
                  {/* No drivers message */}
                  {(!asset.acs_drivers || Object.keys(asset.acs_drivers).length === 0) && !asset.device_class && (
                    <span className="text-xs text-muted-foreground">Run risk analysis to populate</span>
                  )}
              </div>
            </CardContent>
          </Card>

            {/* Vulnerabilities Count */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-muted-foreground">Vulnerabilities</span>
                  <AlertCircle className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-3xl font-bold">{vulnCount}</div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-primary rounded-full" style={{ width: vulnCount > 0 ? '100%' : '0%' }} />
              </div>
            </CardContent>
          </Card>
          </div>

          {/* Tab Navigation */}
          <div className="flex gap-1 mt-6 border-b">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id 
                    ? 'border-primary text-primary bg-primary/5' 
                    : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/50'
                }`}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
                </div>
              </div>
        </div>

      {/* Tab Content */}
      <div className="p-6 space-y-6">
        {/* Details Tab */}
        {activeTab === 'details' && (
          <>
            {/* Asset Information */}
        <Card>
          <CardHeader>
                <div className="flex items-center gap-2">
                  <Monitor className="h-5 w-5" />
                  <CardTitle>Asset</CardTitle>
                </div>
                <CardDescription>General information and properties</CardDescription>
          </CardHeader>
          <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">System Type</span>
                    <span className="font-medium">{asset.system_type || asset.asset_type?.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Operating System</span>
                    <span className="font-medium">{asset.operating_system || '—'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Public</span>
                    <span className="font-medium">{asset.is_public !== false ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">IPv4 Addresses</span>
                    <span className="font-mono text-sm">
                      {(asset.ip_addresses?.length ?? 0) > 0 
                        ? asset.ip_addresses!.join(', ') 
                        : asset.ip_address 
                          ? asset.ip_address 
                          : asset.asset_type === 'ip_address' 
                            ? asset.value 
                            : '—'}
                    </span>
                  </div>
                  {asset.acs_drivers?.overall_risk && (
                    <div className="col-span-2 flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Risk Level</span>
                      <Badge className={`${
                        asset.acs_drivers?.overall_risk?.level === 'critical' ? 'bg-red-500' :
                        asset.acs_drivers?.overall_risk?.level === 'high' ? 'bg-orange-500' :
                        asset.acs_drivers?.overall_risk?.level === 'medium' ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`}>
                        {asset.acs_drivers?.overall_risk?.level?.toUpperCase()}
                      </Badge>
                    </div>
                  )}
                  {asset.acs_drivers?.overall_risk?.factors?.length > 0 && (
                    <div className="col-span-2 py-2 border-b">
                      <span className="text-muted-foreground block mb-2">Risk Factors</span>
                      <div className="flex flex-wrap gap-1">
                        {asset.acs_drivers?.overall_risk?.factors?.map((factor: string, idx: number) => (
                          <Badge key={idx} variant="outline" className="text-xs">
                            {factor}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Device Class</span>
                    <span className="font-medium">{asset.device_class || '—'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Device Subclasses</span>
                    <span className="font-medium">{asset.device_subclass || '—'}</span>
                  </div>
                </div>
          </CardContent>
        </Card>

            {/* Last Seen Information */}
          <Card>
            <CardHeader>
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  <CardTitle>Last Seen</CardTitle>
                </div>
                <CardDescription>General information and properties</CardDescription>
            </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Scan Name</span>
                    <span className="font-medium">{asset.last_scan_name || asset.discovery_source || '—'}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Scan ID</span>
                    <span className="font-mono text-xs">{asset.last_scan_id || '—'}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Seen</span>
                    <span className="font-medium">{formatDate(asset.last_seen)}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Licensed Scan</span>
                    <span className="font-medium">{asset.last_scan_date ? formatDate(asset.last_scan_date) : formatDate(asset.last_seen)}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                <span className="text-muted-foreground">First Seen</span>
                    <span className="font-medium">{formatDate(asset.first_seen)}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Scan Target</span>
                    <span className="font-mono text-sm">{asset.last_scan_target || asset.value}</span>
              </div>
              </div>
              </CardContent>
            </Card>

            {/* Tags */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Tag className="h-5 w-5" />
                  <CardTitle>Tags</CardTitle>
              </div>
              </CardHeader>
              <CardContent>
                {asset.tags && asset.tags.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {asset.tags.map((tag, idx) => (
                      <Badge key={idx} variant="secondary">{tag}</Badge>
                    ))}
                </div>
                ) : (
                  <p className="text-muted-foreground text-sm">No tags assigned</p>
              )}
            </CardContent>
          </Card>

            {/* Network & Location */}
          <Card>
            <CardHeader>
                <div className="flex items-center gap-2">
                <MapPin className="h-5 w-5" />
                  <CardTitle>Network & Location</CardTitle>
                </div>
            </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  {/* Always show IP addresses - including for IP address type assets */}
                  {(() => {
                    // Determine which IPs to show
                    const ips: string[] = [];
                    if (asset.ip_addresses && asset.ip_addresses.length > 0) {
                      ips.push(...asset.ip_addresses);
                    } else if (asset.ip_address) {
                      ips.push(asset.ip_address);
                    } else if (asset.asset_type === 'ip_address' && asset.value) {
                      ips.push(asset.value);
                    }
                    
                    return ips.length > 0 ? (
                      <div className="col-span-2 flex justify-between py-2 border-b">
                        <span className="text-muted-foreground">IPv4 Address{ips.length > 1 ? 'es' : ''}</span>
                        <div className="flex flex-wrap gap-1 justify-end">
                          {ips.filter(Boolean).map((ip, idx) => (
                            <Badge key={idx} variant="outline" className="font-mono text-xs">{ip}</Badge>
                    ))}
                  </div>
                </div>
                    ) : null;
                  })()}
                  
                  {/* Show netblock link if asset is linked to a netblock */}
                  {asset.netblock_id && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Netblock</span>
                      <a href={`/netblocks/${asset.netblock_id}`} className="text-primary hover:underline font-mono text-sm">
                        View CIDR Block →
                      </a>
                </div>
                  )}
                  
              {asset.asn && (
                    <div className="flex justify-between py-2 border-b">
                  <span className="text-muted-foreground">ASN</span>
                  <span className="font-mono">{asset.asn}</span>
                </div>
              )}
              {asset.isp && (
                    <div className="flex justify-between py-2 border-b">
                  <span className="text-muted-foreground">ISP</span>
                      <span className="font-medium">{asset.isp}</span>
                </div>
              )}
                  {asset.city && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">City</span>
                      <span className="font-medium">{asset.city}</span>
                </div>
              )}
                  {asset.country && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Country</span>
                      <span className="font-medium">{asset.country} {asset.country_code && `(${asset.country_code})`}</span>
                </div>
              )}
                  {asset.region && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Region</span>
                      <span className="font-medium">{asset.region}</span>
                    </div>
                  )}
                  
                  {/* Show message only if truly no network info and not an IP asset */}
                  {asset.asset_type !== 'ip_address' && 
                   !asset.ip_address && (!asset.ip_addresses || asset.ip_addresses.length === 0) && 
                   !asset.asn && !asset.isp && !asset.city && !asset.country && !asset.netblock_id && (
                    <div className="col-span-2 text-center py-4 text-muted-foreground">
                      No network information available. Run a discovery scan to populate this data.
                    </div>
              )}
                </div>
            </CardContent>
          </Card>

            {/* DNS Records */}
            {asset.asset_type === 'domain' && asset.metadata_?.dns_records && (
          <Card>
            <CardHeader>
                  <div className="flex items-center gap-2">
                    <Globe className="h-5 w-5" />
                    <CardTitle>DNS Records</CardTitle>
                  </div>
                  <CardDescription>
                    {asset.metadata_?.dns_fetched_at 
                      ? `Last fetched: ${formatDate(asset.metadata_.dns_fetched_at)}`
                      : 'DNS information for this domain'}
                  </CardDescription>
            </CardHeader>
                <CardContent className="space-y-4">
                  {/* Summary badges */}
                  {asset.metadata_?.dns_analysis && (
              <div className="flex flex-wrap gap-2">
                      {asset.metadata_.dns_summary?.has_mail && (
                        <Badge className="bg-blue-500/20 text-blue-600">
                          <Mail className="h-3 w-3 mr-1" />
                          {asset.metadata_.dns_summary?.mail_providers?.join(', ') || 'Email Enabled'}
                        </Badge>
                      )}
                      {asset.metadata_.dns_analysis?.uses_cdn && (
                        <Badge className="bg-purple-500/20 text-purple-600">
                          CDN: {asset.metadata_.dns_analysis.uses_cdn}
                        </Badge>
                      )}
                      {asset.metadata_.dns_analysis?.security_features?.map((feature: string) => (
                        <Badge key={feature} className="bg-green-500/20 text-green-600">
                          {feature}
                  </Badge>
                ))}
              </div>
                  )}
                  
                  {/* A Records */}
                  {asset.metadata_.dns_records?.A?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">A Records (IPv4)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.A.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono">
                            {record.address}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* AAAA Records */}
                  {asset.metadata_.dns_records?.AAAA?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">AAAA Records (IPv6)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.AAAA.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono text-xs">
                            {record.address}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* MX Records */}
                  {asset.metadata_.dns_records?.MX?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">MX Records (Mail)</h4>
                      <div className="space-y-1">
                        {asset.metadata_.dns_records.MX
                          .sort((a: any, b: any) => a.priority - b.priority)
                          .map((record: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-2 text-sm">
                            <span className="text-muted-foreground w-8">{record.priority}</span>
                            <span className="font-mono">{record.target}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* NS Records */}
                  {asset.metadata_.dns_records?.NS?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">NS Records (Nameservers)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.NS.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono">
                            {record.target}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* TXT Records */}
                  {asset.metadata_.dns_records?.TXT?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">TXT Records ({asset.metadata_.dns_records.TXT.length})</h4>
                      <div className="space-y-2 max-h-40 overflow-y-auto">
                        {asset.metadata_.dns_records.TXT.slice(0, 10).map((record: any, idx: number) => (
                          <div key={idx} className="p-2 bg-muted/50 rounded text-xs font-mono break-all">
                            {record.value?.substring(0, 100)}{record.value?.length > 100 ? '...' : ''}
                          </div>
                        ))}
                        {asset.metadata_.dns_records.TXT.length > 10 && (
                          <p className="text-xs text-muted-foreground">
                            +{asset.metadata_.dns_records.TXT.length - 10} more records
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                  
                  {/* TXT Verifications Summary */}
                  {asset.metadata_.dns_summary?.txt_verifications?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">Detected Services</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_summary.txt_verifications.map((svc: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="text-xs">
                            {svc}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
            </CardContent>
          </Card>
        )}

        {/* VirusTotal Reputation */}
        {(asset.asset_type === 'domain' || asset.asset_type === 'subdomain' || asset.asset_type === 'ip_address') && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  <CardTitle>VirusTotal Reputation</CardTitle>
                </div>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={handleVirusTotalLookup} 
                  disabled={lookingUpVT}
                >
                  {lookingUpVT ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Search className="h-4 w-4 mr-2" />
                  )}
                  {lookingUpVT ? 'Looking up...' : 'Lookup VT'}
                </Button>
              </div>
              <CardDescription>
                Malware detection and security categorization from VirusTotal
              </CardDescription>
            </CardHeader>
            <CardContent>
              {asset.metadata_?.virustotal ? (
                <div className="space-y-4">
                  {/* Detection Ratio */}
                  <div className="flex items-center gap-4">
                    {asset.metadata_.virustotal.is_malicious ? (
                      <div className="p-3 rounded-full bg-red-500/10">
                        <ShieldX className="h-8 w-8 text-red-500" />
                      </div>
                    ) : asset.metadata_.virustotal.malicious > 0 || asset.metadata_.virustotal.suspicious > 0 ? (
                      <div className="p-3 rounded-full bg-yellow-500/10">
                        <ShieldAlert className="h-8 w-8 text-yellow-500" />
                      </div>
                    ) : (
                      <div className="p-3 rounded-full bg-green-500/10">
                        <ShieldCheck className="h-8 w-8 text-green-500" />
                      </div>
                    )}
                    <div>
                      <div className="text-2xl font-bold">
                        {asset.metadata_.virustotal.detection_ratio}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Detection Ratio
                      </div>
                    </div>
                    <div className="ml-auto text-right">
                      <div className="text-sm">
                        <span className="text-red-500 font-medium">{asset.metadata_.virustotal.malicious}</span> malicious
                        {asset.metadata_.virustotal.suspicious > 0 && (
                          <>, <span className="text-yellow-500 font-medium">{asset.metadata_.virustotal.suspicious}</span> suspicious</>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {asset.metadata_.virustotal.harmless} harmless, {asset.metadata_.virustotal.undetected} undetected
                      </div>
                    </div>
                  </div>

                  {/* Reputation Score */}
                  {asset.metadata_.virustotal.reputation_score !== undefined && (
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">Reputation Score:</span>
                      <Badge 
                        variant="outline"
                        className={
                          asset.metadata_.virustotal.reputation_score < 0 
                            ? 'text-red-500 border-red-500/30' 
                            : asset.metadata_.virustotal.reputation_score > 0 
                            ? 'text-green-500 border-green-500/30'
                            : ''
                        }
                      >
                        {asset.metadata_.virustotal.reputation_score}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        (negative = bad, positive = good)
                      </span>
                    </div>
                  )}

                  {/* Categories */}
                  {asset.metadata_.virustotal.categories?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">Categories</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.virustotal.categories.map((cat: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="text-xs">
                            {cat}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Community Votes */}
                  {(asset.metadata_.virustotal.community_votes?.harmless > 0 || 
                    asset.metadata_.virustotal.community_votes?.malicious > 0) && (
                    <div className="flex items-center gap-4 text-sm">
                      <span className="text-muted-foreground">Community Votes:</span>
                      <span className="text-green-500">
                        👍 {asset.metadata_.virustotal.community_votes.harmless} harmless
                      </span>
                      <span className="text-red-500">
                        👎 {asset.metadata_.virustotal.community_votes.malicious} malicious
                      </span>
                    </div>
                  )}

                  {/* Last Analysis */}
                  {asset.metadata_.virustotal.last_analysis_date && (
                    <div className="text-xs text-muted-foreground">
                      Last analyzed: {formatDate(asset.metadata_.virustotal.last_analysis_date)}
                      {asset.metadata_.virustotal.lookup_date && (
                        <> • Fetched: {formatDate(asset.metadata_.virustotal.lookup_date)}</>
                      )}
                    </div>
                  )}
                </div>
              ) : asset.metadata_?.virustotal?.error ? (
                <div className="flex items-center gap-2 text-yellow-500">
                  <AlertTriangle className="h-5 w-5" />
                  <span>{asset.metadata_.virustotal.error}</span>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-6 text-center">
                  <Shield className="h-10 w-10 text-muted-foreground mb-3" />
                  <p className="text-muted-foreground">No VirusTotal data available</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Click &quot;Lookup VT&quot; to check reputation
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Technologies */}
        {asset.technologies && asset.technologies.length > 0 && (
          <Card>
            <CardHeader>
                  <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5" />
                    <CardTitle>Technologies ({asset.technologies.length})</CardTitle>
                  </div>
                  <CardDescription>Detected technologies and frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                    {asset.technologies.map((tech: Technology, idx: number) => (
                      <Badge key={idx} variant="outline" className="py-1.5">
                    <span className="font-medium">{tech.name}</span>
                        {tech.version && <span className="text-muted-foreground ml-1">v{tech.version}</span>}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Site map & App Structure - endpoints, parameters, JS files on this asset */}
        {((asset.endpoints && asset.endpoints.length > 0) || 
          (asset.parameters && asset.parameters.length > 0) || 
          (asset.js_files && asset.js_files.length > 0) ||
          (asset.technologies && asset.technologies.length > 0)) && (
          <Card 
            className="cursor-pointer hover:border-primary/50 transition-colors"
            onClick={() => setActiveTab('app-structure')}
          >
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FolderSearch className="h-5 w-5" />
                  <CardTitle>Site map &amp; App Structure</CardTitle>
                </div>
                <Badge variant="outline" className="text-xs">
                  Click to view details →
                </Badge>
              </div>
              <CardDescription>
                Discovered technologies, endpoints, parameters, and JavaScript files for this asset
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <p className="text-2xl font-bold text-purple-500">{asset.technologies?.length || 0}</p>
                  <p className="text-xs text-muted-foreground">Technologies</p>
                </div>
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <p className="text-2xl font-bold text-blue-500">{asset.endpoints?.length || 0}</p>
                  <p className="text-xs text-muted-foreground">Endpoints</p>
                </div>
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <p className="text-2xl font-bold text-orange-500">{asset.parameters?.length || 0}</p>
                  <p className="text-xs text-muted-foreground">Parameters</p>
                </div>
                <div className="text-center p-3 bg-muted/30 rounded-lg">
                  <p className="text-2xl font-bold text-yellow-500">{asset.js_files?.length || 0}</p>
                  <p className="text-xs text-muted-foreground">JS files</p>
                </div>
              </div>
              {/* Show first few JS files on the asset site map */}
              {asset.js_files && asset.js_files.length > 0 && (
                <div className="rounded-lg border bg-muted/20 p-3">
                  <p className="text-sm font-medium text-muted-foreground mb-2">JS files on this site (first 10)</p>
                  <ul className="text-sm space-y-1 break-all">
                    {(typeof asset.js_files[0] === 'string' ? asset.js_files : asset.js_files.map(String))
                      .slice(0, 10)
                      .map((url: string, i: number) => (
                        <li key={i}>
                          <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>
                            {url}
                          </a>
                        </li>
                      ))}
                  </ul>
                  {asset.js_files.length > 10 && (
                    <p className="text-xs text-muted-foreground mt-2">+{asset.js_files.length - 10} more in App Structure tab</p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}

            {/* Screenshot */}
            {(asset.asset_type === 'domain' || asset.asset_type === 'subdomain' || asset.asset_type === 'url') && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Camera className="h-5 w-5" />
                      <CardTitle>Screenshot</CardTitle>
                    </div>
                    <Button variant="outline" size="sm" onClick={handleCaptureScreenshot} disabled={capturingScreenshot}>
                      {capturingScreenshot ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Camera className="h-4 w-4 mr-2" />}
                      {capturingScreenshot ? 'Capturing...' : 'Capture New'}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {screenshots.length > 0 ? (
                    <a href={api.getScreenshotImageUrl(screenshots[0].id)} target="_blank" rel="noopener noreferrer">
                      <img
                        src={api.getScreenshotImageUrl(screenshots[0].id)}
                        alt={`Screenshot of ${asset.value}`}
                        className="w-full max-h-96 object-contain rounded-lg border"
                      />
                    </a>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8">
                      <ImageIcon className="h-12 w-12 text-muted-foreground mb-3" />
                      <p className="text-muted-foreground">No screenshots captured yet</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

          </>
        )}

        {/* Discovery Tab */}
        {activeTab === 'discovery' && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Radar className="h-5 w-5 text-primary" />
                <CardTitle>How This Asset Was Discovered</CardTitle>
              </div>
              <CardDescription>
                The attribution path tracing this asset back to your organization, plus the source that surfaced it
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DiscoveryPath
                value={asset.value}
                assetType={asset.asset_type}
                rootDomain={asset.root_domain}
                liveUrl={asset.live_url}
                discoverySource={asset.discovery_source}
                discoveryChain={asset.discovery_chain}
                associationReason={asset.association_reason}
                associationConfidence={asset.association_confidence}
                hostingType={asset.hosting_type}
                hostingProvider={asset.hosting_provider}
                isEphemeralIp={asset.is_ephemeral_ip}
                resolvedFrom={asset.resolved_from}
              />
            </CardContent>
          </Card>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security Findings ({vulnerabilities.length})
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setAddFindingDialogOpen(true)}
                  >
                    <Plus className="h-4 w-4 mr-1" />
                    Add Finding
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleExportReport}
                    disabled={exportingReport || vulnerabilities.length === 0}
                  >
                    {exportingReport ? (
                      <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                    ) : (
                      <FileDown className="h-4 w-4 mr-1" />
                    )}
                    Export PDF
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {vulnerabilities.length > 0 ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Vulnerability List */}
                  <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
                    {vulnerabilities.map((vuln) => (
                      <div
                        key={vuln.id}
                        onClick={() => setSelectedVuln(vuln)}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          selectedVuln?.id === vuln.id ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity?.toUpperCase()}</Badge>
                              <Badge className={getVulnStatusColor(vuln.status)}>{vuln.status?.replace('_', ' ').toUpperCase()}</Badge>
                            </div>
                            <p className="font-medium text-sm truncate">{vuln.title || vuln.name || vuln.template_id}</p>
                            {vuln.template_id && <p className="text-xs text-muted-foreground font-mono mt-1">{vuln.template_id}</p>}
                          </div>
                          {vuln.cvss_score && (
                            <div className="text-right flex-shrink-0">
                              <div className={`text-lg font-bold ${vuln.cvss_score >= 9 ? 'text-red-500' : vuln.cvss_score >= 7 ? 'text-orange-500' : 'text-yellow-500'}`}>
                                {vuln.cvss_score}
                              </div>
                              <div className="text-xs text-muted-foreground">CVSS</div>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Vulnerability Detail */}
                  <div className="border rounded-lg p-4 bg-muted/20 max-h-[600px] overflow-y-auto">
                    {selectedVuln ? (
                      <div className="space-y-4">
                        <div>
                          <h3 className="font-semibold text-lg">{selectedVuln.title || selectedVuln.name}</h3>
                          <div className="flex flex-wrap gap-2 mt-2">
                            <Badge className={getSeverityColor(selectedVuln.severity)}>{selectedVuln.severity?.toUpperCase()}</Badge>
                            <Badge className={getVulnStatusColor(selectedVuln.status)}>{selectedVuln.status?.replace('_', ' ').toUpperCase()}</Badge>
                          </div>
                        </div>

                        {selectedVuln.description && (
                          <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Description</h4>
                            <p className="text-sm">{selectedVuln.description}</p>
                          </div>
                        )}

                        <div className="space-y-2 pt-2 border-t">
                          <h4 className="text-sm font-medium text-muted-foreground">Vulnerability Information</h4>
                          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                            {selectedVuln.cvss_score && (
                              <>
                                <span className="text-muted-foreground">CVSS Score</span>
                                <span className="font-bold">{selectedVuln.cvss_score}/10</span>
                              </>
                            )}
                            {selectedVuln.cve_id && (
                              <>
                                <span className="text-muted-foreground">CVE ID</span>
                                <a href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`} target="_blank" className="text-primary hover:underline font-mono">{selectedVuln.cve_id}</a>
                              </>
                            )}
                            <span className="text-muted-foreground">First Seen</span>
                            <span>{formatDate(selectedVuln.first_detected)}</span>
                            <span className="text-muted-foreground">Last Seen</span>
                            <span>{formatDate(selectedVuln.last_detected)}</span>
                            <span className="text-muted-foreground">Age</span>
                            <span>{formatVulnAge(selectedVuln.first_detected)}</span>
                          </div>
                        </div>

                        {selectedVuln.remediation && (
                          <div className="pt-2 border-t">
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Solution</h4>
                            <p className="text-sm">{selectedVuln.remediation}</p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full py-12">
                        <Shield className="h-12 w-12 text-muted-foreground mb-3" />
                        <p className="text-muted-foreground">Select a finding to view details</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                  <p className="text-muted-foreground">No security findings detected for this asset</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* App Structure Tab */}
        {activeTab === 'app-structure' && (
          <div className="space-y-6">
            {appStructureLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin" />
                <span className="ml-2 text-muted-foreground">Loading app structure data...</span>
              </div>
            ) : (
              <>
                {/* Summary Stats - Shows data from all scans containing this asset */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <FolderSearch className="h-4 w-4" />
                      Discovered from {appStructure?.summary?.scans_included || 0} Scans
                    </CardTitle>
                    <CardDescription>
                      All paths, URLs, parameters, and JS files from Katana, ParamSpider, and Wayback scans that contain <code className="text-primary">{asset.value}</code>
                    </CardDescription>
                  </CardHeader>
                </Card>

                <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Link2 className="h-6 w-6 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_paths || 0}</p>
                          <p className="text-xs text-muted-foreground">Paths</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-6 w-6 text-green-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_urls || 0}</p>
                          <p className="text-xs text-muted-foreground">URLs</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Hash className="h-6 w-6 text-orange-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_parameters || 0}</p>
                          <p className="text-xs text-muted-foreground">Parameters</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Code className="h-6 w-6 text-yellow-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_js_files || 0}</p>
                          <p className="text-xs text-muted-foreground">JS Files</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Server className="h-6 w-6 text-cyan-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_api_endpoints || 0}</p>
                          <p className="text-xs text-muted-foreground">API Endpoints</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-6 w-6 text-red-500" />
                        <div>
                          <p className="text-2xl font-bold">{appStructure?.summary?.total_interesting_urls || 0}</p>
                          <p className="text-xs text-muted-foreground">Interesting</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Technologies (from asset) */}
                {asset.technologies && asset.technologies.length > 0 && (
                  <Card>
                    <CardHeader>
                      <div className="flex items-center gap-2">
                        <Cpu className="h-5 w-5" />
                        <CardTitle>Technologies ({asset.technologies.length})</CardTitle>
                      </div>
                      <CardDescription>Detected technologies, frameworks, and libraries</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {asset.technologies.map((tech: Technology, idx: number) => (
                          <Badge key={idx} variant="outline" className="py-1.5 px-3">
                            <span className="font-medium">{tech.name}</span>
                            {tech.version && <span className="text-muted-foreground ml-1">v{tech.version}</span>}
                            {tech.categories && tech.categories.length > 0 && (
                              <span className="text-xs text-muted-foreground ml-2">({tech.categories[0]})</span>
                            )}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* URLs (Full URLs from scans) */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Globe className="h-5 w-5 text-green-500" />
                      <CardTitle>URLs ({appStructure?.urls?.length || 0})</CardTitle>
                    </div>
                    <CardDescription>Full URLs discovered from web crawling</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {appStructure?.urls && appStructure.urls.length > 0 ? (
                      <div className="max-h-80 overflow-y-auto space-y-1 bg-muted/30 rounded-lg p-3">
                        {appStructure.urls.slice(0, 100).map((url: string, idx: number) => (
                          <a
                            key={idx}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 font-mono text-xs text-muted-foreground hover:text-blue-500 transition-colors py-1 border-b border-border/50 last:border-0"
                          >
                            <ExternalLink className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{url}</span>
                          </a>
                        ))}
                        {appStructure.urls.length > 100 && (
                          <div className="text-xs text-muted-foreground pt-2 border-t">
                            +{appStructure.urls.length - 100} more URLs
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Globe className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                        <p className="text-muted-foreground">No URLs discovered yet</p>
                        <p className="text-xs text-muted-foreground mt-1">Run Katana or WaybackURLs scan on this domain</p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Paths/Endpoints */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Link2 className="h-5 w-5 text-blue-500" />
                      <CardTitle>Paths ({appStructure?.paths?.length || 0})</CardTitle>
                    </div>
                    <CardDescription>Discovered URL paths and routes</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {appStructure?.paths && appStructure.paths.length > 0 ? (
                      <div className="max-h-80 overflow-y-auto space-y-1 bg-muted/30 rounded-lg p-3">
                        {appStructure.paths.slice(0, 100).map((path: string, idx: number) => (
                          <div key={idx} className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors py-1 border-b border-border/50 last:border-0">
                            {path}
                          </div>
                        ))}
                        {appStructure.paths.length > 100 && (
                          <div className="text-xs text-muted-foreground pt-2 border-t">
                            +{appStructure.paths.length - 100} more paths
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Link2 className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                        <p className="text-muted-foreground">No paths discovered yet</p>
                        <p className="text-xs text-muted-foreground mt-1">Run a Katana scan to discover paths</p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Parameters */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Hash className="h-5 w-5 text-orange-500" />
                      <CardTitle>URL Parameters ({appStructure?.parameters?.length || 0})</CardTitle>
                    </div>
                    <CardDescription>Query parameters that may be vulnerable to injection attacks</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {appStructure?.parameters && appStructure.parameters.length > 0 ? (
                      <div className="space-y-4">
                        <div className="flex flex-wrap gap-2">
                          {appStructure.parameters.slice(0, 150).map((param: string, idx: number) => (
                            <Badge 
                              key={idx} 
                              variant="outline" 
                              className="font-mono text-xs bg-orange-500/10 text-orange-600 border-orange-500/30"
                            >
                              {param}
                            </Badge>
                          ))}
                          {appStructure.parameters.length > 150 && (
                            <Badge variant="outline" className="text-xs">
                              +{appStructure.parameters.length - 150} more
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Test for XSS, SQLi, SSRF, or other injection attacks using Burp Suite or SQLMap.
                        </p>
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Hash className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                        <p className="text-muted-foreground">No parameters discovered yet</p>
                        <p className="text-xs text-muted-foreground mt-1">Run ParamSpider or Katana to discover URL parameters</p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* JavaScript Files */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Code className="h-5 w-5 text-yellow-500" />
                      <CardTitle>JavaScript Files ({appStructure?.js_files?.length || 0})</CardTitle>
                    </div>
                    <CardDescription>JS files that may contain API endpoints, secrets, or sensitive information</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {appStructure?.js_files && appStructure.js_files.length > 0 ? (
                      <div className="max-h-80 overflow-y-auto space-y-1 bg-muted/30 rounded-lg p-3">
                        {appStructure.js_files.slice(0, 50).map((jsFile: string, idx: number) => (
                          <a
                            key={idx}
                            href={jsFile.startsWith('http') ? jsFile : `https://${asset.value}${jsFile}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 font-mono text-xs text-muted-foreground hover:text-blue-500 transition-colors py-1 border-b border-border/50 last:border-0"
                          >
                            <ExternalLink className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{jsFile}</span>
                          </a>
                        ))}
                        {appStructure.js_files.length > 50 && (
                          <div className="text-xs text-muted-foreground pt-2 border-t">
                            +{appStructure.js_files.length - 50} more JS files
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Code className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                        <p className="text-muted-foreground">No JavaScript files discovered yet</p>
                        <p className="text-xs text-muted-foreground mt-1">Run a Katana scan to discover JS files</p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Interesting URLs (from Wayback) */}
                {appStructure?.interesting_urls && appStructure.interesting_urls.length > 0 && (
                  <Card>
                    <CardHeader>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-red-500" />
                        <CardTitle>Interesting URLs ({appStructure.interesting_urls.length})</CardTitle>
                      </div>
                      <CardDescription>Potentially sensitive URLs discovered from Wayback Machine</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="max-h-80 overflow-y-auto space-y-1 bg-muted/30 rounded-lg p-3">
                        {appStructure.interesting_urls.slice(0, 50).map((url: string, idx: number) => (
                          <a
                            key={idx}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 font-mono text-xs text-red-400 hover:text-red-300 transition-colors py-1 border-b border-border/50 last:border-0"
                          >
                            <ExternalLink className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{url}</span>
                          </a>
                        ))}
                        {appStructure.interesting_urls.length > 50 && (
                          <div className="text-xs text-muted-foreground pt-2 border-t">
                            +{appStructure.interesting_urls.length - 50} more interesting URLs
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Source Breakdown */}
                {appStructure?.source_breakdown && Object.keys(appStructure.source_breakdown).length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm">Source Breakdown</CardTitle>
                      <CardDescription>Where this data was discovered from</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {Object.entries(appStructure.source_breakdown).map(([source, counts]: [string, any]) => (
                          <div key={source} className="p-4 bg-muted/30 rounded-lg">
                            <h4 className="font-medium capitalize mb-2">{source}</h4>
                            <div className="flex flex-wrap gap-1">
                              {Object.entries(counts).filter(([_, v]) => (v as number) > 0).map(([key, value]) => (
                                <Badge key={key} variant="secondary" className="text-xs">
                                  {key.replace(/_/g, ' ')}: {value as number}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Testing Recommendations */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Testing Recommendations</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm text-muted-foreground space-y-2">
                    <p>Based on the discovered application structure, consider the following testing approaches:</p>
                    <ul className="list-disc pl-6 space-y-1">
                      {(appStructure?.parameters?.length || 0) > 0 && (
                        <li><strong>Parameter Testing:</strong> {appStructure?.parameters?.length} parameters found - test for XSS, SQLi, SSRF, IDOR</li>
                      )}
                      {(appStructure?.js_files?.length || 0) > 0 && (
                        <li><strong>JS Analysis:</strong> {appStructure?.js_files?.length} JS files - search for hardcoded secrets, API keys, and internal endpoints</li>
                      )}
                      {(appStructure?.paths?.length || 0) > 0 && (
                        <li><strong>Endpoint Fuzzing:</strong> {appStructure?.paths?.length} paths - test for authentication bypass, authorization flaws</li>
                      )}
                      {asset.technologies && asset.technologies.length > 0 && (
                        <li><strong>Technology-specific:</strong> Check for known CVEs in {asset.technologies.slice(0, 3).map((t: Technology) => t.name).join(', ')}</li>
                      )}
                      {(appStructure?.interesting_urls?.length || 0) > 0 && (
                        <li><strong>Historical URLs:</strong> {appStructure?.interesting_urls?.length} interesting URLs from Wayback - check for exposed configs, backups, admin panels</li>
                      )}
                    </ul>
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        )}

        {/* Open Ports Tab */}
        {activeTab === 'ports' && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Open Ports ({asset.port_services?.length || 0})
                </CardTitle>
                {asset.port_services && asset.port_services.length > 0 && (
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={handleVerifyAllPorts}
                    disabled={asset.port_services.every(p => p.verified)}
                  >
                    <ScanLine className="h-4 w-4 mr-2" />
                    Verify All with Nmap
                  </Button>
                )}
              </div>
              <CardDescription>
                {asset.port_services?.filter(p => p.verified).length || 0} of {asset.port_services?.length || 0} ports verified with nmap
              </CardDescription>
            </CardHeader>
            <CardContent>
              {asset.port_services && asset.port_services.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead>Found at IP</TableHead>
                    <TableHead>Product</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Verified</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {asset.port_services.map((port) => (
                    <TableRow key={port.id}>
                      <TableCell className="font-mono font-bold">{port.port}</TableCell>
                      <TableCell className="uppercase text-muted-foreground">{port.protocol}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {port.service || '—'}
                          {port.is_ssl && <Lock className="h-3 w-3 text-green-400" />}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm text-blue-400">
                        {port.scanned_ip || asset.ip_address || '—'}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col">
                          <span>{port.product || '—'}</span>
                          {port.version && <span className="text-xs text-muted-foreground font-mono">{port.version}</span>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={port.state === 'open' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}>
                          {port.state}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {port.verified ? (
                          <div className="flex items-center gap-1">
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                            <div className="flex flex-col">
                              <Badge className={
                                port.verified_state === 'open' ? 'bg-green-500/20 text-green-400' :
                                port.verified_state === 'filtered' ? 'bg-yellow-500/20 text-yellow-400' :
                                port.verified_state === 'closed' ? 'bg-red-500/20 text-red-400' :
                                'bg-gray-500/20 text-gray-400'
                              }>
                                {port.verified_state || 'verified'}
                              </Badge>
                            </div>
                          </div>
                        ) : (
                          <span className="text-muted-foreground text-xs">Not verified</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {port.is_risky ? (
                          <Badge className="bg-red-500/20 text-red-400">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Risky
                          </Badge>
                        ) : '—'}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs"
                          onClick={() => handleVerifyPort(port.id)}
                          disabled={verifyingPorts.has(port.id)}
                          title={port.verified ? 'Re-verify with nmap' : 'Verify with nmap'}
                        >
                          {verifyingPorts.has(port.id) ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <>
                              <ScanLine className="h-3 w-3 mr-1" />
                              {port.verified ? 'Re-verify' : 'Verify'}
                            </>
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              ) : (
                <div className="text-center py-12">
                  <Network className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No open ports detected for this asset</p>
                  <p className="text-xs text-muted-foreground mt-2">Run a port scan to discover open ports</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Activity Tab */}
        {activeTab === 'activity' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Activity Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {asset.last_scan_date && (
                  <div className="flex items-start gap-4 p-4 border rounded-lg">
                    <div className="p-2 rounded-full bg-primary/10">
                      <Shield className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium">Last Scan</p>
                      <p className="text-sm text-muted-foreground">{asset.last_scan_name || 'Security scan'}</p>
                      <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.last_scan_date)}</p>
                    </div>
                  </div>
                )}
                <div className="flex items-start gap-4 p-4 border rounded-lg">
                  <div className="p-2 rounded-full bg-blue-500/10">
                    <Eye className="h-4 w-4 text-blue-500" />
                    </div>
                  <div>
                    <p className="font-medium">Last Seen</p>
                    <p className="text-sm text-muted-foreground">Asset was last observed</p>
                    <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.last_seen)}</p>
                  </div>
                </div>
                <div className="flex items-start gap-4 p-4 border rounded-lg">
                  <div className="p-2 rounded-full bg-green-500/10">
                    <Calendar className="h-4 w-4 text-green-500" />
                  </div>
                  <div>
                    <p className="font-medium">First Discovered</p>
                    <p className="text-sm text-muted-foreground">Asset was first discovered via {asset.discovery_source || 'external discovery'}</p>
                    <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.first_seen)}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Mitigations Tab */}
        {activeTab === 'mitigations' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Mitigations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <Settings className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No mitigations configured for this asset</p>
                <p className="text-sm text-muted-foreground mt-2">Mitigations can be added to document remediation steps</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Application Stack Map */}
        <ApplicationMap
          assetValue={asset.value}
          assetType={asset.asset_type}
          portServices={asset.port_services || []}
          technologies={asset.technologies || []}
          loginPortals={asset.login_portals || []}
          httpStatus={asset.http_status}
          httpTitle={asset.http_title}
        />
      </div>

      {/* ACS Edit Dialog */}
      <Dialog open={acsDialogOpen} onOpenChange={setAcsDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Asset Criticality Score (ACS)</DialogTitle>
            <DialogDescription>
              Set the criticality score for this asset (0-10). Higher scores indicate more critical assets.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="acs-score">ACS Score</Label>
              <div className="flex items-center gap-4">
                <Input
                  id="acs-score"
                  type="number"
                  min={0}
                  max={10}
                  value={editingAcs}
                  onChange={(e) => setEditingAcs(Math.min(10, Math.max(0, parseInt(e.target.value) || 0)))}
                  className="w-24"
                />
                <div className="flex-1">
                  <input
                    type="range"
                    min={0}
                    max={10}
                    value={editingAcs}
                    onChange={(e) => setEditingAcs(parseInt(e.target.value))}
                    className="w-full"
                  />
                </div>
                <span className={`text-lg font-bold ${
                  editingAcs >= 8 ? 'text-red-500' : 
                  editingAcs >= 6 ? 'text-orange-500' : 
                  editingAcs >= 4 ? 'text-yellow-500' : 
                  'text-green-500'
                }`}>
                  {editingAcs}/10
                </span>
              </div>
            </div>
            <div className="text-xs text-muted-foreground space-y-1">
              <p><strong>0-3:</strong> Low criticality (static pages, dev/test systems)</p>
              <p><strong>4-5:</strong> Medium criticality (standard business systems)</p>
              <p><strong>6-7:</strong> High criticality (login portals, customer-facing apps)</p>
              <p><strong>8-10:</strong> Critical (payment systems, admin panels, databases)</p>
            </div>
          </div>
          <DialogFooter className="flex-col sm:flex-row gap-2">
            <Button variant="outline" onClick={handleCalculateRiskDrivers} disabled={savingAcs}>
              {savingAcs ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
              Auto-Calculate
            </Button>
            <Button onClick={handleSaveAcs} disabled={savingAcs}>
              {savingAcs ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Save Score
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Finding Dialog */}
      {asset && (
        <AddFindingDialog
          assetId={parseInt(assetId)}
          assetValue={asset.value}
          open={addFindingDialogOpen}
          onOpenChange={setAddFindingDialogOpen}
          onFindingAdded={handleFindingAdded}
        />
      )}
    </MainLayout>
  );
}
