'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
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
  Play,
  ScanLine,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  StopCircle,
  Cloud,
} from 'lucide-react';
import { api, NmapProfileConfig } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import { ScanNavTabs } from '@/components/scanning/ScanNavTabs';
import { NmapScanConfigurator, DEFAULT_NMAP_CONFIG } from '@/components/scanning/NmapScanConfigurator';

interface Scan {
  id: number;
  name: string;
  organization_id: number;
  organization_name?: string;
  scan_type: string;
  status: string;
  targets?: string[];
  progress?: number;
  assets_discovered?: number;
  vulnerabilities_found?: number;
  started_at?: string;
  completed_at?: string;
  targets_count?: number;
  findings_count?: number;
  created_at: string;
  results?: {
    ports_found?: number;
    ports_imported?: number;
    live_hosts?: number;
    host_results?: Array<{
      host: string;
      ip: string;
      is_live: boolean;
      open_ports: number[];
      port_count: number;
      asset_id?: number;
      asset_created?: boolean;
    }>;
    targets_expanded?: number;
    [key: string]: any;
  };
}

interface QueueStatus {
  max_concurrent: number;
  running: number;
  pending: number;
  available_slots: number;
  can_start_immediately: boolean;
  running_scans: Array<{
    id: number;
    name: string;
    scan_type: string;
    started_at: string;
    current_step?: string;
    is_scheduled: boolean;
  }>;
}

export default function ScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [queueStatus, setQueueStatus] = useState<QueueStatus | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    organization_id: '',
    scan_type: 'vulnerability',
    targets: '',
    scanner: 'naabu',  // Port scanner: naabu, masscan, nmap
    ports: '',         // Port specification for port scans
    severity: ['critical', 'high'] as string[],  // Default to critical & high for faster scans
    katana_batch_stdin: false,  // One process, all JS URLs for AI/sensitive-data assessment
    // Themis (Prowler CSPM) options
    themis_provider: 'aws',
    themis_compliance: '',
    themis_aws_profile: '',
    themis_aws_region: '',
    themis_azure_subscription: '',
    themis_gcp_project: '',
    themis_kubeconfig: '',
    themis_kube_context: '',
    themis_services: '', // comma-separated
  });
  const [nmapConfig, setNmapConfig] = useState<NmapProfileConfig>(DEFAULT_NMAP_CONFIG);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [scansData, orgsData, queueData] = await Promise.all([
        api.getScans({ limit: 50 }),
        api.getOrganizations(),
        api.getScanQueueStatus().catch(() => null),
      ]);

      setScans(scansData.items || scansData || []);
      setOrganizations(orgsData);
      setQueueStatus(queueData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch scans',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Poll for updates every 10 seconds
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleCreateScan = async () => {
    if (!formData.organization_id) {
      toast({
        title: 'Error',
        description: 'Please select an organization',
        variant: 'destructive',
      });
      return;
    }

    if (!formData.name.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter a scan name',
        variant: 'destructive',
      });
      return;
    }

    setSubmitting(true);
    try {
      const targets = formData.targets
        .split('\n')
        .map((t) => t.trim())
        .filter((t) => t);

      // Build config based on scan type
      const config: Record<string, any> = {};
      if (formData.scan_type === 'port_scan') {
        config.scanner = formData.scanner;
        if (formData.scanner === 'nmap') {
          // Nmap picker owns the full configuration, including ports.
          config.nmap_scan_type = nmapConfig.nmap_scan_type;
          config.timing = nmapConfig.timing;
          config.service_detection = nmapConfig.service_detection;
          config.os_detection = nmapConfig.os_detection;
          config.nse_scripts = nmapConfig.nse_scripts;
          if (nmapConfig.ports && nmapConfig.ports.trim()) {
            config.ports = nmapConfig.ports.trim();
          }
        } else if (formData.ports) {
          config.ports = formData.ports;
        }
      } else if (formData.scan_type === 'vulnerability') {
        config.severity = formData.severity;
      } else if (formData.scan_type === 'katana') {
        config.depth = 5;
        config.batch_stdin = formData.katana_batch_stdin;
      } else if (formData.scan_type === 'llm_red_team') {
        config.auto_discover = true;
        config.use_llm_grading = true;
      } else if (formData.scan_type === 'themis_cspm') {
        config.provider = formData.themis_provider;
        if (formData.themis_compliance) config.compliance = formData.themis_compliance;
        if (formData.themis_services.trim()) {
          config.services = formData.themis_services.split(',').map((s) => s.trim()).filter(Boolean);
        }
        if (formData.themis_provider === 'aws') {
          if (formData.themis_aws_profile) config.profile = formData.themis_aws_profile;
          if (formData.themis_aws_region) config.region = formData.themis_aws_region;
        } else if (formData.themis_provider === 'azure') {
          if (formData.themis_azure_subscription) config.subscription = formData.themis_azure_subscription;
        } else if (formData.themis_provider === 'gcp') {
          if (formData.themis_gcp_project) config.project_id = formData.themis_gcp_project;
        } else if (formData.themis_provider === 'kubernetes') {
          if (formData.themis_kubeconfig) config.kubeconfig = formData.themis_kubeconfig;
          if (formData.themis_kube_context) config.context = formData.themis_kube_context;
        }
      }

      await api.createScan({
        name: formData.name.trim(),
        organization_id: parseInt(formData.organization_id),
        scan_type: formData.scan_type,
        targets: targets.length > 0 ? targets : undefined,
        config: Object.keys(config).length > 0 ? config : undefined,
      });

      toast({
        title: 'Scan Started',
        description: 'The scan has been queued and will start shortly.',
      });

      setCreateDialogOpen(false);
      setFormData({
        name: '',
        organization_id: '',
        scan_type: 'vulnerability',
        targets: '',
        scanner: 'naabu',
        ports: '',
        severity: ['critical', 'high'],
        katana_batch_stdin: false,
        themis_provider: 'aws',
        themis_compliance: '',
        themis_aws_profile: '',
        themis_aws_region: '',
        themis_azure_subscription: '',
        themis_gcp_project: '',
        themis_kubeconfig: '',
        themis_kube_context: '',
        themis_services: '',
      });
      setNmapConfig(DEFAULT_NMAP_CONFIG);
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to start scan',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent row click navigation
    try {
      await api.cancelScan(scanId);
      toast({
        title: 'Scan Cancelled',
        description: 'The scan has been stopped.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to cancel scan',
        variant: 'destructive',
      });
    }
  };

  const handleRetryScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent row click navigation
    try {
      await api.retryScan(scanId);
      toast({
        title: 'Scan Retry Started',
        description: 'The scan has been reset and will be processed shortly.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to retry scan',
        variant: 'destructive',
      });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running':
      case 'in_progress':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'pending':
      case 'queued':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'bg-green-500/20 text-green-400';
      case 'running':
      case 'in_progress':
        return 'bg-blue-500/20 text-blue-400';
      case 'failed':
        return 'bg-red-500/20 text-red-400';
      case 'pending':
      case 'queued':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <MainLayout>
      <Header title="Scanning" subtitle="Manage scans and schedules" />
      <ScanNavTabs />

      <div className="p-6">
        {/* Queue Status Indicator */}
        {queueStatus && (
          <div className="mb-4 p-3 rounded-lg border bg-card">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className="flex items-center gap-2">
                  <div className={`h-2 w-2 rounded-full ${queueStatus.can_start_immediately ? 'bg-green-500' : 'bg-amber-500'} animate-pulse`} />
                  <span className="text-sm text-muted-foreground">
                    {queueStatus.can_start_immediately ? 'Ready for scans' : 'Queue busy'}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-muted-foreground">
                    Running: <span className="text-foreground font-medium">{queueStatus.running}/{queueStatus.max_concurrent}</span>
                  </span>
                  <span className="text-muted-foreground">
                    Pending: <span className="text-foreground font-medium">{queueStatus.pending}</span>
                  </span>
                  <span className="text-muted-foreground">
                    Available: <span className={`font-medium ${queueStatus.available_slots > 0 ? 'text-green-500' : 'text-amber-500'}`}>
                      {queueStatus.available_slots} slot{queueStatus.available_slots !== 1 ? 's' : ''}
                    </span>
                  </span>
                </div>
              </div>
              {queueStatus.running_scans.length > 0 && (
                <div className="text-xs text-muted-foreground">
                  Active: {queueStatus.running_scans.map(s => s.name).join(', ')}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Button variant="outline" size="sm" onClick={fetchData}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Play className="h-4 w-4 mr-2" />
                New Scan
              </Button>
            </DialogTrigger>
            <DialogContent className="max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Start New Scan</DialogTitle>
                <DialogDescription>
                  Configure and start a new vulnerability or discovery scan.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Scan Name</Label>
                  <Input
                    placeholder="e.g., Weekly vulnerability scan"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Organization</Label>
                  <Select
                    value={formData.organization_id}
                    onValueChange={(value) =>
                      setFormData({ ...formData, organization_id: value })
                    }
                  >
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
                  <Label>Scan Type</Label>
                  <Select
                    value={formData.scan_type}
                    onValueChange={(value) => setFormData({ ...formData, scan_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="vulnerability">Vulnerability Scan (Nuclei)</SelectItem>
                      <SelectItem value="nuclei_critical">Nuclei - Critical Only</SelectItem>
                      <SelectItem value="nuclei_critical_high">Nuclei - Critical & High</SelectItem>
                      <SelectItem value="web_scan">Web Application Scan</SelectItem>
                      <SelectItem value="discovery">Asset Discovery</SelectItem>
                      <SelectItem value="subdomain_enum">Subdomain Enumeration</SelectItem>
                      <SelectItem value="port_scan">Port Scan</SelectItem>
                      <SelectItem value="critical_ports">Critical Port Monitoring</SelectItem>
                      <SelectItem value="technology">Technology Detection</SelectItem>
                      <SelectItem value="http_probe">HTTP Probe</SelectItem>
                      <SelectItem value="screenshot">Screenshot Capture</SelectItem>
                      <SelectItem value="katana">Deep Web Crawl (Katana)</SelectItem>
                      <SelectItem value="paramspider">Parameter Discovery</SelectItem>
                      <SelectItem value="waybackurls">Historical URLs (Wayback)</SelectItem>
                      <SelectItem value="tldfinder">TLD/Domain Discovery (tldfinder)</SelectItem>
                      <SelectItem value="login_portal">Login Portal Detection</SelectItem>
                      <SelectItem value="dns_resolution">DNS Resolution</SelectItem>
                      <SelectItem value="geo_enrich">Geolocation Enrichment</SelectItem>
                      <SelectItem value="full">Full Scan (All)</SelectItem>
                      <SelectItem value="llm_red_team">AI/LLM Red Team (Chatbot Testing)</SelectItem>
                      <SelectItem value="themis_cspm">
                        <span className="flex items-center gap-2">
                          <Cloud className="h-3.5 w-3.5 text-cyan-400" />
                          Themis — Cloud CSPM (Prowler)
                        </span>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Themis (Prowler) Cloud CSPM Options */}
                {formData.scan_type === 'themis_cspm' && (
                  <div className="space-y-4 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4">
                    <div className="flex items-center gap-2">
                      <Cloud className="h-4 w-4 text-cyan-400" />
                      <p className="text-sm font-medium">Themis — Cloud Security Posture Management</p>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Runs Prowler against your cloud provider and ingests every misconfiguration as a finding.
                      Targets are ignored — provider credentials must be available to the worker container.
                    </p>

                    <div className="space-y-2">
                      <Label>Cloud Provider</Label>
                      <Select
                        value={formData.themis_provider}
                        onValueChange={(value) => setFormData({ ...formData, themis_provider: value })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="aws">AWS</SelectItem>
                          <SelectItem value="azure">Azure</SelectItem>
                          <SelectItem value="gcp">GCP</SelectItem>
                          <SelectItem value="kubernetes">Kubernetes</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Compliance framework (optional)</Label>
                      <Select
                        value={formData.themis_compliance || '__none__'}
                        onValueChange={(value) =>
                          setFormData({ ...formData, themis_compliance: value === '__none__' ? '' : value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="All checks" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="__none__">All checks (default)</SelectItem>
                          <SelectItem value="cis_1.5_aws">CIS AWS Foundations 1.5</SelectItem>
                          <SelectItem value="cis_2.0_aws">CIS AWS Foundations 2.0</SelectItem>
                          <SelectItem value="cis_1.5_azure">CIS Azure 1.5</SelectItem>
                          <SelectItem value="cis_2.0_gcp">CIS GCP 2.0</SelectItem>
                          <SelectItem value="cis_1.8_kubernetes">CIS Kubernetes 1.8</SelectItem>
                          <SelectItem value="pci_3.2.1_aws">PCI DSS 3.2.1 (AWS)</SelectItem>
                          <SelectItem value="soc2_aws">SOC 2 (AWS)</SelectItem>
                          <SelectItem value="hipaa_aws">HIPAA (AWS)</SelectItem>
                          <SelectItem value="iso27001_2013_aws">ISO 27001:2013 (AWS)</SelectItem>
                          <SelectItem value="nist_800_53_revision_5_aws">NIST 800-53 r5 (AWS)</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        Pass any Prowler-supported compliance ID. Common ones are listed above.
                      </p>
                    </div>

                    {formData.themis_provider === 'aws' && (
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-2">
                          <Label>AWS Profile (optional)</Label>
                          <Input
                            placeholder="default"
                            value={formData.themis_aws_profile}
                            onChange={(e) => setFormData({ ...formData, themis_aws_profile: e.target.value })}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>AWS Region (optional)</Label>
                          <Input
                            placeholder="us-east-1"
                            value={formData.themis_aws_region}
                            onChange={(e) => setFormData({ ...formData, themis_aws_region: e.target.value })}
                          />
                        </div>
                      </div>
                    )}

                    {formData.themis_provider === 'azure' && (
                      <div className="space-y-2">
                        <Label>Azure Subscription ID (optional)</Label>
                        <Input
                          placeholder="00000000-0000-0000-0000-000000000000"
                          value={formData.themis_azure_subscription}
                          onChange={(e) =>
                            setFormData({ ...formData, themis_azure_subscription: e.target.value })
                          }
                        />
                      </div>
                    )}

                    {formData.themis_provider === 'gcp' && (
                      <div className="space-y-2">
                        <Label>GCP Project ID</Label>
                        <Input
                          placeholder="my-gcp-project-123"
                          value={formData.themis_gcp_project}
                          onChange={(e) => setFormData({ ...formData, themis_gcp_project: e.target.value })}
                        />
                      </div>
                    )}

                    {formData.themis_provider === 'kubernetes' && (
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-2">
                          <Label>Kubeconfig path (optional)</Label>
                          <Input
                            placeholder="/root/.kube/config"
                            value={formData.themis_kubeconfig}
                            onChange={(e) => setFormData({ ...formData, themis_kubeconfig: e.target.value })}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Context (optional)</Label>
                          <Input
                            placeholder="my-cluster"
                            value={formData.themis_kube_context}
                            onChange={(e) => setFormData({ ...formData, themis_kube_context: e.target.value })}
                          />
                        </div>
                      </div>
                    )}

                    <div className="space-y-2">
                      <Label>Services filter (optional, comma-separated)</Label>
                      <Input
                        placeholder="iam,s3,ec2"
                        value={formData.themis_services}
                        onChange={(e) => setFormData({ ...formData, themis_services: e.target.value })}
                      />
                      <p className="text-xs text-muted-foreground">
                        Limit Prowler to specific services. Leave empty to scan everything.
                      </p>
                    </div>
                  </div>
                )}

                {/* Vulnerability Scan - Severity Selection */}
                {formData.scan_type === 'vulnerability' && (
                  <div className="space-y-3">
                    <Label>Severity Levels</Label>
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { id: 'critical', label: 'Critical', color: 'text-red-500' },
                        { id: 'high', label: 'High', color: 'text-orange-500' },
                        { id: 'medium', label: 'Medium', color: 'text-yellow-500' },
                        { id: 'low', label: 'Low', color: 'text-blue-500' },
                        { id: 'info', label: 'Info', color: 'text-gray-500' },
                      ].map((sev) => (
                        <div key={sev.id} className="flex items-center space-x-2">
                          <Checkbox
                            id={`severity-${sev.id}`}
                            checked={formData.severity.includes(sev.id)}
                            onCheckedChange={(checked) => {
                              if (checked) {
                                setFormData({
                                  ...formData,
                                  severity: [...formData.severity, sev.id],
                                });
                              } else {
                                setFormData({
                                  ...formData,
                                  severity: formData.severity.filter((s) => s !== sev.id),
                                });
                              }
                            }}
                          />
                          <label
                            htmlFor={`severity-${sev.id}`}
                            className={`text-sm font-medium cursor-pointer ${sev.color}`}
                          >
                            {sev.label}
                          </label>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Fewer severities = faster scan. Critical & High recommended for quick scans.
                    </p>
                  </div>
                )}

                {/* Katana: batch mode for JS collection / AI review */}
                {formData.scan_type === 'katana' && (
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="katana_batch_stdin"
                        checked={formData.katana_batch_stdin}
                        onCheckedChange={(checked) =>
                          setFormData({ ...formData, katana_batch_stdin: !!checked })
                        }
                      />
                      <label htmlFor="katana_batch_stdin" className="text-sm font-medium cursor-pointer">
                        Collect all JS in one run (for AI / sensitive-data assessment)
                      </label>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      One Katana process with URLs on stdin; outputs a single list of JS URLs for review.
                    </p>
                  </div>
                )}

                {/* LLM Red Team Options */}
                {formData.scan_type === 'llm_red_team' && (
                  <div className="space-y-2 rounded-lg border border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950 p-3">
                    <p className="text-sm font-medium">AI/LLM Red Team Assessment</p>
                    <p className="text-xs text-muted-foreground">
                      Tests chatbot and AI endpoints for prompt injection, jailbreak, data exfiltration, SSRF,
                      system prompt leakage, excessive agency, hallucination, and harmful content generation.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      <strong>Targets:</strong> Enter full URLs (e.g. https://example.com). The scanner will auto-discover
                      chatbot API endpoints (/api/chat, /api/message, etc.) and test them against OWASP Top 10 for LLMs.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Findings are mapped to CWE IDs and created automatically in the findings table.
                    </p>
                  </div>
                )}

                {/* Port Scan Options */}
                {formData.scan_type === 'port_scan' && (
                  <>
                    <div className="space-y-2">
                      <Label>Scanner Tool</Label>
                      <Select
                        value={formData.scanner}
                        onValueChange={(value) => setFormData({ ...formData, scanner: value })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="naabu">
                            <div className="flex flex-col">
                              <span>Naabu (Recommended)</span>
                              <span className="text-xs text-muted-foreground">Fast, reliable port scanner</span>
                            </div>
                          </SelectItem>
                          <SelectItem value="masscan">
                            <div className="flex flex-col">
                              <span>Masscan</span>
                              <span className="text-xs text-muted-foreground">Fastest scanner, good for large ranges</span>
                            </div>
                          </SelectItem>
                          <SelectItem value="nmap">
                            <div className="flex flex-col">
                              <span>Nmap</span>
                              <span className="text-xs text-muted-foreground">Most accurate, includes service detection</span>
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {formData.scanner === 'nmap' ? (
                      <NmapScanConfigurator value={nmapConfig} onChange={setNmapConfig} />
                    ) : (
                      <div className="space-y-2">
                        <Label>Ports (optional)</Label>
                        <Input
                          placeholder="80,443,8080 or 1-1000 or - for all"
                          value={formData.ports}
                          onChange={(e) => setFormData({ ...formData, ports: e.target.value })}
                        />
                        <p className="text-xs text-muted-foreground">
                          Leave empty to scan top 100 common ports
                        </p>
                      </div>
                    )}
                  </>
                )}

                {formData.scan_type !== 'themis_cspm' && (
                  <div className="space-y-2">
                    <Label>Targets (optional, one per line)</Label>
                    <textarea
                      className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      placeholder="example.com&#10;sub.example.com&#10;192.168.1.1"
                      value={formData.targets}
                      onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">
                      Leave empty to scan all assets in the organization
                    </p>
                  </div>
                )}
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateScan} disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Starting...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Start Scan
                    </>
                  )}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Live Assets</TableHead>
                <TableHead>Ports</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead className="w-[80px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8 text-muted-foreground">
                    No scans yet. Start a new scan to begin discovering vulnerabilities.
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow 
                    key={scan.id} 
                    className="cursor-pointer hover:bg-secondary/50 transition-colors"
                    onClick={() => router.push(`/scans/${scan.id}`)}
                  >
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium text-primary hover:underline">{scan.name}</span>
                        {scan.progress !== undefined && scan.progress > 0 && scan.progress < 100 && (
                          <div className="flex items-center gap-2 mt-1">
                            <div className="w-20 h-1.5 bg-secondary rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-primary transition-all" 
                                style={{ width: `${scan.progress}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground">{scan.progress}%</span>
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <Badge className={getStatusColor(scan.status)}>{scan.status}</Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{scan.scan_type?.replace(/_/g, ' ')}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {scan.organization_name || '-'}
                    </TableCell>
                    <TableCell>
                      {scan.results?.targets_expanded || scan.targets_count || scan.targets?.length ? (
                        <div className="flex flex-col">
                          <span className="font-mono text-sm">
                            {scan.results?.targets_expanded || scan.targets_count || scan.targets?.length}
                          </span>
                          {scan.targets?.length && scan.targets.length <= 3 && (
                            <span className="text-xs text-muted-foreground truncate max-w-[120px]">
                              {scan.targets.slice(0, 2).join(', ')}
                              {scan.targets.length > 2 && '...'}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const liveHosts = scan.results?.live_hosts || 
                          scan.results?.host_results?.filter((h: any) => h.is_live).length || 
                          0;
                        const totalHosts = scan.results?.host_results_count || scan.results?.host_results?.length || scan.assets_discovered || 0;
                        
                        if (liveHosts > 0) {
                          return (
                            <div className="flex items-center gap-1">
                              <Badge className="bg-green-500/20 text-green-400">{liveHosts}</Badge>
                              {totalHosts > liveHosts && (
                                <span className="text-xs text-muted-foreground">/ {totalHosts}</span>
                              )}
                            </div>
                          );
                        } else if (scan.assets_discovered !== undefined && scan.assets_discovered > 0) {
                          return <Badge variant="secondary">{scan.assets_discovered}</Badge>;
                        }
                        return <span className="text-muted-foreground">—</span>;
                      })()}
                    </TableCell>
                    <TableCell>
                      {scan.results?.ports_found !== undefined && scan.results.ports_found > 0 ? (
                        <Badge variant="outline" className="font-mono">{scan.results.ports_found}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.findings_count !== undefined && scan.findings_count > 0 ? (
                        <Badge variant="destructive">{scan.findings_count}</Badge>
                      ) : scan.vulnerabilities_found !== undefined && scan.vulnerabilities_found > 0 ? (
                        <Badge variant="destructive">{scan.vulnerabilities_found}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                      {scan.started_at ? formatDate(scan.started_at) : formatDate(scan.created_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                      {scan.started_at && scan.completed_at
                        ? `${Math.round(
                            (new Date(scan.completed_at).getTime() -
                              new Date(scan.started_at).getTime()) /
                              1000
                          )}s`
                        : scan.status?.toLowerCase() === 'running'
                        ? 'In progress...'
                        : scan.status?.toLowerCase() === 'pending'
                        ? 'Waiting...'
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {(scan.status?.toLowerCase() === 'running' || scan.status?.toLowerCase() === 'pending') && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0 text-red-500 hover:text-red-600 hover:bg-red-500/10"
                            onClick={(e) => handleCancelScan(scan.id, e)}
                            title="Cancel scan"
                          >
                            <StopCircle className="h-4 w-4" />
                          </Button>
                        )}
                        {(scan.status?.toLowerCase() === 'running' || scan.status?.toLowerCase() === 'failed' || scan.status?.toLowerCase() === 'cancelled') && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0 text-blue-500 hover:text-blue-600 hover:bg-blue-500/10"
                            onClick={(e) => handleRetryScan(scan.id, e)}
                            title="Retry scan"
                          >
                            <RefreshCw className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>
      </div>
    </MainLayout>
  );
}














