'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { 
  Settings, 
  Key, 
  Bell, 
  Shield, 
  Database, 
  Loader2, 
  CheckCircle, 
  AlertCircle,
  Plus,
  X,
  Building2,
  Mail,
  Globe,
  Sparkles,
  Flame,
  TrendingUp,
  RefreshCw,
  Search,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface ApiConfig {
  id: number;
  service_name: string;
  api_key_masked: string | null;
  api_user: string | null;
  config: Record<string, any>;
  is_active: boolean;
  is_valid: boolean;
  last_used: string | null;
  usage_count: number;
}

const API_SERVICES = [
  {
    name: 'anthropic',
    label: 'Anthropic (Claude)',
    description: 'BYOK for the AI agent — planning, analysis, and offensive workflows. Use a Console API key (sk-ant-…), not a Claude Code / Cursor key.',
    free: false,
    hasUser: false,
    link: 'https://console.anthropic.com/settings/keys',
    group: 'AI / LLM',
  },
  {
    name: 'openai',
    label: 'OpenAI',
    description: 'BYOK for GPT models via the agent model router (provider string: openai).',
    free: false,
    hasUser: false,
    link: 'https://platform.openai.com/api-keys',
    group: 'AI / LLM',
  },
  {
    name: 'deepseek',
    label: 'DeepSeek',
    description: 'OpenAI-compatible DeepSeek models for agent tasks (provider string: deepseek).',
    free: false,
    hasUser: false,
    link: 'https://platform.deepseek.com/',
    group: 'AI / LLM',
  },
  {
    name: 'kimi',
    label: 'Kimi (Moonshot)',
    description: 'Moonshot Kimi models for the agent (provider string: kimi). Keys from platform.kimi.ai; default model kimi-k3.',
    free: false,
    hasUser: false,
    link: 'https://platform.kimi.ai/',
    group: 'AI / LLM',
  },
  {
    name: 'groq',
    label: 'Groq',
    description: 'Fast cloud inference with a free tier (provider string: groq). Default model llama-3.3-70b-versatile.',
    free: true,
    hasUser: false,
    link: 'https://console.groq.com/keys',
    group: 'AI / LLM',
  },
  {
    name: 'ollama',
    label: 'Ollama (local)',
    description: 'Local models via Ollama — no cloud key. Used automatically as fallback when other providers have no API key. Default model qwen2.5:14b. Optional: save "ollama" as the key to mark configured.',
    free: true,
    hasUser: false,
    link: 'https://ollama.com/',
    group: 'AI / LLM',
  },
  {
    name: 'vulncheck',
    label: 'VulnCheck',
    description: 'KEV exploit intelligence — recently-added known-exploited CVEs, ransomware associations, threat-actor attribution, weaponized exploit evidence. Powers the Vulnerability Intelligence feed and OPES X-component scoring.',
    free: false,
    hasUser: false,
    link: 'https://vulncheck.com/',
    group: 'Vulnerability Intelligence',
  },
  {
    name: 'pdcp',
    label: 'ProjectDiscovery Cloud Platform',
    description: 'Nuclei template availability (is_template), PoC detection, remote exploitability flags per CVE. Powers the Vulnerability Intelligence detection coverage column and raises vulnx rate limits.',
    free: true,
    hasUser: false,
    link: 'https://cloud.projectdiscovery.io/',
    group: 'Vulnerability Intelligence',
  },
  {
    name: 'nvd',
    label: 'NVD (NIST)',
    description: 'Raises NVD API rate limits for CVE enrichment lookups (fallback when PDCP does not have a new CVE yet). Free key from nvd.nist.gov.',
    free: true,
    hasUser: false,
    link: 'https://nvd.nist.gov/developers/request-an-api-key',
    group: 'Vulnerability Intelligence',
  },
  { 
    name: 'virustotal', 
    label: 'VirusTotal', 
    description: 'Subdomain discovery via VT database (up to 100 subdomains per domain)',
    free: false,
    hasUser: true,
    link: 'https://www.virustotal.com/gui/join-us',
    group: 'Asset Discovery',
  },
  { 
    name: 'whoisxml', 
    label: 'WhoisXML API', 
    description: 'Discover IP ranges and CIDRs by organization name, DNS enrichment',
    free: false,
    hasUser: false,
    needsOrgNames: true,
    link: 'https://whoisxmlapi.com/',
    group: 'Asset Discovery',
  },
  { 
    name: 'otx', 
    label: 'AlienVault OTX', 
    description: 'Threat intelligence passive DNS and URL data (free API key available)',
    free: true,
    hasUser: false,
    link: 'https://otx.alienvault.com/api',
    group: 'Asset Discovery',
  },
  { 
    name: 'whoxy', 
    label: 'Whoxy', 
    description: 'Reverse WHOIS lookup by domain registration email',
    free: false,
    hasUser: false,
    needsEmails: true,
    link: 'https://www.whoxy.com/',
    group: 'Asset Discovery',
  },
  { 
    name: 'tracxn', 
    label: 'Tracxn', 
    description: 'Import M&A and acquisition history to discover domains from acquired companies',
    free: false,
    hasUser: false,
    link: 'https://platform.tracxn.com/',
    group: 'Asset Discovery',
  },
];

export default function SettingsPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [apiConfigs, setApiConfigs] = useState<ApiConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [apiUsers, setApiUsers] = useState<Record<string, string>>({});
  // Delphi enrichment status
  const [delphiStatus, setDelphiStatus] = useState<any>(null);
  const [delphiLoading, setDelphiLoading] = useState(false);
  const [delphiRefreshing, setDelphiRefreshing] = useState(false);
  const [delphiBatchRunning, setDelphiBatchRunning] = useState(false);
  const [delphiBatchResult, setDelphiBatchResult] = useState<any>(null);
  
  // Organization names for WhoisXML
  const [orgNames, setOrgNames] = useState<string[]>([]);
  const [newOrgName, setNewOrgName] = useState('');
  
  // Registration emails for Whoxy
  const [regEmails, setRegEmails] = useState<string[]>([]);
  const [newRegEmail, setNewRegEmail] = useState('');

  // CommonCrawl enumeration settings
  const [ccEnabled, setCcEnabled] = useState(true);
  const [ccYears, setCcYears] = useState('last1');
  const [ccMaxPerYear, setCcMaxPerYear] = useState('1');
  const [ccTimeout, setCcTimeout] = useState('120');
  const [ccKeywordSearch, setCcKeywordSearch] = useState(true);
  const [ccSettingsLoaded, setCcSettingsLoaded] = useState(false);
  
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const orgsData = await api.getOrganizations();
      setOrganizations(orgsData);
      if (orgsData.length > 0) {
        setSelectedOrg(orgsData[0].id.toString());
      }
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchApiConfigs = async (orgId: number) => {
    try {
      const data = await api.getApiConfigs(orgId);
      setApiConfigs(data.configs || []);
      
      // Load existing organization names and emails from config
      // Always set these values (even to empty arrays) to ensure clean state
      const whoisxmlConfig = data.configs?.find((c: ApiConfig) => c.service_name === 'whoisxml');
      setOrgNames(whoisxmlConfig?.config?.organization_names || []);
      
      const whoxyConfig = data.configs?.find((c: ApiConfig) => c.service_name === 'whoxy');
      setRegEmails(whoxyConfig?.config?.registration_emails || []);
    } catch (error) {
      console.error('Failed to fetch API configs:', error);
      // Reset to empty on error
      setOrgNames([]);
      setRegEmails([]);
    }
  };

  useEffect(() => {
    fetchData();
    fetchDelphiStatus();
  }, []);

  const fetchDelphiStatus = async () => {
    setDelphiLoading(true);
    try {
      const data = await api.getDelphiStatus();
      setDelphiStatus(data);
    } catch (error) {
      console.error('Failed to fetch Delphi status:', error);
    } finally {
      setDelphiLoading(false);
    }
  };

  const handleDelphiRefresh = async () => {
    setDelphiRefreshing(true);
    try {
      const data = await api.refreshDelphi();
      setDelphiStatus(data);
      toast({
        title: 'Delphi feeds refreshed',
        description: `KEV: ${data.kev_entries.toLocaleString()} · EPSS: ${data.epss_entries.toLocaleString()}`,
      });
    } catch (error: any) {
      toast({
        title: 'Refresh failed',
        description: error?.response?.data?.detail || 'Could not refresh KEV / EPSS feeds',
        variant: 'destructive',
      });
    } finally {
      setDelphiRefreshing(false);
    }
  };

  const handleDelphiBatchEnrich = async () => {
    setDelphiBatchRunning(true);
    setDelphiBatchResult(null);
    try {
      const data = await api.batchEnrichDelphi();
      setDelphiBatchResult(data);
      toast({
        title: 'Batch enrichment complete',
        description: `${data.kev_hits} KEV hits, ${data.epss_hits} EPSS scored across ${data.total} CVEs`,
      });
    } catch (error: any) {
      toast({
        title: 'Batch enrichment failed',
        description: error?.response?.data?.detail || 'Could not enrich findings',
        variant: 'destructive',
      });
    } finally {
      setDelphiBatchRunning(false);
    }
  };

  const fetchCcSettings = async (orgId: number) => {
    try {
      const data = await api.getProjectSettings(orgId, 'commoncrawl');
      setCcEnabled(data.enabled ?? true);
      setCcYears(data.years ?? 'last1');
      setCcMaxPerYear(String(data.max_per_year ?? 1));
      setCcTimeout(String(data.timeout ?? 120));
      setCcKeywordSearch(data.use_keyword_search ?? true);
      setCcSettingsLoaded(true);
    } catch {
      setCcSettingsLoaded(true);
    }
  };

  const handleSaveCcSettings = async () => {
    if (!selectedOrg) return;
    setSaving('commoncrawl');
    try {
      await api.updateProjectSettingsModule(parseInt(selectedOrg), 'commoncrawl', {
        enabled: ccEnabled,
        years: ccYears,
        max_per_year: parseInt(ccMaxPerYear),
        timeout: parseInt(ccTimeout),
        use_keyword_search: ccKeywordSearch,
      });
      toast({ title: 'Saved', description: 'CommonCrawl settings updated' });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error?.response?.data?.detail || 'Failed to save CommonCrawl settings',
        variant: 'destructive',
      });
    } finally {
      setSaving(null);
    }
  };

  useEffect(() => {
    if (selectedOrg) {
      // Clear current state and fetch new config
      // The reset happens in fetchApiConfigs after data loads
      setApiKeys({});
      setApiUsers({});
      setCcSettingsLoaded(false);
      fetchApiConfigs(parseInt(selectedOrg));
      fetchCcSettings(parseInt(selectedOrg));
    }
  }, [selectedOrg]);

  const getConfigForService = (serviceName: string) => {
    return apiConfigs.find(c => c.service_name === serviceName);
  };

  const handleSaveApiKey = async (serviceName: string) => {
    const key = apiKeys[serviceName];
    if (!key || !selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please enter an API key',
        variant: 'destructive',
      });
      return;
    }

    setSaving(serviceName);
    try {
      const payload: any = {
        service_name: serviceName,
        api_key: key,
      };
      
      // Add user for VirusTotal
      if (serviceName === 'virustotal' && apiUsers[serviceName]) {
        payload.api_user = apiUsers[serviceName];
      }
      
      // Add organization names for WhoisXML
      if (serviceName === 'whoisxml' && orgNames.length > 0) {
        payload.config = { organization_names: orgNames };
      }
      
      // Add registration emails for Whoxy
      if (serviceName === 'whoxy' && regEmails.length > 0) {
        payload.config = { registration_emails: regEmails };
      }
      
      await api.saveApiConfig(parseInt(selectedOrg), payload);
      
      toast({
        title: 'Success',
        description: `${serviceName} API key saved successfully`,
      });
      
      setApiKeys({ ...apiKeys, [serviceName]: '' });
      setApiUsers({ ...apiUsers, [serviceName]: '' });
      fetchApiConfigs(parseInt(selectedOrg));
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to save API key',
        variant: 'destructive',
      });
    } finally {
      setSaving(null);
    }
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

  // Save discovery settings (org names and emails) without requiring API key change
  const handleSaveDiscoverySettings = async () => {
    if (!selectedOrg) return;
    
    setSaving('discovery');
    try {
      // Save org names to whoisxml config (if config exists or has org names)
      const whoisxmlConfig = getConfigForService('whoisxml');
      if (whoisxmlConfig || orgNames.length > 0) {
        await api.saveApiConfig(parseInt(selectedOrg), {
          service_name: 'whoisxml',
          config: { organization_names: orgNames },
        });
      }
      
      // Save registration emails to whoxy config (if config exists or has emails)
      const whoxyConfig = getConfigForService('whoxy');
      if (whoxyConfig || regEmails.length > 0) {
        await api.saveApiConfig(parseInt(selectedOrg), {
          service_name: 'whoxy',
          config: { registration_emails: regEmails },
        });
      }
      
      toast({
        title: 'Success',
        description: 'Discovery settings saved successfully',
      });
      
      fetchApiConfigs(parseInt(selectedOrg));
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to save discovery settings',
        variant: 'destructive',
      });
    } finally {
      setSaving(null);
    }
  };

  return (
    <MainLayout>
      <Header title="Settings" subtitle="Configure API keys and platform settings" />

      <div className="p-6 space-y-6">
        {/* Organization Selector */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              Organization Settings
            </CardTitle>
            <CardDescription>
              API keys and discovery settings are configured per organization
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="w-64">
              <Label>Select Organization</Label>
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
          </CardContent>
        </Card>

        {/* Discovery Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Building2 className="h-5 w-5" />
              Default Discovery Settings
            </CardTitle>
            <CardDescription>
              These are saved as defaults for your organization. You can override them per-discovery in the Discovery page's Advanced Options.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Organization Names for WhoisXML */}
            <div className="space-y-3">
              <Label className="flex items-center gap-2">
                <Building2 className="h-4 w-4" />
                Organization Names (for WhoisXML IP Range Discovery)
              </Label>
              <p className="text-sm text-muted-foreground">
                Enter company/organization names to discover IP ranges and CIDRs they own
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., Rockwell Automation"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addOrgName()}
                />
                <Button onClick={addOrgName} variant="outline">
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {orgNames.map((name) => (
                  <Badge key={name} variant="secondary" className="flex items-center gap-1 px-3 py-1">
                    {name}
                    <button onClick={() => removeOrgName(name)} className="ml-1 hover:text-destructive">
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                {orgNames.length === 0 && (
                  <span className="text-sm text-muted-foreground">No organization names configured</span>
                )}
              </div>
            </div>

            {/* Registration Emails for Whoxy */}
            <div className="space-y-3">
              <Label className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Registration Emails (for Whoxy Reverse WHOIS)
              </Label>
              <p className="text-sm text-muted-foreground">
                Enter email addresses used to register domains to discover all domains registered with those emails
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., domains@yourcompany.com"
                  value={newRegEmail}
                  onChange={(e) => setNewRegEmail(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addRegEmail()}
                />
                <Button onClick={addRegEmail} variant="outline">
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {regEmails.map((email) => (
                  <Badge key={email} variant="secondary" className="flex items-center gap-1 px-3 py-1">
                    {email}
                    <button onClick={() => removeRegEmail(email)} className="ml-1 hover:text-destructive">
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                {regEmails.length === 0 && (
                  <span className="text-sm text-muted-foreground">No registration emails configured</span>
                )}
              </div>
            </div>
            
            {/* Save Discovery Settings Button */}
            <div className="pt-4 border-t">
              <Button 
                onClick={handleSaveDiscoverySettings}
                disabled={saving === 'discovery'}
              >
                {saving === 'discovery' ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <CheckCircle className="h-4 w-4 mr-2" />
                    Save Discovery Settings
                  </>
                )}
              </Button>
              <p className="text-xs text-muted-foreground mt-2">
                Save organization names and registration emails to use as defaults in Discovery
              </p>
            </div>
          </CardContent>
        </Card>

        {/* API Keys */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              API Keys
            </CardTitle>
            <CardDescription>
              Configure API keys for AI models, vulnerability intelligence, and asset discovery. Keys are encrypted at rest and scoped per organization.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {['AI / LLM', 'Vulnerability Intelligence', 'Asset Discovery'].map((group) => {
              const groupServices = API_SERVICES.filter((s: any) => (s.group || 'Asset Discovery') === group);
              return (
                <div key={group} className="space-y-4">
                  <div className="flex items-center gap-2">
                    <div className="h-px flex-1 bg-border" />
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-2">{group}</span>
                    <div className="h-px flex-1 bg-border" />
                  </div>
                  {groupServices.map((service: any) => {
              const config = getConfigForService(service.name);
              return (
                <div key={service.name} className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{service.label}</h3>
                        {config?.is_valid && (
                          <Badge variant="default" className="bg-green-600">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Configured
                          </Badge>
                        )}
                        {config && !config.is_valid && (
                          <Badge variant="destructive">
                            <AlertCircle className="h-3 w-3 mr-1" />
                            Invalid
                          </Badge>
                        )}
                        <Badge variant={service.free ? 'secondary' : 'outline'}>
                          {service.free ? 'Free Tier Available' : 'Paid'}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{service.description}</p>
                      <a 
                        href={service.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-xs text-primary hover:underline"
                      >
                        Get API Key →
                      </a>
                    </div>
                  </div>
                  
                  {config?.api_key_masked && (
                    <div className="text-sm text-muted-foreground">
                      Current key: <code className="bg-muted px-1 rounded">{config.api_key_masked}</code>
                      {config.usage_count > 0 && (
                        <span className="ml-2">• Used {config.usage_count} times</span>
                      )}
                    </div>
                  )}
                  
                  <div className="space-y-2">
                    <div className="flex gap-2">
                      <Input
                        type="password"
                        placeholder={config ? 'Enter new API key to update...' : 'Enter API key...'}
                        value={apiKeys[service.name] || ''}
                        onChange={(e) => setApiKeys({ ...apiKeys, [service.name]: e.target.value })}
                        className="flex-1"
                      />
                      <Button
                        onClick={() => handleSaveApiKey(service.name)}
                        disabled={saving === service.name || !apiKeys[service.name]}
                      >
                        {saving === service.name ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          'Save'
                        )}
                      </Button>
                    </div>
                    
                    {service.hasUser && (
                      <div className="flex gap-2">
                        <Input
                          placeholder="API Username (optional)"
                          value={apiUsers[service.name] || ''}
                          onChange={(e) => setApiUsers({ ...apiUsers, [service.name]: e.target.value })}
                          className="flex-1"
                        />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Free Sources Info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Free Discovery Sources (No API Key Required)
            </CardTitle>
            <CardDescription>These sources are automatically used during discovery</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🔐 Certificate Transparency</p>
                <p className="text-xs text-muted-foreground">crt.sh - SSL/TLS certificate logs</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">📜 Wayback Machine</p>
                <p className="text-xs text-muted-foreground">Historical URLs and subdomains</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🌐 RapidDNS</p>
                <p className="text-xs text-muted-foreground">DNS enumeration</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">☁️ Microsoft 365</p>
                <p className="text-xs text-muted-foreground">Federated domain discovery</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* CommonCrawl Enumeration Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              CommonCrawl Subdomain Enumeration
            </CardTitle>
            <CardDescription>
              Controls how far back into CommonCrawl's petabyte-scale web archive we search for
              historically observed subdomains when an organization is created or a scan is triggered.
              Wider ranges yield more coverage but take longer to complete.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {!ccSettingsLoaded ? (
              <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading settings…
              </div>
            ) : (
              <>
                {/* Enable / disable */}
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Enable CommonCrawl enumeration</p>
                    <p className="text-sm text-muted-foreground">
                      Automatically query the CommonCrawl CDX API when an organization is seeded
                    </p>
                  </div>
                  <Switch checked={ccEnabled} onCheckedChange={setCcEnabled} />
                </div>

                <div className={`space-y-5 ${!ccEnabled ? 'opacity-40 pointer-events-none' : ''}`}>
                  {/* Year range */}
                  <div className="space-y-2">
                    <Label>Year range</Label>
                    <p className="text-xs text-muted-foreground">
                      How many years of crawl data to query. "Last 1 year" is the default — fast and
                      covers recent infrastructure. Extend for acquisitions or older assets.
                    </p>
                    <Select value={ccYears} onValueChange={setCcYears}>
                      <SelectTrigger className="w-64">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="last1">Last 1 year (default — fastest)</SelectItem>
                        <SelectItem value="last2">Last 2 years</SelectItem>
                        <SelectItem value="last3">Last 3 years</SelectItem>
                        <SelectItem value="last5">Last 5 years</SelectItem>
                        <SelectItem value="all">All available years (slowest, most complete)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Datasets per year */}
                  <div className="space-y-2">
                    <Label>Datasets per year</Label>
                    <p className="text-xs text-muted-foreground">
                      CommonCrawl publishes multiple crawl snapshots per year. 1 uses only the most
                      recent snapshot for each year (recommended). Higher values add breadth at the
                      cost of longer scan times.
                    </p>
                    <Select value={ccMaxPerYear} onValueChange={setCcMaxPerYear}>
                      <SelectTrigger className="w-64">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">1 dataset / year (recommended)</SelectItem>
                        <SelectItem value="2">2 datasets / year</SelectItem>
                        <SelectItem value="3">3 datasets / year</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Timeout */}
                  <div className="space-y-2">
                    <Label>Request timeout (seconds)</Label>
                    <p className="text-xs text-muted-foreground">
                      Maximum wait time for each CDX API response. Increase if scans fail on slow
                      connections or large domains.
                    </p>
                    <Input
                      type="number"
                      min={30}
                      max={600}
                      className="w-32"
                      value={ccTimeout}
                      onChange={(e) => setCcTimeout(e.target.value)}
                    />
                  </div>

                  {/* Brand / keyword discovery toggle */}
                  <div className="flex items-start justify-between gap-4 pt-2 border-t">
                    <div className="space-y-1">
                      <p className="font-medium text-sm">Brand keyword discovery</p>
                      <p className="text-xs text-muted-foreground">
                        Also sweep CommonCrawl for hostnames matching brand or product name patterns.
                        For each keyword, three CDX query patterns are run automatically:
                      </p>
                      <div className="mt-1.5 space-y-1 font-mono text-xs text-muted-foreground pl-2 border-l-2 border-muted">
                        <p><span className="text-foreground">*keyword*</span> — hostname contains the term (partner portals, hyphenated names)</p>
                        <p><span className="text-foreground">keyword.*</span> — domain starts with keyword in any TLD (.net, .de, .io, …)</p>
                        <p><span className="text-foreground">*.keyword.*</span> — subdomains of any keyword.TLD domain</p>
                      </div>
                      <p className="text-xs text-muted-foreground pt-1">
                        Tip: add both the full name <em>and</em> common short forms as separate keywords
                        (e.g. <code className="bg-muted px-1 rounded">rockwellautomation</code> +{' '}
                        <code className="bg-muted px-1 rounded">rockwell</code> +{' '}
                        <code className="bg-muted px-1 rounded">factorytalk</code> +{' '}
                        <code className="bg-muted px-1 rounded">allen-bradley</code>).
                        Keywords are set in{' '}
                        <span className="text-foreground font-medium">Discovery → Advanced Options</span>.
                      </p>
                    </div>
                    <Switch
                      checked={ccKeywordSearch}
                      onCheckedChange={setCcKeywordSearch}
                      className="mt-0.5 shrink-0"
                    />
                  </div>

                  {ccKeywordSearch && (
                    <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-start gap-3 text-xs">
                      <Globe className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                      <p className="text-muted-foreground">
                        Configure keywords in{' '}
                        <a href="/discovery" className="text-amber-400 hover:underline font-medium">
                          Discovery → Advanced Options
                        </a>{' '}
                        → "CommonCrawl Org Name" and "CommonCrawl Keywords". Without keywords set,
                        only Mode 1 subdomain enumeration will run.
                      </p>
                    </div>
                  )}

                  {/* Coverage summary badge */}
                  <div className="p-3 rounded-lg bg-muted/50 flex items-start gap-3">
                    <Globe className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                    <div className="text-xs text-muted-foreground space-y-0.5">
                      <p className="font-medium text-foreground">Current coverage estimate</p>
                      <p>
                        Querying{' '}
                        <span className="text-foreground font-medium">
                          {ccYears === 'all'
                            ? 'all available years'
                            : ccYears.startsWith('last')
                            ? `the last ${ccYears.replace('last', '')} year${parseInt(ccYears.replace('last', '')) > 1 ? 's' : ''}`
                            : ccYears}
                        </span>{' '}
                        × {ccMaxPerYear} dataset{parseInt(ccMaxPerYear) > 1 ? 's' : ''} per year ={' '}
                        <span className="text-foreground font-medium">
                          {ccYears === 'all'
                            ? `up to ~${parseInt(ccMaxPerYear) * 18}+ CDX requests`
                            : `up to ${parseInt(ccYears.replace('last', '') || '1') * parseInt(ccMaxPerYear)} CDX request${
                                parseInt(ccYears.replace('last', '') || '1') * parseInt(ccMaxPerYear) > 1 ? 's' : ''
                              }`}
                        </span>{' '}
                        per domain at scan time.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t">
                  <Button onClick={handleSaveCcSettings} disabled={saving === 'commoncrawl'}>
                    {saving === 'commoncrawl' ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Saving…
                      </>
                    ) : (
                      <>
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Save CommonCrawl Settings
                      </>
                    )}
                  </Button>
                  <p className="text-xs text-muted-foreground mt-2">
                    These settings take effect the next time a CommonCrawl enumeration scan is queued
                    for this organization.
                  </p>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5" />
              Notifications
            </CardTitle>
            <CardDescription>Configure alert and notification preferences</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Critical Vulnerability Alerts</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when critical vulnerabilities are discovered
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">New Asset Discovery</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when new assets are discovered
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Scan Completion</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when scans complete
                </p>
              </div>
              <Switch />
            </div>
          </CardContent>
        </Card>

        {/* Delphi Enrichment (CISA KEV + FIRST EPSS) */}
        <Card className="border-purple-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-purple-400" />
              Delphi Enrichment
            </CardTitle>
            <CardDescription>
              CISA KEV (Known Exploited Vulnerabilities) + FIRST EPSS (Exploit Prediction Scoring System).
              Both feeds are public — no API keys required. New CVE findings are auto-enriched at ingestion.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {delphiLoading ? (
              <div className="flex items-center justify-center py-6 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading Delphi status…
              </div>
            ) : delphiStatus ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-3 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-2 mb-1">
                      <Flame className="h-4 w-4 text-red-400" />
                      <span className="text-sm text-muted-foreground">CISA KEV</span>
                    </div>
                    <p className="text-2xl font-bold">{(delphiStatus.kev_entries || 0).toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground">
                      {delphiStatus.kev_catalog_version
                        ? `v${delphiStatus.kev_catalog_version}`
                        : delphiStatus.kev_date_released
                        ? `Released ${delphiStatus.kev_date_released}`
                        : 'entries'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-2 mb-1">
                      <TrendingUp className="h-4 w-4 text-purple-400" />
                      <span className="text-sm text-muted-foreground">FIRST EPSS</span>
                    </div>
                    <p className="text-2xl font-bold">{(delphiStatus.epss_entries || 0).toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground">
                      {delphiStatus.epss_score_date ? `Scored ${delphiStatus.epss_score_date}` : 'CVEs scored'}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-2 mb-1">
                      <RefreshCw className="h-4 w-4 text-cyan-400" />
                      <span className="text-sm text-muted-foreground">Refresh window</span>
                    </div>
                    <p className="text-2xl font-bold">{delphiStatus.refresh_hours}h</p>
                    <p className="text-xs text-muted-foreground">Auto-refetch interval</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-2 mb-1">
                      <CheckCircle
                        className={`h-4 w-4 ${delphiStatus.enabled ? 'text-green-400' : 'text-muted-foreground'}`}
                      />
                      <span className="text-sm text-muted-foreground">Status</span>
                    </div>
                    <Badge
                      variant={delphiStatus.enabled ? 'default' : 'secondary'}
                      className={delphiStatus.enabled ? 'bg-green-600' : ''}
                    >
                      {delphiStatus.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                    {delphiStatus.last_loaded && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Loaded {new Date(delphiStatus.last_loaded).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 pt-2 border-t">
                  <Button onClick={handleDelphiRefresh} disabled={delphiRefreshing} variant="outline">
                    {delphiRefreshing ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <RefreshCw className="h-4 w-4 mr-2" />
                    )}
                    Refresh KEV + EPSS now
                  </Button>
                  <Button onClick={handleDelphiBatchEnrich} disabled={delphiBatchRunning}>
                    {delphiBatchRunning ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Sparkles className="h-4 w-4 mr-2" />
                    )}
                    Re-enrich all findings
                  </Button>
                  {delphiBatchResult && (
                    <span className="text-xs text-muted-foreground ml-auto">
                      Last batch: {delphiBatchResult.total} CVEs · {delphiBatchResult.kev_hits} KEV ·{' '}
                      {delphiBatchResult.epss_hits} EPSS
                      {delphiBatchResult.errors > 0 && ` · ${delphiBatchResult.errors} errors`}
                    </span>
                  )}
                </div>
              </>
            ) : (
              <div className="flex items-center gap-2 text-muted-foreground text-sm py-2">
                <AlertCircle className="h-4 w-4" />
                Could not load Delphi status. Check the backend logs.
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scan Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Scan Settings
            </CardTitle>
            <CardDescription>Configure default scan parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Default Severity Filter</Label>
                <div className="flex gap-2">
                  <Badge variant="critical">Critical</Badge>
                  <Badge variant="high">High</Badge>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Scan Rate Limit</Label>
                <Input type="number" placeholder="150" defaultValue={150} />
                <p className="text-xs text-muted-foreground">Requests per second</p>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Auto-update Nuclei Templates</p>
                <p className="text-sm text-muted-foreground">
                  Automatically update templates before each scan
                </p>
              </div>
              <Switch defaultChecked />
            </div>
          </CardContent>
        </Card>

        {/* System Info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Version</p>
                <p className="font-medium">1.0.0</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Nuclei Version</p>
                <p className="font-medium">v3.x</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Templates</p>
                <p className="font-medium">8000+</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Database</p>
                <p className="font-medium">PostgreSQL 15</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
