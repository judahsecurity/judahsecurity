'use client';

import { 
  Globe, 
  Shield, 
  Search, 
  FileText, 
  Link as LinkIcon, 
  Server, 
  Lock,
  Mail,
  Building,
  Building2,
  ArrowRight,
  ChevronRight,
  ChevronDown,
  ExternalLink,
  Database,
  Radar,
  Cloud,
  AlertTriangle,
  CheckCircle,
  Network,
  Users
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

// Enhanced discovery step with relationship information
interface DiscoveryStep {
  step: number;
  source: string;
  entity_type?: string;  // organization, subsidiary, domain, subdomain, ip_address, certificate
  entity_value?: string;  // The actual value (company name, domain, IP, etc.)
  relationship?: string;  // How this entity relates to the previous one
  match_type?: string;
  match_value?: string;
  query_domain?: string;
  timestamp?: string;
  confidence?: number;
}

interface DiscoveryPathProps {
  value: string;  // The asset hostname or IP
  assetType: string;
  rootDomain?: string;
  liveUrl?: string;
  discoverySource?: string;
  discoveryChain?: DiscoveryStep[];
  associationReason?: string;
  associationConfidence?: number;
  // Organization info
  organizationName?: string;
  parentOrganization?: string;
  // Hosting classification for IP assets
  hostingType?: string;  // owned, cloud, cdn, third_party, unknown
  hostingProvider?: string;  // azure, aws, gcp, cloudflare, etc.
  isEphemeralIp?: boolean;  // True if IP could change
  resolvedFrom?: string;  // Domain this IP was resolved from
}

// Entity type configurations
const entityTypeConfig: Record<string, {
  icon: any;
  colorClass: string;
  label: string;
}> = {
  parent_company: {
    icon: Building2,
    colorClass: 'bg-violet-500/10 text-violet-500 border-violet-500/20',
    label: 'Parent Company'
  },
  organization: {
    icon: Building,
    colorClass: 'bg-blue-600/10 text-blue-600 border-blue-600/20',
    label: 'Organization'
  },
  subsidiary: {
    icon: Building,
    colorClass: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
    label: 'Subsidiary'
  },
  domain: {
    icon: Globe,
    colorClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    label: 'Domain'
  },
  subdomain: {
    icon: Globe,
    colorClass: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
    label: 'Subdomain'
  },
  ip_address: {
    icon: Server,
    colorClass: 'bg-green-500/10 text-green-500 border-green-500/20',
    label: 'IP Address'
  },
  ip_range: {
    icon: Network,
    colorClass: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
    label: 'IP Range (CIDR)'
  },
  certificate: {
    icon: Lock,
    colorClass: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    label: 'SSL Certificate'
  },
  registrant: {
    icon: Users,
    colorClass: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
    label: 'Registrant'
  },
  default: {
    icon: Search,
    colorClass: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
    label: 'Asset'
  }
};

// Discovery source configurations
const sourceConfig: Record<string, {
  icon: any;
  name: string;
  colorClass: string;
}> = {
  manual: { icon: Globe, name: 'Manual Entry', colorClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
  seed: { icon: Globe, name: 'Seed Domain', colorClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
  whoxy: { icon: Mail, name: 'Whoxy Reverse WHOIS', colorClass: 'bg-purple-500/10 text-purple-500 border-purple-500/20' },
  crtsh: { icon: Lock, name: 'Certificate Transparency', colorClass: 'bg-green-500/10 text-green-500 border-green-500/20' },
  crt_name: { icon: Lock, name: 'crt.name Index', colorClass: 'bg-green-500/10 text-green-500 border-green-500/20' },
  shodan_ctl: { icon: Lock, name: 'Shodan CTL', colorClass: 'bg-green-500/10 text-green-500 border-green-500/20' },
  subfaster: { icon: Radar, name: 'Subfaster', colorClass: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20' },
  virustotal: { icon: Shield, name: 'VirusTotal', colorClass: 'bg-red-500/10 text-red-500 border-red-500/20' },
  otx: { icon: Database, name: 'AlienVault OTX', colorClass: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
  wayback: { icon: FileText, name: 'Wayback Machine', colorClass: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
  rapiddns: { icon: Search, name: 'RapidDNS', colorClass: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20' },
  subfinder: { icon: Radar, name: 'Subfinder', colorClass: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20' },
  m365: { icon: Building, name: 'Microsoft 365 Federation', colorClass: 'bg-blue-600/10 text-blue-600 border-blue-600/20' },
  commoncrawl: { icon: Database, name: 'Common Crawl', colorClass: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' },
  sni_ip_ranges: { icon: Cloud, name: 'SNI/Cloud Discovery', colorClass: 'bg-pink-500/10 text-pink-500 border-pink-500/20' },
  dns_enumeration: { icon: Globe, name: 'DNS Resolution', colorClass: 'bg-teal-500/10 text-teal-500 border-teal-500/20' },
  subdomain_resolution: { icon: Server, name: 'Subdomain Resolution', colorClass: 'bg-lime-500/10 text-lime-500 border-lime-500/20' },
  ssl_certificate: { icon: Lock, name: 'SSL Certificate SAN', colorClass: 'bg-green-500/10 text-green-500 border-green-500/20' },
  whoisxml: { icon: Building, name: 'WhoisXML API', colorClass: 'bg-violet-500/10 text-violet-500 border-violet-500/20' },
  default: { icon: Search, name: 'External Discovery', colorClass: 'bg-gray-500/10 text-gray-400 border-gray-500/20' },
};

// Attribution chain node component
function AttributionNode({ 
  entityType,
  entityValue,
  relationship,
  isLast = false,
  isFirst = false,
  confidence
}: { 
  entityType: string;
  entityValue: string;
  relationship?: string;
  isLast?: boolean;
  isFirst?: boolean;
  confidence?: number;
}) {
  const config = entityTypeConfig[entityType] || entityTypeConfig.default;
  const Icon = config.icon;
  
  return (
    <div className="flex items-stretch">
      {/* Connector line and node */}
      <div className="flex flex-col items-center mr-4">
        {/* Top connector */}
        {!isFirst && (
          <div className="w-0.5 h-4 bg-border" />
        )}
        {/* Node circle */}
        <div className={cn(
          "w-10 h-10 rounded-full flex items-center justify-center border flex-shrink-0",
          config.colorClass
        )}>
          <Icon className="h-5 w-5" />
        </div>
        {/* Bottom connector */}
        {!isLast && (
          <div className="w-0.5 flex-1 bg-border min-h-[16px]" />
        )}
      </div>
      
      {/* Content */}
      <div className="pb-4 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium">{entityValue}</span>
          <Badge variant="outline" className={cn("text-xs", config.colorClass)}>
            {config.label}
          </Badge>
          {confidence && confidence < 100 && (
            <Badge variant="outline" className="text-xs">
              {confidence}%
            </Badge>
          )}
        </div>
        {relationship && (
          <p className="text-sm text-muted-foreground mt-1">
            {relationship}
          </p>
        )}
      </div>
    </div>
  );
}

// Build attribution chain from discovery data
function buildAttributionChain(props: DiscoveryPathProps): Array<{
  entityType: string;
  entityValue: string;
  relationship?: string;
  confidence?: number;
}> {
  const chain: Array<{
    entityType: string;
    entityValue: string;
    relationship?: string;
    confidence?: number;
  }> = [];
  
  // 1. If we have organization info, start with that
  if (props.parentOrganization) {
    chain.push({
      entityType: 'parent_company',
      entityValue: props.parentOrganization,
      relationship: 'Parent organization'
    });
  }
  
  if (props.organizationName && props.organizationName !== props.parentOrganization) {
    chain.push({
      entityType: props.parentOrganization ? 'subsidiary' : 'organization',
      entityValue: props.organizationName,
      relationship: props.parentOrganization 
        ? `Subsidiary of ${props.parentOrganization}`
        : 'Target organization'
    });
  }
  
  // 2. Add root domain if different from current asset
  if (props.rootDomain && props.rootDomain !== props.value) {
    // Determine relationship based on discovery source
    let relationship = 'Primary domain for organization';
    if (props.discoveryChain?.length) {
      const domainStep = props.discoveryChain.find(s => 
        s.entity_value === props.rootDomain || s.match_value === props.rootDomain
      );
      if (domainStep?.relationship) {
        relationship = domainStep.relationship;
      } else if (domainStep?.source === 'whoxy') {
        relationship = `Domain registered by ${props.organizationName || 'organization'}`;
      }
    }
    
    chain.push({
      entityType: 'domain',
      entityValue: props.rootDomain,
      relationship
    });
  }
  
  // 3. For subdomains, show the parent relationship
  if (props.assetType === 'subdomain') {
    // Check if discovered via certificate SAN
    const certSource = props.discoveryChain?.find(s => 
      s.source === 'ssl_certificate' || s.source === 'crtsh' || s.source === 'crt_name' || s.source === 'shodan_ctl'
    );
    
    let relationship = `Subdomain of ${props.rootDomain || 'parent domain'}`;
    if (certSource) {
      if (certSource.match_value && certSource.match_value !== props.value) {
        relationship = `Listed as alternative name in SSL certificate of ${certSource.match_value}`;
      } else {
        relationship = 'Discovered via Certificate Transparency logs';
      }
    } else if (props.discoverySource === 'subfinder') {
      relationship = 'Discovered via passive subdomain enumeration';
    } else if (props.discoverySource === 'dns_enumeration') {
      relationship = 'Discovered via DNS brute-force enumeration';
    }
    
    chain.push({
      entityType: 'subdomain',
      entityValue: props.value,
      relationship,
      confidence: props.associationConfidence
    });
  }
  
  // 4. For domains (not subdomains), add the domain itself
  if (props.assetType === 'domain' && props.value !== props.rootDomain) {
    let relationship = 'Related domain';
    const domainStep = props.discoveryChain?.find(s => s.entity_value === props.value);
    if (domainStep?.relationship) {
      relationship = domainStep.relationship;
    } else if (props.discoverySource === 'whoxy') {
      const matchInfo = props.discoveryChain?.find(s => s.match_type);
      if (matchInfo?.match_type === 'email') {
        relationship = `Found via Whoxy reverse WHOIS - matched registrant email '${matchInfo.match_value}'`;
      } else if (matchInfo?.match_type === 'company') {
        relationship = `Found via Whoxy reverse WHOIS - matched company name '${matchInfo.match_value}'`;
      }
    } else if (props.discoverySource === 'm365') {
      relationship = `Found via Microsoft 365 federation from ${props.rootDomain}`;
    }
    
    chain.push({
      entityType: 'domain',
      entityValue: props.value,
      relationship,
      confidence: props.associationConfidence
    });
  }
  
  // 5. For IP addresses, show the resolution path
  if (props.assetType === 'ip_address') {
    // First show the domain it was resolved from
    if (props.resolvedFrom) {
      chain.push({
        entityType: props.resolvedFrom.includes('.') && props.resolvedFrom.split('.').length > 2 ? 'subdomain' : 'domain',
        entityValue: props.resolvedFrom,
        relationship: props.rootDomain && props.resolvedFrom !== props.rootDomain 
          ? `Subdomain of ${props.rootDomain}` 
          : 'Domain for organization'
      });
    }
    
    // Then show the IP with hosting info
    let ipRelationship = 'IP address discovered via DNS resolution';
    if (props.hostingType === 'owned') {
      ipRelationship = 'IP is within owned CIDR blocks - static infrastructure';
    } else if (props.hostingType === 'cloud') {
      ipRelationship = `IP hosted on ${props.hostingProvider?.toUpperCase() || 'cloud'} - ephemeral, may change`;
    } else if (props.hostingType === 'cdn') {
      ipRelationship = `IP behind ${props.hostingProvider?.toUpperCase() || 'CDN'} - shared infrastructure`;
    }
    
    if (props.resolvedFrom) {
      ipRelationship = `Resolved from ${props.resolvedFrom} via DNS A record. ${ipRelationship}`;
    }
    
    chain.push({
      entityType: 'ip_address',
      entityValue: props.value,
      relationship: ipRelationship,
      confidence: props.associationConfidence
    });
  }
  
  // If chain is empty, add a basic entry
  if (chain.length === 0) {
    chain.push({
      entityType: props.assetType || 'default',
      entityValue: props.value,
      relationship: props.associationReason || 'Asset discovered during enumeration',
      confidence: props.associationConfidence
    });
  }
  
  return chain;
}

export function DiscoveryPath(props: DiscoveryPathProps) {
  const {
    value,
    assetType,
    discoverySource,
    discoveryChain,
    associationReason,
    associationConfidence,
    hostingType,
    hostingProvider,
    isEphemeralIp,
    resolvedFrom
  } = props;
  
  const isIpAsset = assetType === 'ip_address';
  const isCloudOrCdn = hostingType === 'cloud' || hostingType === 'cdn';
  
  // Build the attribution chain
  const attributionChain = buildAttributionChain(props);
  
  // Get discovery source info
  const source = discoverySource?.toLowerCase() || 'default';
  const sourceInfo = sourceConfig[source] || sourceConfig.default;
  
  return (
    <div className="space-y-4">
      {/* Cloud/Ephemeral IP Warning Banner */}
      {isIpAsset && isCloudOrCdn && (
        <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-orange-500 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-orange-600 dark:text-orange-400">
                Ephemeral Cloud IP - Do Not Scan Directly
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                This IP ({value}) is hosted on <span className="font-medium">{hostingProvider?.toUpperCase() || 'cloud infrastructure'}</span> and 
                could change at any time. Scanning this IP directly may target someone else's infrastructure.
                {resolvedFrom && (
                  <span className="block mt-1">
                    <span className="font-medium">Scan by hostname instead:</span> {resolvedFrom}
                  </span>
                )}
              </p>
            </div>
          </div>
        </div>
      )}
      
      {/* Owned Infrastructure Banner */}
      {isIpAsset && hostingType === 'owned' && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-green-600 dark:text-green-400">
                Owned Infrastructure - Safe to Scan
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                This IP is within your organization's allocated CIDR blocks (from WhoisXML). 
                It is static infrastructure that you control.
              </p>
            </div>
          </div>
        </div>
      )}
      
      {/* Discovery method summary */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-10 h-10 rounded-lg flex items-center justify-center border flex-shrink-0",
            sourceInfo.colorClass
          )}>
            <sourceInfo.icon className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide">Discovered via</p>
            <p className="text-sm font-medium">{sourceInfo.name}</p>
          </div>
        </div>
        {associationConfidence != null && (
          <Badge variant="outline" className="text-xs">
            {associationConfidence}% confidence
          </Badge>
        )}
      </div>

      {/* Attribution timeline */}
      <div className="pt-1">
        {attributionChain.map((node, index) => (
          <AttributionNode
            key={index}
            entityType={node.entityType}
            entityValue={node.entityValue}
            relationship={node.relationship}
            confidence={node.confidence}
            isFirst={index === 0}
            isLast={index === attributionChain.length - 1}
          />
        ))}
      </div>

      {/* Why this asset is attributed here */}
      {associationReason && (
        <p className="text-sm text-muted-foreground bg-muted/40 rounded-lg p-3">
          {associationReason}
        </p>
      )}
      
      {/* Detailed Chain (raw data - collapsible) */}
      {discoveryChain && discoveryChain.length > 0 && (
        <details className="group">
          <summary className="text-sm text-muted-foreground cursor-pointer hover:text-foreground flex items-center gap-1">
            <ChevronRight className="h-4 w-4 group-open:rotate-90 transition-transform" />
            View raw discovery chain data ({discoveryChain.length} steps)
          </summary>
          <div className="mt-2 pl-5 space-y-2">
            {discoveryChain.map((step, index) => (
              <div key={index} className="text-sm bg-muted/30 rounded p-2 font-mono">
                <span className="text-muted-foreground">Step {step.step}:</span>{' '}
                <span className="text-primary">{step.source}</span>
                {step.entity_type && (
                  <span className="text-muted-foreground"> [{step.entity_type}]</span>
                )}
                {step.entity_value && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ entity: </span>
                    <span className="text-blue-500">{step.entity_value}</span>
                  </>
                )}
                {step.relationship && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ relationship: </span>
                    <span className="text-green-500">{step.relationship}</span>
                  </>
                )}
                {step.match_type && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ match_type: </span>
                    <span>{step.match_type}</span>
                  </>
                )}
                {step.match_value && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ matched: </span>
                    <span className="text-yellow-500">{step.match_value}</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
