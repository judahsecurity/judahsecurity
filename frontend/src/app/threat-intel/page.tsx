'use client';

import { useEffect, useState, useCallback } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  RefreshCw,
  ExternalLink,
  Shield,
  Zap,
  Activity,
  FileCode,
  Target,
  Flame,
  Radio,
  Eye,
  EyeOff,
  TrendingUp,
  Clock,
  AlertCircle,
  Loader2,
  ChevronDown,
  ChevronUp,
  Info,
  Crosshair,
  Sparkles,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

type DetectionTier = 'nuclei_template' | 'poc_available' | 'remote_no_template' | 'no_detection';

interface EmergingEntry {
  cve_id: string;
  date_added_kev: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  short_description: string;
  known_ransomware_use: string;
  kev_sources: string[];
  severity: string;
  cvss_score: number | null;
  epss_score: number | null;
  is_template: boolean;
  is_poc: boolean;
  is_remote: boolean;
  detection_tier: DetectionTier;
  template_count: number;
  otx_pulse_count: number;
  otx_active_campaign: boolean;
  tags: string[];
  affected_products: { vendor: string; product: string }[];
  oracle_analyzed: boolean;
  opes_score: number | null;
  opes_category: string | null;
  delphi_priority: string | null;
}

interface Summary {
  total: number;
  with_nuclei_template: number;
  with_poc: number;
  remote_exploitable: number;
  ransomware_associated: number;
  otx_active_campaigns: number;
  oracle_analyzed: number;
  by_severity: { critical: number; high: number; medium: number; low: number };
  by_source: {
    cisa_kev: number;
    vulncheck_kev: number;
    enisa_kev: number;
    euvd: number;
    shadowserver?: number;
    kevintel?: number;
  };
  multi_source_count: number;
  vulncheck_configured: boolean;
  pdcp_configured: boolean;
}

interface EmergingResponse {
  total: number;
  days: number;
  entries: EmergingEntry[];
  summary: Summary;
}

// ── Style helpers ─────────────────────────────────────────────────────────────

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  unknown: 'bg-muted text-muted-foreground border-border',
};

const OPES_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  informational: 'bg-muted text-muted-foreground border-border',
};

function severityBadge(severity: string) {
  const s = (severity || 'unknown').toLowerCase();
  return (
    <Badge variant="outline" className={cn('text-xs font-semibold uppercase', SEVERITY_STYLE[s] ?? SEVERITY_STYLE.unknown)}>
      {s}
    </Badge>
  );
}

// ── Detection coverage badge ───────────────────────────────────────────────────

function DetectionBadge({ entry }: { entry: EmergingEntry }) {
  if (entry.is_template) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 gap-1 cursor-default">
              <FileCode className="h-3 w-3" />
              Nuclei Template
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">Nuclei template exists — automated detection possible with ProjectDiscovery tooling</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  if (entry.is_poc) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="bg-yellow-500/15 text-yellow-400 border-yellow-500/30 gap-1 cursor-default">
              <FileCode className="h-3 w-3" />
              PoC Available
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">Public PoC exists — manual verification possible but no auto-detection template</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  if (entry.is_remote) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="bg-orange-500/15 text-orange-400 border-orange-500/30 gap-1 cursor-default">
              <Radio className="h-3 w-3" />
              Remote / No Template
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">Remotely exploitable — no Nuclei template or PoC yet. Manual assessment required.</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }
  return (
    <Badge variant="outline" className="bg-muted text-muted-foreground border-border gap-1 cursor-default">
      <EyeOff className="h-3 w-3" />
      No Detection
    </Badge>
  );
}

// ── OTX badge ─────────────────────────────────────────────────────────────────

function OTXBadge({ count, active }: { count: number; active: boolean }) {
  if (count === 0) return <span className="text-muted-foreground text-xs">—</span>;
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className={cn(
              'gap-1 cursor-default text-xs',
              active
                ? 'bg-red-500/15 text-red-400 border-red-500/30'
                : 'bg-purple-500/15 text-purple-400 border-purple-500/30'
            )}
          >
            <Activity className="h-3 w-3" />
            {count} {active ? '🔥' : ''}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p className="text-xs">
            {count} AlienVault OTX threat-intel pulse(s) referencing this CVE.
            {active ? ' 20+ pulses = active attacker campaigns with deployed tooling.' : ''}
          </p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── Oracle analysis badge ─────────────────────────────────────────────────────

function OracleBadge({ entry }: { entry: EmergingEntry }) {
  if (!entry.oracle_analyzed) {
    return <span className="text-muted-foreground text-xs">Not analyzed</span>;
  }
  const cat = (entry.opes_category || 'unknown').toLowerCase();
  return (
    <div className="flex flex-col gap-1">
      <Badge variant="outline" className={cn('text-xs font-semibold uppercase', OPES_STYLE[cat] ?? OPES_STYLE.informational)}>
        {cat}
      </Badge>
      {entry.opes_score != null && (
        <span className="text-xs text-muted-foreground">OPES {entry.opes_score.toFixed(1)}</span>
      )}
    </div>
  );
}

// ── Days ago ──────────────────────────────────────────────────────────────────

function daysAgo(dateStr: string): string {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const diff = Math.floor((Date.now() - d.getTime()) / 86400000);
    if (diff === 0) return 'Today';
    if (diff === 1) return 'Yesterday';
    return `${diff}d ago`;
  } catch {
    return dateStr;
  }
}

// ── Oracle analysis badge ─────────────────────────────────────────────────────

const ATTACK_PATH_STYLE: Record<string, string> = {
  'Remote Code Execution': 'bg-red-500/15 text-red-400 border-red-500/30',
  'Privilege Escalation':  'bg-orange-500/15 text-orange-400 border-orange-500/30',
  'Authentication Bypass': 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  'Information Disclosure':'bg-blue-500/15 text-blue-400 border-blue-500/30',
  'Denial of Service':     'bg-purple-500/15 text-purple-400 border-purple-500/30',
  'SQL Injection':         'bg-orange-500/15 text-orange-400 border-orange-500/30',
  'File Upload':           'bg-red-500/15 text-red-400 border-red-500/30',
  'SSRF':                  'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
};

interface OracleResult {
  cve_id: string;
  analysis_status: string;
  opes_score?: number;
  opes_category?: string;
  opes_label?: string;
  attack_path_class?: string;
  lateral_movement_potential?: boolean;
  remote_triggerability?: string;
  exploit_complexity?: string;
  attacker_capability?: string;
  confidence?: string;
  analyst_brief?: string;
  preconditions?: string[];
}

function OracleScoreBadge({ entry, oracleResult }: { entry: EmergingEntry; oracleResult?: OracleResult }) {
  const score = oracleResult?.opes_score ?? entry.opes_score;
  const category = oracleResult?.opes_category ?? entry.opes_category;
  const attackPath = oracleResult?.attack_path_class;

  if (score != null) {
    const style = OPES_STYLE[(category || '').toLowerCase()] ?? OPES_STYLE.informational;
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className={cn('text-xs font-bold cursor-default gap-1', style)}>
              <Sparkles className="h-3 w-3" />
              {score.toFixed(1)}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">Oracle OPES score: {score.toFixed(1)} — {category}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  if (attackPath) {
    const style = ATTACK_PATH_STYLE[attackPath] ?? 'bg-muted text-muted-foreground border-border';
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className={cn('text-xs cursor-default gap-1 max-w-32 truncate', style)}>
              <Crosshair className="h-3 w-3 shrink-0" />
              <span className="truncate">{attackPath}</span>
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">Oracle: {attackPath}</p>
            {oracleResult?.confidence && <p className="text-xs text-muted-foreground">Confidence: {oracleResult.confidence}</p>}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return null;
}

// ── Source badges ─────────────────────────────────────────────────────────────

const SOURCE_META: Record<string, { label: string; color: string; url: string; desc: string }> = {
  cisa_kev:    { label: 'CISA',    color: 'bg-blue-500/15 text-blue-400 border-blue-500/30',    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',          desc: 'CISA Known Exploited Vulnerabilities Catalog' },
  vulncheck_kev: { label: 'VulnCheck', color: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30', url: 'https://vulncheck.com/advisories',                               desc: 'VulnCheck KEV — broadest exploitation catalog (150+ sources; primary prioritization signal)' },
  enisa_kev:   { label: 'ENISA',   color: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',   url: 'https://github.com/enisaeu/KEV',                                        desc: 'ENISA EU CSIRT Network KEV List' },
  euvd:        { label: 'EUVD',    color: 'bg-teal-500/15 text-teal-400 border-teal-500/30',   url: 'https://euvd.enisa.europa.eu',                                          desc: 'EU Vulnerability Database — exploited-in-the-wild entries' },
  shadowserver: { label: 'Shadowserver', color: 'bg-orange-500/15 text-orange-400 border-orange-500/30', url: 'https://www.shadowserver.org/', desc: 'Shadowserver honeypot exploited vulnerabilities (via CIRCL)' },
  kevintel:    { label: 'KEVIntel', color: 'bg-rose-500/15 text-rose-400 border-rose-500/30', url: 'https://kevintel.com/', desc: 'KEVIntel exploitation attestations (via CIRCL KEV catalog)' },
};

function SourceBadges({ sources }: { sources: string[] }) {
  if (!sources || sources.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {sources.map(src => {
        const meta = SOURCE_META[src];
        if (!meta) return null;
        return (
          <TooltipProvider key={src}>
            <Tooltip>
              <TooltipTrigger asChild>
                <a
                  href={meta.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={e => e.stopPropagation()}
                >
                  <Badge variant="outline" className={cn('text-xs font-semibold cursor-pointer hover:opacity-80', meta.color)}>
                    {meta.label}
                  </Badge>
                </a>
              </TooltipTrigger>
              <TooltipContent><p className="text-xs">{meta.desc}</p></TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      })}
      {sources.length > 1 && (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="outline" className="text-xs bg-amber-500/15 text-amber-400 border-amber-500/30 cursor-default">
                ×{sources.length} sources
              </Badge>
            </TooltipTrigger>
            <TooltipContent>
              <p className="text-xs">Confirmed by {sources.length} independent intelligence feeds — higher exploitation confidence</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
    </div>
  );
}

// ── Detail dialog ─────────────────────────────────────────────────────────────

function EntryDetail({ entry, open, onClose, oracleResult, onAnalyze, analyzing }: {
  entry: EmergingEntry | null;
  open: boolean;
  onClose: () => void;
  oracleResult?: OracleResult;
  onAnalyze: (cveId: string) => void;
  analyzing: boolean;
}) {
  if (!entry) return null;
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Shield className="h-4 w-4 text-primary" />
            {entry.cve_id}
            {severityBadge(entry.severity)}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          {/* Description */}
          {entry.vulnerability_name && (
            <p className="font-medium text-foreground">{entry.vulnerability_name}</p>
          )}
          {entry.short_description && (
            <p className="text-muted-foreground leading-relaxed">{entry.short_description}</p>
          )}

          {/* Intel sources */}
          {entry.kev_sources?.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Intelligence Sources</p>
              <SourceBadges sources={entry.kev_sources} />
              {entry.kev_sources.length > 1 && (
                <p className="text-xs text-amber-400">Confirmed by {entry.kev_sources.length} independent sources — high exploitation confidence</p>
              )}
            </div>
          )}

          {/* Key signals */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Vendor / Product</p>
              <p className="font-medium">{entry.vendor_project} — {entry.product}</p>
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Added to KEV</p>
              <p className="font-medium">{entry.date_added_kev} ({daysAgo(entry.date_added_kev)})</p>
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">CVSS Score</p>
              <p className="font-medium">{entry.cvss_score ?? '—'}</p>
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">EPSS (informational)</p>
              <p className="font-medium text-muted-foreground">
                {entry.epss_score != null ? `${(entry.epss_score * 100).toFixed(1)}%` : '—'}
              </p>
            </div>
          </div>

          {/* Detection */}
          <div className="border border-border rounded-lg p-3 space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Detection Coverage</p>
            <div className="flex flex-wrap gap-2">
              <DetectionBadge entry={entry} />
              {entry.otx_pulse_count > 0 && (
                <OTXBadge count={entry.otx_pulse_count} active={entry.otx_active_campaign} />
              )}
              {entry.known_ransomware_use === 'Known' && (
                <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 gap-1">
                  <Flame className="h-3 w-3" /> Ransomware
                </Badge>
              )}
            </div>
            <div className="grid grid-cols-3 gap-2 mt-2">
              <div className="flex items-center gap-1.5 text-xs">
                {entry.is_template ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground" />}
                <span className={entry.is_template ? 'text-foreground' : 'text-muted-foreground'}>Nuclei Template</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                {entry.is_poc ? <CheckCircle2 className="h-3.5 w-3.5 text-yellow-400" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground" />}
                <span className={entry.is_poc ? 'text-foreground' : 'text-muted-foreground'}>Public PoC</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                {entry.is_remote ? <CheckCircle2 className="h-3.5 w-3.5 text-orange-400" /> : <XCircle className="h-3.5 w-3.5 text-muted-foreground" />}
                <span className={entry.is_remote ? 'text-foreground' : 'text-muted-foreground'}>Remote Exploit</span>
              </div>
            </div>
          </div>

          {/* Oracle */}
          {(entry.oracle_analyzed || oracleResult) ? (
            <div className="border border-border rounded-lg p-3 space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Oracle Analysis</p>
              <div className="flex flex-wrap items-center gap-3">
                <OracleBadge entry={entry} />
                <OracleScoreBadge entry={entry} oracleResult={oracleResult} />
                {(oracleResult?.attack_path_class || entry.opes_category) && (
                  <div>
                    <p className="text-xs text-muted-foreground">Attack Path</p>
                    <p className="font-medium text-sm">{oracleResult?.attack_path_class || entry.opes_category}</p>
                  </div>
                )}
                {oracleResult?.confidence && (
                  <div>
                    <p className="text-xs text-muted-foreground">Confidence</p>
                    <p className="font-medium text-sm capitalize">{oracleResult.confidence}</p>
                  </div>
                )}
                {entry.delphi_priority && (
                  <div>
                    <p className="text-xs text-muted-foreground">Delphi Priority</p>
                    <p className="font-medium capitalize">{entry.delphi_priority}</p>
                  </div>
                )}
              </div>
              {oracleResult?.analyst_brief && (
                <p className="text-xs text-muted-foreground leading-relaxed mt-2 border-t border-border pt-2">
                  {oracleResult.analyst_brief}
                </p>
              )}
            </div>
          ) : (
            <div className="border border-border rounded-lg p-3 bg-muted/20 space-y-2">
              <p className="text-xs text-muted-foreground">This CVE has not yet been analyzed by Oracle.</p>
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-primary/40 text-primary hover:bg-primary/10"
                disabled={analyzing}
                onClick={() => onAnalyze(entry.cve_id)}
              >
                {analyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                {analyzing ? 'Analyzing…' : 'Analyze with Oracle'}
              </Button>
            </div>
          )}

          {/* Tags */}
          {entry.tags.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground mb-1.5">Tags</p>
              <div className="flex flex-wrap gap-1">
                {entry.tags.map(t => (
                  <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Links */}
          <div className="flex gap-2 pt-1">
            <Button variant="outline" size="sm" asChild>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${entry.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="gap-1.5"
              >
                <ExternalLink className="h-3.5 w-3.5" /> NVD
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a
                href={`https://vulncheck.com/advisories?cve=${entry.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="gap-1.5"
              >
                <ExternalLink className="h-3.5 w-3.5" /> VulnCheck
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a
                href={`https://otx.alienvault.com/indicator/cve/${entry.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="gap-1.5"
              >
                <ExternalLink className="h-3.5 w-3.5" /> OTX
              </a>
            </Button>
            {entry.is_template ? (
              <Button variant="outline" size="sm" asChild>
                <a
                  href={`https://cloud.projectdiscovery.io/templates?cveId=${entry.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="gap-1.5 border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
                >
                  <FileCode className="h-3.5 w-3.5" /> Nuclei Templates
                </a>
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-purple-500/40 text-purple-400 hover:bg-purple-500/10"
                onClick={() => {
                  window.location.href = `/nuclei-templates?generate=${entry.cve_id}`;
                }}
              >
                <Sparkles className="h-3.5 w-3.5" /> Generate Template
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  label, value, icon: Icon, color, tooltip,
}: {
  label: string; value: number | string; icon: React.ElementType;
  color: string; tooltip?: string;
}) {
  const card = (
    <Card className="border-border bg-card">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={cn('p-2 rounded-lg', color)}>
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
  if (!tooltip) return card;
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>{card}</TooltipTrigger>
        <TooltipContent><p className="text-xs max-w-xs">{tooltip}</p></TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const { toast } = useToast();
  const [data, setData] = useState<EmergingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [days, setDays] = useState(30);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [detectionFilter, setDetectionFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<EmergingEntry | null>(null);
  const [sortField, setSortField] = useState<'date_added_kev' | 'cvss_score' | 'otx_pulse_count'>('date_added_kev');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [oracleResults, setOracleResults] = useState<Record<string, OracleResult>>({});
  const [analyzingCves, setAnalyzingCves] = useState<Set<string>>(new Set());

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    try {
      const params: Record<string, string> = { days: String(days), limit: '500' };
      if (severityFilter !== 'all') params.severity = severityFilter;
      if (detectionFilter !== 'all') params.detection = detectionFilter;
      if (sourceFilter !== 'all') params.source = sourceFilter;
      // OTX is deferred to CVE detail — emerging used to fan-out ~10s/CVE and hang the UI.
      const resp = await api.get('/threat-intel/emerging', params, { timeout: 60000 });
      setData(resp.data);
    } catch (err: any) {
      const timedOut = err?.code === 'ECONNABORTED' || String(err?.message || '').toLowerCase().includes('timeout');
      toast({
        title: 'Failed to load emerging threats',
        description: timedOut
          ? 'Request timed out while aggregating intel feeds. Retry or narrow the date window.'
          : (err?.response?.data?.detail || err.message),
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [days, severityFilter, detectionFilter, sourceFilter, toast]);

  useEffect(() => { load(); }, [load]);

  const analyzeWithOracle = useCallback(async (cveId: string) => {
    if (analyzingCves.has(cveId)) return;
    setAnalyzingCves(prev => new Set(prev).add(cveId));
    try {
      const resp = await api.post(`/threat-intel/analyze/${cveId}`, {});
      setOracleResults(prev => ({ ...prev, [cveId]: resp.data }));
      toast({ title: `Oracle analysis complete`, description: `${cveId}: ${resp.data.attack_path_class || resp.data.opes_category || 'Analysis stored'}` });
    } catch (err: any) {
      toast({ title: 'Oracle analysis failed', description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    } finally {
      setAnalyzingCves(prev => { const s = new Set(prev); s.delete(cveId); return s; });
    }
  }, [analyzingCves, toast]);

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const filtered = (data?.entries ?? []).filter(e => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      e.cve_id.toLowerCase().includes(q) ||
      e.vendor_project.toLowerCase().includes(q) ||
      e.product.toLowerCase().includes(q) ||
      e.vulnerability_name?.toLowerCase().includes(q) ||
      e.tags.some(t => t.toLowerCase().includes(q))
    );
  }).sort((a, b) => {
    let av: any = a[sortField] ?? 0;
    let bv: any = b[sortField] ?? 0;
    if (sortField === 'date_added_kev') { av = av || ''; bv = bv || ''; }
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const SortIcon = ({ field }: { field: typeof sortField }) =>
    sortField === field
      ? sortDir === 'asc' ? <ChevronUp className="h-3 w-3 inline ml-0.5" /> : <ChevronDown className="h-3 w-3 inline ml-0.5" />
      : null;

  const summary = data?.summary;

  if (loading) {
    return (
      <MainLayout>
        <Header title="Vulnerability Intelligence" subtitle="Loading exploitation intelligence from all sources…" />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header
        title="Vulnerability Intelligence"
        subtitle={`All exploitation intelligence sources — ${days === 0 ? 'all time' : `last ${days} days`}${data ? ` · ${data.total} CVEs across CISA, VulnCheck, ENISA & EUVD` : ''}`}
      />

      <div className="p-6 space-y-6">

        {/* Source status banner */}
        {summary && (
          <div className="flex items-start gap-2 p-3 rounded-lg border border-border bg-muted/20 text-sm text-muted-foreground">
            <Info className="h-4 w-4 mt-0.5 shrink-0 text-primary" />
            <div className="space-y-1">
              <p className="text-foreground font-medium text-xs">Active intelligence sources</p>
              <div className="flex flex-wrap gap-2 text-xs">
                <span className="text-blue-400">✓ CISA KEV <span className="text-muted-foreground">(free)</span></span>
                {summary.vulncheck_configured
                  ? <span className="text-indigo-400">✓ VulnCheck KEV</span>
                  : <span className="text-yellow-500">⚠ VulnCheck — add <code className="bg-black/20 px-0.5 rounded">VULNCHECK_API_TOKEN</code> for 150+ source aggregation</span>
                }
                <span className="text-cyan-400">✓ ENISA EU KEV <span className="text-muted-foreground">(free)</span></span>
                <span className="text-teal-400">✓ EUVD <span className="text-muted-foreground">(free)</span></span>
                <span className="text-orange-400">✓ Shadowserver <span className="text-muted-foreground">(free via CIRCL)</span></span>
                <span className="text-rose-400">✓ KEVIntel <span className="text-muted-foreground">(free via CIRCL)</span></span>
                {!summary.pdcp_configured && (
                  <span className="text-yellow-500">⚠ PDCP — add <code className="bg-black/20 px-0.5 rounded">PDCP_API_KEY</code> for Nuclei template data (<a href="https://cloud.projectdiscovery.io" target="_blank" rel="noopener noreferrer" className="underline">free key</a>)</span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Summary stat cards */}
        {summary && (
          <>
            {/* Top row: source breakdown */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
              <StatCard label="Total CVEs" value={summary.total} icon={TrendingUp}
                color="bg-primary/10 text-primary" tooltip="Unique CVEs from all exploitation intelligence sources combined" />
              <StatCard label="CISA KEV" value={summary.by_source?.cisa_kev ?? 0} icon={Shield}
                color="bg-blue-500/10 text-blue-400" tooltip="CVEs in the CISA Known Exploited Vulnerabilities catalog" />
              <StatCard label="VulnCheck KEV" value={summary.by_source?.vulncheck_kev ?? 0} icon={Crosshair}
                color="bg-indigo-500/10 text-indigo-400" tooltip="VulnCheck KEV — broadest exploitation catalog; primary Delphi prioritization signal" />
              <StatCard label="ENISA KEV" value={summary.by_source?.enisa_kev ?? 0} icon={AlertCircle}
                color="bg-cyan-500/10 text-cyan-400" tooltip="CVEs in the ENISA EU CSIRT Network KEV List" />
              <StatCard label="EUVD" value={summary.by_source?.euvd ?? 0} icon={Info}
                color="bg-teal-500/10 text-teal-400" tooltip="Exploited-in-the-wild entries from the EU Vulnerability Database" />
              <StatCard label="Shadowserver" value={summary.by_source?.shadowserver ?? 0} icon={Activity}
                color="bg-orange-500/10 text-orange-400" tooltip="CVEs observed in Shadowserver honeypot exploited feed" />
              <StatCard label="KEVIntel" value={summary.by_source?.kevintel ?? 0} icon={Zap}
                color="bg-rose-500/10 text-rose-400" tooltip="CVEs attested by KEVIntel (via CIRCL)" />
            </div>
            {/* Bottom row: signal stats */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <StatCard label="Multi-Source" value={summary.multi_source_count} icon={Sparkles}
                color="bg-amber-500/10 text-amber-400" tooltip="CVEs confirmed by 2+ independent sources — highest confidence of active exploitation" />
              <StatCard label="Critical" value={summary.by_severity?.critical ?? 0} icon={AlertTriangle}
                color="bg-red-500/10 text-red-400" />
              <StatCard label="High" value={summary.by_severity?.high ?? 0} icon={AlertTriangle}
                color="bg-orange-500/10 text-orange-400" />
              <StatCard label="Nuclei Templates" value={summary.with_nuclei_template} icon={FileCode}
                color="bg-emerald-500/10 text-emerald-400"
                tooltip="Vulnerabilities with a Nuclei detection template — can be auto-detected" />
              <StatCard label="Active Campaigns" value={summary.otx_active_campaigns} icon={Activity}
                color="bg-purple-500/10 text-purple-400"
                tooltip={(summary as any).otx_deferred
                  ? 'OTX campaign pulses load on CVE detail (deferred so the list stays fast)'
                  : 'CVEs with 20+ OTX threat-intel pulses — active attacker campaigns'} />
              <StatCard label="Ransomware" value={summary.ransomware_associated} icon={Flame}
                color="bg-red-700/10 text-red-500"
                tooltip="CVEs associated with known ransomware operators" />
            </div>
          </>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-48 max-w-80">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search CVE, vendor, product, tag…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 h-9"
            />
          </div>

          <Select value={String(days)} onValueChange={v => setDays(Number(v))}>
            <SelectTrigger className="w-36 h-9">
              <Clock className="h-3.5 w-3.5 mr-1.5 text-muted-foreground" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="14">Last 14 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="60">Last 60 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
              <SelectItem value="180">Last 180 days</SelectItem>
              <SelectItem value="365">Last year</SelectItem>
              <SelectItem value="0">All time</SelectItem>
            </SelectContent>
          </Select>

          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-36 h-9">
              <Shield className="h-3.5 w-3.5 mr-1.5 text-muted-foreground" />
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>

          <Select value={detectionFilter} onValueChange={setDetectionFilter}>
            <SelectTrigger className="w-48 h-9">
              <Eye className="h-3.5 w-3.5 mr-1.5 text-muted-foreground" />
              <SelectValue placeholder="Detection" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Detection Tiers</SelectItem>
              <SelectItem value="nuclei_template">Nuclei Template</SelectItem>
              <SelectItem value="poc_available">PoC Available</SelectItem>
              <SelectItem value="remote_no_template">Remote / No Template</SelectItem>
              <SelectItem value="no_detection">No Detection</SelectItem>
            </SelectContent>
          </Select>

          <Select value={sourceFilter} onValueChange={setSourceFilter}>
            <SelectTrigger className="w-44 h-9">
              <Zap className="h-3.5 w-3.5 mr-1.5 text-muted-foreground" />
              <SelectValue placeholder="Source" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Sources</SelectItem>
              <SelectItem value="cisa_kev">CISA KEV only</SelectItem>
              <SelectItem value="vulncheck_kev">VulnCheck only</SelectItem>
              <SelectItem value="enisa_kev">ENISA KEV only</SelectItem>
              <SelectItem value="euvd">EUVD only</SelectItem>
              <SelectItem value="shadowserver">Shadowserver only</SelectItem>
              <SelectItem value="kevintel">KEVIntel only</SelectItem>
            </SelectContent>
          </Select>

          <Button
            variant="outline"
            size="sm"
            onClick={() => load(true)}
            disabled={refreshing}
            className="gap-1.5 h-9 ml-auto"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} />
            Refresh
          </Button>
        </div>

        {/* Table */}
        <Card className="border-border">
          <CardContent className="p-0">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Shield className="h-10 w-10 mb-3 opacity-30" />
                <p className="font-medium">No entries found</p>
                <p className="text-sm mt-1">
                  {!summary?.vulncheck_configured
                    ? 'Configure VULNCHECK_API_TOKEN to see emerging KEV data'
                    : 'Try adjusting your filters or time window'}
                </p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-border hover:bg-transparent">
                    <TableHead className="w-36">CVE</TableHead>
                    <TableHead>Vulnerability</TableHead>
                    <TableHead className="w-24">Severity</TableHead>
                    <TableHead className="w-44">Oracle</TableHead>
                    <TableHead
                      className="w-28 cursor-pointer select-none hover:text-foreground"
                      onClick={() => toggleSort('cvss_score')}
                    >
                      CVSS <SortIcon field="cvss_score" />
                    </TableHead>
                    <TableHead className="w-48">Intel Sources</TableHead>
                    <TableHead className="w-40">Detection</TableHead>
                    <TableHead
                      className="w-20 cursor-pointer select-none hover:text-foreground"
                      onClick={() => toggleSort('otx_pulse_count')}
                    >
                      OTX <SortIcon field="otx_pulse_count" />
                    </TableHead>
                    <TableHead className="w-28">Ransomware</TableHead>
                    <TableHead
                      className="w-24 cursor-pointer select-none hover:text-foreground"
                      onClick={() => toggleSort('date_added_kev')}
                    >
                      Added <SortIcon field="date_added_kev" />
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map(entry => (
                    <TableRow
                      key={entry.cve_id}
                      className="border-border cursor-pointer hover:bg-muted/30"
                      onClick={() => setSelected(entry)}
                    >
                      {/* CVE ID */}
                      <TableCell className="font-mono text-xs font-semibold text-primary">
                        {entry.cve_id}
                        {entry.known_ransomware_use === 'Known' && (
                          <Flame className="h-3 w-3 text-red-400 inline ml-1" />
                        )}
                        {entry.otx_active_campaign && (
                          <Activity className="h-3 w-3 text-purple-400 inline ml-1" />
                        )}
                      </TableCell>

                      {/* Name / vendor */}
                      <TableCell>
                        <div className="space-y-0.5">
                          <p className="text-sm font-medium leading-snug line-clamp-1">
                            {entry.vulnerability_name || entry.short_description || '—'}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {entry.vendor_project}
                            {entry.product ? ` — ${entry.product}` : ''}
                          </p>
                        </div>
                      </TableCell>

                      {/* Severity */}
                      <TableCell>{severityBadge(entry.severity)}</TableCell>

                      {/* Oracle */}
                      <TableCell onClick={e => e.stopPropagation()}>
                        {(() => {
                          const result = oracleResults[entry.cve_id];
                          const isAnalyzing = analyzingCves.has(entry.cve_id);
                          const hasResult = result || entry.oracle_analyzed;
                          if (isAnalyzing) {
                            return <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />;
                          }
                          if (hasResult) {
                            return <OracleScoreBadge entry={entry} oracleResult={result} />;
                          }
                          return (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="h-6 px-2 text-xs text-muted-foreground hover:text-primary gap-1"
                                    onClick={() => analyzeWithOracle(entry.cve_id)}
                                  >
                                    <Sparkles className="h-3 w-3" />
                                    Analyze
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p className="text-xs">Run Oracle intrinsic analysis on this CVE</p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          );
                        })()}
                      </TableCell>

                      {/* CVSS */}
                      <TableCell>
                        {entry.cvss_score != null ? (
                          <span className="font-mono text-sm font-semibold">{entry.cvss_score.toFixed(1)}</span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>

                      {/* Intel Sources */}
                      <TableCell onClick={e => e.stopPropagation()}>
                        <SourceBadges sources={entry.kev_sources} />
                      </TableCell>

                      {/* Detection */}
                      <TableCell>
                        <DetectionBadge entry={entry} />
                      </TableCell>

                      {/* OTX */}
                      <TableCell>
                        <OTXBadge count={entry.otx_pulse_count} active={entry.otx_active_campaign} />
                      </TableCell>

                      {/* Ransomware */}
                      <TableCell>
                        {entry.known_ransomware_use === 'Known' ? (
                          <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 gap-1 text-xs">
                            <Flame className="h-3 w-3" /> Known
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </TableCell>

                      {/* Date */}
                      <TableCell>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="text-xs text-muted-foreground">{daysAgo(entry.date_added_kev)}</span>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="text-xs">{entry.date_added_kev}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </TableCell>
                    </TableRow>

                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <p className="text-xs text-muted-foreground text-center">
          Sources: CISA KEV · VulnCheck KEV · ENISA EU KEV · EUVD · AlienVault OTX (campaign signals) · ProjectDiscovery PDCP (template availability) · Oracle OPES
        </p>
      </div>

      <EntryDetail
        entry={selected}
        open={!!selected}
        onClose={() => setSelected(null)}
        oracleResult={selected ? oracleResults[selected.cve_id] : undefined}
        onAnalyze={analyzeWithOracle}
        analyzing={selected ? analyzingCves.has(selected.cve_id) : false}
      />
    </MainLayout>
  );
}
