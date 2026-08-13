'use client';

import { useEffect, useRef, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent } from '@/components/ui/card';
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  Shield,
  Search,
  Download,
  Loader2,
  ExternalLink,
  ChevronRight,
  Filter,
  AlertCircle,
  Clock,
  Tag,
  FileCode,
  Target,
  Activity,
  User,
  Calendar,
  Link as LinkIcon,
  Info,
  CheckCircle,
  XCircle,
  Users,
  Flame,
  TrendingUp,
  Sparkles,
  ArrowUpDown,
  RefreshCw,
  Ticket,
  ShieldCheck,
  ShieldOff,
  Bug,
  Copy,
  Camera,
} from 'lucide-react';
import Link from 'next/link';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV, cn } from '@/lib/utils';
import { RemediationPanel } from '@/components/remediation/RemediationPanel';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { JiraProjectPicker } from '@/components/integrations/JiraProjectPicker';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface DelphiKEV {
  cve_id: string;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  date_added?: string;
  short_description?: string;
  required_action?: string;
  due_date?: string;
  known_ransomware_use?: string;
  notes?: string;
}

interface DelphiEPSS {
  score: number;
  percentile: number;
  /** display_label replaced 'bucket' — informational only, not used in scoring */
  display_label?: string;
  /** Legacy field kept for backward-compat with old enrichment records */
  bucket?: string;
  date?: string;
  informational_only?: boolean;
  scoring_note?: string;
}

/** Exploitation-likelihood factor breakdown (each normalized 0..1). */
interface DelphiFactors {
  /** Severity magnitude = cvss_score / 10 */
  severity?: number;
  /** Exploitability conditions = AV x AC x AT x PR x UI */
  exploitability?: number;
  /** Reachability from asset exposure (internet-facing / live / WAF) */
  reachability?: number;
  /** Detection confidence (exploit_confirmed .. version_only) */
  confidence?: number;
  cvss_score?: number;
}

interface DelphiEnrichment {
  kev?: DelphiKEV | null;
  epss?: DelphiEPSS | null;
  priority?: 'critical' | 'high' | 'elevated' | 'moderate' | 'low' | 'none';
  /** 0-100 exploitation-likelihood score that drives the priority tier. */
  likelihood_score?: number;
  priority_reason?: string;
  priority_signals?: string[];
  factors?: DelphiFactors;
  enriched_at?: string;
}

interface Finding {
  id: number;
  title: string;
  name?: string;
  template_id: string;
  severity: string;
  host: string;
  matched_at?: string;
  description?: string;
  references?: string[];
  reference?: string[];
  tags?: string[];
  created_at: string;
  updated_at?: string;
  first_detected?: string;
  last_detected?: string;
  // Extended metadata
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  status?: string;
  assigned_to?: string;
  evidence?: string;
  proof_of_concept?: string;
  remediation?: string;
  remediation_deadline?: string;
  detected_by?: string;
  matcher_name?: string;
  asset_id?: number;
  organization_id?: number;
  scan_id?: number;
  resolved_at?: string;
  validation_status?: string;
  last_validation_verdict?: string;
  last_validated_at?: string;
  // Latest asset screenshot for analyst visual context
  screenshot_id?: number | null;
  screenshot_page_title?: string | null;
  screenshot_captured_at?: string | null;
  // Delphi (CISA KEV + FIRST EPSS) enrichment
  delphi?: DelphiEnrichment;
  // Aegis Oracle enrichment — denormalised payload persisted by the
  // backend's oracle_enrichment_service. Either a full Phase A+B+OPES
  // analysis (mode='full'), Phase-A intrinsic only (mode='intrinsic'), or
  // ASM-native non-CVE analysis (mode='generic_finding').
  oracle?: OracleEnrichment;
}

interface OracleEnrichment {
  mode: 'full' | 'intrinsic' | 'generic_finding';
  enriched_at?: string;
  analysis_status?: string;
  analysis_error?: string;
  finding_class?: string;
  opes_score?: number;
  opes_category?: 'urgent' | 'critical' | 'high' | 'medium' | 'low' | 'informational';
  opes_label?: string;
  opes_confidence?: 'high' | 'medium' | 'low';
  attack_path_class?: string;
  recommendation_text?: string;
  analyst_brief?: {
    title?: string;
    attack_vector_summary?: string;
    real_world_likelihood?: string;
    exploitability_score?: number;
    exploitability_tier?: string;
  };
}

type SortMode = 'opes' | 'severity' | 'delphi' | 'recent' | 'cvss';

const opesSortRank: Record<string, number> = {
  urgent: 0,
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  informational: 5,
  info: 5,
};

/** Effective priority for display/sort: OPES category, else scanner severity. */
function effectivePriority(finding: {
  severity?: string;
  oracle?: { opes_category?: string; opes_score?: number | null } | null;
}): string {
  const opes = finding.oracle?.opes_category?.toLowerCase();
  if (opes) return opes === 'urgent' ? 'critical' : opes;
  const sev = (finding.severity || 'info').toLowerCase();
  return sev === 'info' ? 'informational' : sev;
}

function priorityBadgeLabel(category: string): string {
  if (category === 'informational' || category === 'info') return 'info';
  return category;
}

// Matches the backend's TIER_RANK in delphi_enrichment_service.py.
const delphiPriorityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  elevated: 2,
  moderate: 3,
  low: 4,
  none: 5,
};

const delphiPriorityStyle: Record<string, { label: string; className: string }> = {
  critical: { label: 'Delphi Critical', className: 'bg-red-600/20 text-red-400 border-red-600/40' },
  high: { label: 'Delphi High', className: 'bg-orange-500/20 text-orange-400 border-orange-500/40' },
  elevated: { label: 'Delphi Elevated', className: 'bg-amber-500/20 text-amber-400 border-amber-500/40' },
  moderate: { label: 'Delphi Moderate', className: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' },
  low: { label: 'Delphi Low', className: 'bg-blue-500/20 text-blue-400 border-blue-500/40' },
};

function isRansomwareKev(kev?: DelphiKEV | null): boolean {
  const v = (kev?.known_ransomware_use || '').toLowerCase();
  return v === 'known' || v === 'yes';
}

// OPES priority styles — match the colour scheme used on the dedicated
// /oracle page so badges read consistently across the app.
// "urgent" is a manual-only override; the engine never auto-assigns it.
const opesCategoryStyle: Record<string, { label: string; className: string }> = {
  urgent:       { label: 'OPES Urgent',       className: 'bg-purple-600/20 text-purple-300 border-purple-600/40' },
  critical:     { label: 'OPES Critical',     className: 'bg-red-600/20 text-red-300 border-red-600/40' },
  high:         { label: 'OPES High',         className: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
  medium:       { label: 'OPES Medium',       className: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' },
  low:          { label: 'OPES Low',          className: 'bg-blue-500/20 text-blue-300 border-blue-500/40' },
  informational:{ label: 'OPES Info',         className: 'bg-muted text-muted-foreground border-muted-foreground/30' },
};

function OracleBadge({ oracle, compact = false }: { oracle?: OracleEnrichment; compact?: boolean }) {
  if (!oracle || !oracle.opes_category) return null;
  const style = opesCategoryStyle[oracle.opes_category] ?? opesCategoryStyle.informational;
  const score = oracle.opes_score != null ? ` · ${oracle.opes_score.toFixed(1)}` : '';
  const title = [
    `${style.label}${score}`,
    oracle.opes_label,
    oracle.attack_path_class ? `Attack path: ${oracle.attack_path_class}` : null,
    oracle.opes_confidence ? `Confidence: ${oracle.opes_confidence}` : null,
  ].filter(Boolean).join(' · ');
  return (
    <Badge
      variant="outline"
      className={cn('text-[10px] px-1.5 py-0 h-5 border font-semibold', style.className, compact ? '' : '')}
      title={title}
    >
      <Sparkles className="h-3 w-3 mr-0.5" />
      {style.label}{score}
    </Badge>
  );
}

// OracleEnrichmentPanel renders the Aegis Oracle analysis attached to a
// vulnerability. Falls back to a small "no analysis yet" card with an
// "Analyze with Oracle" button so an analyst can request enrichment
// on demand. When enrichment already exists, the button refreshes it
// (force=true) so the analyst can re-run after asset signals change.
function OracleEnrichmentPanel({
  finding,
  onUpdate,
}: {
  finding: Finding | null;
  onUpdate: (oracle: OracleEnrichment) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  if (!finding) return null;

  const oracle = finding.oracle;
  const canEnrich = !!finding.id;

  async function runEnrich(force: boolean) {
    if (!finding || !finding.id) return;
    if (!canEnrich) {
      setError('Oracle cannot run analysis for this finding.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // The single-vuln route returns a summary, but the persisted payload
      // on the row carries the full narrative. Re-fetch the vulnerability
      // would be cleaner but we already get the most useful fields on the
      // response; merge them and trust the next list reload for the full
      // recommendation text.
      const summary = await api.oracleEnrichVulnerability(finding.id, force);
      // We optimistically reflect the new headline data; full narrative
      // becomes available the next time findings are reloaded from /api.
      onUpdate({
        ...(oracle ?? { mode: finding.cve_id ? 'intrinsic' : 'generic_finding' }),
        mode: (summary.mode as OracleEnrichment['mode']) || (finding.cve_id ? 'intrinsic' : 'generic_finding'),
        enriched_at: summary.enriched_at ?? new Date().toISOString(),
        analysis_status: summary.analysis_status ?? oracle?.analysis_status,
        analysis_error: summary.analysis_error ?? oracle?.analysis_error,
        opes_score: summary.opes_score ?? oracle?.opes_score,
        opes_category: (summary.opes_category as OracleEnrichment['opes_category']) ?? oracle?.opes_category,
        opes_label: summary.opes_label ?? oracle?.opes_label,
        attack_path_class: summary.attack_path_class ?? oracle?.attack_path_class,
      });
      toast({
        title: 'Oracle analysis updated',
        description: summary.opes_category
          ? `${summary.opes_category} · ${summary.opes_label ?? ''}`
          : 'Phase-A analysis fetched (no asset linked yet).',
      });
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable.';
      setError(msg);
      toast({ variant: 'destructive', title: 'Oracle enrichment failed', description: msg });
    } finally {
      setBusy(false);
    }
  }

  // No enrichment yet — show a call-to-action card.
  if (!oracle) {
    return (
      <div className="space-y-2">
        <p className="text-sm font-medium flex items-center gap-2 text-orange-300">
          <Sparkles className="h-4 w-4" /> Aegis Oracle
        </p>
        <div className="rounded-lg border bg-orange-500/5 border-orange-500/30 p-3 text-sm">
          <p className="text-muted-foreground">
            No Oracle analysis on this finding yet. Run Oracle to get an OPES
            priority, attack-path classification, analyst brief, and a
            recommendation narrative.
          </p>
          <div className="mt-3 flex items-center gap-2">
            <Button size="sm" disabled={busy || !canEnrich} onClick={() => runEnrich(false)}>
              {busy ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1.5" />}
              Analyze with Oracle
            </Button>
            {error && <span className="text-xs text-red-400">{error}</span>}
          </div>
        </div>
      </div>
    );
  }

  // Enrichment present — render the OPES headline, attack path, analyst brief
  // summary, and the recommendation narrative.
  const style = oracle.opes_category ? opesCategoryStyle[oracle.opes_category] : null;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-sm font-medium flex items-center gap-2 text-orange-300">
          <Sparkles className="h-4 w-4" /> Aegis Oracle
          {oracle.mode === 'intrinsic' && (
            <Badge variant="outline" className="text-[10px] border-yellow-500/40 text-yellow-300">
              Phase-A only (no asset)
            </Badge>
          )}
          {oracle.mode === 'generic_finding' && (
            <Badge variant="outline" className="text-[10px] border-blue-500/40 text-blue-300">
              ASM finding
            </Badge>
          )}
        </p>
        <Button size="sm" variant="outline" disabled={busy || !canEnrich} onClick={() => runEnrich(true)}>
          {busy ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
          Refresh
        </Button>
      </div>

      <div className="rounded-lg border bg-orange-500/5 border-orange-500/30 p-3 space-y-3">
        {oracle.analysis_status === 'failed' && oracle.analysis_error && (
          <div className="rounded border border-red-500/40 bg-red-500/5 p-2 text-xs text-red-300">
            {oracle.analysis_error}
          </div>
        )}

        {/* Headline row: OPES category + score + label + confidence */}
        <div className="flex items-center gap-2 flex-wrap">
          {style && oracle.opes_category && (
            <Badge variant="outline" className={cn('text-xs font-semibold', style.className)}>
              {style.label}
              {oracle.opes_score != null && ` · ${oracle.opes_score.toFixed(1)}`}
            </Badge>
          )}
          {oracle.opes_label && <span className="text-sm">{oracle.opes_label}</span>}
          {oracle.opes_confidence && (
            <span className="text-xs text-muted-foreground">{oracle.opes_confidence} confidence</span>
          )}
          {oracle.attack_path_class && (
            <Badge variant="outline" className="text-[10px]">
              {oracle.attack_path_class.replace(/_/g, ' ')}
            </Badge>
          )}
        </div>

        {/* Analyst brief highlights — single attack-vector summary + likelihood line */}
        {oracle.analyst_brief?.attack_vector_summary && (
          <div className="border-l-2 border-orange-500/50 pl-2 text-xs">
            <p className="text-foreground/90">{oracle.analyst_brief.attack_vector_summary}</p>
          </div>
        )}

        {/* Recommendation narrative — section-headed, monospace so the
            ATTACK PATH / EVIDENCE / NEXT STEPS structure stays legible. */}
        {oracle.recommendation_text && (
          <details className="text-xs" open>
            <summary className="text-muted-foreground cursor-pointer hover:text-foreground">
              Recommendation narrative
            </summary>
            <pre className="mt-2 whitespace-pre-wrap font-mono leading-relaxed text-foreground/80 text-[11px]">
              {oracle.recommendation_text}
            </pre>
          </details>
        )}

        {oracle.enriched_at && (
          <p className="text-[10px] text-muted-foreground">
            Enriched {formatDate(oracle.enriched_at)}
          </p>
        )}
      </div>
    </div>
  );
}

function DelphiBadges({ delphi, compact = false }: { delphi?: DelphiEnrichment; compact?: boolean }) {
  const hasPriority = !!delphi?.priority && delphi.priority !== 'none';
  if (!delphi || (!delphi.kev && !delphi.epss && !hasPriority)) return null;
  const ransomware = isRansomwareKev(delphi.kev);
  return (
    <div className={cn('flex items-center gap-1 flex-wrap', compact ? '' : 'mt-1')}>
      {delphi.kev && (
        <Badge
          variant="outline"
          className={cn(
            'text-[10px] px-1.5 py-0 h-5 border',
            ransomware
              ? 'bg-red-600/20 text-red-300 border-red-600/40'
              : 'bg-red-500/15 text-red-400 border-red-500/30'
          )}
          title={
            ransomware
              ? 'On CISA KEV — known ransomware use'
              : `On CISA KEV${delphi.kev.date_added ? ` (added ${delphi.kev.date_added})` : ''}`
          }
        >
          <Flame className="h-3 w-3 mr-0.5" />
          {ransomware ? 'KEV · Ransomware' : 'CISA KEV'}
        </Badge>
      )}
      {delphi.epss && (
        <Badge
          variant="outline"
          className="text-[10px] px-1.5 py-0 h-5 border bg-muted/40 text-muted-foreground border-muted-foreground/20"
          title={`EPSS (informational only — not used in scoring)\nScore: ${delphi.epss.score.toFixed(3)} · Percentile: ${(delphi.epss.percentile * 100).toFixed(1)}%\nEPSS is a probabilistic estimate. Priority is driven by KEV status and CVSS analysis.`}
        >
          <TrendingUp className="h-3 w-3 mr-0.5 opacity-60" />
          EPSS {(delphi.epss.percentile * 100).toFixed(0)}%
          <Info className="h-2.5 w-2.5 ml-0.5 opacity-60" />
        </Badge>
      )}
      {delphi.priority && delphi.priority !== 'none' && delphiPriorityStyle[delphi.priority] && (
        <Badge
          variant="outline"
          className={cn('text-[10px] px-1.5 py-0 h-5 border', delphiPriorityStyle[delphi.priority].className)}
          title={delphi.priority_reason || ''}
        >
          <Sparkles className="h-3 w-3 mr-0.5" />
          {compact
            ? delphi.priority.charAt(0).toUpperCase() + delphi.priority.slice(1)
            : delphiPriorityStyle[delphi.priority].label}
          {typeof delphi.likelihood_score === 'number' && (
            <span className="ml-1 font-mono opacity-80">{delphi.likelihood_score}</span>
          )}
        </Badge>
      )}
    </div>
  );
}

/**
 * Exploitation-likelihood breakdown for the finding detail panel: the 0-100
 * score plus the four factors that produced it (severity, exploitability,
 * reachability, detection confidence). Rendered only when a computed score is
 * present (KEV/breach findings floored by facts still show it).
 */
function DelphiLikelihood({ delphi }: { delphi?: DelphiEnrichment }) {
  if (!delphi || typeof delphi.likelihood_score !== 'number') return null;
  const score = delphi.likelihood_score;
  const f = delphi.factors || {};

  const scoreColor =
    score >= 80 ? 'text-red-400' :
    score >= 60 ? 'text-orange-400' :
    score >= 40 ? 'text-amber-400' :
    score >= 20 ? 'text-yellow-400' : 'text-blue-400';
  const barColor =
    score >= 80 ? 'bg-red-500' :
    score >= 60 ? 'bg-orange-500' :
    score >= 40 ? 'bg-amber-500' :
    score >= 20 ? 'bg-yellow-500' : 'bg-blue-500';

  const factorRows: { label: string; value?: number; hint: string }[] = [
    { label: 'Severity', value: f.severity, hint: 'CVSS base score / 10' },
    { label: 'Exploitability', value: f.exploitability, hint: 'Attack vector, complexity, privileges, user interaction' },
    { label: 'Reachability', value: f.reachability, hint: 'Asset exposure: internet-facing, live, WAF' },
    { label: 'Detection confidence', value: f.confidence, hint: 'How confirmed the vulnerable feature is (vs. version-only)' },
  ];

  return (
    <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3 space-y-2.5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Exploitation likelihood</p>
          <p className="text-[11px] text-muted-foreground">
            score = severity x exploitability x reachability x confidence
          </p>
        </div>
        <div className="text-right">
          <span className={cn('text-2xl font-bold font-mono', scoreColor)}>{score}</span>
          <span className="text-sm text-muted-foreground">/100</span>
        </div>
      </div>
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn('h-full', barColor)} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
      </div>
      {factorRows.some((r) => typeof r.value === 'number') && (
        <div className="space-y-1.5 pt-1">
          {factorRows.map((r) => (
            <div key={r.label} className="flex items-center gap-2" title={r.hint}>
              <span className="text-xs text-muted-foreground w-36 shrink-0">{r.label}</span>
              <div className="flex-1 h-1 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-purple-400/70"
                  style={{ width: `${Math.round((r.value ?? 0) * 100)}%` }}
                />
              </div>
              <span className="text-[11px] font-mono text-muted-foreground w-9 text-right">
                {typeof r.value === 'number' ? r.value.toFixed(2) : '—'}
              </span>
            </div>
          ))}
        </div>
      )}
      {delphi.priority_signals && delphi.priority_signals.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1">
          {delphi.priority_signals.map((sig) => (
            <span
              key={sig}
              className="text-[10px] px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground font-mono"
            >
              {sig}
            </span>
          ))}
        </div>
      )}
      <p className="text-[11px] text-muted-foreground pt-0.5">
        Driven by confirmed exploitation (CISA KEV, breach intel) and the conditions required to
        exploit. EPSS is not used in this score.
      </p>
    </div>
  );
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const severityConfig: Record<Severity, { color: string; bgColor: string; textColor: string; borderColor: string }> = {
  critical: { 
    color: 'bg-red-600', 
    bgColor: 'bg-red-600/10', 
    textColor: 'text-red-400',
    borderColor: 'border-red-600/30'
  },
  high: { 
    color: 'bg-orange-500', 
    bgColor: 'bg-orange-500/10', 
    textColor: 'text-orange-400',
    borderColor: 'border-orange-500/30'
  },
  medium: { 
    color: 'bg-yellow-500', 
    bgColor: 'bg-yellow-500/10', 
    textColor: 'text-yellow-400',
    borderColor: 'border-yellow-500/30'
  },
  low: { 
    color: 'bg-green-500', 
    bgColor: 'bg-green-500/10', 
    textColor: 'text-green-400',
    borderColor: 'border-green-500/30'
  },
  info: { 
    color: 'bg-blue-500', 
    bgColor: 'bg-blue-500/10', 
    textColor: 'text-blue-400',
    borderColor: 'border-blue-500/30'
  },
};

const statusConfig: Record<string, { label: string; color: string }> = {
  open: { label: 'Open', color: 'bg-red-600/20 text-red-400 border-red-600/30' },
  in_progress: { label: 'In Progress', color: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30' },
  resolved: { label: 'Resolved', color: 'bg-green-600/20 text-green-400 border-green-600/30' },
  mitigated: { label: 'Mitigated', color: 'bg-cyan-600/20 text-cyan-400 border-cyan-600/30' },
  accepted: { label: 'Risk Accepted', color: 'bg-blue-600/20 text-blue-400 border-blue-600/30' },
  false_positive: { label: 'False Positive', color: 'bg-gray-600/20 text-gray-400 border-gray-600/30' },
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [remediationData, setRemediationData] = useState<any>(null);
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<number>>(new Set());
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [assignee, setAssignee] = useState('');
  const [sortMode, setSortMode] = useState<SortMode>('opes');
  const [onlyKev, setOnlyKev] = useState(false);
  const [oracleBatchBusy, setOracleBatchBusy] = useState(false);
  const [capturingScreenshot, setCapturingScreenshot] = useState(false);
  const [screenshotLightboxOpen, setScreenshotLightboxOpen] = useState(false);
  const { toast } = useToast();

  // Generate Nuclei Template state
  const [generateTemplateOpen, setGenerateTemplateOpen] = useState(false);
  const [generatingTemplate, setGeneratingTemplate] = useState(false);
  const [generateTemplateCveId, setGenerateTemplateCveId] = useState('');
  const [generateTemplateEvidence, setGenerateTemplateEvidence] = useState('');
  const [firstOrgId, setFirstOrgId] = useState<number | null>(null);

  // Jira ticket state
  const [jiraDialogOpen, setJiraDialogOpen] = useState(false);
  const [jiraDialogMode, setJiraDialogMode] = useState<'create' | 'associate'>('create');
  const [jiraIssueTypes, setJiraIssueTypes] = useState<{ id: string; name: string }[]>([]);
  const [jiraHasIntegration, setJiraHasIntegration] = useState<boolean | null>(null);
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [jiraIssueType, setJiraIssueType] = useState('Bug');
  const [jiraIncludeEvidence, setJiraIncludeEvidence] = useState(true);
  const [jiraIncludeRemediation, setJiraIncludeRemediation] = useState(true);
  const [jiraIncludeEnrichment, setJiraIncludeEnrichment] = useState(true);
  const [jiraCreating, setJiraCreating] = useState(false);
  const [jiraExistingTickets, setJiraExistingTickets] = useState<import('@/lib/api').JiraTicket[]>([]);
  const [jiraAssociateKey, setJiraAssociateKey] = useState('');
  const [jiraDisconnecting, setJiraDisconnecting] = useState<number | null>(null);
  const [jiraRefreshing, setJiraRefreshing] = useState<number | null>(null);

  // ServiceNow push / sync state
  const [snowDialogOpen, setSnowDialogOpen] = useState(false);
  const [snowDialogMode, setSnowDialogMode] = useState<'push' | 'associate'>('push');
  const [snowHasIntegration, setSnowHasIntegration] = useState<boolean | null>(null);
  const [snowSyncEnabled, setSnowSyncEnabled] = useState(false);
  const [snowDeliveries, setSnowDeliveries] = useState<import('@/lib/api').ServiceNowDelivery[]>([]);
  const [snowPushing, setSnowPushing] = useState(false);
  const [snowDisconnecting, setSnowDisconnecting] = useState<number | null>(null);
  const [snowRefreshing, setSnowRefreshing] = useState<number | null>(null);
  const [snowAssociateKey, setSnowAssociateKey] = useState('');
  const [snowIncludeEvidence, setSnowIncludeEvidence] = useState(true);
  const [snowIncludeRemediation, setSnowIncludeRemediation] = useState(true);
  const [snowIncludeEnrichment, setSnowIncludeEnrichment] = useState(true);

  // HackerOne report linking state
  const [h1DialogOpen, setH1DialogOpen] = useState(false);
  const [h1HasIntegration, setH1HasIntegration] = useState<boolean | null>(null);
  const [h1Links, setH1Links] = useState<import('@/lib/api').HackerOneReportLink[]>([]);
  const [h1AssociateKey, setH1AssociateKey] = useState('');
  const [h1Linking, setH1Linking] = useState(false);
  const [h1Disconnecting, setH1Disconnecting] = useState<number | null>(null);
  const [h1Refreshing, setH1Refreshing] = useState<number | null>(null);

  const openServiceNowDialog = async (finding: Finding) => {
    setSnowDialogOpen(true);
    setSnowDialogMode('push');
    setSnowDeliveries([]);
    setSnowAssociateKey('');
    const orgId = finding.organization_id;
    if (!orgId) {
      toast({
        title: 'Could not load ServiceNow data',
        description: 'This finding has no associated organization.',
        variant: 'destructive',
      });
      setSnowDialogOpen(false);
      return;
    }
    try {
      const [integrationData, deliveriesData] = await Promise.all([
        api.getServiceNowIntegration(orgId).catch(() => null),
        api.getServiceNowDeliveriesForVulnerability(finding.id, orgId),
      ]);
      setSnowHasIntegration(integrationData !== null && integrationData.is_active);
      setSnowSyncEnabled(!!integrationData?.sync_enabled);
      setSnowDeliveries(deliveriesData);
    } catch (err: any) {
      if (err?.response?.status === 404) {
        setSnowHasIntegration(false);
      } else {
        toast({ title: 'Could not load ServiceNow data', description: getApiErrorMessage(err), variant: 'destructive' });
        setSnowDialogOpen(false);
      }
    }
  };

  const handlePushServiceNow = async () => {
    if (!selectedFinding) return;
    setSnowPushing(true);
    try {
      const delivery = await api.pushServiceNowVulnerability(selectedFinding.id, {
        include_evidence: snowIncludeEvidence,
        include_remediation: snowIncludeRemediation,
        include_enrichment: snowIncludeEnrichment,
      }, selectedFinding.organization_id);
      const label = delivery.snow_number || delivery.snow_sys_id || `delivery #${delivery.id}`;
      toast({
        title: `Pushed to ServiceNow: ${label}`,
        description: delivery.snow_url || `HTTP ${delivery.http_status ?? 'OK'}`,
      });
      setSnowDeliveries((prev) => [delivery, ...prev]);
    } catch (err) {
      toast({ title: 'Failed to push to ServiceNow', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSnowPushing(false);
    }
  };

  const handleAssociateServiceNow = async () => {
    if (!selectedFinding || !snowAssociateKey.trim()) return;
    setSnowPushing(true);
    try {
      const key = snowAssociateKey.trim();
      const looksLikeSysId = /^[0-9a-f]{32}$/i.test(key);
      const delivery = await api.associateServiceNowDelivery(
        selectedFinding.id,
        looksLikeSysId ? { sys_id: key } : { number: key.toUpperCase() },
        selectedFinding.organization_id,
      );
      const label = delivery.snow_number || delivery.snow_sys_id || `#${delivery.id}`;
      toast({ title: `Linked ServiceNow record ${label}.` });
      setSnowDeliveries((prev) => [delivery, ...prev]);
      setSnowAssociateKey('');
      setSnowDialogMode('push');
    } catch (err) {
      toast({ title: 'Failed to associate', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSnowPushing(false);
    }
  };

  const handleRefreshServiceNow = async (deliveryId: number) => {
    setSnowRefreshing(deliveryId);
    try {
      const result = await api.refreshServiceNowDelivery(deliveryId, selectedFinding?.organization_id);
      toast({
        title: result.validation_queued ? 'Close validation queued' : 'Status refreshed',
        description: result.message,
      });
      if (selectedFinding?.organization_id) {
        const deliveries = await api.getServiceNowDeliveriesForVulnerability(
          selectedFinding.id,
          selectedFinding.organization_id,
        );
        setSnowDeliveries(deliveries);
      }
    } catch (err) {
      toast({ title: 'Refresh failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSnowRefreshing(null);
    }
  };

  const handleDisconnectServiceNow = async (deliveryId: number, label: string) => {
    setSnowDisconnecting(deliveryId);
    try {
      await api.disconnectServiceNowDelivery(deliveryId, selectedFinding?.organization_id);
      toast({ title: `ServiceNow delivery ${label} disconnected.` });
      setSnowDeliveries((prev) => prev.filter((d) => d.id !== deliveryId));
    } catch (err) {
      toast({ title: 'Failed to disconnect', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSnowDisconnecting(null);
    }
  };

  const openHackerOneDialog = async (finding: Finding) => {
    setH1DialogOpen(true);
    setH1Links([]);
    setH1AssociateKey('');
    const orgId = finding.organization_id;
    if (!orgId) {
      toast({
        title: 'Could not load HackerOne data',
        description: 'This finding has no associated organization.',
        variant: 'destructive',
      });
      setH1DialogOpen(false);
      return;
    }
    try {
      const [integrations, links] = await Promise.all([
        api.getHackerOneIntegrations(orgId).catch(() => []),
        api.getHackerOneReportsForVulnerability(finding.id, orgId),
      ]);
      const active = (integrations || []).filter((i) => i.is_active);
      setH1HasIntegration(active.length > 0);
      setH1Links(links || []);
    } catch (err) {
      toast({ title: 'Could not load HackerOne data', description: getApiErrorMessage(err), variant: 'destructive' });
    }
  };

  const handleAssociateHackerOne = async () => {
    if (!selectedFinding || !h1AssociateKey.trim()) return;
    setH1Linking(true);
    try {
      const link = await api.associateHackerOneReport(
        selectedFinding.id,
        h1AssociateKey.trim(),
        selectedFinding.organization_id,
      );
      toast({ title: `Linked HackerOne report #${link.hackerone_report_id}.` });
      setH1AssociateKey('');
      setH1Links((prev) => [link, ...prev.filter((l) => l.id !== link.id)]);
      // Refresh finding so status mapping is reflected
      if (selectedFinding.id) {
        try {
          const updated = await api.getVulnerability(selectedFinding.id);
          setSelectedFinding({ ...selectedFinding, ...updated });
        } catch { /* ignore */ }
      }
    } catch (err) {
      toast({ title: 'Failed to link report', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setH1Linking(false);
    }
  };

  const handleRefreshHackerOne = async (linkId: number) => {
    setH1Refreshing(linkId);
    try {
      const updated = await api.refreshHackerOneReport(linkId, selectedFinding?.organization_id);
      setH1Links((prev) => prev.map((l) => (l.id === linkId ? updated : l)));
      toast({ title: `Refreshed report #${updated.hackerone_report_id}`, description: updated.hackerone_state || undefined });
      if (selectedFinding?.id) {
        try {
          const finding = await api.getVulnerability(selectedFinding.id);
          setSelectedFinding({ ...selectedFinding, ...finding });
        } catch { /* ignore */ }
      }
    } catch (err) {
      toast({ title: 'Refresh failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setH1Refreshing(null);
    }
  };

  const handleDisconnectHackerOne = async (linkId: number, reportId: string) => {
    setH1Disconnecting(linkId);
    try {
      await api.disconnectHackerOneReport(linkId, selectedFinding?.organization_id);
      toast({ title: `Disconnected HackerOne report #${reportId}.` });
      setH1Links((prev) => prev.filter((l) => l.id !== linkId));
    } catch (err) {
      toast({ title: 'Failed to disconnect', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setH1Disconnecting(null);
    }
  };

  // Open Jira ticket dialog for a finding
  const openJiraDialog = async (finding: Finding, mode: 'create' | 'associate' = 'create') => {
    setJiraDialogOpen(true);
    setJiraDialogMode(mode);
    setJiraProjectKey('');
    setJiraIssueType('Bug');
    setJiraExistingTickets([]);
    setJiraAssociateKey('');

    // Use the finding's org so admin/superuser accounts (often with no
    // organization_id) load the correct client's Jira integration.
    const orgId = finding.organization_id;
    if (!orgId) {
      toast({
        title: 'Could not load Jira data',
        description: 'This finding has no associated organization. Link it to an asset in a client org first.',
        variant: 'destructive',
      });
      setJiraDialogOpen(false);
      return;
    }

    try {
      const [integrationData, ticketsData] = await Promise.all([
        api.getJiraIntegration(orgId).catch(() => null),
        api.getJiraTicketsForVulnerability(finding.id, orgId),
      ]);
      // Integration endpoint 404 means not configured; other errors still mean
      // we may have tickets but no usable integration for create.
      setJiraHasIntegration(integrationData !== null);
      setJiraExistingTickets(ticketsData);

      const savedProject = integrationData?.default_project_key || '';
      const savedIssueType = integrationData?.default_issue_type || 'Bug';
      setJiraProjectKey(savedProject);
      setJiraIssueType(savedIssueType);

      if (savedProject) {
        const typesData = await api.getJiraIssueTypes(savedProject, orgId);
        setJiraIssueTypes(typesData.issue_types);
        const typeExists = typesData.issue_types.some((t) => t.name === savedIssueType);
        if (!typeExists && typesData.issue_types.length > 0) {
          setJiraIssueType(typesData.issue_types[0].name);
        }
      }
    } catch (err: any) {
      if (err?.response?.status === 404) {
        setJiraHasIntegration(false);
      } else {
        toast({ title: 'Could not load Jira data', description: getApiErrorMessage(err), variant: 'destructive' });
        setJiraDialogOpen(false);
      }
    }
  };

  const handleAssociateJiraTicket = async () => {
    if (!selectedFinding || !jiraAssociateKey.trim()) return;
    setJiraCreating(true);
    try {
      const ticket = await api.associateJiraTicket(
        selectedFinding.id,
        jiraAssociateKey.trim(),
        undefined,
        selectedFinding.organization_id,
      );
      toast({ title: `Ticket ${ticket.jira_issue_key} linked.` });
      setJiraExistingTickets((prev) => [ticket, ...prev]);
      setJiraAssociateKey('');
    } catch (err) {
      toast({ title: 'Failed to associate ticket', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setJiraCreating(false);
    }
  };

  const handleDisconnectJiraTicket = async (ticketId: number, issueKey: string) => {
    setJiraDisconnecting(ticketId);
    try {
      await api.disconnectJiraTicket(ticketId, selectedFinding?.organization_id);
      toast({ title: `Ticket ${issueKey} disconnected.` });
      setJiraExistingTickets((prev) => prev.filter((t) => t.id !== ticketId));
    } catch (err) {
      toast({ title: 'Failed to disconnect', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setJiraDisconnecting(null);
    }
  };

  const handleRefreshJiraTicket = async (ticketId: number) => {
    setJiraRefreshing(ticketId);
    try {
      const updated = await api.refreshJiraTicketStatus(ticketId, selectedFinding?.organization_id);
      setJiraExistingTickets((prev) => prev.map((t) => (t.id === ticketId ? updated : t)));
    } catch (err) {
      toast({ title: 'Could not refresh ticket status', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setJiraRefreshing(null);
    }
  };

  const handleJiraProjectChange = async (key: string) => {
    setJiraProjectKey(key);
    setJiraIssueTypes([]);
    if (!key) return;
    try {
      const data = await api.getJiraIssueTypes(key, selectedFinding?.organization_id);
      setJiraIssueTypes(data.issue_types);
      if (data.issue_types.length > 0) setJiraIssueType(data.issue_types[0].name);
    } catch {
      // silently ignore; user can still type
    }
  };

  const handleCreateJiraTicket = async () => {
    if (!selectedFinding || !jiraProjectKey) return;
    setJiraCreating(true);
    try {
      const ticket = await api.createJiraTicket(selectedFinding.id, {
        project_key: jiraProjectKey,
        issue_type: jiraIssueType || 'Bug',
        include_evidence: jiraIncludeEvidence,
        include_remediation: jiraIncludeRemediation,
        include_enrichment: jiraIncludeEnrichment,
      }, selectedFinding.organization_id);
      toast({
        title: `Jira ticket created: ${ticket.jira_issue_key}`,
        description: `View at ${ticket.jira_issue_url}`,
      });
      setJiraExistingTickets((prev) => [ticket, ...prev]);
    } catch (err) {
      toast({ title: 'Failed to create ticket', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setJiraCreating(false);
    }
  };

  // Fetch remediation playbook when a finding is selected
  const fetchRemediation = async (findingId: number) => {
    setLoadingRemediation(true);
    setRemediationData(null);
    try {
      const data = await api.getRemediationForFinding(findingId);
      setRemediationData(data);
    } catch (err) {
      console.error('Failed to fetch remediation:', err);
      // Silently fail - will show fallback remediation
    } finally {
      setLoadingRemediation(false);
    }
  };

  const handleCaptureFindingScreenshot = async () => {
    if (!selectedFinding?.asset_id) {
      toast({
        title: 'No asset linked',
        description: 'This finding has no asset to screenshot.',
        variant: 'destructive',
      });
      return;
    }
    setCapturingScreenshot(true);
    try {
      const shot = await api.captureScreenshot(selectedFinding.asset_id);
      if (shot?.status === 'success' && shot?.id) {
        const updated = {
          ...selectedFinding,
          screenshot_id: shot.id,
          screenshot_page_title: shot.page_title ?? null,
          screenshot_captured_at: shot.captured_at ?? null,
        };
        setSelectedFinding(updated);
        setFindings((prev) =>
          prev.map((f) => (f.id === selectedFinding.id ? { ...f, ...updated } : f)),
        );
        toast({ title: 'Screenshot captured', description: 'Saved and linked to this asset.' });
      } else {
        toast({
          title: 'Screenshot failed',
          description: shot?.error_message || 'Capture completed but no image was saved.',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({
        title: 'Screenshot failed',
        description: getApiErrorMessage(err, 'Could not capture screenshot. Check Playwright/EyeWitness status.'),
        variant: 'destructive',
      });
    } finally {
      setCapturingScreenshot(false);
    }
  };

  // Handle finding selection
  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setScreenshotLightboxOpen(false);
    fetchRemediation(finding.id);
  };

  // Handle status change
  const [updatingStatus, setUpdatingStatus] = useState(false);
  
  const handleStatusChange = async (findingId: number, newStatus: string) => {
    setUpdatingStatus(true);
    try {
      await api.updateVulnerability(findingId, { status: newStatus });
      toast({
        title: 'Status Updated',
        description: `Finding marked as ${statusConfig[newStatus]?.label || newStatus}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        f.id === findingId ? { ...f, status: newStatus } : f
      ));
      // Update selected finding if it's the one being changed
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(prev => prev ? { ...prev, status: newStatus } : null);
      }
      // Refresh stats
      const summaryData = await api.getFindingsSummary();
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to update status:', err);
      toast({
        title: 'Error',
        description: `Failed to update status: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setUpdatingStatus(false);
    }
  };

  // Handle inline status change from table dropdown
  const handleInlineStatusChange = async (findingId: number, newStatus: string, e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation();
    }
    await handleStatusChange(findingId, newStatus);
  };

    // ── Finding validation (native detector / steps replay) ─────────────────────
  const [validationResult, setValidationResult] = useState<any>(null);
  const [validating, setValidating] = useState(false);
  const [detectionIssueText, setDetectionIssueText] = useState('');
  const [loggingIssue, setLoggingIssue] = useState(false);
  const [detectionFeedback, setDetectionFeedback] = useState<any>(null);
  const [refiningTemplate, setRefiningTemplate] = useState(false);
  const [templatePattern, setTemplatePattern] = useState<any>(null);
  const openFindingIdRef = useRef<number | null>(null);

  // Load the latest validation result whenever a finding is opened.
  useEffect(() => {
    openFindingIdRef.current = selectedFinding?.id ?? null;
    setDetectionIssueText('');
    setDetectionFeedback(null);
    setTemplatePattern(null);
    if (!selectedFinding) {
      setValidationResult(null);
      return;
    }
    const findingId = selectedFinding.id;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.getValidationResult(findingId);
        if (!cancelled) {
          setValidationResult(res || null);
          // If a run is still in progress, resume polling.
          if (res && (res.status === 'queued' || res.status === 'running')) {
            pollValidation(findingId);
          }
        }
      } catch {
        if (!cancelled) setValidationResult(null);
      }
    })();
    // Surface any pattern-based suppression recommendation/rule for this template.
    if (selectedFinding.template_id) {
      (async () => {
        try {
          const rows = await api.getDetectionSuppressions({
            template_id: selectedFinding.template_id,
            include_coverage: true,
            limit: 1,
          });
          if (!cancelled) setTemplatePattern(Array.isArray(rows) && rows.length ? rows[0] : null);
        } catch {
          if (!cancelled) setTemplatePattern(null);
        }
      })();
    }
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFinding?.id]);

  const pollValidation = async (findingId: number) => {
    // Poll up to ~15 minutes (5s interval) for the agent to finish.
    for (let i = 0; i < 180; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      if (openFindingIdRef.current !== findingId) return; // user navigated away
      let res: any;
      try {
        res = await api.getValidationResult(findingId);
      } catch {
        continue;
      }
      if (openFindingIdRef.current !== findingId) return;
      setValidationResult(res);
      if (res && (res.status === 'completed' || res.status === 'failed')) {
        return;
      }
    }
  };

  const handleValidateFinding = async () => {
    if (!selectedFinding) return;
    const findingId = selectedFinding.id;
    setValidating(true);
    try {
      const initial = await api.validateFinding(findingId);
      setValidationResult(initial);
      toast({
        title: 'Validation queued',
        description:
          'Replaying the original detection steps against the live target on the scanner.',
      });
      await pollValidation(findingId);
    } catch (err: any) {
      toast({
        title: 'Could not start validation',
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    } finally {
      setValidating(false);
    }
  };

  const handleLogDetectionIssue = async () => {
    if (!selectedFinding) return;
    const logic =
      detectionIssueText.trim() ||
      validationResult?.template_logic_issue ||
      'Detection template produced a false positive under active re-testing.';
    setLoggingIssue(true);
    try {
      const fb = await api.createDetectionFeedback(selectedFinding.id, {
        logic_issue: logic,
        verdict: 'false_positive',
      });
      setDetectionFeedback(fb);
      toast({
        title: 'Detection issue logged',
        description: `Recorded a logic issue for template ${fb.template_id}.`,
      });
      // A new FP signal may have crossed the pattern threshold — refresh the callout.
      if (selectedFinding.template_id) {
        try {
          const rows = await api.getDetectionSuppressions({
            template_id: selectedFinding.template_id,
            include_coverage: true,
            limit: 1,
          });
          setTemplatePattern(Array.isArray(rows) && rows.length ? rows[0] : null);
        } catch {
          /* non-fatal */
        }
      }
    } catch (err: any) {
      toast({
        title: 'Could not log detection issue',
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    } finally {
      setLoggingIssue(false);
    }
  };

  // Generate a more accurate template from the validated mis-detection.
  const handleRefineTemplate = async () => {
    if (!selectedFinding || !firstOrgId) return;
    const issue =
      detectionIssueText.trim() || validationResult?.template_logic_issue;
    if (!issue) {
      toast({
        title: 'No detection logic issue to refine from',
        description: 'Describe the flawed detection logic first.',
        variant: 'destructive',
      });
      return;
    }
    if (!selectedFinding.template_id) {
      toast({
        title: 'No template on this finding',
        description: 'Refinement needs the matched template id.',
        variant: 'destructive',
      });
      return;
    }
    setRefiningTemplate(true);
    try {
      const resp = await api.post('/nuclei-templates/refine', {
        organization_id: firstOrgId,
        template_id: selectedFinding.template_id,
        template_logic_issue: issue,
        target: selectedFinding.matched_at || selectedFinding.host || undefined,
        evidence: validationResult?.evidence || undefined,
        reasoning: validationResult?.reasoning || undefined,
        cve_ids: selectedFinding.cve_id ? [selectedFinding.cve_id] : undefined,
        vulnerability_id: selectedFinding.id,
        recheck: true,
      });
      toast({
        title: 'Refined template created',
        description: `${resp.data?.template_id}: ${resp.data?.refinement_note || 'Saved as draft — review before activating.'}`,
      });
    } catch (err: any) {
      toast({
        title: 'Refinement failed',
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    } finally {
      setRefiningTemplate(false);
    }
  };

  const copyUpstreamReport = async () => {
    const report = detectionFeedback?.upstream_report;
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report);
      toast({ title: 'Copied', description: 'Upstream report copied to clipboard.' });
    } catch {
      toast({ title: 'Copy failed', description: 'Could not access clipboard.', variant: 'destructive' });
    }
  };

  // Handle bulk status change
  const handleBulkStatusChange = async (newStatus: string) => {
    if (selectedFindingIds.size === 0) return;
    
    setBulkUpdating(true);
    try {
      await api.bulkUpdateVulnerabilities({
        vulnerability_ids: Array.from(selectedFindingIds),
        status: newStatus,
      });
      toast({
        title: 'Bulk Update Complete',
        description: `Updated ${selectedFindingIds.size} findings to ${statusConfig[newStatus]?.label || newStatus}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        selectedFindingIds.has(f.id) ? { ...f, status: newStatus } : f
      ));
      setSelectedFindingIds(new Set());
      // Refresh stats
      const summaryData = await api.getFindingsSummary();
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to bulk update:', err);
      toast({
        title: 'Error',
        description: `Failed to bulk update: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setBulkUpdating(false);
    }
  };

  // Handle bulk assignment
  const handleBulkAssign = async () => {
    if (selectedFindingIds.size === 0 || !assignee.trim()) return;
    
    setBulkUpdating(true);
    try {
      await api.bulkUpdateVulnerabilities({
        vulnerability_ids: Array.from(selectedFindingIds),
        assigned_to: assignee.trim(),
      });
      toast({
        title: 'Assignment Complete',
        description: `Assigned ${selectedFindingIds.size} findings to ${assignee}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        selectedFindingIds.has(f.id) ? { ...f, assigned_to: assignee.trim() } : f
      ));
      setSelectedFindingIds(new Set());
      setAssignDialogOpen(false);
      setAssignee('');
    } catch (err: any) {
      console.error('Failed to assign:', err);
      toast({
        title: 'Error',
        description: `Failed to assign: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setBulkUpdating(false);
    }
  };

  // Handle single assignment from dialog
  const handleAssignFinding = async (findingId: number, assigneeValue: string) => {
    try {
      await api.updateVulnerability(findingId, { assigned_to: assigneeValue || undefined });
      toast({
        title: 'Assignment Updated',
        description: assigneeValue ? `Assigned to ${assigneeValue}` : 'Assignment removed',
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        f.id === findingId ? { ...f, assigned_to: assigneeValue || undefined } : f
      ));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(prev => prev ? { ...prev, assigned_to: assigneeValue || undefined } : null);
      }
    } catch (err: any) {
      toast({
        title: 'Error',
        description: `Failed to update assignment: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    }
  };

  // Toggle selection for a single finding
  const toggleFindingSelection = (findingId: number, e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation();
    }
    setSelectedFindingIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  // Toggle all visible findings
  const toggleAllFindings = () => {
    if (selectedFindingIds.size === filteredFindings.length) {
      setSelectedFindingIds(new Set());
    } else {
      setSelectedFindingIds(new Set(filteredFindings.map(f => f.id)));
    }
  };

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch findings and summary in parallel
      const [findingsData, summaryData] = await Promise.all([
        api.getFindings({
          // Top chips filter by OPES priority score (scanner severity as unscored fallback)
          opes_category: selectedSeverity || undefined,
          limit: 100,
        }),
        api.getFindingsSummary(),
      ]);

      // Handle both array and paginated responses
      const items = Array.isArray(findingsData) ? findingsData : (findingsData.items || []);
      setFindings(items);
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to fetch findings:', err);
      // Provide more specific error message
      const errorMessage = err.response?.data?.detail || err.message || 'Failed to fetch findings';
      setError(errorMessage);
      toast({
        title: 'Error',
        description: `Failed to fetch findings: ${errorMessage}`,
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Grab the first org for template generation
    api.getOrganizations().then((orgs: any[]) => {
      if (orgs?.length) setFirstOrgId(orgs[0].id);
    }).catch(() => {});
  }, [selectedSeverity]);

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const handleSeverityFilter = (severity: Severity | null) => {
    setSelectedSeverity(severity === selectedSeverity ? null : severity);
  };

  const handleOracleBatchEnrich = async () => {
    setOracleBatchBusy(true);
    try {
      const result = await api.oracleEnrichBatch(200, false);
      if (result.queued) {
        toast({
          title: 'Oracle batch enrichment queued',
          description: `${result.selected} vulnerabilities queued for background analysis. Results will appear as each completes — refresh the page in a minute.`,
        });
      } else if (result.selected === 0) {
        toast({ title: 'Nothing to enrich', description: result.message ?? 'All open vulnerabilities are already enriched.' });
      } else {
        toast({
          title: 'Oracle enrichment complete',
          description: `${result.enriched ?? 0} enriched · ${result.skipped_cached ?? 0} cached · ${result.errors ?? 0} errors. Refresh to see updated badges.`,
        });
        // Refresh in place so updated rows show their new OPES badges.
        try {
          const refreshed = await api.getVulnerabilities({ limit: 500 });
          if (Array.isArray(refreshed)) {
            setFindings(refreshed as Finding[]);
          }
        } catch {
          // Non-fatal — the user can refresh manually.
        }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable.';
      toast({ variant: 'destructive', title: 'Oracle batch failed', description: msg });
    } finally {
      setOracleBatchBusy(false);
    }
  };

  const handleExport = () => {
    if (filteredFindings.length === 0) {
      toast({
        title: 'No Data',
        description: 'No findings to export.',
        variant: 'destructive',
      });
      return;
    }

    downloadCSV(
      filteredFindings.map((f) => ({
        title: f.title || f.name || '',
        severity: f.severity,
        host: f.host || '',
        template_id: f.template_id || '',
        cve_id: f.cve_id || '',
        cvss_score: f.cvss_score || '',
        status: f.status || 'open',
        detected_by: f.detected_by || '',
        matched_at: f.matched_at || '',
        first_detected: f.first_detected || f.created_at,
        description: f.description || '',
      })),
      'findings'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  // Severity order for sorting (lower = higher priority)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  // Filter findings by search query
  const filteredFindings = findings
    .filter((f) => {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        (f.title || f.name || '').toLowerCase().includes(searchLower) ||
        (f.host || '').toLowerCase().includes(searchLower) ||
        (f.template_id || '').toLowerCase().includes(searchLower) ||
        (f.description || '').toLowerCase().includes(searchLower) ||
        (f.cve_id || '').toLowerCase().includes(searchLower);
      if (!matchesSearch) return false;
      if (onlyKev && !f.delphi?.kev) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortMode === 'opes') {
        const aRank = opesSortRank[effectivePriority(a)] ?? 5;
        const bRank = opesSortRank[effectivePriority(b)] ?? 5;
        if (aRank !== bRank) return aRank - bRank;
        const aScore = a.oracle?.opes_score ?? -1;
        const bScore = b.oracle?.opes_score ?? -1;
        if (aScore !== bScore) return bScore - aScore;
      }
      if (sortMode === 'delphi') {
        const aRansom = isRansomwareKev(a.delphi?.kev) ? 0 : 1;
        const bRansom = isRansomwareKev(b.delphi?.kev) ? 0 : 1;
        if (aRansom !== bRansom) return aRansom - bRansom;
        const aKev = a.delphi?.kev ? 0 : 1;
        const bKev = b.delphi?.kev ? 0 : 1;
        if (aKev !== bKev) return aKev - bKev;
        const aRank = delphiPriorityRank[a.delphi?.priority || 'none'] ?? 5;
        const bRank = delphiPriorityRank[b.delphi?.priority || 'none'] ?? 5;
        if (aRank !== bRank) return aRank - bRank;
        const aScore = a.delphi?.likelihood_score ?? -1;
        const bScore = b.delphi?.likelihood_score ?? -1;
        if (aScore !== bScore) return bScore - aScore;
        const aCvss = a.cvss_score ?? 0;
        const bCvss = b.cvss_score ?? 0;
        if (aCvss !== bCvss) return bCvss - aCvss;
        // Fall through to severity tie-break
      }
      if (sortMode === 'recent') {
        const aT = new Date(a.last_detected || a.first_detected || a.created_at).getTime();
        const bT = new Date(b.last_detected || b.first_detected || b.created_at).getTime();
        return bT - aT;
      }
      if (sortMode === 'cvss') {
        const aS = a.cvss_score ?? -1;
        const bS = b.cvss_score ?? -1;
        if (aS !== bS) return bS - aS;
      }
      const orderA = severityOrder[a.severity?.toLowerCase()] ?? 5;
      const orderB = severityOrder[b.severity?.toLowerCase()] ?? 5;
      return orderA - orderB;
    });

  const kevCount = findings.filter((f) => f.delphi?.kev).length;
  const ransomwareCount = findings.filter((f) => isRansomwareKev(f.delphi?.kev)).length;

  // Priority chip counts — OPES category (falls back to scanner severity when unscored)
  const opesCounts = stats?.by_opes_category || {};
  const severityCounts: Record<Severity, number> = {
    critical: opesCounts.critical || 0,
    high: opesCounts.high || 0,
    medium: opesCounts.medium || 0,
    low: opesCounts.low || 0,
    info: opesCounts.informational || opesCounts.info || 0,
  };

  const totalCount = stats?.total || findings.length;

  const getSeverityBadgeClass = (severity: string) => {
    const config = severityConfig[severity.toLowerCase() as Severity];
    return config 
      ? `${config.bgColor} ${config.textColor} ${config.borderColor} border` 
      : 'bg-gray-600/20 text-gray-400 border-gray-600/30 border';
  };

  const getStatusBadge = (status: string) => {
    const config = statusConfig[status] || statusConfig.open;
    return (
      <Badge className={`${config.color} border`}>
        {config.label}
      </Badge>
    );
  };

  return (
    <MainLayout>
      <Header title="Findings" subtitle="Security vulnerabilities and issues discovered in your assets" />

      <div className="p-6 space-y-6">
        {/* Priority Filter Pills — OPES score (scanner severity only when unscored) */}
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Filter by OPES priority score
          </p>
          <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleSeverityFilter(null)}
            className={cn(
              'rounded-full px-4 py-2 text-sm font-medium transition-all',
              !selectedSeverity
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
            )}
          >
            All ({totalCount})
          </button>
          {severities.map((severity) => {
            const config = severityConfig[severity];
            return (
              <button
                key={severity}
                onClick={() => handleSeverityFilter(severity)}
                className={cn(
                  'rounded-full px-4 py-2 text-sm font-medium transition-all flex items-center gap-2',
                  selectedSeverity === severity
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
                )}
              >
                <span className={cn('w-2 h-2 rounded-full', config.color)} />
                <span className="capitalize">{severity}</span>
                <span className={cn('text-xs px-1.5 py-0.5 rounded-full', config.bgColor, config.textColor)}>
                  {severityCounts[severity]}
                </span>
              </button>
            );
          })}
          </div>
        </div>

        {/* Search and Actions */}
        <div className="flex gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search findings by title, host, CVE, template..."
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              className="pl-10 bg-secondary/50 border-border"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={sortMode} onValueChange={(v) => setSortMode(v as SortMode)}>
              <SelectTrigger className="h-9 w-[200px] text-sm">
                <ArrowUpDown className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="opes">
                  <span className="flex items-center gap-2">
                    <Sparkles className="h-3.5 w-3.5 text-orange-400" />
                    Sort: OPES priority
                  </span>
                </SelectItem>
                <SelectItem value="severity">Sort: Scanner severity</SelectItem>
                <SelectItem value="delphi">
                  <span className="flex items-center gap-2">
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    Sort: Delphi likelihood
                  </span>
                </SelectItem>
                <SelectItem value="cvss">Sort: CVSS score</SelectItem>
                <SelectItem value="recent">Sort: Most recent</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={onlyKev ? 'default' : 'outline'}
              size="sm"
              onClick={() => setOnlyKev((v) => !v)}
              title="Show only findings on the CISA Known Exploited Vulnerabilities catalog"
            >
              <Flame className="h-4 w-4 mr-2" />
              KEV only {kevCount > 0 && <span className="ml-1 text-xs opacity-70">({kevCount})</span>}
            </Button>
            <Button variant="outline" size="sm">
              <Filter className="h-4 w-4 mr-2" />
              More Filters
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleOracleBatchEnrich}
              disabled={oracleBatchBusy}
              title="Run Aegis Oracle analysis on open vulnerabilities in your organization"
            >
              {oracleBatchBusy ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Sparkles className="h-4 w-4 mr-2 text-orange-400" />
              )}
              Enrich with Oracle
            </Button>
          </div>
        </div>

        {/* Delphi summary strip */}
        {(kevCount > 0 || findings.some((f) => f.delphi?.epss)) && (
          <Card className="border-purple-500/20 bg-purple-500/5">
            <CardContent className="p-3 flex items-center gap-4 flex-wrap text-sm">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-purple-400" />
                <span className="font-medium">Delphi enrichment</span>
                <span className="text-muted-foreground">KEV · CVSS analysis · breach intel</span>
              </div>
              <div className="flex items-center gap-3 ml-auto flex-wrap">
                {ransomwareCount > 0 && (
                  <span className="flex items-center gap-1 text-red-300">
                    <Flame className="h-3.5 w-3.5" />
                    {ransomwareCount} known-ransomware
                  </span>
                )}
                {kevCount > 0 && (
                  <span className="flex items-center gap-1 text-red-400">
                    <Flame className="h-3.5 w-3.5" />
                    {kevCount} on CISA KEV
                  </span>
                )}
                <span className="flex items-center gap-1 text-muted-foreground" title="EPSS is fetched for reference but does not affect priority scoring">
                  <TrendingUp className="h-3.5 w-3.5 opacity-50" />
                  {findings.filter((f) => f.delphi?.epss).length} with EPSS (reference)
                </span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error State */}
        {error && (
          <Card className="border-red-600/30 bg-red-600/10">
            <CardContent className="p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-red-400 font-medium">Failed to load findings</p>
                <p className="text-sm text-muted-foreground">{error}</p>
              </div>
              <Button variant="outline" size="sm" onClick={fetchData} className="ml-auto">
                Retry
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Bulk Actions Bar */}
        {selectedFindingIds.size > 0 && (
          <Card className="border-primary/30 bg-primary/5">
            <CardContent className="p-4 flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-primary" />
                <span className="font-medium">{selectedFindingIds.size} selected</span>
              </div>
              <div className="flex-1" />
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm text-muted-foreground mr-2">Change Status:</span>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('in_progress')}
                  disabled={bulkUpdating}
                  className="border-yellow-600/30 hover:bg-yellow-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  In Progress
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('resolved')}
                  disabled={bulkUpdating}
                  className="border-green-600/30 hover:bg-green-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Resolved
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('mitigated')}
                  disabled={bulkUpdating}
                  className="border-cyan-600/30 hover:bg-cyan-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Mitigated
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('false_positive')}
                  disabled={bulkUpdating}
                  className="border-gray-600/30 hover:bg-gray-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  False Positive
                </Button>
                <div className="h-6 w-px bg-border mx-2" />
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => setAssignDialogOpen(true)}
                  disabled={bulkUpdating}
                >
                  <Users className="h-4 w-4 mr-1" />
                  Assign
                </Button>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  onClick={() => setSelectedFindingIds(new Set())}
                >
                  <XCircle className="h-4 w-4 mr-1" />
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Findings Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40px]">
                  <Checkbox
                    checked={filteredFindings.length > 0 && selectedFindingIds.size === filteredFindings.length}
                    onCheckedChange={toggleAllFindings}
                    aria-label="Select all"
                  />
                </TableHead>
                <TableHead className="w-[110px]">Priority</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Host</TableHead>
                <TableHead className="w-[140px]">Status</TableHead>
                <TableHead>Assigned</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Detected</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Loader2 className="h-8 w-8 animate-spin text-primary" />
                      <p className="text-muted-foreground">Loading findings...</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : filteredFindings.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="h-12 w-12 text-muted-foreground/50" />
                      <p className="text-muted-foreground">
                        {searchQuery 
                          ? 'No findings match your search criteria.' 
                          : 'No findings discovered yet. Run a scan to discover security issues.'}
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredFindings.map((finding) => (
                  <TableRow
                    key={finding.id}
                    className={cn(
                      "cursor-pointer hover:bg-muted/50",
                      selectedFindingIds.has(finding.id) && "bg-primary/5"
                    )}
                    onClick={() => handleSelectFinding(finding)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedFindingIds.has(finding.id)}
                        onCheckedChange={() => toggleFindingSelection(finding.id)}
                        aria-label={`Select finding ${finding.id}`}
                      />
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const priority = effectivePriority(finding);
                        const label = priorityBadgeLabel(priority);
                        const scanner = (finding.severity || '').toLowerCase();
                        const diverges =
                          Boolean(finding.oracle?.opes_category) &&
                          scanner &&
                          scanner !== label &&
                          !(scanner === 'info' && label === 'info');
                        return (
                          <div className="flex flex-col gap-0.5">
                            <Badge className={getSeverityBadgeClass(label === 'info' ? 'info' : label)}>
                              {label}
                            </Badge>
                            {diverges && (
                              <span className="text-[10px] text-muted-foreground truncate">
                                Scanner: {finding.severity}
                              </span>
                            )}
                          </div>
                        );
                      })()}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
                          <span className="font-medium line-clamp-1">
                            {finding.title || finding.name || finding.template_id}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {finding.cve_id && (
                            <span className="text-xs text-primary font-mono">{finding.cve_id}</span>
                          )}
                          <OracleBadge oracle={finding.oracle} compact />
                          <DelphiBadges delphi={finding.delphi} compact />
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {finding.host ? (
                        <a
                          href={`https://${finding.host}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="truncate max-w-[200px]">{finding.host}</span>
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Select
                        value={finding.status || 'open'}
                        onValueChange={(value) => handleInlineStatusChange(finding.id, value)}
                      >
                        <SelectTrigger className="h-8 w-[130px] text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="open">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-red-500" />
                              Open
                            </span>
                          </SelectItem>
                          <SelectItem value="in_progress">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-yellow-500" />
                              In Progress
                            </span>
                          </SelectItem>
                          <SelectItem value="resolved">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-green-500" />
                              Resolved
                            </span>
                          </SelectItem>
                          <SelectItem value="mitigated">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-cyan-500" />
                              Mitigated
                            </span>
                          </SelectItem>
                          <SelectItem value="accepted">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-blue-500" />
                              Risk Accepted
                            </span>
                          </SelectItem>
                          <SelectItem value="false_positive">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-gray-500" />
                              False Positive
                            </span>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      {finding.assigned_to ? (
                        <span className="text-sm flex items-center gap-1">
                          <User className="h-3 w-3" />
                          {finding.assigned_to}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-sm">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {finding.cvss_score ? (
                        <span className={cn(
                          'font-mono font-medium',
                          finding.cvss_score >= 9 ? 'text-red-400' :
                          finding.cvss_score >= 7 ? 'text-orange-400' :
                          finding.cvss_score >= 4 ? 'text-yellow-400' :
                          'text-green-400'
                        )}>
                          {finding.cvss_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(finding.first_detected || finding.created_at)}
                    </TableCell>
                    <TableCell>
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {/* Finding Detail Flyout */}
        <Sheet
          open={!!selectedFinding}
          onOpenChange={(open) => {
            if (!open) setSelectedFinding(null);
          }}
        >
          <SheetContent
            side="right"
            className="w-full sm:max-w-xl lg:max-w-2xl xl:max-w-3xl overflow-y-auto"
          >
            <SheetHeader>
              <div className="flex items-center gap-2 flex-wrap pr-8">
                {(() => {
                  const priority = selectedFinding
                    ? effectivePriority(selectedFinding)
                    : 'info';
                  const label = priorityBadgeLabel(priority);
                  const score = selectedFinding?.oracle?.opes_score;
                  return (
                    <Badge className={getSeverityBadgeClass(label === 'info' ? 'info' : label)}>
                      {label}
                      {score != null ? ` · ${score.toFixed(1)}` : ''}
                    </Badge>
                  );
                })()}
                {selectedFinding?.oracle?.opes_category &&
                  selectedFinding.severity &&
                  selectedFinding.severity.toLowerCase() !==
                    priorityBadgeLabel(effectivePriority(selectedFinding)) && (
                    <Badge variant="outline" className="text-muted-foreground">
                      Scanner: {selectedFinding.severity}
                    </Badge>
                  )}
                {selectedFinding?.status && getStatusBadge(selectedFinding.status)}
                {selectedFinding?.cvss_score && (
                  <Badge variant="outline" className="font-mono">
                    CVSS: {selectedFinding.cvss_score.toFixed(1)}
                  </Badge>
                )}
              </div>
              <div className="flex items-center justify-between mt-2 gap-2 pr-8">
                <SheetTitle className="text-xl text-left">
                  {selectedFinding?.title || selectedFinding?.name || selectedFinding?.template_id}
                </SheetTitle>
                <div className="flex items-center gap-1.5 shrink-0">
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-[#0052CC]/40 hover:bg-[#0052CC]/15 text-[#4C9AFF]"
                    onClick={() => selectedFinding && openJiraDialog(selectedFinding)}
                  >
                    <Ticket className="h-4 w-4 mr-1.5" />
                    Jira
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-[#81B5A1]/40 hover:bg-[#81B5A1]/15 text-[#81B5A1]"
                    onClick={() => selectedFinding && openServiceNowDialog(selectedFinding)}
                  >
                    <Shield className="h-4 w-4 mr-1.5" />
                    ServiceNow
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-[#494649]/40 hover:bg-[#494649]/20 text-foreground"
                    onClick={() => selectedFinding && openHackerOneDialog(selectedFinding)}
                  >
                    <Bug className="h-4 w-4 mr-1.5" />
                    HackerOne
                  </Button>
                </div>
              </div>
              <SheetDescription className="text-left">
                Complete finding details and remediation information
              </SheetDescription>
            </SheetHeader>

            <div className="space-y-6 py-4">
              {/* Quick Info Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="flex items-start gap-2">
                  <Target className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Host</p>
                    {selectedFinding?.host ? (
                      <a
                        href={`https://${selectedFinding.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.host}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <p className="text-sm text-muted-foreground">-</p>
                    )}
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <FileCode className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Template ID</p>
                    <p className="text-sm font-mono">{selectedFinding?.template_id || '-'}</p>
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <Activity className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Detected By</p>
                    <p className="text-sm">{selectedFinding?.detected_by || 'Nuclei'}</p>
                  </div>
                </div>

                {selectedFinding?.cve_id && (
                  <div className="flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVE ID</p>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cve_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cwe_id && (
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CWE ID</p>
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cwe_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cvss_vector && (
                  <div className="flex items-start gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVSS Vector</p>
                      <p className="text-sm font-mono text-xs">{selectedFinding.cvss_vector}</p>
                    </div>
                  </div>
                )}

                <div className="flex items-start gap-2">
                  <User className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div className="flex-1">
                    <p className="text-xs text-muted-foreground mb-1">Assigned To</p>
                    <div className="flex items-center gap-2">
                      <Input
                        placeholder="Enter email or name..."
                        defaultValue={selectedFinding?.assigned_to || ''}
                        className="h-8 text-sm"
                        onBlur={(e) => {
                          if (selectedFinding && e.target.value !== (selectedFinding.assigned_to || '')) {
                            handleAssignFinding(selectedFinding.id, e.target.value);
                          }
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const input = e.target as HTMLInputElement;
                            if (selectedFinding && input.value !== (selectedFinding.assigned_to || '')) {
                              handleAssignFinding(selectedFinding.id, input.value);
                            }
                            input.blur();
                          }
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Timestamps */}
              <div className="flex flex-wrap gap-4 text-sm">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>First Detected: {formatDate(selectedFinding?.first_detected || selectedFinding?.created_at || '')}</span>
                </div>
                {selectedFinding?.last_detected && selectedFinding.last_detected !== selectedFinding.first_detected && (
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Calendar className="h-4 w-4" />
                    <span>Last Detected: {formatDate(selectedFinding.last_detected)}</span>
                  </div>
                )}
                {selectedFinding?.resolved_at && (
                  <div className="flex items-center gap-2 text-green-400">
                    <Clock className="h-4 w-4" />
                    <span>Resolved: {formatDate(selectedFinding.resolved_at)}</span>
                  </div>
                )}
              </div>

              {/* Delphi enrichment panel */}
              {selectedFinding?.delphi &&
                (selectedFinding.delphi.kev ||
                  selectedFinding.delphi.epss ||
                  (selectedFinding.delphi.priority && selectedFinding.delphi.priority !== 'none')) && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2 text-purple-300">
                    <Sparkles className="h-4 w-4" />
                    Delphi Priority
                    {selectedFinding.delphi.priority && selectedFinding.delphi.priority !== 'none' &&
                      delphiPriorityStyle[selectedFinding.delphi.priority] && (
                        <Badge
                          variant="outline"
                          className={cn('ml-1', delphiPriorityStyle[selectedFinding.delphi.priority].className)}
                        >
                          {delphiPriorityStyle[selectedFinding.delphi.priority].label}
                        </Badge>
                      )}
                  </p>
                  {selectedFinding.delphi.priority_reason && (
                    <p className="text-sm text-muted-foreground">{selectedFinding.delphi.priority_reason}</p>
                  )}
                  <DelphiLikelihood delphi={selectedFinding.delphi} />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {selectedFinding.delphi.kev && (
                      <div className={cn(
                        'rounded-lg border p-3 space-y-1',
                        isRansomwareKev(selectedFinding.delphi.kev)
                          ? 'border-red-600/40 bg-red-600/10'
                          : 'border-red-500/30 bg-red-500/5'
                      )}>
                        <div className="flex items-center gap-2">
                          <Flame className="h-4 w-4 text-red-400" />
                          <p className="text-sm font-medium text-red-300">CISA Known Exploited Vulnerabilities</p>
                        </div>
                        {selectedFinding.delphi.kev.vulnerability_name && (
                          <p className="text-sm">{selectedFinding.delphi.kev.vulnerability_name}</p>
                        )}
                        {(selectedFinding.delphi.kev.vendor_project || selectedFinding.delphi.kev.product) && (
                          <p className="text-xs text-muted-foreground">
                            {selectedFinding.delphi.kev.vendor_project} {selectedFinding.delphi.kev.product}
                          </p>
                        )}
                        {selectedFinding.delphi.kev.short_description && (
                          <p className="text-xs text-muted-foreground line-clamp-3">
                            {selectedFinding.delphi.kev.short_description}
                          </p>
                        )}
                        <div className="flex items-center gap-3 text-xs pt-1">
                          {selectedFinding.delphi.kev.date_added && (
                            <span className="text-muted-foreground">Added: {selectedFinding.delphi.kev.date_added}</span>
                          )}
                          {selectedFinding.delphi.kev.due_date && (
                            <span className="text-yellow-400">CISA Due: {selectedFinding.delphi.kev.due_date}</span>
                          )}
                          {isRansomwareKev(selectedFinding.delphi.kev) && (
                            <Badge variant="outline" className="bg-red-600/20 text-red-300 border-red-600/40 text-[10px]">
                              Known ransomware use
                            </Badge>
                          )}
                        </div>
                        {selectedFinding.delphi.kev.required_action && (
                          <p className="text-xs text-red-200/90 pt-1">
                            <span className="font-medium">Required action:</span> {selectedFinding.delphi.kev.required_action}
                          </p>
                        )}
                      </div>
                    )}
                    {selectedFinding.delphi.epss && (
                      <div className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <TrendingUp className="h-4 w-4 text-muted-foreground" />
                            <p className="text-sm font-medium text-muted-foreground">FIRST EPSS — Reference Only</p>
                          </div>
                          <Badge variant="outline" className="text-[10px] px-1.5 h-4 text-muted-foreground border-muted-foreground/30">
                            Not used in scoring
                          </Badge>
                        </div>
                        <div className="grid grid-cols-3 gap-2 text-center">
                          <div>
                            <p className="text-xs text-muted-foreground">Score</p>
                            <p className="text-lg font-mono text-muted-foreground">{selectedFinding.delphi.epss.score.toFixed(3)}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Percentile</p>
                            <p className="text-lg font-mono text-muted-foreground">{(selectedFinding.delphi.epss.percentile * 100).toFixed(1)}%</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Tier</p>
                            <p className="text-sm text-muted-foreground">
                              {selectedFinding.delphi.epss.display_label ?? selectedFinding.delphi.epss.bucket}
                            </p>
                          </div>
                        </div>
                        <div className="h-1 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-muted-foreground/40"
                            style={{ width: `${Math.min(100, selectedFinding.delphi.epss.percentile * 100)}%` }}
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          EPSS is a probabilistic 30-day exploit prediction. Priority is driven by CISA KEV status,
                          CVSS vector analysis, and breach intelligence — not EPSS.
                          {selectedFinding.delphi.epss.date && ` Score date: ${selectedFinding.delphi.epss.date}.`}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Aegis Oracle enrichment panel — OPES priority + analyst brief
                  + recommendation narrative. Includes an inline "Analyze" button
                  to run/refresh the enrichment on demand. */}
              <OracleEnrichmentPanel
                finding={selectedFinding}
                onUpdate={(updated) => {
                  if (!selectedFinding) return;
                  setSelectedFinding({ ...selectedFinding, oracle: updated });
                  setFindings((prev) =>
                    prev.map((f) => (f.id === selectedFinding.id ? { ...f, oracle: updated } : f)),
                  );
                }}
              />

              {/* Generate Nuclei Template CTA */}
              {selectedFinding && (selectedFinding.cve_id || selectedFinding.template_id) && (
                <div className="flex items-center gap-2 p-2.5 rounded-lg border border-purple-500/20 bg-purple-500/5">
                  <FileCode className="h-4 w-4 text-purple-400 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-purple-300 font-medium">Detection Coverage</p>
                    <p className="text-xs text-muted-foreground">
                      Generate or manage a custom Nuclei template for this finding
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="shrink-0 text-xs border-purple-500/30 text-purple-300 hover:bg-purple-500/10 gap-1"
                    onClick={() => {
                      setGenerateTemplateCveId(selectedFinding?.cve_id || '');
                      setGenerateTemplateEvidence(selectedFinding?.evidence || selectedFinding?.matched_at || '');
                      setGenerateTemplateOpen(true);
                    }}
                  >
                    <Sparkles className="h-3 w-3" />
                    Generate Template
                  </Button>
                </div>
              )}

              {/* Asset screenshot — visual context for analyst triage */}
              {selectedFinding?.asset_id && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium flex items-center gap-2">
                      <Camera className="h-4 w-4" />
                      Asset Screenshot
                    </p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs"
                      onClick={handleCaptureFindingScreenshot}
                      disabled={capturingScreenshot}
                    >
                      {capturingScreenshot ? (
                        <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                      ) : (
                        <Camera className="h-3.5 w-3.5 mr-1.5" />
                      )}
                      {capturingScreenshot
                        ? 'Capturing...'
                        : selectedFinding.screenshot_id
                          ? 'Recapture'
                          : 'Capture'}
                    </Button>
                  </div>
                  {selectedFinding.screenshot_id ? (
                    <div className="rounded-lg border border-border bg-secondary/30 overflow-hidden">
                      <button
                        type="button"
                        className="block w-full text-left"
                        onClick={() => setScreenshotLightboxOpen(true)}
                      >
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                          src={api.getScreenshotImageUrl(selectedFinding.screenshot_id)}
                          alt={
                            selectedFinding.screenshot_page_title ||
                            `Screenshot of ${selectedFinding.host || 'asset'}`
                          }
                          className="w-full max-h-64 object-cover object-top hover:opacity-95 transition-opacity"
                        />
                      </button>
                      <div className="px-3 py-2 flex items-center justify-between gap-2 text-xs text-muted-foreground border-t border-border/60">
                        <span className="truncate">
                          {selectedFinding.screenshot_page_title || selectedFinding.host || 'Web asset'}
                        </span>
                        <div className="flex items-center gap-2 shrink-0">
                          {selectedFinding.screenshot_captured_at && (
                            <span>{formatDate(selectedFinding.screenshot_captured_at)}</span>
                          )}
                          <a
                            href={api.getScreenshotImageUrl(selectedFinding.screenshot_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:underline inline-flex items-center gap-1"
                          >
                            Open
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-lg border border-dashed border-border p-4 text-center space-y-1">
                      <p className="text-sm text-muted-foreground">
                        No screenshot for this asset yet.
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Capture one to help validate what the host looks like during analysis.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Matched At / Evidence */}
              {selectedFinding?.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    Matched At
                  </p>
                  <div className="p-3 bg-secondary/50 rounded-lg">
                    <code className="text-sm break-all">{selectedFinding.matched_at}</code>
                  </div>
                </div>
              )}

              {/* Description */}
              {selectedFinding?.description && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Description</p>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

              {/* Evidence */}
              {selectedFinding?.evidence && selectedFinding.evidence !== selectedFinding.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Evidence</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                </div>
              )}

              {/* Proof of Concept */}
              {selectedFinding?.proof_of_concept && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Proof of Concept</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.proof_of_concept}
                    </pre>
                  </div>
                </div>
              )}

              {/* Remediation Panel */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-green-400 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Remediation Guidance
                  {selectedFinding?.remediation_deadline && (
                    <Badge variant="outline" className="text-yellow-400 border-yellow-400/30 ml-2">
                      Due: {formatDate(selectedFinding.remediation_deadline)}
                    </Badge>
                  )}
                </p>
                {loadingRemediation ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                  </div>
                ) : (
                  <RemediationPanel 
                    playbook={remediationData?.has_playbook ? remediationData.playbook : undefined}
                    fallbackRemediation={selectedFinding?.remediation || remediationData?.remediation}
                    cwe={remediationData?.cwe}
                    cweId={remediationData?.cwe_id || selectedFinding?.cwe_id}
                  />
                )}
              </div>

              {/* Status Actions */}
              <div className="space-y-2 pt-4 border-t border-border">
                <p className="text-sm font-medium flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Update Status
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'open' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'open')}
                    disabled={updatingStatus || selectedFinding?.status === 'open'}
                    className="flex-1 min-w-[120px]"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Open
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'in_progress' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'in_progress')}
                    disabled={updatingStatus || selectedFinding?.status === 'in_progress'}
                    className="flex-1 min-w-[120px] border-yellow-600/30 hover:bg-yellow-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    In Progress
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'resolved' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'resolved')}
                    disabled={updatingStatus || selectedFinding?.status === 'resolved'}
                    className="flex-1 min-w-[120px] border-green-600/30 hover:bg-green-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Resolved
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'mitigated' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'mitigated')}
                    disabled={updatingStatus || selectedFinding?.status === 'mitigated'}
                    className="flex-1 min-w-[120px] border-cyan-600/30 hover:bg-cyan-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Mitigated
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'accepted' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'accepted')}
                    disabled={updatingStatus || selectedFinding?.status === 'accepted'}
                    className="flex-1 min-w-[120px] border-blue-600/30 hover:bg-blue-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Accept Risk
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'false_positive' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'false_positive')}
                    disabled={updatingStatus || selectedFinding?.status === 'false_positive'}
                    className="flex-1 min-w-[120px] border-gray-600/30 hover:bg-gray-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    False Positive
                  </Button>
                </div>
              </div>

              {/* Validate with agent */}
              <div className="space-y-3 pt-4 border-t border-border">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4" />
                    Detection Validation
                  </p>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleValidateFinding}
                    disabled={
                      validating ||
                      validationResult?.status === 'queued' ||
                      validationResult?.status === 'running'
                    }
                  >
                    {validating ||
                    validationResult?.status === 'queued' ||
                    validationResult?.status === 'running' ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        Re-validating…
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="h-4 w-4 mr-2" />
                        Re-validate finding
                      </>
                    )}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Replays the original detection path on the live target: nuclei
                  template re-run, port probes, or the finding’s steps to reproduce.
                  Confirms whether the issue is still open and catches bad matches
                  (e.g. LDAP on port 443).
                </p>

                {templatePattern && (
                  <Link
                    href="/detection-patterns"
                    className={cn(
                      'flex items-start gap-2 rounded-md border p-3 text-sm transition-colors hover:bg-muted/50',
                      templatePattern.status === 'approved'
                        ? 'border-red-600/30 bg-red-600/10'
                        : templatePattern.status === 'recommended'
                        ? 'border-amber-600/30 bg-amber-600/10'
                        : 'border-border'
                    )}
                  >
                    <ShieldOff className="h-4 w-4 mt-0.5 shrink-0" />
                    <div className="space-y-0.5">
                      {templatePattern.status === 'approved' ? (
                        <p className="font-medium">
                          Suppression approved for this template — new matches are auto-marked false positive.
                        </p>
                      ) : templatePattern.status === 'recommended' ? (
                        <p className="font-medium">
                          False-positive pattern detected across{' '}
                          {templatePattern.host_count} host(s) — suppression recommended for review.
                        </p>
                      ) : (
                        <p className="font-medium">Suppression recommendation dismissed for this template.</p>
                      )}
                      <p className="text-xs text-muted-foreground">
                        {templatePattern.validation_coverage
                          ? `${templatePattern.validation_coverage.validated}/${templatePattern.validation_coverage.open} open findings validated. `
                          : ''}
                        View in Detection Patterns
                        <ChevronRight className="inline h-3 w-3" />
                      </p>
                    </div>
                  </Link>
                )}

                {(validationResult?.status === 'queued' ||
                  validationResult?.status === 'running') && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Agent is re-testing the target…
                  </div>
                )}

                {validationResult?.status === 'failed' && (
                  <div className="text-sm text-red-400">
                    Validation failed{validationResult?.error ? `: ${validationResult.error}` : '.'}
                  </div>
                )}

                {validationResult?.status === 'completed' && validationResult?.verdict && (
                  <div className="space-y-2 rounded-md border border-border p-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      {validationResult.verdict === 'confirmed' && (
                        <Badge className="bg-red-600/20 text-red-400 border-red-600/30">
                          <CheckCircle className="h-3 w-3 mr-1" /> Confirmed
                        </Badge>
                      )}
                      {validationResult.verdict === 'false_positive' && (
                        <Badge className="bg-gray-600/20 text-gray-400 border-gray-600/30">
                          <XCircle className="h-3 w-3 mr-1" /> False Positive
                        </Badge>
                      )}
                      {validationResult.verdict === 'needs_more_evidence' && (
                        <Badge className="bg-yellow-600/20 text-yellow-400 border-yellow-600/30">
                          <AlertCircle className="h-3 w-3 mr-1" /> Needs More Evidence
                        </Badge>
                      )}
                      {validationResult.still_open === true && (
                        <Badge className="bg-orange-600/20 text-orange-300 border-orange-600/30">
                          Still open
                        </Badge>
                      )}
                      {validationResult.still_open === false && (
                        <Badge className="bg-green-600/20 text-green-400 border-green-600/30">
                          No longer open
                        </Badge>
                      )}
                      {validationResult.logical_mismatch && (
                        <Badge className="bg-purple-600/20 text-purple-300 border-purple-600/30">
                          Logical mismatch
                        </Badge>
                      )}
                      {validationResult.confidence && (
                        <span className="text-xs text-muted-foreground">
                          confidence: {validationResult.confidence}
                        </span>
                      )}
                      {validationResult.recommended_severity && (
                        <span className="text-xs text-muted-foreground">
                          recommended severity: {validationResult.recommended_severity}
                        </span>
                      )}
                    </div>
                    {validationResult.reasoning && (
                      <p className="text-sm">{validationResult.reasoning}</p>
                    )}
                    {validationResult.evidence && (
                      <pre className="text-xs bg-muted/50 rounded p-2 whitespace-pre-wrap break-words max-h-48 overflow-auto">
                        {validationResult.evidence}
                      </pre>
                    )}

                    {validationResult.verdict === 'false_positive' && (
                      <div className="space-y-2 pt-2 border-t border-border">
                        <p className="text-sm font-medium flex items-center gap-2">
                          <Bug className="h-4 w-4" />
                          Log detection logic issue
                        </p>
                        <textarea
                          className="w-full text-sm rounded-md border border-border bg-background p-2 min-h-[72px]"
                          placeholder="Describe the flawed detection logic (prefilled from the agent when available)…"
                          value={
                            detectionIssueText ||
                            validationResult.template_logic_issue ||
                            ''
                          }
                          onChange={(e) => setDetectionIssueText(e.target.value)}
                        />
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={handleLogDetectionIssue}
                            disabled={loggingIssue}
                          >
                            {loggingIssue ? (
                              <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            ) : (
                              <Bug className="h-4 w-4 mr-2" />
                            )}
                            Log detection issue
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={handleRefineTemplate}
                            disabled={refiningTemplate || !selectedFinding?.template_id}
                            className="border-purple-600/30 hover:bg-purple-600/20"
                          >
                            {refiningTemplate ? (
                              <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            ) : (
                              <Sparkles className="h-4 w-4 mr-2" />
                            )}
                            Generate refined template
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              selectedFinding &&
                              handleStatusChange(selectedFinding.id, 'false_positive')
                            }
                            disabled={
                              updatingStatus || selectedFinding?.status === 'false_positive'
                            }
                            className="border-gray-600/30 hover:bg-gray-600/20"
                          >
                            Mark finding false positive
                          </Button>
                        </div>

                        {detectionFeedback?.upstream_report && (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <p className="text-xs font-medium text-muted-foreground">
                                Upstream Nuclei report
                              </p>
                              <Button size="sm" variant="ghost" onClick={copyUpstreamReport}>
                                <Copy className="h-3 w-3 mr-1" /> Copy
                              </Button>
                            </div>
                            <pre className="text-xs bg-muted/50 rounded p-2 whitespace-pre-wrap break-words max-h-64 overflow-auto">
                              {detectionFeedback.upstream_report}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Tags */}
              {selectedFinding?.tags && selectedFinding.tags.length > 0 && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Tag className="h-4 w-4" />
                    Tags
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {selectedFinding.tags.map((tag, i) => (
                      <Badge key={i} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {((selectedFinding?.references && selectedFinding.references.length > 0) ||
                (selectedFinding?.reference && selectedFinding.reference.length > 0)) && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <LinkIcon className="h-4 w-4" />
                    References
                  </p>
                  <div className="space-y-1">
                    {(selectedFinding.references || selectedFinding.reference || []).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1 break-all"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </SheetContent>
        </Sheet>

        {/* Screenshot lightbox */}
        <Dialog open={screenshotLightboxOpen} onOpenChange={setScreenshotLightboxOpen}>
          <DialogContent className="max-w-4xl p-2 sm:p-4">
            <DialogHeader>
              <DialogTitle className="text-base">
                {selectedFinding?.screenshot_page_title || selectedFinding?.host || 'Asset screenshot'}
              </DialogTitle>
              <DialogDescription>
                Visual context for analyst review
              </DialogDescription>
            </DialogHeader>
            {selectedFinding?.screenshot_id && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={api.getScreenshotImageUrl(selectedFinding.screenshot_id)}
                alt={selectedFinding.screenshot_page_title || selectedFinding.host || 'Screenshot'}
                className="w-full max-h-[75vh] object-contain rounded-md"
              />
            )}
          </DialogContent>
        </Dialog>

        {/* Bulk Assignment Dialog */}
        <Dialog open={assignDialogOpen} onOpenChange={setAssignDialogOpen}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Assign Findings
              </DialogTitle>
              <DialogDescription>
                Assign {selectedFindingIds.size} selected finding(s) to a team member.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Assignee</label>
                <Input
                  placeholder="Enter email or name..."
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  className="w-full"
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setAssignDialogOpen(false);
                    setAssignee('');
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleBulkAssign}
                  disabled={bulkUpdating || !assignee.trim()}
                >
                  {bulkUpdating ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Users className="h-4 w-4 mr-2" />
                  )}
                  Assign
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Jira Dialog — Create / Associate */}
        <Dialog open={jiraDialogOpen} onOpenChange={(v) => { if (!jiraCreating) setJiraDialogOpen(v); }}>
          <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <div className="w-6 h-6 rounded bg-[#0052CC] flex items-center justify-center shrink-0">
                  <svg viewBox="0 0 24 24" fill="white" className="w-4 h-4">
                    <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
                  </svg>
                </div>
                Jira
              </DialogTitle>
              <DialogDescription className="truncate">{selectedFinding?.title || selectedFinding?.name}</DialogDescription>
            </DialogHeader>

            {/* Mode tabs */}
            {jiraHasIntegration !== false && (
              <div className="flex gap-1 border-b border-border pb-2">
                {(['create', 'associate'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setJiraDialogMode(m)}
                    className={cn(
                      'px-3 py-1 text-sm rounded-md transition-colors',
                      jiraDialogMode === m
                        ? 'bg-[#0052CC]/20 text-[#4C9AFF] border border-[#0052CC]/30'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
                    )}
                  >
                    {m === 'create' ? 'Create new ticket' : 'Link existing ticket'}
                  </button>
                ))}
              </div>
            )}

            <div className="space-y-4 py-2">
              {jiraHasIntegration === false ? (
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm space-y-2">
                  <p className="text-yellow-300 font-medium flex items-center gap-2">
                    <AlertCircle className="h-4 w-4" />Jira not configured
                  </p>
                  <p className="text-muted-foreground">
                    Set up the Jira integration on the{' '}
                    <a href="/integrations" className="text-primary underline">Integrations page</a>.
                  </p>
                </div>
              ) : (
                <>
                  {/* Active linked tickets */}
                  {jiraExistingTickets.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Linked tickets</p>
                      <div className="space-y-1.5">
                        {jiraExistingTickets.map((t) => (
                          <div key={t.id} className="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-sm">
                            <a href={t.jira_issue_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 text-[#4C9AFF] hover:underline flex-1 min-w-0">
                              <ExternalLink className="h-3 w-3 shrink-0" />
                              <span className="font-mono">{t.jira_issue_key}</span>
                            </a>
                            {t.jira_status && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0">{t.jira_status}</Badge>
                            )}
                            {t.jira_assignee && (
                              <span className="text-xs text-muted-foreground shrink-0 hidden sm:inline">{t.jira_assignee}</span>
                            )}
                            {t.is_associated && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0 text-muted-foreground">linked</Badge>
                            )}
                            <button
                              onClick={() => handleRefreshJiraTicket(t.id)}
                              disabled={jiraRefreshing === t.id}
                              className="text-muted-foreground hover:text-foreground"
                              title="Refresh status from Jira"
                            >
                              {jiraRefreshing === t.id
                                ? <Loader2 className="h-3 w-3 animate-spin" />
                                : <RefreshCw className="h-3 w-3" />}
                            </button>
                            <button
                              onClick={() => handleDisconnectJiraTicket(t.id, t.jira_issue_key)}
                              disabled={jiraDisconnecting === t.id}
                              className="text-muted-foreground hover:text-red-400"
                              title="Disconnect ticket"
                            >
                              {jiraDisconnecting === t.id
                                ? <Loader2 className="h-3 w-3 animate-spin" />
                                : <XCircle className="h-3 w-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Create mode */}
                  {jiraDialogMode === 'create' && (
                    <>
                      <div className="space-y-1.5">
                        <label className="text-sm font-medium">Project</label>
                        <JiraProjectPicker
                          orgId={selectedFinding?.organization_id}
                          value={jiraProjectKey}
                          enabled={jiraHasIntegration === true}
                          onChange={(key) => handleJiraProjectChange(key)}
                          placeholder="Search e.g. ITVM or Vulnerability Management…"
                        />
                        <p className="text-[11px] text-muted-foreground">
                          Tip: search by key (<span className="font-mono">ITVM</span>) or name (Vulnerability Management).
                        </p>
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-sm font-medium">Issue type</label>
                        {jiraIssueTypes.length > 0 ? (
                          <Select value={jiraIssueType} onValueChange={setJiraIssueType}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              {jiraIssueTypes.map((t) => (
                                <SelectItem key={t.id} value={t.name}>{t.name}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Input placeholder="Bug" value={jiraIssueType} onChange={(e) => setJiraIssueType(e.target.value)} />
                        )}
                      </div>
                      <div className="space-y-2 pt-1">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Include in ticket</p>
                        {[
                          { label: 'Evidence & Proof of Concept', value: jiraIncludeEvidence, set: setJiraIncludeEvidence },
                          { label: 'Remediation playbook', value: jiraIncludeRemediation, set: setJiraIncludeRemediation },
                          { label: 'Delphi KEV/EPSS + Oracle OPES', value: jiraIncludeEnrichment, set: setJiraIncludeEnrichment },
                        ].map(({ label, value, set }) => (
                          <label key={label} className="flex items-center gap-2 cursor-pointer text-sm">
                            <Checkbox checked={value} onCheckedChange={(v) => set(!!v)} className="shrink-0" />
                            {label}
                          </label>
                        ))}
                      </div>
                    </>
                  )}

                  {/* Associate mode */}
                  {jiraDialogMode === 'associate' && (
                    <div className="space-y-3">
                      <p className="text-sm text-muted-foreground">
                        Enter an existing Jira issue key to link it to this finding. The ticket will not be modified in Jira, but status sync will apply going forward.
                      </p>
                      <div className="space-y-1.5">
                        <label className="text-sm font-medium">Jira issue key</label>
                        <Input
                          placeholder="e.g. SEC-123"
                          value={jiraAssociateKey}
                          onChange={(e) => setJiraAssociateKey(e.target.value.toUpperCase())}
                          onKeyDown={(e) => e.key === 'Enter' && handleAssociateJiraTicket()}
                        />
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setJiraDialogOpen(false)} disabled={jiraCreating}>
                {jiraHasIntegration === false ? 'Close' : 'Cancel'}
              </Button>
              {jiraHasIntegration !== false && jiraDialogMode === 'create' && (
                <Button onClick={handleCreateJiraTicket} disabled={jiraCreating || !jiraProjectKey} className="bg-[#0052CC] hover:bg-[#0065FF] text-white">
                  {jiraCreating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Ticket className="h-4 w-4 mr-2" />}
                  Create issue
                </Button>
              )}
              {jiraHasIntegration !== false && jiraDialogMode === 'associate' && (
                <Button onClick={handleAssociateJiraTicket} disabled={jiraCreating || !jiraAssociateKey.trim()} className="bg-[#0052CC] hover:bg-[#0065FF] text-white">
                  {jiraCreating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Ticket className="h-4 w-4 mr-2" />}
                  Link ticket
                </Button>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* ServiceNow push / sync dialog */}
        <Dialog open={snowDialogOpen} onOpenChange={setSnowDialogOpen}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <div className="w-6 h-6 rounded bg-[#81B5A1] flex items-center justify-center shrink-0">
                  <Shield className="w-4 h-4 text-[#1B3C34]" />
                </div>
                ServiceNow
              </DialogTitle>
              <DialogDescription className="truncate">{selectedFinding?.title || selectedFinding?.name}</DialogDescription>
            </DialogHeader>

            {snowHasIntegration !== false && (
              <div className="flex gap-1 border-b border-border pb-2">
                {(['push', 'associate'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setSnowDialogMode(m)}
                    className={cn(
                      'px-3 py-1 text-sm rounded-md transition-colors',
                      snowDialogMode === m
                        ? 'bg-[#81B5A1]/20 text-[#81B5A1] border border-[#81B5A1]/30'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
                    )}
                  >
                    {m === 'push' ? 'Push finding' : 'Link existing'}
                  </button>
                ))}
              </div>
            )}

            <div className="space-y-4 py-2">
              {snowHasIntegration === false ? (
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm space-y-2">
                  <p className="text-yellow-300 font-medium flex items-center gap-2">
                    <AlertCircle className="h-4 w-4" />ServiceNow not configured
                  </p>
                  <p className="text-muted-foreground">
                    Set up the ServiceNow integration on the{' '}
                    <a href="/integrations" className="text-primary underline">Integrations page</a>.
                  </p>
                </div>
              ) : (
                <>
                  {snowDeliveries.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Linked records</p>
                      <div className="space-y-1.5">
                        {snowDeliveries.map((d) => {
                          const label = d.snow_number || d.snow_sys_id || `#${d.id}`;
                          return (
                            <div key={d.id} className="rounded border border-border px-2 py-1.5 text-sm space-y-1">
                              <div className="flex items-center gap-2">
                                {d.snow_url ? (
                                  <a href={d.snow_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 text-[#81B5A1] hover:underline flex-1 min-w-0">
                                    <ExternalLink className="h-3 w-3 shrink-0" />
                                    <span className="font-mono truncate">{label}</span>
                                  </a>
                                ) : (
                                  <span className="font-mono flex-1 truncate">{label}</span>
                                )}
                                {d.snow_state_label && (
                                  <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0">{d.snow_state_label}</Badge>
                                )}
                                {snowSyncEnabled && (
                                  <button
                                    onClick={() => handleRefreshServiceNow(d.id)}
                                    disabled={snowRefreshing === d.id}
                                    className="text-muted-foreground hover:text-foreground"
                                    title="Refresh from ServiceNow (may queue close validation)"
                                  >
                                    {snowRefreshing === d.id
                                      ? <Loader2 className="h-3 w-3 animate-spin" />
                                      : <RefreshCw className="h-3 w-3" />}
                                  </button>
                                )}
                                <button
                                  onClick={() => handleDisconnectServiceNow(d.id, label)}
                                  disabled={snowDisconnecting === d.id}
                                  className="text-muted-foreground hover:text-red-400"
                                  title="Disconnect delivery"
                                >
                                  {snowDisconnecting === d.id
                                    ? <Loader2 className="h-3 w-3 animate-spin" />
                                    : <XCircle className="h-3 w-3" />}
                                </button>
                              </div>
                              {d.pending_close_validation && (
                                <p className="text-[11px] text-yellow-400">Close-claim validation in progress…</p>
                              )}
                              {d.last_close_validation_verdict && !d.pending_close_validation && (
                                <p className="text-[11px] text-muted-foreground">
                                  Last close validation: {d.last_close_validation_verdict}
                                </p>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {snowDialogMode === 'push' && snowDeliveries.length === 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Include in payload</p>
                      {[
                        { label: 'Evidence & Proof of Concept', value: snowIncludeEvidence, set: setSnowIncludeEvidence },
                        { label: 'Remediation', value: snowIncludeRemediation, set: setSnowIncludeRemediation },
                        { label: 'Delphi / Oracle enrichment', value: snowIncludeEnrichment, set: setSnowIncludeEnrichment },
                      ].map(({ label, value, set }) => (
                        <label key={label} className="flex items-center gap-2 cursor-pointer text-sm">
                          <Checkbox checked={value} onCheckedChange={(v) => set(!!v)} className="shrink-0" />
                          {label}
                        </label>
                      ))}
                    </div>
                  )}

                  {snowDialogMode === 'associate' && (
                    <div className="space-y-3">
                      <p className="text-sm text-muted-foreground">
                        Link an existing ServiceNow incident by number (INC0012345) or sys_id so status sync and close validation can apply.
                      </p>
                      <Input
                        placeholder="INC0012345 or sys_id"
                        value={snowAssociateKey}
                        onChange={(e) => setSnowAssociateKey(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleAssociateServiceNow()}
                      />
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setSnowDialogOpen(false)} disabled={snowPushing}>
                {snowHasIntegration === false ? 'Close' : 'Cancel'}
              </Button>
              {snowHasIntegration !== false && snowDialogMode === 'push' && (
                <Button
                  onClick={handlePushServiceNow}
                  disabled={snowPushing || snowDeliveries.length > 0}
                  className="bg-[#81B5A1] hover:bg-[#6FA38F] text-[#1B3C34]"
                >
                  {snowPushing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Shield className="h-4 w-4 mr-2" />}
                  {snowDeliveries.length > 0 ? 'Already linked' : 'Push finding'}
                </Button>
              )}
              {snowHasIntegration !== false && snowDialogMode === 'associate' && (
                <Button
                  onClick={handleAssociateServiceNow}
                  disabled={snowPushing || !snowAssociateKey.trim()}
                  className="bg-[#81B5A1] hover:bg-[#6FA38F] text-[#1B3C34]"
                >
                  {snowPushing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Shield className="h-4 w-4 mr-2" />}
                  Link record
                </Button>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* HackerOne report link dialog */}
        <Dialog open={h1DialogOpen} onOpenChange={(v) => { if (!h1Linking) setH1DialogOpen(v); }}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <div className="w-6 h-6 rounded bg-[#494649] flex items-center justify-center shrink-0">
                  <Bug className="w-4 h-4 text-white" />
                </div>
                HackerOne
              </DialogTitle>
              <DialogDescription className="truncate">{selectedFinding?.title || selectedFinding?.name}</DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              {h1HasIntegration === false ? (
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm space-y-2">
                  <p className="text-yellow-300 font-medium flex items-center gap-2">
                    <AlertCircle className="h-4 w-4" />HackerOne not configured
                  </p>
                  <p className="text-muted-foreground">
                    Set up the HackerOne integration on the{' '}
                    <a href="/integrations" className="text-primary underline">Integrations page</a>.
                  </p>
                </div>
              ) : (
                <>
                  {h1Links.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Linked reports</p>
                      <div className="space-y-1.5">
                        {h1Links.map((l) => (
                          <div key={l.id} className="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-sm">
                            <a
                              href={l.hackerone_report_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1.5 text-primary hover:underline flex-1 min-w-0"
                            >
                              <ExternalLink className="h-3 w-3 shrink-0" />
                              <span className="font-mono truncate">#{l.hackerone_report_id}</span>
                            </a>
                            {l.hackerone_state && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0">{l.hackerone_state}</Badge>
                            )}
                            {l.hackerone_severity && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0 capitalize">{l.hackerone_severity}</Badge>
                            )}
                            {l.is_associated && (
                              <Badge variant="outline" className="text-[10px] h-4 px-1 shrink-0 text-muted-foreground">linked</Badge>
                            )}
                            <button
                              onClick={() => handleRefreshHackerOne(l.id)}
                              disabled={h1Refreshing === l.id}
                              className="text-muted-foreground hover:text-foreground"
                              title="Refresh status from HackerOne"
                            >
                              {h1Refreshing === l.id
                                ? <Loader2 className="h-3 w-3 animate-spin" />
                                : <RefreshCw className="h-3 w-3" />}
                            </button>
                            <button
                              onClick={() => handleDisconnectHackerOne(l.id, l.hackerone_report_id)}
                              disabled={h1Disconnecting === l.id}
                              className="text-muted-foreground hover:text-red-400"
                              title="Disconnect report"
                            >
                              {h1Disconnecting === l.id
                                ? <Loader2 className="h-3 w-3 animate-spin" />
                                : <XCircle className="h-3 w-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground">
                      Link an existing HackerOne report to this finding. The report is not modified in HackerOne; status can be refreshed from H1.
                    </p>
                    <div className="space-y-1.5">
                      <label className="text-sm font-medium">Report ID or URL</label>
                      <Input
                        placeholder="e.g. 1234567 or https://hackerone.com/reports/1234567"
                        value={h1AssociateKey}
                        onChange={(e) => setH1AssociateKey(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleAssociateHackerOne()}
                      />
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setH1DialogOpen(false)} disabled={h1Linking}>
                {h1HasIntegration === false ? 'Close' : 'Cancel'}
              </Button>
              {h1HasIntegration !== false && (
                <Button
                  onClick={handleAssociateHackerOne}
                  disabled={h1Linking || !h1AssociateKey.trim()}
                  className="bg-[#494649] hover:bg-[#5a5759] text-white"
                >
                  {h1Linking ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Bug className="h-4 w-4 mr-2" />}
                  Link report
                </Button>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* Generate Nuclei Template Dialog */}
        <Dialog open={generateTemplateOpen} onOpenChange={setGenerateTemplateOpen}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-purple-400" />
                Generate Nuclei Template
              </DialogTitle>
              <DialogDescription>
                The AI will generate a Nuclei YAML detection template based on this finding. Saved as draft for your review.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <div className="space-y-1">
                <label className="text-xs font-medium">CVE ID</label>
                <Input
                  placeholder="CVE-2024-12345"
                  value={generateTemplateCveId}
                  onChange={e => setGenerateTemplateCveId(e.target.value.toUpperCase())}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium">Affected URL / Matched Evidence <span className="text-muted-foreground">(optional)</span></label>
                <Input
                  placeholder="/path/to/vulnerable/endpoint"
                  value={generateTemplateEvidence}
                  onChange={e => setGenerateTemplateEvidence(e.target.value)}
                />
              </div>
              <p className="text-xs text-muted-foreground p-2 rounded border border-purple-500/20 bg-purple-500/5 text-purple-400">
                Template will be saved to <strong>Nuclei Templates</strong> as a draft. Review the YAML before activating.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setGenerateTemplateOpen(false)} disabled={generatingTemplate}>
                Cancel
              </Button>
              <Button
                onClick={async () => {
                  if (!firstOrgId) {
                    toast({ title: 'No organization found', variant: 'destructive' });
                    return;
                  }
                  const runGenerate = async (force: boolean) => {
                    setGeneratingTemplate(true);
                    try {
                      const resp = await api.post('/nuclei-templates/generate', {
                        organization_id: firstOrgId,
                        cve_id: generateTemplateCveId.trim() || undefined,
                        vulnerability_description: selectedFinding?.description || undefined,
                        affected_url: generateTemplateEvidence.trim() || undefined,
                        affected_product: selectedFinding?.detected_by || undefined,
                        force,
                      });
                      toast({
                        title: 'Template generated',
                        description: `Saved as draft: ${resp.data.template_id} — view in Nuclei Templates`,
                      });
                      setGenerateTemplateOpen(false);
                    } catch (err: any) {
                      const detail = err?.response?.data?.detail;
                      if (err?.response?.status === 409 && detail?.error === 'template_already_exists') {
                        setGeneratingTemplate(false);
                        const proceed = window.confirm(`${detail.message}\n\nGenerate a custom (secondary) template anyway?`);
                        if (proceed) return runGenerate(true);
                        toast({ title: 'Template already exists', description: detail.message });
                        return;
                      }
                      const msg = typeof detail === 'string' ? detail : (detail?.message || err.message);
                      toast({ title: 'Generation failed', description: msg, variant: 'destructive' });
                    } finally {
                      setGeneratingTemplate(false);
                    }
                  };
                  await runGenerate(false);
                }}
                disabled={generatingTemplate || (!generateTemplateCveId.trim() && !selectedFinding?.description)}
                className="gap-1.5 bg-purple-600 hover:bg-purple-700"
              >
                {generatingTemplate ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                {generatingTemplate ? 'Generating…' : 'Generate'}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}
