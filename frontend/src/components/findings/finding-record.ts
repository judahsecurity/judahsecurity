import type { AgentDetection } from './DemonstratedChain';
import type { ScannerDetection } from './DetectionPanel';
import type { RiskAssessment } from './RiskAssessmentPanel';

export interface FindingRecord {
  id: number;
  title: string;
  host?: string;
  asset_id?: number;
  description?: string;
  impact?: string;
  evidence?: string;
  proof_of_concept?: string;
  steps_to_reproduce?: string;
  remediation?: string;
  matched_at?: string;
  affected_component?: string;
  severity: string;
  status?: string;
  assigned_to?: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  template_id?: string;
  detected_by?: string;
  tags?: string[];
  references?: string[];
  reference?: string[];
  first_detected?: string;
  last_detected?: string;
  created_at?: string;
  resolved_at?: string;
  last_validated_at?: string;
  validation_status?: string;
  agent_detection?: AgentDetection;
  detection?: ScannerDetection;
  risk_assessment?: RiskAssessment;
  netbrain_exposure?: {
    verdict?: 'prerequisite_present' | 'prerequisite_absent' | 'unknown';
    analysis?: string;
    reason?: string;
    device_hostname?: string;
    device_management_ip?: string;
    configuration_time?: string;
    configuration_age_hours?: number;
    relevant_configuration?: string[];
    exploitable_transports?: string[];
    suggested_remediation?: string;
    evaluated_at?: string;
  };
  oracle?: { opes_score?: number; opes_category?: string; opes_confidence?: string; opes_label?: string };
}

export interface ReviewDecision {
  state: 'draft' | 'reviewed';
  decision: 'confirm' | 'correct' | 'needs_evidence' | null;
  rationale: string;
  correction: string;
  evidence_references: string[];
  task_id?: string;
  reviewer?: string;
  saved_at?: string;
}
export interface ReviewItem {
  id: string;
  title: string;
  guidance: string;
  context: 'evidence' | 'assets';
  reviewed: boolean;
  stale: boolean;
  review?: ReviewDecision | null;
}
export interface TriageState {
  revision: number;
  evidence_version: string;
  status: 'needs_review' | 'in_review' | 'reviewed';
  pending: number;
  items: ReviewItem[];
  history: ReviewDecision[];
  last_reviewed_at?: string;
}
export interface AssetContextRow {
  value: string;
  asset_id: number | null;
  relationship: 'linked' | 'mentioned';
}

/** Never turn raw scanner output, a database endpoint, or a script URI into a web link. */
export function webUrl(value?: string | null): string | null {
  if (!value || /[\s\\]/.test(value)) return null;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password && !url.hash
      ? url.href : null;
  } catch { return null; }
}

export function captureUrl(finding: FindingRecord, liveUrl?: string | null): string | null {
  const assetHost = (() => {
    try { return new URL(webUrl(finding.host) || `https://${finding.host || ''}`).hostname.toLowerCase(); }
    catch { return ''; }
  })();
  const live = webUrl(liveUrl);
  const allowed = new Set([assetHost, live ? new URL(live).hostname.toLowerCase() : '']);
  for (const candidate of [finding.detection?.match, finding.matched_at, finding.host, live]) {
    const url = webUrl(candidate);
    if (url && allowed.has(new URL(url).hostname.toLowerCase())) return url;
  }
  return null;
}

export function findingType(finding: Pick<FindingRecord, 'tags' | 'cve_id'>): string {
  if (finding.cve_id) return 'CVE vulnerability';
  const tags = (finding.tags || []).map(tag => tag.toLowerCase());
  if (tags.some(tag => ['tls', 'ssl', 'certificate'].includes(tag))) return 'TLS / certificate';
  if (tags.some(tag => ['exposure', 'exposed', 'network', 'database'].includes(tag))) return 'Service exposure';
  if (tags.some(tag => ['misconfig', 'misconfiguration', 'config'].includes(tag))) return 'Misconfiguration';
  return 'Other finding';
}

export const emptyDecision = (): ReviewDecision => ({
  state: 'draft', decision: null, rationale: '', correction: '', evidence_references: [],
});
