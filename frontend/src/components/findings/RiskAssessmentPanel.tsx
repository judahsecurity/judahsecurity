'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';

export interface RiskAssessment {
  status?: string;
  verdict?: string;
  confirmed_severity?: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cvss_basis?: string;
  why_this_severity?: string;
  why_not_higher?: string;
  why_not_lower?: string;
  demonstrated?: { asset?: string; result?: string }[];
  not_demonstrated?: { target?: string; outcome?: string }[];
  control_failures?: { control?: string; failure?: string }[];
  business_risk?: string;
  remediation_sequence?: { when?: string; action?: string; done_when?: string }[];
  retest_criteria?: string[];
  ticket_title?: string;
  ra_note?: string;
  sla?: string;
  cwes?: string[];
  error?: string;
  updated_at?: string;
}

interface RiskAssessmentPanelProps {
  assessment?: RiskAssessment | null;
  asking?: boolean;
  onAskMarcus?: () => void;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-semibold">{title}</p>
      {children}
    </div>
  );
}

export function raStatusLabel(assessment?: RiskAssessment | null): string | null {
  const status = (assessment?.status || '').toLowerCase();
  if (!status) return null;
  if (status === 'complete') return 'RA complete';
  if (status === 'queued' || status === 'in_progress' || status === 'pending') return 'RA in progress';
  if (status === 'failed') return 'RA failed';
  return `RA ${status}`;
}

export function RiskAssessmentPanel({
  assessment,
  asking,
  onAskMarcus,
}: RiskAssessmentPanelProps) {
  const status = (assessment?.status || '').toLowerCase();
  const complete = status === 'complete';
  const inFlight = asking || status === 'queued' || status === 'in_progress';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-sm font-medium">Risk assessment</p>
        <div className="flex items-center gap-2">
          {status && (
            <Badge variant="outline" className="capitalize">
              {raStatusLabel(assessment)}
            </Badge>
          )}
          {onAskMarcus && (
            <Button
              size="sm"
              variant="outline"
              onClick={onAskMarcus}
              disabled={inFlight}
            >
              {inFlight ? (
                <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
              ) : null}
              Ask Marcus
            </Button>
          )}
        </div>
      </div>

      {!complete && (
        <p className="text-sm text-muted-foreground">
          {status === 'failed'
            ? assessment?.error || 'Marcus did not persist a complete RA.'
            : 'Marcus scores the demonstrated packet only — no live retest. Confirm vs inflate vs downgrade, CVSS, close criteria.'}
        </p>
      )}

      {complete && (
        <div className="space-y-5">
          <div className="flex flex-wrap gap-2">
            {assessment?.verdict && (
              <Badge className="capitalize">{assessment.verdict}</Badge>
            )}
            {assessment?.confirmed_severity && (
              <Badge variant="outline" className="capitalize">
                {assessment.confirmed_severity}
              </Badge>
            )}
            {assessment?.cvss_score != null && (
              <Badge variant="outline" className="font-mono">
                CVSS {Number(assessment.cvss_score).toFixed(1)}
              </Badge>
            )}
            {assessment?.sla && (
              <Badge variant="outline">{assessment.sla.replace('_', ' ')}</Badge>
            )}
          </div>
          {assessment?.cvss_vector && (
            <p className="text-xs font-mono text-muted-foreground break-all">
              {assessment.cvss_vector}
            </p>
          )}
          {assessment?.why_this_severity && (
            <Section title="Why this severity">
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {assessment.why_this_severity}
              </p>
            </Section>
          )}
          {assessment?.why_not_higher && (
            <Section title="Why not higher">
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {assessment.why_not_higher}
              </p>
            </Section>
          )}
          {assessment?.why_not_lower && (
            <Section title="Why not lower">
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {assessment.why_not_lower}
              </p>
            </Section>
          )}
          {!!assessment?.demonstrated?.length && (
            <Section title="Demonstrated">
              <ul className="space-y-1 text-sm text-muted-foreground">
                {assessment.demonstrated.map((row, i) => (
                  <li key={`${row.asset}-${i}`}>
                    <span className="text-foreground">{row.asset}</span>
                    {row.result ? ` — ${row.result}` : ''}
                  </li>
                ))}
              </ul>
            </Section>
          )}
          {!!assessment?.not_demonstrated?.length && (
            <Section title="Not demonstrated">
              <ul className="space-y-1 text-sm text-muted-foreground">
                {assessment.not_demonstrated.map((row, i) => (
                  <li key={`${row.target}-${i}`}>
                    <span className="text-foreground">{row.target}</span>
                    {row.outcome ? ` — ${row.outcome}` : ''}
                  </li>
                ))}
              </ul>
            </Section>
          )}
          {!!assessment?.control_failures?.length && (
            <Section title="Control failures">
              <ul className="space-y-1 text-sm text-muted-foreground">
                {assessment.control_failures.map((row, i) => (
                  <li key={`${row.control}-${i}`}>
                    <span className="text-foreground">{row.control}</span>
                    {row.failure ? ` — ${row.failure}` : ''}
                  </li>
                ))}
              </ul>
            </Section>
          )}
          {assessment?.business_risk && (
            <Section title="Business risk">
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {assessment.business_risk}
              </p>
            </Section>
          )}
          {!!assessment?.remediation_sequence?.length && (
            <Section title="Remediation sequence">
              <ol className="list-decimal pl-5 space-y-2 text-sm text-muted-foreground">
                {assessment.remediation_sequence.map((row, i) => (
                  <li key={i}>
                    {row.when ? <span className="text-foreground">{row.when}: </span> : null}
                    {row.action}
                    {row.done_when ? (
                      <span className="block text-xs mt-0.5">Done when: {row.done_when}</span>
                    ) : null}
                  </li>
                ))}
              </ol>
            </Section>
          )}
          {!!assessment?.retest_criteria?.length && (
            <Section title="Close only if">
              <ol className="list-decimal pl-5 space-y-1 text-sm text-muted-foreground">
                {assessment.retest_criteria.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ol>
            </Section>
          )}
          {assessment?.ra_note && (
            <Section title="Ticket note">
              {assessment.ticket_title && (
                <p className="text-sm font-medium mb-1">{assessment.ticket_title}</p>
              )}
              <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
                {assessment.ra_note}
              </p>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}
