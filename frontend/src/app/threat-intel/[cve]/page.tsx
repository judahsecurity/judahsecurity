'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { formatDistanceToNowStrict } from 'date-fns';
import {
  ArrowLeft,
  Bot,
  Crosshair,
  ExternalLink,
  Globe,
  Layers,
  Loader2,
  Radar,
  ShieldCheck,
} from 'lucide-react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { SeverityChip } from '@/components/ui/severity-chip';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

type Validation = 'exploit_verified' | 'demonstrated' | 'detected';
type Exposure = 'internet_exposed' | 'public_not_live' | 'internal' | 'unknown';

interface ImpactAsset {
  asset_id: number;
  asset: string;
  asset_type: string;
  exposure: Exposure;
  validation: Validation;
  open: boolean;
  severity: string;
  finding_ids: number[];
  first_detected?: string | null;
}

interface CveImpact {
  cve_id: string;
  counts: { affected: number; exposed: number; exploit_verified: number; demonstrated: number; resolved: number };
  assets: ImpactAsset[];
  sessions: { session_id: string; finding_ids: number[]; validation: Validation }[];
}

/** Loose view of /threat-intel/cve/{id}: sources vary, so every field is optional. */
interface CveDetail {
  pdcp?: Record<string, any>;
  catalog?: { nvd?: Record<string, any> | null; osv?: Record<string, any> | null };
  signals?: {
    observed_exploitation?: { known_exploited?: boolean; observed_scanning?: boolean };
    exploitation_probability?: { score?: number | null; percentile?: number | null };
    detection_coverage?: { nuclei_template?: boolean; templates?: { template_id: string; name: string }[] };
  };
  exploit_intelligence?: { label?: string; artifact_count?: number };
}

const VALIDATION_META: Record<Validation, { label: string; bars: number; className: string; hint: string }> = {
  exploit_verified: {
    label: 'Exploit verified',
    bars: 4,
    className: 'text-red-400',
    hint: 'The independent verifier reproduced it against the live asset, or an analyst confirmed it',
  },
  demonstrated: {
    label: 'Demonstrated',
    bars: 3,
    className: 'text-orange-400',
    hint: 'The agent attached an exploit chain, not yet independently verified',
  },
  detected: {
    label: 'Not validated',
    bars: 1,
    className: 'text-muted-foreground',
    hint: 'Detected by a scanner or version match; the agent has not tried it',
  },
};

const EXPOSURE_LABEL: Record<Exposure, string> = {
  internet_exposed: 'Internet-exposed',
  public_not_live: 'Public, not live',
  internal: 'Internal',
  unknown: 'Unknown',
};

function Bars({ n, className }: { n: number; className?: string }) {
  return (
    <span className={cn('inline-flex items-end gap-[2px]', className)} aria-hidden>
      {[1, 2, 3, 4].map((i) => (
        <span
          key={i}
          className={cn('w-[3px] rounded-[1px] bg-current', i > n && 'opacity-20')}
          style={{ height: 3 + i * 2 }}
        />
      ))}
    </span>
  );
}

function Stat({ icon: Icon, value, label, tone }: { icon: typeof Layers; value: number; label: string; tone: string }) {
  return (
    <div>
      <div className="flex items-center gap-3">
        <Icon className={cn('h-7 w-7', tone)} strokeWidth={1.6} />
        <span className={cn('text-4xl font-light tabular-nums', tone)}>{value}</span>
      </div>
      <p className="mt-1 text-sm text-muted-foreground">{label}</p>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

export default function CveIncidentPage() {
  const params = useParams<{ cve: string }>();
  const cve = decodeURIComponent(params.cve || '').toUpperCase();
  const [impact, setImpact] = useState<CveImpact | null>(null);
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [impactError, setImpactError] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(true);

  useEffect(() => {
    let live = true;
    // Local and fast: render "am I affected" before the slow external enrichment.
    api
      .get(`/threat-intel/cve/${encodeURIComponent(cve)}/impact`)
      .then((r: any) => live && setImpact(r?.data ?? r))
      .catch((e: any) => live && setImpactError(e?.response?.data?.detail || 'Could not load impact'));
    api
      .get(`/threat-intel/cve/${encodeURIComponent(cve)}`, {}, { timeout: 30000 })
      .then((r: any) => live && setDetail(r?.data ?? r))
      .catch(() => live && setDetail(null))
      .finally(() => live && setDetailLoading(false));
    return () => {
      live = false;
    };
  }, [cve]);

  const pdcp = detail?.pdcp || {};
  const nvd = detail?.catalog?.nvd || {};
  const osv = detail?.catalog?.osv || {};
  const description: string = pdcp.description || nvd.description || osv.summary || '';
  const name: string = pdcp.name || '';
  const cvss: number | undefined = pdcp.cvss_score ?? nvd.cvss_score ?? undefined;
  const severity: string =
    pdcp.severity || (cvss == null ? '' : cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low');
  const kev = !!detail?.signals?.observed_exploitation?.known_exploited;
  const scanning = !!detail?.signals?.observed_exploitation?.observed_scanning;
  const epss = detail?.signals?.exploitation_probability?.score;
  const templates = detail?.signals?.detection_coverage?.templates || [];
  const products: { vendor?: string; product?: string }[] = Array.isArray(pdcp.affected_products)
    ? pdcp.affected_products.slice(0, 6).map((p: any) => (typeof p === 'string' ? { product: p } : p))
    : [];

  const counts = impact?.counts;
  const unvalidatedExposed = useMemo(
    () => (impact?.assets || []).filter((a) => a.open && a.validation === 'detected' && a.exposure === 'internet_exposed'),
    [impact]
  );

  return (
    <MainLayout>
      <Header title="Threat intelligence" subtitle="Am I affected, and has it been proven?" />
      <div className="mx-auto max-w-6xl space-y-8 p-6">
        <div className="space-y-3">
          <Link href="/threat-intel" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3 w-3" /> Back to threat intel
          </Link>
          <div className="flex flex-wrap items-center gap-3">
            {severity ? <SeverityChip severity={severity} className="h-6 w-6 text-xs" /> : null}
            <h1 className="text-xl font-semibold">
              {cve}
              {name ? <span className="font-normal text-muted-foreground"> — {name}</span> : null}
            </h1>
            {kev ? (
              <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs text-red-400">
                Known exploited
              </span>
            ) : null}
            {scanning ? (
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-400">
                Mass scanning observed
              </span>
            ) : null}
          </div>
        </div>

        <Section title="What happened">
          {detailLoading ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading advisory…
            </p>
          ) : description ? (
            <p className="max-w-3xl text-sm leading-relaxed text-foreground/90">{description}</p>
          ) : (
            <p className="text-sm text-muted-foreground">No advisory text available from the intel sources.</p>
          )}
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted-foreground">
            {cvss != null ? <span>CVSS <span className="text-foreground">{cvss}</span></span> : null}
            {epss != null ? (
              <span>EPSS <span className="text-foreground">{(epss * 100).toFixed(1)}%</span></span>
            ) : null}
            {detail?.exploit_intelligence?.label ? (
              <span>Exploit maturity <span className="text-foreground">{detail.exploit_intelligence.label}</span></span>
            ) : null}
          </div>
        </Section>

        <Section title="How do I know I'm affected">
          <ul className="space-y-2 text-sm">
            {products.length ? (
              <li className="flex items-start gap-2">
                <Layers className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                <span>
                  Affected products:{' '}
                  {products.map((p, i) => (
                    <code key={i} className="mr-1.5 rounded bg-primary/10 px-1.5 py-0.5 font-mono text-xs text-primary">
                      {[p.vendor, p.product].filter(Boolean).join(' ')}
                    </code>
                  ))}
                </span>
              </li>
            ) : null}
            <li className="flex items-start gap-2">
              <Radar className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              {templates.length ? (
                <span>
                  Judah detects it with{' '}
                  {templates.slice(0, 3).map((t) => (
                    <code key={t.template_id} className="mr-1.5 rounded bg-primary/10 px-1.5 py-0.5 font-mono text-xs text-primary">
                      {t.template_id}
                    </code>
                  ))}
                  — assets below were matched by scans.
                </span>
              ) : (
                <span>
                  No detection template. Assets below come from version matches or agent findings; use the agent to
                  validate others.
                </span>
              )}
            </li>
            <li className="flex items-start gap-2">
              <Bot className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <span>Agent validation shows whether exploitation was actually proven on your asset, not just detected.</span>
            </li>
          </ul>
        </Section>

        <Section title="Impact in your environment">
          {impactError ? (
            <p className="text-sm text-red-400">{impactError}</p>
          ) : !counts ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking your assets…
            </p>
          ) : (
            <div className="grid grid-cols-2 gap-6 py-2 md:grid-cols-4">
              <Stat icon={Layers} value={counts.affected} label="Affected assets" tone="text-primary" />
              <Stat icon={Globe} value={counts.exposed} label="Internet-exposed" tone="text-primary" />
              <Stat icon={ShieldCheck} value={counts.exploit_verified} label="Exploit verified" tone={counts.exploit_verified ? 'text-red-400' : 'text-primary'} />
              <Stat icon={Crosshair} value={counts.demonstrated} label="Demonstrated by agent" tone={counts.demonstrated ? 'text-orange-400' : 'text-primary'} />
            </div>
          )}
          {unvalidatedExposed.length ? (
            <p className="text-xs text-amber-400">
              {unvalidatedExposed.length} internet-exposed asset{unvalidatedExposed.length === 1 ? ' has' : 's have'} not been
              validated yet.
            </p>
          ) : null}
        </Section>

        {impact ? (
          <Section title={`Affected assets (${impact.assets.length})`}>
            {impact.assets.length === 0 ? (
              <p className="rounded-lg border border-dashed border-border py-8 text-center text-sm text-muted-foreground">
                No findings for {cve} on your assets.
                {counts?.resolved ? ` ${counts.resolved} resolved.` : ''}
              </p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full min-w-[720px] text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs text-muted-foreground">
                      <th className="px-4 py-2.5 font-normal">Asset</th>
                      <th className="px-4 py-2.5 font-normal">Exposure</th>
                      <th className="px-4 py-2.5 font-normal">Status</th>
                      <th className="px-4 py-2.5 font-normal">Agent validation</th>
                      <th className="px-4 py-2.5 font-normal">First seen</th>
                      <th className="px-4 py-2.5" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {impact.assets.map((a) => {
                      const v = VALIDATION_META[a.validation];
                      return (
                        <tr key={a.asset_id} className={cn(!a.open && 'opacity-55')}>
                          <td className="px-4 py-2.5">
                            <Link href={`/findings?id=${a.finding_ids[0]}`} className="flex items-center gap-2 hover:text-primary">
                              <SeverityChip severity={a.severity} />
                              <span className="font-mono text-[13px]">{a.asset}</span>
                              {a.finding_ids.length > 1 ? (
                                <span className="text-xs text-muted-foreground">+{a.finding_ids.length - 1}</span>
                              ) : null}
                            </Link>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={cn('flex items-center gap-1.5', a.exposure === 'internet_exposed' && 'text-foreground')}>
                              {a.exposure === 'internet_exposed' ? <Globe className="h-3.5 w-3.5 text-primary" /> : null}
                              <span className={a.exposure === 'internet_exposed' ? '' : 'text-muted-foreground'}>
                                {EXPOSURE_LABEL[a.exposure]}
                              </span>
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-muted-foreground">{a.open ? 'Open' : 'Resolved'}</td>
                          <td className="px-4 py-2.5" title={v.hint}>
                            <span className={cn('flex items-center gap-2', v.className)}>
                              <Bars n={v.bars} />
                              {v.label}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-xs text-muted-foreground">
                            {a.first_detected ? `${formatDistanceToNowStrict(Date.parse(a.first_detected))} ago` : '—'}
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            {a.open && a.validation !== 'exploit_verified' ? (
                              <Button asChild variant="ghost" size="sm" className="h-7 text-xs">
                                <Link
                                  href={`/agent?target=${encodeURIComponent(a.asset)}&question=${encodeURIComponent(
                                    `Validate whether ${a.asset} is exploitable via ${cve}. Prove impact with evidence or rule it out.`
                                  )}`}
                                >
                                  Validate <ExternalLink className="ml-1 h-3 w-3" />
                                </Link>
                              </Button>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        ) : null}

        {impact?.sessions.length ? (
          <Section title="Agent engagements on this CVE">
            <ul className="divide-y divide-border/60 text-sm">
              {impact.sessions.map((s) => {
                const v = VALIDATION_META[s.validation];
                return (
                  <li key={s.session_id} className="flex items-center gap-3 py-2">
                    <Bot className="h-4 w-4 text-primary" />
                    <span className="font-mono text-xs text-muted-foreground">{s.session_id.slice(0, 12)}</span>
                    <span className={cn('flex items-center gap-1.5 text-xs', v.className)}>
                      <Bars n={v.bars} /> {v.label}
                    </span>
                    <span className="ml-auto flex gap-2 text-xs">
                      {s.finding_ids.slice(0, 5).map((id) => (
                        <Link key={id} href={`/findings?id=${id}`} className="text-primary hover:underline">
                          #{id}
                        </Link>
                      ))}
                    </span>
                  </li>
                );
              })}
            </ul>
          </Section>
        ) : null}
      </div>
    </MainLayout>
  );
}
