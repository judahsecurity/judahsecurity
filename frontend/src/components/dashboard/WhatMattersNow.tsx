'use client';

import Link from 'next/link';
import { formatDistanceToNowStrict } from 'date-fns';
import { Bot, Clock, Crosshair, Layers, Radar, Server, ShieldCheck } from 'lucide-react';
import { SeverityChip, normalizeSeverity } from '@/components/ui/severity-chip';
import { SeverityBar } from './SeverityBar';

/** Subset of an attack-workspace path the dashboard needs. */
export interface PriorityPath {
  id: string;
  title: string;
  severity: string;
  hosts: string[];
  finding_ids: number[];
  demonstrated: boolean;
  verified?: boolean;
  timeframe?: string | null;
}

export interface FeedFinding {
  id: number;
  name?: string | null;
  title?: string | null;
  host?: string | null;
  severity?: string | null;
  detected_by?: string | null;
  first_detected?: string | null;
}

export interface FeedEngagement {
  id: number;
  name: string;
  target_url: string;
  phase: string;
  total_exploits_confirmed: number;
  started_at?: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Verified first, then demonstrated, then severity, then recency. */
export function rankPaths(paths: PriorityPath[]): PriorityPath[] {
  return [...paths].sort((a, b) => {
    const key = (p: PriorityPath) => [
      p.verified ? 1 : 0,
      p.demonstrated ? 1 : 0,
      SEV_RANK[normalizeSeverity(p.severity)],
      p.timeframe ? Date.parse(p.timeframe) || 0 : 0,
    ];
    const ka = key(a), kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return kb[i] - ka[i];
    return 0;
  });
}

function ago(iso?: string | null): string {
  if (!iso) return '';
  const t = Date.parse(iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`);
  return Number.isFinite(t) ? `${formatDistanceToNowStrict(t)} ago` : '';
}

function Chip({ icon: Icon, children }: { icon: typeof Layers; children: React.ReactNode }) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1 text-xs text-primary/90">
      <Icon className="h-3 w-3" />
      {children}
    </span>
  );
}

function ProofTag({ path }: { path: PriorityPath }) {
  if (path.verified)
    return (
      <span className="inline-flex shrink-0 items-center gap-1 text-xs text-red-400">
        <ShieldCheck className="h-3 w-3" />
        Proven
      </span>
    );
  if (path.demonstrated)
    return <span className="shrink-0 text-xs text-amber-400/90">Demonstrated</span>;
  return null;
}

function SectionTitle({ icon: Icon, title, hint, href, cta }: {
  icon: typeof Layers;
  title: string;
  hint?: string;
  href?: string;
  cta?: string;
}) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <p className="flex items-center gap-2 text-sm font-medium">
        <Icon className="h-4 w-4 text-primary" />
        {title}
        {hint ? <span className="font-normal text-muted-foreground">{hint}</span> : null}
      </p>
      {href ? (
        <Link href={href} className="shrink-0 text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
          {cta}
        </Link>
      ) : null}
    </div>
  );
}

export function WhatMattersNow({
  paths,
  findings,
  engagements,
  counts,
  loading,
}: {
  paths: PriorityPath[];
  findings: FeedFinding[];
  engagements: FeedEngagement[];
  counts: { critical: number; high: number; medium: number; low: number };
  loading?: boolean;
}) {
  const top = rankPaths(paths).slice(0, 6);
  const openTotal = counts.critical + counts.high + counts.medium + counts.low;

  type Item = { key: string; at: number; node: React.ReactNode };
  const feed: Item[] = [
    ...findings.map((f) => ({
      key: `f-${f.id}`,
      at: Date.parse(f.first_detected || '') || 0,
      node: (
        <Link href={`/findings?id=${f.id}`} className="group flex items-center gap-3 py-2">
          <SeverityChip severity={f.severity} />
          <span className="min-w-0 flex-1 truncate text-sm group-hover:text-primary">
            {f.title || f.name || 'Finding'}
          </span>
          {f.detected_by === 'agent' ? <Chip icon={Bot}>Agent</Chip> : null}
          {f.host ? (
            <span className="hidden max-w-[10rem] shrink-0 truncate text-xs text-muted-foreground lg:inline">{f.host}</span>
          ) : null}
          <span className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            {ago(f.first_detected)}
          </span>
        </Link>
      ),
    })),
    ...engagements.map((e) => ({
      key: `e-${e.id}`,
      at: Date.parse(e.started_at || '') || 0,
      node: (
        <Link href="/pentest" className="group flex items-center gap-3 py-2">
          <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-primary/60 text-primary">
            <Crosshair className="h-3 w-3" />
          </span>
          <span className="min-w-0 flex-1 truncate text-sm group-hover:text-primary">
            {e.name} <span className="text-muted-foreground">· {e.phase}</span>
          </span>
          {e.total_exploits_confirmed ? (
            <span className="shrink-0 text-xs text-red-400">{e.total_exploits_confirmed} confirmed</span>
          ) : null}
          <span className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            {ago(e.started_at)}
          </span>
        </Link>
      ),
    })),
  ]
    .sort((a, b) => b.at - a.at)
    .slice(0, 6);

  return (
    <section className="rounded-lg border border-border bg-card p-5">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">What matters now</h2>
          <p className="text-xs text-muted-foreground">
            Ranked by proof first: verified exploits, then demonstrated chains, then severity.
          </p>
        </div>
        <div className="w-full max-w-md">
          <p className="mb-2 text-xs text-muted-foreground">
            Open findings <span className="tabular-nums text-foreground">{openTotal.toLocaleString()}</span>
          </p>
          <SeverityBar counts={counts} />
        </div>
      </div>

      <div className="grid gap-x-10 gap-y-6 lg:grid-cols-2">
        <div>
          <SectionTitle icon={Radar} title="Top attack paths" hint="by proof and impact" href="/attacks" cta="All paths" />
          {loading ? (
            <p className="py-6 text-center text-xs text-muted-foreground">Loading…</p>
          ) : top.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">
              No attack paths yet. Launch an engagement to have Aegis test your exposure.
            </p>
          ) : (
            <ul className="divide-y divide-border/60">
              {top.map((p) => (
                <li key={p.id}>
                  <Link href={`/attacks?path=${encodeURIComponent(p.id)}`} className="group flex items-center gap-3 py-2">
                    <SeverityChip severity={p.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm group-hover:text-primary">{p.title}</span>
                    <ProofTag path={p} />
                    <Chip icon={Server}>
                      {p.hosts.length} host{p.hosts.length === 1 ? '' : 's'}
                    </Chip>
                    <Chip icon={Layers}>
                      {p.finding_ids.length} finding{p.finding_ids.length === 1 ? '' : 's'}
                    </Chip>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <SectionTitle icon={Clock} title="Happening now" hint="new findings and engagements" href="/findings" cta="All findings" />
          {loading ? (
            <p className="py-6 text-center text-xs text-muted-foreground">Loading…</p>
          ) : feed.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">Nothing new yet.</p>
          ) : (
            <ul className="divide-y divide-border/60">
              {feed.map((item) => (
                <li key={item.key}>{item.node}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
