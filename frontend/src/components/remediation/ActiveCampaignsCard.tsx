'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, ChevronDown, ChevronRight, ExternalLink, Search } from 'lucide-react';

/** A compromise check (behaviour to hunt) from an active campaign. */
export interface CampaignCompromiseCheck {
  title?: string;
  look_for: string;
  log_source?: string;
  why?: string;
  action?: string;
  source_url?: string | null;
  source_name?: string;
}

/** Active exploitation campaign matched to a finding (from /remediation/for-finding). */
export interface ActiveCampaign {
  id: string;
  name: string;
  category?: string;
  published?: string;
  last_updated?: string;
  headline?: string;
  caveat?: string;
  cves: string[];
  products: string[];
  mitigations: string[];
  compromise_checks: CampaignCompromiseCheck[];
  sources: Array<{ label: string; url: string }>;
  hunt_queries: Array<{ platform?: string; language?: string; url: string }>;
  url: string;
  match: { type: 'cve' | 'product'; value: string };
}

export interface ActiveCampaignsData {
  campaigns: ActiveCampaign[];
  source?: string;
  source_url?: string;
  licence?: string;
  feed_last_updated?: string;
}

/** Only follow https links from third-party feed data. */
function safeHref(url?: string | null): string | undefined {
  return url && url.startsWith('https://') ? url : undefined;
}

function ExtLink({ href, children }: { href?: string; children: React.ReactNode }) {
  if (!href) return <span>{children}</span>;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="text-red-300 hover:text-red-200 inline-flex items-center gap-1"
    >
      <ExternalLink className="h-3 w-3" />
      {children}
    </a>
  );
}

function CampaignBlock({ campaign }: { campaign: ActiveCampaign }) {
  const [showChecks, setShowChecks] = useState(false);
  const checks = campaign.compromise_checks || [];
  const matchLabel =
    campaign.match.type === 'cve'
      ? `Exploited CVE: ${campaign.match.value}`
      : `Targets exposed product: ${campaign.match.value}`;

  return (
    <div className="space-y-3 rounded-lg border border-red-600/20 bg-background/40 p-3">
      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{campaign.name}</span>
          {campaign.category && (
            <Badge variant="outline" className="text-xs">
              {campaign.category}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline" className="text-xs text-red-400 border-red-400/30">
            {matchLabel}
          </Badge>
          {campaign.published && <span>Reported {campaign.published}</span>}
          {campaign.last_updated && campaign.last_updated !== campaign.published && (
            <span>· updated {campaign.last_updated}</span>
          )}
        </div>
        {campaign.headline && <p className="text-sm text-muted-foreground">{campaign.headline}</p>}
      </div>

      {campaign.mitigations.length > 0 && (
        <div>
          <p className="text-xs font-medium text-red-400 mb-1.5">
            Interim mitigations (apply now, alongside the fix below)
          </p>
          <ol className="list-decimal space-y-1.5 pl-5 text-sm">
            {campaign.mitigations.map((m, i) => (
              <li key={i}>{m}</li>
            ))}
          </ol>
        </div>
      )}

      {checks.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setShowChecks((v) => !v)}
            className="flex items-center gap-1.5 text-xs font-medium text-amber-400 hover:text-amber-300"
            aria-expanded={showChecks}
          >
            {showChecks ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            <Search className="h-3.5 w-3.5" />
            Check for prior compromise ({checks.length})
          </button>
          {showChecks && (
            <ul className="mt-2 space-y-2">
              {checks.map((c, i) => (
                <li key={i} className="border-l-2 border-amber-600/30 pl-2 text-sm space-y-0.5">
                  {c.title && <p className="font-medium">{c.title}</p>}
                  <p className="text-muted-foreground">{c.look_for}</p>
                  {c.log_source && (
                    <p className="text-xs text-muted-foreground/80">Where to look: {c.log_source}</p>
                  )}
                  {c.source_name && safeHref(c.source_url) && (
                    <p className="text-xs">
                      <ExtLink href={safeHref(c.source_url)}>{c.source_name}</ExtLink>
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {campaign.caveat && (
        <p className="text-xs text-muted-foreground italic">Caveat: {campaign.caveat}</p>
      )}

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {campaign.sources.slice(0, 4).map((s) => (
          <ExtLink key={s.url} href={safeHref(s.url)}>
            {s.label}
          </ExtLink>
        ))}
        {campaign.hunt_queries.map((q) => (
          <ExtLink key={q.url} href={safeHref(q.url)}>
            {q.platform || q.language} hunt query
          </ExtLink>
        ))}
        <ExtLink href={safeHref(campaign.url)}>Full write-up</ExtLink>
      </div>
    </div>
  );
}

/**
 * Active exploitation campaigns that name this finding's CVE or exposed product,
 * with interim mitigations and compromise checks. Feed content is rendered as
 * plain text only.
 */
export function ActiveCampaignsCard({ data }: { data?: ActiveCampaignsData | null }) {
  const campaigns = data?.campaigns || [];
  if (campaigns.length === 0) return null;

  return (
    <Card className="border-red-600/30 bg-red-600/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          Actively exploited in the wild
          <Badge variant="outline" className="text-xs text-red-400 border-red-400/30">
            {campaigns.length} campaign{campaigns.length === 1 ? '' : 's'}
          </Badge>
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          A current campaign targets this {campaigns.some((c) => c.match.type === 'cve') ? 'vulnerability' : 'product'}.
          Patching may not be enough on its own; apply the interim mitigations and check whether the
          asset was already compromised.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {campaigns.map((c) => (
          <CampaignBlock key={c.id} campaign={c} />
        ))}
        <p className="text-[11px] text-muted-foreground/70">
          Source:{' '}
          <ExtLink href={safeHref(data?.source_url)}>{data?.source || 'Rapid Threat Intel'}</ExtLink>
          {data?.licence ? ` (${data.licence})` : ''}. Community-curated and AI-assisted; verify
          against the linked vendor and researcher reports.
          {data?.feed_last_updated ? ` Feed updated ${data.feed_last_updated}.` : ''}
        </p>
      </CardContent>
    </Card>
  );
}
