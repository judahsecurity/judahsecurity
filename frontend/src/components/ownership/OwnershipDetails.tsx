'use client';

import { ExternalLink } from 'lucide-react';
import type { OwnershipSummary } from '@/lib/api';

const SOURCE_LABEL: Record<string, string> = {
  manual: 'Linked by an analyst',
  entry_point: 'Matched a ServiceNow entry point',
  service_map: 'Matched a CI in the ServiceNow service map',
  relationship: 'Matched a CI related in the ServiceNow CMDB',
};

function Field({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className={`text-sm truncate ${mono ? 'font-mono' : ''}`} title={value || undefined}>
        {value || <span className="text-muted-foreground">—</span>}
      </p>
    </div>
  );
}

function Linked({ number, name, url }: { number?: string | null; name?: string | null; url?: string | null }) {
  if (!number && !name) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0">
      {number && <span className="font-mono text-xs shrink-0">{number}</span>}
      <span className="truncate">{name}</span>
      {url && (
        <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary shrink-0" aria-label="Open in ServiceNow">
          <ExternalLink className="h-3 w-3" />
        </a>
      )}
    </span>
  );
}

/** Business application / application service attribution with owner,
 *  support group and business unit. */
export function OwnershipDetails({ ownership, compact }: { ownership?: OwnershipSummary | null; compact?: boolean }) {
  if (!ownership) {
    return (
      <p className="text-sm text-muted-foreground">
        Not attributed to a business application or application service. Run the ServiceNow CMDB sync from
        Integrations, or link it by hand.
      </p>
    );
  }
  const o = ownership;
  return (
    <div className="space-y-3">
      <div className={`grid gap-3 ${compact ? 'grid-cols-2' : 'grid-cols-2 md:grid-cols-4'}`}>
        <div className="min-w-0 col-span-2">
          <p className="text-[11px] text-muted-foreground uppercase tracking-wider">Business application</p>
          <p className="text-sm">
            <Linked number={o.business_app_number} name={o.business_app_name} url={o.business_app_url} />
          </p>
        </div>
        <div className="min-w-0 col-span-2">
          <p className="text-[11px] text-muted-foreground uppercase tracking-wider">Application service</p>
          <p className="text-sm">
            <Linked number={o.app_service_number} name={o.app_service_name} url={o.app_service_url} />
          </p>
        </div>
        <Field label="Owner" value={o.owner} />
        <Field label="IT owner" value={o.it_owner} />
        <Field label="Support group" value={o.support_group} />
        <Field label="Business unit" value={o.business_unit || o.department} />
        {!compact && <Field label="Environment" value={o.environment} />}
        {!compact && <Field label="Criticality" value={o.business_criticality} />}
        {!compact && <Field label="Company" value={o.company} />}
      </div>
      {(o.link_source || o.link_detail) && (
        <p className="text-xs text-muted-foreground">
          {o.inherited_from_asset ? 'From the asset. ' : ''}
          {(o.link_source && SOURCE_LABEL[o.link_source]) || o.link_source}
          {o.link_detail && o.link_source !== 'manual' ? ` — ${o.link_detail}` : ''}
        </p>
      )}
    </div>
  );
}
