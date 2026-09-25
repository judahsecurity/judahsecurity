'use client';

import type { ReactNode } from 'react';
import { ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FindingWriteupProps {
  description?: string | null;
  impact?: string | null;
  assets?: string[] | null;
  host?: string | null;
  affectedComponent?: string | null;
  recommendation?: string | null;
  references?: string[] | null;
  notDemonstrated?: string | null;
  className?: string;
}

function WriteupSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-semibold">{title}</p>
      {children}
    </div>
  );
}

function Prose({ text }: { text: string }) {
  return (
    <div className="space-y-2 text-sm leading-relaxed text-muted-foreground">
      {text.split(/\r?\n/).map((line, index) => {
        const value = line.trim();
        if (!value) return null;
        const heading = value.match(/^(?:#{1,4}\s+|\*\*)([^*]+?)(?:\*\*)?(?::)?$/);
        if (heading) {
          return <h4 key={index} className="pt-2 font-semibold text-foreground">{heading[1]}</h4>;
        }
        const listItem = value.match(/^([-*]|\d+\.)\s+(.+)$/);
        if (listItem) {
          return (
            <div key={index} className="flex gap-2 pl-2">
              <span className="shrink-0 text-foreground">{listItem[1]}</span>
              <span className="min-w-0 break-words">{listItem[2].replace(/\*\*/g, '')}</span>
            </div>
          );
        }
        return <p key={index} className="break-words">{value.replace(/\*\*/g, '')}</p>;
      })}
    </div>
  );
}

function assetHref(value: string): string {
  if (/^https?:\/\//i.test(value)) return value;
  return `https://${value.replace(/^\/+/, '')}`;
}

export function FindingWriteup({
  description,
  impact,
  assets,
  host,
  affectedComponent,
  recommendation,
  references,
  notDemonstrated,
  className,
}: FindingWriteupProps) {
  const assetList = [
    ...(assets || []),
    ...(host && !(assets || []).some((a) => a.includes(host)) ? [host] : []),
  ].filter((url, i, arr) => url && arr.indexOf(url) === i);

  const refs = (references || []).filter((url, i, arr) => url && arr.indexOf(url) === i);
  const mentionedIps = Array.from(new Set<string>((description || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))
    .filter((address) => address.split('.').every((octet: string) => Number(octet) <= 255));

  if (
    !description &&
    !impact &&
    !assetList.length &&
    !recommendation &&
    !refs.length &&
    !notDemonstrated &&
    !affectedComponent
  ) {
    return null;
  }

  return (
    <div className={cn('space-y-5', className)}>
      {description && (
        <WriteupSection title="Vulnerability Description">
          <Prose text={description} />
          {mentionedIps.length > 0 && (
            <details className="rounded-md border border-border bg-muted/20 p-3">
              <summary className="cursor-pointer text-xs font-medium text-foreground">
                {mentionedIps.length} IP address{mentionedIps.length === 1 ? '' : 'es'} mentioned in this description
              </summary>
              <p className="mt-2 text-xs text-muted-foreground">
                These are text mentions. The linked asset is shown separately above.
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {mentionedIps.map((address) => (
                  <code key={address} className="rounded bg-secondary px-2 py-1 text-xs">{address}</code>
                ))}
              </div>
            </details>
          )}
        </WriteupSection>
      )}

      {impact && (
        <WriteupSection title="Impact">
          <Prose text={impact} />
        </WriteupSection>
      )}

      {(assetList.length > 0 || affectedComponent) && (
        <WriteupSection title="Linked or agent-reported assets">
          <ul className="space-y-1">
            {assetList.map((asset) => (
              <li key={asset}>
                <a
                  href={assetHref(asset)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-primary hover:underline inline-flex items-center gap-1 break-all"
                >
                  {asset}
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              </li>
            ))}
          </ul>
          {affectedComponent && (
            <p className="text-sm text-muted-foreground">{affectedComponent}</p>
          )}
        </WriteupSection>
      )}

      {recommendation && (
        <WriteupSection title="Recommendation">
          <Prose text={recommendation} />
        </WriteupSection>
      )}

      {refs.length > 0 && (
        <WriteupSection title="References">
          <ul className="space-y-1">
            {refs.map((url) => (
              <li key={url}>
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-primary hover:underline inline-flex items-center gap-1 break-all"
                >
                  {url}
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              </li>
            ))}
          </ul>
        </WriteupSection>
      )}

      {notDemonstrated && (
        <WriteupSection title="Not demonstrated">
          <Prose text={notDemonstrated} />
        </WriteupSection>
      )}
    </div>
  );
}
