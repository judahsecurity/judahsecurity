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
    <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
      {text}
    </p>
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
        </WriteupSection>
      )}

      {impact && (
        <WriteupSection title="Impact">
          <Prose text={impact} />
        </WriteupSection>
      )}

      {(assetList.length > 0 || affectedComponent) && (
        <WriteupSection title="Assets Affected">
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
