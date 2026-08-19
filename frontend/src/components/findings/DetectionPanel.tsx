'use client';

// Praetorian-style scanner Detection panel for Nuclei findings.

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export interface ScannerDetection {
  request?: string;
  curl_command?: string;
  response?: string;
  match?: string;
  match_criteria?: string;
  template_id?: string;
  template_yaml?: string;
  matcher_name?: string;
}

interface DetectionPanelProps {
  detection?: ScannerDetection | null;
  className?: string;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="h-7 px-2 text-xs"
      onClick={onCopy}
      aria-label={`Copy ${label}`}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-green-400" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </Button>
  );
}

function DumpBlock({
  title,
  text,
  copyable = true,
  collapsed = false,
}: {
  title: string;
  text: string;
  copyable?: boolean;
  collapsed?: boolean;
}) {
  const [open, setOpen] = useState(!collapsed);
  const large = collapsed || text.length > 4000;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-semibold">{title}</p>
        <div className="flex items-center gap-1">
          {large && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={() => setOpen((v) => !v)}
            >
              {open ? 'Collapse' : 'Expand'}
            </Button>
          )}
          {copyable && <CopyButton text={text} label={title} />}
        </div>
      </div>
      {open && (
        <pre className="text-xs font-mono whitespace-pre-wrap break-all rounded-md bg-black/40 border border-border/50 p-3 overflow-x-auto max-h-[32rem] overflow-y-auto">
          {text}
        </pre>
      )}
    </div>
  );
}

export function hasScannerDetection(detection?: ScannerDetection | null): boolean {
  if (!detection) return false;
  return Boolean(
    detection.request ||
      detection.curl_command ||
      detection.response ||
      detection.match ||
      detection.match_criteria ||
      detection.template_yaml,
  );
}

export function DetectionPanel({ detection, className }: DetectionPanelProps) {
  if (!hasScannerDetection(detection)) {
    return null;
  }

  const d = detection!;

  return (
    <div className={cn('space-y-5', className)}>
      <div className="space-y-1">
        <p className="text-sm font-semibold">Detection</p>
        <p className="text-xs text-muted-foreground">
          How this vulnerability was detected and matched
        </p>
      </div>

      {d.request && <DumpBlock title="Request" text={d.request} />}
      {d.curl_command && <DumpBlock title="cURL Command" text={d.curl_command} />}
      {d.response && <DumpBlock title="Response" text={d.response} />}
      {d.match && (
        <div className="space-y-2">
          <p className="text-sm font-semibold">Match</p>
          <p className="text-sm font-mono break-all text-muted-foreground">{d.match}</p>
        </div>
      )}
      {d.match_criteria && (
        <div className="space-y-2">
          <p className="text-sm font-semibold">Match Criteria</p>
          <pre className="text-xs font-mono whitespace-pre-wrap break-all rounded-md bg-black/40 border border-border/50 p-3 overflow-x-auto">
            {d.match_criteria}
          </pre>
        </div>
      )}
      {d.template_yaml && (
        <DumpBlock title="Template" text={d.template_yaml} collapsed />
      )}
    </div>
  );
}
