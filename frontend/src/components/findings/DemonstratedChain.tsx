'use client';

import { useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  ChevronDown,
  ChevronRight,
  ChevronsDownUp,
  ChevronsUpDown,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export interface DemonstratedChainStep {
  step: number;
  summary: string;
  outcome?: string;
  tool?: string;
  display_tool?: string;
  args?: string[];
  result?: Record<string, unknown> | {
    stdout?: string;
    stderr?: string;
    exit_code?: number | string | null;
  };
}

export interface AgentDetection {
  source?: string;
  session_id?: string;
  step_count?: number;
  chain?: DemonstratedChainStep[];
  context?: string;
  not_demonstrated?: string;
  references?: string[];
  assets?: string[];
}

interface DemonstratedChainProps {
  detection?: AgentDetection | null;
  className?: string;
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value ?? '');
  }
}

function toolAlias(step: DemonstratedChainStep): string {
  return (step.display_tool || step.tool || 'tool').replace(/^execute_/, '');
}

function isCliResult(result: DemonstratedChainStep['result']): boolean {
  if (!result || typeof result !== 'object') return false;
  const keys = Object.keys(result);
  return keys.includes('stdout') && keys.includes('exit_code') && !keys.includes('url') && !keys.includes('elements');
}

function StepCard({
  step,
  expanded,
  onToggle,
}: {
  step: DemonstratedChainStep;
  expanded: boolean;
  onToggle: () => void;
}) {
  const alias = toolAlias(step);
  const showArgs = Array.isArray(step.args) && step.args.length > 0 && isCliResult(step.result);
  const jsonBody = showArgs
    ? {
        stdout: (step.result as { stdout?: string })?.stdout || '',
        stderr: (step.result as { stderr?: string })?.stderr || '',
        exit_code: (step.result as { exit_code?: number })?.exit_code ?? 0,
      }
    : step.result || {};

  return (
    <div className="rounded-lg border border-border/80 bg-secondary/20 overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-3 py-3 text-left hover:bg-secondary/40 transition-colors"
      >
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-orange-500/15 text-xs font-semibold text-orange-400 border border-orange-500/30">
          {step.step}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium leading-snug">{step.summary}</p>
          {step.outcome && (
            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{step.outcome}</p>
          )}
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 mt-1 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 mt-1 shrink-0 text-muted-foreground" />
        )}
      </button>
      {expanded && (
        <div className="border-t border-border/60 px-3 py-3 space-y-3">
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">tool call</p>
            {showArgs ? (
              <pre className="text-xs font-mono whitespace-pre-wrap break-all rounded-md bg-black/40 border border-border/50 p-3 overflow-x-auto">
                {prettyJson({ args: step.args })}
              </pre>
            ) : (
              <p className="text-sm font-mono text-orange-300/90">{alias}</p>
            )}
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">json</p>
            <pre className="text-xs font-mono whitespace-pre-wrap break-all rounded-md bg-black/40 border border-border/50 p-3 overflow-x-auto max-h-96 overflow-y-auto">
              {prettyJson(jsonBody)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export function DemonstratedChain({ detection, className }: DemonstratedChainProps) {
  const steps = useMemo(
    () => (Array.isArray(detection?.chain) ? detection!.chain : []),
    [detection],
  );
  const [openSteps, setOpenSteps] = useState<Set<number>>(() => new Set());
  const allOpen = steps.length > 0 && openSteps.size === steps.length;

  if (!steps.length) {
    return null;
  }

  const toggleAll = () => {
    if (allOpen) {
      setOpenSteps(new Set());
    } else {
      setOpenSteps(new Set(steps.map((s) => s.step)));
    }
  };

  const toggleStep = (n: number) => {
    setOpenSteps((prev) => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });
  };

  return (
    <div className={cn('space-y-3', className)}>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-semibold">
          Detection Claims
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            {steps.length} step{steps.length === 1 ? '' : 's'}
          </span>
        </p>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 text-xs"
          onClick={toggleAll}
        >
          {allOpen ? (
            <>
              <ChevronsDownUp className="h-3.5 w-3.5 mr-1" />
              Collapse all
            </>
          ) : (
            <>
              <ChevronsUpDown className="h-3.5 w-3.5 mr-1" />
              Expand all
            </>
          )}
        </Button>
      </div>
      <div className="space-y-2">
        {steps.map((step) => (
          <StepCard
            key={step.step}
            step={step}
            expanded={openSteps.has(step.step)}
            onToggle={() => toggleStep(step.step)}
          />
        ))}
      </div>
    </div>
  );
}
