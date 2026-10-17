"use client";

import { Badge } from "@/components/ui/badge";
import type { AgentRunLedger } from "./RunLedgerPanel";

export function AssessmentStatusStrip({ run }: { run: AgentRunLedger | null }) {
  if (!run?.run_id) return null;

  const funnel = run.input_testing;
  const active = [...run.actions].reverse().find((action) => action.status === "running");
  const last = run.actions.at(-1);
  const current = active || last;
  const unverifiedInputLeads = Math.max(0, (funnel?.candidates || 0) - (funnel?.verified || 0));
  const duration = Math.round((run.coverage?.duration_seconds || 0) / 60);

  return (
    <section aria-label="Assessment status" className="rounded-lg border border-border bg-card px-4 py-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">Assessment status</h2>
        <Badge variant="outline" className="capitalize">{run.status.replaceAll("_", " ")}</Badge>
        <span className="text-xs text-muted-foreground">{duration} min elapsed</span>
        <a href="#agent-work-performed" className="ml-auto text-xs text-primary hover:underline">
          View work record
        </a>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Metric label="Published findings" value={run.coverage?.published_findings || 0} />
        <Metric label="Input leads" value={funnel?.candidates || 0} />
        <Metric label="Verified input leads" value={funnel?.verified || 0} />
        <Metric label="Open class checks" value={funnel?.open || 0} />
      </div>

      {current && (
        <p className="text-xs text-muted-foreground truncate" title={`${current.tool_name} · ${current.status}`}>
          {active ? "Running" : "Last recorded"}: <span className="font-mono text-foreground">{current.tool_name}</span>
          {active ? "" : ` · ${current.status}`}
        </p>
      )}
      {unverifiedInputLeads > 0 && (
        <p className="text-xs text-amber-400">
          {unverifiedInputLeads} input lead{unverifiedInputLeads === 1 ? "" : "s"} still need independent proof.
          A claim in the chat report is not a published finding.
        </p>
      )}
      {run.reason && !["running", "stalled"].includes(run.status) && (
        <p className="text-xs text-muted-foreground">Stopped: {run.reason}</p>
      )}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border/70 bg-muted/20 px-3 py-2">
      <p className="text-lg font-semibold tabular-nums leading-tight">{value}</p>
      <p className="text-[11px] text-muted-foreground">{label}</p>
    </div>
  );
}
