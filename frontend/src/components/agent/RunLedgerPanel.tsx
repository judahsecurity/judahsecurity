"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ScenarioSurface } from "./TrustBoundaryMap";

export type AgentRunLedger = {
  run_id: string | null;
  status: string;
  reason?: string;
  started_at?: string;
  coverage: {
    actions: number;
    by_status: Record<string, number>;
    duration_seconds?: number;
    repeated_tool_target_actions?: number;
    model_calls?: number;
    test_actions?: number;
    completed_by_stage?: Record<string, number>;
    hypotheses_by_state?: Record<string, number>;
    untested_stages?: string[];
    published_findings: number;
  };
  actions: Array<{
    id: string;
    tool_name: string;
    target: string;
    status: string;
    detail?: string;
    started_at: string;
    ended_at?: string;
    evidence_ids?: string[];
  }>;
  hypotheses?: Array<{
    id: string;
    title: string;
    specialist: string;
    state: string;
    attempts: number;
    blocked_reason?: string;
    evidence_ids?: string[];
  }>;
  scenario_surface?: ScenarioSurface;
};

export function RunLedgerPanel({ run }: { run: AgentRunLedger | null }) {
  if (!run?.run_id) return null;
  const counts = run.coverage?.by_status || {};
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          Work performed
          <Badge variant="outline" className="ml-auto capitalize">{run.status}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs">
        <p className="text-muted-foreground">
          {run.coverage?.actions || 0} actions · {counts.completed || 0} completed · {counts.failed || 0} failed · {counts.interrupted || 0} interrupted · {counts.skipped || 0} skipped · {run.coverage?.published_findings || 0} published findings
        </p>
        <p className="text-muted-foreground">
          {Math.round((run.coverage?.duration_seconds || 0) / 60)} min elapsed · {run.coverage?.model_calls || 0} model calls · {run.coverage?.repeated_tool_target_actions || 0} repeated tool/target actions
        </p>
        {run.coverage?.completed_by_stage && (
          <p className="text-muted-foreground">
            Completed by stage: {Object.entries(run.coverage.completed_by_stage)
              .map(([stage, count]) => `${stage.replaceAll("_", " ")} ${count}`).join(" · ")}
          </p>
        )}
        {run.hypotheses?.length ? (
          <div className="space-y-1">
            <p className="font-medium text-foreground">Hypothesis coverage</p>
            <p className="text-muted-foreground">
              {Object.entries(run.coverage?.hypotheses_by_state || {})
                .map(([state, count]) => `${state.replaceAll("_", " ")} ${count}`).join(" · ")}
            </p>
            <div className="max-h-44 overflow-y-auto space-y-1">
              {run.hypotheses.map((hypothesis) => (
                <div key={hypothesis.id} className="rounded-md border border-border/60 px-2.5 py-1.5">
                  <span className="text-foreground">{hypothesis.title || hypothesis.id}</span>
                  <span className="text-muted-foreground"> · {hypothesis.state.replaceAll("_", " ")}</span>
                  {hypothesis.blocked_reason && <p className="text-muted-foreground">{hypothesis.blocked_reason}</p>}
                  {hypothesis.evidence_ids?.length ? (
                    <p className="text-muted-foreground">Evidence IDs: {hypothesis.evidence_ids.join(", ")}</p>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {!(["running", "stalled"].includes(run.status)) && Boolean(run.coverage?.untested_stages?.length) && (
          <p className="text-amber-400">
            No completed actions recorded for: {run.coverage.untested_stages!.map((stage) => stage.replaceAll("_", " ")).join(", ")}.
          </p>
        )}
        {run.reason && <p className="text-muted-foreground">Run ended: {run.reason}</p>}
        {!run.coverage?.test_actions && (
          <p className="text-amber-400">No test action was recorded. The run may have stopped during planning.</p>
        )}
        <div className="max-h-80 overflow-y-auto space-y-1">
          {run.actions.map((action) => (
            <div key={action.id} className="rounded-md border border-border/60 px-2.5 py-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-foreground">{action.tool_name}</span>
                <Badge variant="outline" className="ml-auto capitalize">{action.status}</Badge>
              </div>
              {action.target && <p className="text-muted-foreground">{action.target}</p>}
              {action.detail && <p className="text-muted-foreground">{action.detail}</p>}
              {action.evidence_ids?.length ? (
                <p className="text-muted-foreground">Evidence IDs: {action.evidence_ids.join(", ")}</p>
              ) : null}
            </div>
          ))}
        </div>
        <p className="text-muted-foreground">Completed actions show execution coverage. Evidence IDs may expire with the session. This record does not establish that the target is free of vulnerabilities.</p>
      </CardContent>
    </Card>
  );
}
