"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Brain, CheckCircle, DollarSign, Wrench, XCircle } from "lucide-react";

export type ReplayStep = {
  iteration?: number | null;
  phase?: string;
  agent?: string;
  thought?: string;
  tool_name?: string | null;
  success?: boolean | null;
  evidence?: string[];
  finding_title?: string | null;
  output_preview?: string;
};

export type TokenUsage = {
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  cost_usd?: number;
};

export function EngagementReplay({
  steps,
  tokenUsage,
  costUsd,
  title = "Engagement replay",
}: {
  steps?: ReplayStep[] | null;
  tokenUsage?: TokenUsage | null;
  costUsd?: number | null;
  title?: string;
}) {
  const list = steps || [];
  const cost = costUsd ?? tokenUsage?.cost_usd;
  if (list.length === 0 && cost == null) return null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Brain className="h-4 w-4" />
          {title}
          {cost != null && (
            <Badge variant="outline" className="ml-auto text-xs font-normal gap-1">
              <DollarSign className="h-3 w-3" />
              ${Number(cost).toFixed(4)}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {tokenUsage && (tokenUsage.input_tokens || tokenUsage.output_tokens) ? (
          <p className="text-xs text-muted-foreground">
            {(tokenUsage.input_tokens || 0).toLocaleString()} in /{" "}
            {(tokenUsage.output_tokens || 0).toLocaleString()} out tokens
          </p>
        ) : null}
        <div className="max-h-72 overflow-y-auto space-y-2">
          {list.map((step, i) => (
            <div key={i} className="rounded-md border border-border/60 px-2.5 py-2 text-xs space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">
                  #{step.iteration ?? i + 1}
                  {step.agent || step.phase ? ` · ${step.agent || step.phase}` : ""}
                </span>
                {step.tool_name && (
                  <span className="flex items-center gap-1 font-mono text-yellow-400">
                    <Wrench className="h-3 w-3" />
                    {step.tool_name}
                  </span>
                )}
                {step.success === true && <CheckCircle className="h-3 w-3 text-green-500 ml-auto" />}
                {step.success === false && <XCircle className="h-3 w-3 text-red-500 ml-auto" />}
              </div>
              {step.thought && <p className="text-foreground/90">{step.thought}</p>}
              {(step.evidence || []).length > 0 && (
                <ul className="list-disc pl-4 text-muted-foreground space-y-0.5">
                  {step.evidence!.map((e, j) => (
                    <li key={j}>{e}</li>
                  ))}
                </ul>
              )}
              {step.finding_title && (
                <p className="text-red-400">Finding: {step.finding_title}</p>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
