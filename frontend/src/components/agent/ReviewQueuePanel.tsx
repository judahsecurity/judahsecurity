"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";

export type AgentCandidate = {
  id: string;
  title: string;
  severity?: string;
  target?: string;
  status?: string;
  vulnerability_class?: string;
  specialist?: string;
  verifier_summary?: string;
  review_status?: string;
  challenge?: Record<string, string>;
  proof_gap?: { reason?: string; next_step?: string };
};

const CHALLENGE_LABELS: Record<string, string> = {
  reachability: "Reachability",
  preconditions: "Preconditions",
  downstream_controls: "Downstream controls",
  scope: "Scope",
  benign_explanation: "Benign explanation",
  strongest_objection: "Strongest objection",
  disproof_test: "Disproof test",
};

/**
 * Inconclusive candidates that carry hunter evidence and a completed
 * self-challenge. Verification could not prove them, so they need a person.
 */
export function ReviewQueuePanel({ sessionId, refreshKey }: { sessionId: string; refreshKey?: unknown }) {
  const [rows, setRows] = useState<AgentCandidate[]>([]);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.listAgentCandidates(sessionId)
      .then((data: { candidates?: AgentCandidate[] }) => {
        if (!active) return;
        setRows((data.candidates || []).filter((c) => c.review_status === "needs_analyst_review"));
      })
      .catch(() => { if (active) setRows([]); });
    return () => { active = false; };
  }, [sessionId, refreshKey]);

  if (!rows.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          Needs analyst review
          <Badge variant="outline" className="ml-auto">{rows.length}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <p className="text-muted-foreground">
          Independent verification could not prove these, but the hunter left evidence and
          argued against its own claim. They are not findings until someone confirms them.
        </p>
        {rows.map((row) => (
          <div key={row.id} className="rounded border border-border p-2">
            <button
              type="button"
              className="flex w-full items-start gap-2 text-left"
              onClick={() => setOpen(open === row.id ? null : row.id)}
              aria-expanded={open === row.id}
            >
              <span className="font-medium">{row.title}</span>
              {row.severity && (
                <Badge variant="outline" className="ml-auto shrink-0 capitalize">{row.severity}</Badge>
              )}
            </button>
            {row.target && <p className="mt-1 break-all text-muted-foreground">{row.target}</p>}
            {row.proof_gap?.reason && (
              <p className="mt-1"><span className="text-muted-foreground">Proof gap: </span>{row.proof_gap.reason}</p>
            )}
            {row.proof_gap?.next_step && (
              <p className="mt-1"><span className="text-muted-foreground">Next step: </span>{row.proof_gap.next_step}</p>
            )}
            {open === row.id && row.challenge && (
              <dl className="mt-2 space-y-1 border-t border-border pt-2">
                {Object.entries(CHALLENGE_LABELS).map(([key, label]) =>
                  row.challenge?.[key] ? (
                    <div key={key}>
                      <dt className="text-muted-foreground">{label}</dt>
                      <dd className="break-words">{row.challenge[key]}</dd>
                    </div>
                  ) : null,
                )}
              </dl>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
