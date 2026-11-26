"use client";

import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import type { AgentCandidate } from "@/components/agent/ReviewQueuePanel";

type Verdict = "confirmed" | "refuted" | "inconclusive" | "pending";

const VERDICTS: { key: Verdict; label: string; meaning: string; className: string }[] = [
  {
    key: "confirmed",
    label: "True positive",
    meaning: "The independent verifier reproduced it with fresh requests.",
    className: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
  },
  {
    key: "refuted",
    label: "False positive",
    meaning: "The verifier's controls showed the signal was not a vulnerability.",
    className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  },
  {
    key: "inconclusive",
    label: "Inconclusive",
    meaning: "Verification could not prove or disprove it.",
    className: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  },
  {
    key: "pending",
    label: "Not yet verified",
    meaning: "Waiting for the verifier; a lead, not a finding.",
    className: "border-border bg-muted text-muted-foreground",
  },
];

const SOURCE_LABELS: Record<string, string> = {
  budget_settlement: "Saved at budget end",
  vanguard_external: "External lead",
};

function verdictOf(row: AgentCandidate): Verdict {
  const status = String(row.status || "pending").toLowerCase();
  return (["confirmed", "refuted", "inconclusive"].includes(status) ? status : "pending") as Verdict;
}

/**
 * Every candidate this session produced, grouped by the independent
 * verifier's verdict, so true and false positives are visible side by side.
 */
export function FindingValidationPanel({ sessionId, refreshKey }: { sessionId: string; refreshKey?: unknown }) {
  const [rows, setRows] = useState<AgentCandidate[]>([]);
  const [filter, setFilter] = useState<Verdict | "all">("all");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.listAgentCandidates(sessionId)
      .then((data: { candidates?: AgentCandidate[] }) => { if (active) setRows(data.candidates || []); })
      .catch(() => { if (active) setRows([]); });
    return () => { active = false; };
  }, [sessionId, refreshKey]);

  const counts = useMemo(() => {
    const out: Record<Verdict, number> = { confirmed: 0, refuted: 0, inconclusive: 0, pending: 0 };
    rows.forEach((row) => { out[verdictOf(row)] += 1; });
    return out;
  }, [rows]);

  if (!rows.length) return null;
  const shown = filter === "all" ? rows : rows.filter((row) => verdictOf(row) === filter);
  const decided = counts.confirmed + counts.refuted;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          Findings and validation
          <Badge variant="outline" className="ml-auto">{rows.length}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by verdict">
          <button
            type="button"
            onClick={() => setFilter("all")}
            aria-pressed={filter === "all"}
            className={`rounded border px-2 py-1 ${filter === "all" ? "border-foreground" : "border-border"}`}
          >
            All {rows.length}
          </button>
          {VERDICTS.map((v) => (
            <button
              key={v.key}
              type="button"
              onClick={() => setFilter(v.key)}
              aria-pressed={filter === v.key}
              title={v.meaning}
              className={`rounded border px-2 py-1 ${v.className} ${filter === v.key ? "ring-1 ring-foreground" : ""}`}
            >
              {v.label} {counts[v.key]}
            </button>
          ))}
        </div>
        {decided > 0 && (
          <p className="text-muted-foreground">
            Of {decided} candidates the verifier decided, {counts.confirmed} were true positives and{" "}
            {counts.refuted} were false positives it caught before publication.
          </p>
        )}
        {shown.map((row) => {
          const verdict = VERDICTS.find((v) => v.key === verdictOf(row))!;
          const source = row.specialist ? SOURCE_LABELS[row.specialist] : undefined;
          return (
            <div key={row.id} className="rounded border border-border p-2">
              <button
                type="button"
                className="flex w-full items-start gap-2 text-left"
                onClick={() => setOpen(open === row.id ? null : row.id)}
                aria-expanded={open === row.id}
              >
                <span className={`shrink-0 rounded border px-1.5 py-0.5 ${verdict.className}`}>{verdict.label}</span>
                <span className="font-medium">{row.title}</span>
                {row.severity && (
                  <Badge variant="outline" className="ml-auto shrink-0 capitalize">{row.severity}</Badge>
                )}
              </button>
              <p className="mt-1 text-muted-foreground">
                {[row.vulnerability_class, source].filter(Boolean).join(" · ")}
              </p>
              {row.target && <p className="mt-1 break-all text-muted-foreground">{row.target}</p>}
              {open === row.id && (
                <div className="mt-2 space-y-1 border-t border-border pt-2">
                  <p className="text-muted-foreground">{verdict.meaning}</p>
                  {row.verifier_summary ? (
                    <p className="whitespace-pre-wrap break-words">
                      <span className="text-muted-foreground">Verifier: </span>{row.verifier_summary}
                    </p>
                  ) : (
                    <p className="text-muted-foreground">No verifier result yet.</p>
                  )}
                  {row.proof_gap?.reason && (
                    <p><span className="text-muted-foreground">Proof gap: </span>{row.proof_gap.reason}</p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
