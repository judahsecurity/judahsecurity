"use client";

import type { AgentRunLedger } from "./RunLedgerPanel";

export function ExplorationStatusPanel({ run }: { run: AgentRunLedger | null }) {
  if (!run?.run_id) return null;
  const exploration = run.exploration;
  if (!exploration) return null;

  return (
    <section aria-label="Browser exploration" className="rounded-lg border border-border bg-card px-4 py-3 space-y-2 text-xs">
      <div className="flex flex-wrap items-baseline gap-2">
        <h2 className="text-sm font-semibold">Browser exploration</h2>
        <span className="text-muted-foreground">
          {exploration.pages_observed} pages · {exploration.safe_interactions} safe interactions · {exploration.forms_observed} forms · {exploration.links_observed} links
        </span>
      </div>
      {exploration.pages_observed === 0 ? (
        <p className="text-amber-400">No browser page has been recorded for this run yet.</p>
      ) : (
        <div className="space-y-1">
          <p className="text-muted-foreground">Observed paths: {exploration.page_paths.slice(0, 8).join(" · ")}{exploration.page_paths.length > 8 ? " …" : ""}</p>
          {exploration.safe_interactions === 0 && (
            <p className="text-amber-400">No link or safe UI control interaction is recorded. The agent may have only loaded pages.</p>
          )}
          {exploration.recent_actions.length > 0 && (
            <details>
              <summary className="cursor-pointer text-primary">Show browser actions ({exploration.browser_actions})</summary>
              <ol className="mt-1 space-y-1">
                {exploration.recent_actions.map((action, index) => (
                  <li key={`${action.kind}-${action.path}-${index}`} className="font-mono text-muted-foreground">
                    {action.kind} {action.path} · {action.status} · {action.request_count} requests
                  </li>
                ))}
              </ol>
            </details>
          )}
        </div>
      )}
      <p className="text-muted-foreground">These are observed surfaces, not vulnerability findings. Form submission and state-changing actions require a separate approved test.</p>
    </section>
  );
}
