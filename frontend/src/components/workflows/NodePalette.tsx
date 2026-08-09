'use client';

import { useMemo, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import type { ToolDef, WorkflowScript, WorkflowSummary } from './types';

interface Props {
  tools: ToolDef[];
  scripts: WorkflowScript[];
  modules: WorkflowSummary[];
  onAddTool: (tool: ToolDef) => void;
  onAddScript: (script: WorkflowScript) => void;
  onAddModule: (mod: WorkflowSummary) => void;
  onAddPrimitive: () => void;
  onAddSink: () => void;
}

export function NodePalette({
  tools,
  scripts,
  modules,
  onAddTool,
  onAddScript,
  onAddModule,
  onAddPrimitive,
  onAddSink,
}: Props) {
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();

  const filteredTools = useMemo(
    () => tools.filter((t) => !query || t.name.toLowerCase().includes(query) || t.id.includes(query)),
    [tools, query]
  );
  const filteredScripts = useMemo(
    () => scripts.filter((s) => !query || s.name.toLowerCase().includes(query)),
    [scripts, query]
  );
  const filteredModules = useMemo(
    () => modules.filter((m) => !query || m.name.toLowerCase().includes(query)),
    [modules, query]
  );

  return (
    <div className="flex flex-col h-full border-r border-border bg-card/40">
      <div className="p-3 border-b border-border space-y-2">
        <div className="text-sm font-medium">Palette</div>
        <Input placeholder="Search tools…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onAddPrimitive}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted"
          >
            + Input
          </button>
          <button
            type="button"
            onClick={onAddSink}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted"
          >
            + Sink
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        <section>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-2">Tools</div>
          <div className="space-y-1.5">
            {filteredTools.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => onAddTool(t)}
                className="w-full text-left rounded-md border border-border/80 px-2.5 py-2 hover:border-primary/50 hover:bg-muted/40"
              >
                <div className="text-sm font-medium">{t.name}</div>
                <div className="text-[11px] text-muted-foreground line-clamp-2">{t.description}</div>
                <Badge variant="outline" className="mt-1 text-[10px]">
                  {t.category}
                </Badge>
              </button>
            ))}
          </div>
        </section>
        <section>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-2">Scripts</div>
          <div className="space-y-1.5">
            {filteredScripts.length === 0 && (
              <div className="text-xs text-muted-foreground">No scripts yet</div>
            )}
            {filteredScripts.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => onAddScript(s)}
                className="w-full text-left rounded-md border border-border/80 px-2.5 py-2 hover:border-violet-500/50 hover:bg-muted/40"
              >
                <div className="text-sm font-medium">{s.name}</div>
                <div className="text-[11px] text-muted-foreground">{s.language}</div>
              </button>
            ))}
          </div>
        </section>
        <section>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-2">Modules</div>
          <div className="space-y-1.5">
            {filteredModules.map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => onAddModule(m)}
                className="w-full text-left rounded-md border border-border/80 px-2.5 py-2 hover:border-sky-500/50 hover:bg-muted/40"
              >
                <div className="text-sm font-medium">{m.name}</div>
                <div className="text-[11px] text-muted-foreground line-clamp-2">{m.description}</div>
              </button>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
