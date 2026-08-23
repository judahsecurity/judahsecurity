'use client';

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import {
  ChevronDown,
  ChevronRight,
  Download,
  GitFork,
  Home,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn, formatDate } from '@/lib/utils';
import { AttackPathCanvas, exportAttackPathPng } from '@/components/attacks/AttackPathCanvas';
import { AttackPathNarrative } from '@/components/attacks/AttackPathNarrative';
import type { AttackPath, AttackWorkspace } from '@/components/attacks/types';

type Org = { id: number; name: string };

export default function AttacksPage() {
  return (
    <Suspense
      fallback={
        <MainLayout>
          <div className="flex h-[100vh] items-center justify-center text-muted-foreground">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        </MainLayout>
      }
    >
      <AttacksPageInner />
    </Suspense>
  );
}

function AttacksPageInner() {
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgId] = useState<string>('');
  const [workspace, setWorkspace] = useState<AttackWorkspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [pathId, setPathId] = useState<string>('');
  const [view, setView] = useState<'graph' | 'narrative'>('graph');
  const [tab, setTab] = useState('paths');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getOrganizations({ limit: 100 });
        const items: Org[] = Array.isArray(data) ? data : data?.items || [];
        if (cancelled) return;
        setOrgs(items);
        const fromQuery = searchParams.get('organization_id');
        if (fromQuery && items.some((o) => String(o.id) === fromQuery)) {
          setOrgId(fromQuery);
        } else if (items.length) {
          setOrgId(String(items[0].id));
        } else {
          setLoading(false);
        }
      } catch (err) {
        toast({ title: 'Could not load organizations', description: getApiErrorMessage(err), variant: 'destructive' });
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [searchParams, toast]);

  const loadWorkspace = useCallback(async (id: string) => {
    if (!id) return;
    setLoading(true);
    try {
      const data = await api.getAttackWorkspace(parseInt(id, 10));
      setWorkspace(data);
      setPathId((current) => {
        if (current && data.paths?.some((p: AttackPath) => p.id === current)) return current;
        return data.paths?.[0]?.id || '';
      });
    } catch (err) {
      toast({ title: 'Could not load attacks', description: getApiErrorMessage(err), variant: 'destructive' });
      setWorkspace(null);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    if (orgId) loadWorkspace(orgId);
  }, [orgId, loadWorkspace]);

  const orgName = workspace?.organization?.name || orgs.find((o) => String(o.id) === orgId)?.name || 'Organization';
  const path = useMemo(
    () => workspace?.paths.find((p) => p.id === pathId) || workspace?.paths[0] || null,
    [workspace, pathId]
  );

  const handleExport = async () => {
    if (!path) return;
    setExporting(true);
    try {
      const slug = path.title.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 60);
      await exportAttackPathPng(`${slug || 'attack-path'}.png`);
    } catch (err) {
      toast({ title: 'Export failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  return (
    <MainLayout>
      <div className="flex h-[100vh] min-h-0 flex-col overflow-hidden">
        <div className="flex items-center justify-between gap-4 border-b border-border bg-card/40 px-6 py-3">
          <div className="min-w-0">
            <div className="mb-1 flex items-center gap-1.5 text-xs text-muted-foreground">
              <Home className="h-3.5 w-3.5" />
              <ChevronRight className="h-3 w-3 opacity-50" />
              <span className="truncate">{orgName}</span>
              <ChevronRight className="h-3 w-3 opacity-50" />
              <span className="text-foreground">Attacks</span>
            </div>
            <h1 className="page-title text-2xl font-bold tracking-tight">Attacks</h1>
          </div>
          <div className="flex items-center gap-2">
            {orgs.length > 1 && (
              <Select value={orgId} onValueChange={setOrgId}>
                <SelectTrigger className="h-9 w-[220px]">
                  <SelectValue placeholder="Organization" />
                </SelectTrigger>
                <SelectContent>
                  {orgs.map((org) => (
                    <SelectItem key={org.id} value={String(org.id)}>
                      {org.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Button variant="outline" size="sm" onClick={() => loadWorkspace(orgId)} disabled={loading || !orgId}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </div>
        </div>

        <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col">
          <div className="border-b border-border px-6">
            <TabsList className="h-11 w-full justify-start gap-1 rounded-none bg-transparent p-0">
              {[
                ['paths', 'Attack Paths'],
                ['capabilities', 'Capabilities'],
                ['signatures', 'Signatures'],
                ['red-team', 'Red Team'],
                ['phishing', 'Phishing'],
                ['juicy', 'Juicy Fruit'],
              ].map(([value, label]) => (
                <TabsTrigger
                  key={value}
                  value={value}
                  className="rounded-none border-b-2 border-transparent px-3 pb-3 pt-2 data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                >
                  {label}
                </TabsTrigger>
              ))}
            </TabsList>
          </div>

          <TabsContent value="paths" className="mt-0 flex min-h-0 flex-1 flex-col overflow-hidden px-6 py-4">
            {loading && !workspace ? (
              <div className="flex flex-1 items-center justify-center text-muted-foreground">
                <Loader2 className="h-6 w-6 animate-spin" />
              </div>
            ) : !path ? (
              <EmptyState
                title="No attack paths yet"
                body="Demonstrated-compromise findings from the agent will compose into named campaigns here — attacker, MITRE technique, host, and vulnerability."
              />
            ) : (
              <>
                <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    {workspace && workspace.paths.length > 1 && (
                      <Select value={path.id} onValueChange={setPathId}>
                        <SelectTrigger className="mb-2 h-8 w-full max-w-xl text-left">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {workspace.paths.map((p) => (
                            <SelectItem key={p.id} value={p.id}>
                              {p.title}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                    <h2 className="text-lg font-semibold leading-snug">{path.title}</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" disabled={exporting || view !== 'graph'}>
                          {exporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Download className="mr-2 h-4 w-4" />}
                          Export PNG
                          <ChevronDown className="ml-1 h-3.5 w-3.5 opacity-60" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={handleExport}>Download PNG</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    <div className="flex overflow-hidden rounded-md border border-border">
                      {(['graph', 'narrative'] as const).map((mode) => (
                        <Button
                          key={mode}
                          variant={view === mode ? 'secondary' : 'ghost'}
                          size="sm"
                          className="rounded-none"
                          onClick={() => setView(mode)}
                        >
                          {mode === 'graph' ? 'Graph View' : 'Narrative View'}
                        </Button>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mb-3 rounded-md border border-border/70 bg-muted/30 px-4 py-3">
                  <p className="text-sm leading-relaxed text-muted-foreground">{path.summary}</p>
                  <div className="mt-3 flex flex-wrap gap-x-8 gap-y-1 text-xs text-muted-foreground">
                    <span>
                      <span className="mr-2 font-semibold uppercase tracking-wide text-slate-400">Target</span>
                      <span className="font-mono text-foreground">{path.target || '—'}</span>
                    </span>
                    <span>
                      <span className="mr-2 font-semibold uppercase tracking-wide text-slate-400">Timeframe</span>
                      <span className="text-foreground">{path.timeframe ? formatDate(path.timeframe) : '—'}</span>
                    </span>
                    {path.demonstrated ? (
                      <Badge variant="outline" className="border-red-500/40 text-red-300">Demonstrated</Badge>
                    ) : (
                      <Badge variant="outline">Inferred</Badge>
                    )}
                  </div>
                </div>

                <div className="relative min-h-0 flex-1">
                  {view === 'graph' ? (
                    <AttackPathCanvas path={path} />
                  ) : (
                    <AttackPathNarrative steps={path.narrative} notDemonstrated={path.not_demonstrated} />
                  )}
                </div>
              </>
            )}
          </TabsContent>

          <TabsContent value="capabilities" className="mt-0 flex-1 overflow-y-auto px-6 py-4">
            {!workspace?.capabilities?.length ? (
              <EmptyState title="No capability maps" body="Run an agent assessment with deep crawl / interceptor recon and capability maps will land here." />
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {workspace.capabilities.map((cap) => (
                  <div key={cap.session_id} className="rounded-lg border border-border/70 bg-card/40 p-4">
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <p className="truncate font-mono text-sm">{cap.target}</p>
                      <Badge variant={cap.ready_for_attack ? 'default' : 'outline'}>
                        {cap.ready_for_attack ? 'ready' : 'thin'}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {cap.capabilities.map((c) => (
                        <Badge key={c} variant="secondary" className="text-[10px]">{c}</Badge>
                      ))}
                    </div>
                    {cap.ranked_hunt_queue?.length ? (
                      <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
                        {cap.ranked_hunt_queue.slice(0, 5).map((h, i) => (
                          <li key={`${cap.session_id}-${i}`}>{h.hunt}{h.why ? ` — ${h.why}` : ''}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="signatures" className="mt-0 flex-1 overflow-y-auto px-6 py-4">
            {!workspace?.signatures?.length ? (
              <EmptyState title="No detection signatures" body="Nuclei template IDs from findings will show here." />
            ) : (
              <div className="space-y-2">
                {workspace.signatures.map((sig) => (
                  <div key={sig.template_id} className="flex items-center justify-between rounded-md border border-border/60 bg-card/30 px-3 py-2">
                    <div>
                      <p className="font-mono text-sm">{sig.template_id}</p>
                      <p className="text-[11px] text-muted-foreground">{sig.hosts.slice(0, 4).join(', ')}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{sig.severity}</Badge>
                      <span className="text-xs text-muted-foreground">{sig.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="red-team" className="mt-0 flex-1 overflow-y-auto px-6 py-4">
            {!workspace?.red_team?.length ? (
              <EmptyState title="No red-team sessions" body="Autonomous pentest sessions for this organization will appear here." />
            ) : (
              <div className="space-y-2">
                {workspace.red_team.map((s) => (
                  <Link
                    key={s.id}
                    href="/pentest"
                    className="flex items-center justify-between rounded-md border border-border/60 bg-card/30 px-3 py-3 hover:bg-muted/40"
                  >
                    <div>
                      <p className="text-sm font-medium">{s.name}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">{s.target_url}</p>
                    </div>
                    <div className="text-right text-xs text-muted-foreground">
                      <p className="capitalize">{s.phase.replace(/_/g, ' ')}</p>
                      <p>{s.total_exploits_confirmed} confirmed / {s.total_exploits_attempted} attempted</p>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="phishing" className="mt-0 flex-1 overflow-y-auto px-6 py-4">
            {!workspace?.phishing?.length ? (
              <EmptyState title="No phishing paths" body="Findings classified as phishing delivery will appear here." />
            ) : (
              <FindingList rows={workspace.phishing} />
            )}
          </TabsContent>

          <TabsContent value="juicy" className="mt-0 flex-1 overflow-y-auto px-6 py-4">
            {!workspace?.juicy_fruit?.length ? (
              <EmptyState title="No juicy fruit" body="Critical and high demonstrated findings land in this tray." />
            ) : (
              <FindingList rows={workspace.juicy_fruit} />
            )}
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6 py-16 text-center text-muted-foreground">
      <GitFork className="mb-2 h-8 w-8 opacity-40" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      <p className="max-w-md text-xs leading-relaxed">{body}</p>
    </div>
  );
}

function FindingList({
  rows,
}: {
  rows: { finding_id: number; title: string; host: string; severity: string; status?: string; demonstrated?: boolean }[];
}) {
  return (
    <div className="space-y-2">
      {rows.map((row) => (
        <Link
          key={row.finding_id}
          href="/findings"
          className={cn(
            'flex items-center justify-between rounded-md border border-border/60 bg-card/30 px-3 py-2 hover:bg-muted/40'
          )}
        >
          <div className="min-w-0">
            <p className="truncate text-sm">{row.title}</p>
            <p className="font-mono text-[11px] text-muted-foreground">{row.host}</p>
          </div>
          <div className="ml-3 flex items-center gap-2">
            {row.demonstrated ? <Badge variant="outline" className="border-red-500/40 text-red-300">shown</Badge> : null}
            <Badge variant="outline">{row.severity}</Badge>
          </div>
        </Link>
      ))}
    </div>
  );
}
