'use client';

import { useMemo, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Check, ChevronDown, ChevronRight, Download, ExternalLink, FileJson, Filter, Search } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

export type SitemapNode = {
  kind: string;
  path: string;
  url: string;
  host?: string | null;
  method?: string | null;
  has_secrets?: boolean;
  has_login?: boolean;
  has_sso?: boolean;
  screenshot_count?: number;
  screenshot_id?: number | null;
  http_status?: number | null;
  response_title?: string | null;
  source?: string | null;
  sources?: string[];
  parameters?: string[];
  param_count?: number;
  access?: string | null;
};

type FilterKey = 'secrets' | 'login' | 'sso' | 'screenshots' | 'response';

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: 'secrets', label: 'Secrets' },
  { key: 'login', label: 'Login' },
  { key: 'sso', label: 'SSO' },
  { key: 'screenshots', label: 'Screenshots' },
  { key: 'response', label: 'Response' },
];

function matchesFilters(row: SitemapNode, active: Set<FilterKey>) {
  if (active.size === 0) return true;
  if (active.has('secrets') && !row.has_secrets) return false;
  if (active.has('login') && !row.has_login) return false;
  if (active.has('sso') && !row.has_sso) return false;
  if (active.has('screenshots') && !(row.screenshot_count && row.screenshot_count > 0)) return false;
  if (active.has('response') && row.http_status == null) return false;
  return true;
}

function Flag({ on }: { on?: boolean }) {
  if (!on) {
    return <span className="text-muted-foreground/40">—</span>;
  }
  return (
    <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-400">
      <Check className="h-3 w-3" />
    </span>
  );
}

function statusClass(status?: number | null) {
  if (status == null) return 'text-muted-foreground';
  if (status >= 200 && status < 300) return 'text-emerald-400';
  if (status >= 300 && status < 400) return 'text-sky-400';
  if (status >= 400 && status < 500) return 'text-amber-400';
  return 'text-red-400';
}

function accessLabel(access?: string | null) {
  if (access === 'auth_required') return 'Auth Required';
  if (access === 'no_auth') return 'No Auth';
  return 'Unknown';
}

function relativeCaptured(iso?: string | null) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const sec = Math.max(0, (Date.now() - t) / 1000);
  if (sec < 60) return 'just now';
  if (sec < 3600) {
    const n = Math.floor(sec / 60);
    return `${n} minute${n === 1 ? '' : 's'} ago`;
  }
  if (sec < 86400) {
    const n = Math.floor(sec / 3600);
    return `${n} hour${n === 1 ? '' : 's'} ago`;
  }
  const n = Math.floor(sec / 86400);
  return `${n} day${n === 1 ? '' : 's'} ago`;
}

function RestApiTable({
  rows,
  summary,
  specs,
  assetId,
}: {
  rows: SitemapNode[];
  summary?: Record<string, any>;
  specs?: Array<Record<string, any>>;
  assetId?: number;
}) {
  const [methodFilter, setMethodFilter] = useState<string | null>(null);
  const [accessFilter, setAccessFilter] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [collapsed, setCollapsed] = useState(false);

  const filtered = rows.filter((row) => {
    if (methodFilter && (row.method || 'GET') !== methodFilter) return false;
    if (accessFilter && (row.access || 'unknown') !== accessFilter) return false;
    if (query.trim()) {
      const q = query.toLowerCase();
      if (!(row.path || '').toLowerCase().includes(q) && !(row.url || '').toLowerCase().includes(q)) {
        return false;
      }
    }
    return true;
  });

  const downloadYaml = async () => {
    if (!assetId) return;
    try {
      const blob = await api.downloadAssetOpenapi(assetId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'openapi.yaml';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      // 404 when nothing is stored yet
    }
  };

  const viewSpec = async () => {
    if (!assetId) return;
    const remote = specs?.[0]?.url;
    if (remote && !specs?.[0]?.has_spec) {
      window.open(String(remote), '_blank');
      return;
    }
    try {
      const body = await api.getAssetApiSpec(assetId, 0);
      const blob = new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' });
      window.open(URL.createObjectURL(blob), '_blank');
    } catch {
      if (remote) window.open(String(remote), '_blank');
    }
  };

  if (rows.length === 0 && !(specs && specs.length)) return null;

  const discovered = summary?.discovered_by || rows[0]?.source || 'vespasian';

  return (
    <Card>
      <CardHeader className="py-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">REST API Endpoints</CardTitle>
            <CardDescription>
              Discovered by {discovered}
              {summary?.last_captured ? ` · Last captured ${relativeCaptured(summary.last_captured)}` : ''}
            </CardDescription>
            <div className="flex flex-wrap gap-2 mt-2 text-xs text-muted-foreground">
              <span>{summary?.endpoint_count ?? rows.length} Endpoints</span>
              <span>· {summary?.method_count ?? new Set(rows.map((r) => r.method)).size} Methods</span>
              <span>· {summary?.unauthenticated_count ?? 0} Unauthenticated</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {assetId && (
              <>
                <Button variant="outline" size="sm" onClick={downloadYaml}>
                  <Download className="h-3.5 w-3.5 mr-1.5" />
                  Download OpenAPI YAML
                </Button>
                <Button variant="outline" size="sm" onClick={viewSpec}>
                  <FileJson className="h-3.5 w-3.5 mr-1.5" />
                  View Spec
                </Button>
              </>
            )}
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setCollapsed((v) => !v)}>
              {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      {!collapsed && (
        <CardContent className="pt-0 space-y-3">
          <div className="flex flex-wrap gap-2">
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search endpoints"
              className="max-w-xs h-8"
            />
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
              <Button
                key={m}
                size="sm"
                variant={methodFilter === m ? 'default' : 'outline'}
                className="h-8"
                onClick={() => setMethodFilter((cur) => (cur === m ? null : m))}
              >
                {m}
              </Button>
            ))}
            <Button
              size="sm"
              variant={accessFilter === 'no_auth' ? 'default' : 'outline'}
              className="h-8"
              onClick={() => setAccessFilter((cur) => (cur === 'no_auth' ? null : 'no_auth'))}
            >
              No Auth
            </Button>
            <Button
              size="sm"
              variant={accessFilter === 'auth_required' ? 'default' : 'outline'}
              className="h-8"
              onClick={() => setAccessFilter((cur) => (cur === 'auth_required' ? null : 'auth_required'))}
            >
              Auth Required
            </Button>
          </div>
          <div className="rounded-md border border-border max-h-[480px] overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Method</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead className="w-28">Parameters</TableHead>
                  <TableHead className="w-32">Access</TableHead>
                  <TableHead className="w-24">Response</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-sm text-muted-foreground py-6">
                      No endpoints match the current filters
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((row, idx) => (
                  <TableRow key={`${row.method}-${row.path}-${idx}`}>
                    <TableCell className="font-mono text-xs">{row.method || 'GET'}</TableCell>
                    <TableCell className="font-mono text-xs">
                      <a
                        href={row.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-primary hover:underline"
                      >
                        {row.path}
                      </a>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {row.param_count ?? row.parameters?.length ?? 0} param
                      {(row.param_count ?? row.parameters?.length ?? 0) === 1 ? '' : 's'}
                    </TableCell>
                    <TableCell className="text-xs">{accessLabel(row.access)}</TableCell>
                    <TableCell className={cn('font-mono text-xs', statusClass(row.http_status))}>
                      {row.http_status ?? '—'}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

function SitemapTable({
  title,
  count,
  rows,
  showMethod,
}: {
  title: string;
  count: number;
  rows: SitemapNode[];
  showMethod?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? rows : rows.slice(0, 200);

  return (
    <Card>
      <CardHeader className="py-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle className="text-base">
              {title} ({count})
            </CardTitle>
            <CardDescription>
              Path attributes: secrets, login, SSO, screenshots, response
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {rows.length > 200 && (
              <Button variant="ghost" size="sm" onClick={() => setShowAll((v) => !v)}>
                {showAll ? 'Collapse all' : 'Show all'}
              </Button>
            )}
            <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setCollapsed((v) => !v)}>
              {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      {!collapsed && (
        <CardContent className="pt-0">
          {rows.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">None discovered yet</p>
          ) : (
            <div className="rounded-md border border-border max-h-[480px] overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {showMethod && <TableHead className="w-20">Method</TableHead>}
                    <TableHead>Path</TableHead>
                    <TableHead className="w-20 text-center">Secrets</TableHead>
                    <TableHead className="w-20 text-center">Login</TableHead>
                    <TableHead className="w-16 text-center">SSO</TableHead>
                    <TableHead className="w-24 text-center">Screenshots</TableHead>
                    <TableHead className="w-24 text-center">Response</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((row, idx) => (
                    <TableRow key={`${row.kind}-${row.method}-${row.path}-${idx}`}>
                      {showMethod && (
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {row.method || 'GET'}
                        </TableCell>
                      )}
                      <TableCell className="font-mono text-xs">
                        <a
                          href={row.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 text-foreground hover:text-primary hover:underline max-w-[42rem]"
                        >
                          <span className="truncate">{row.path || row.url}</span>
                          <ExternalLink className="h-3 w-3 shrink-0 text-muted-foreground" />
                        </a>
                      </TableCell>
                      <TableCell className="text-center"><Flag on={row.has_secrets} /></TableCell>
                      <TableCell className="text-center"><Flag on={row.has_login} /></TableCell>
                      <TableCell className="text-center"><Flag on={row.has_sso} /></TableCell>
                      <TableCell className="text-center">
                        {(row.screenshot_count || 0) > 0 ? (
                          <span className="text-xs tabular-nums">{row.screenshot_count}</span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </TableCell>
                      <TableCell className={cn('text-center font-mono text-xs tabular-nums', statusClass(row.http_status))}>
                        {row.http_status ?? '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {!showAll && rows.length > 200 && (
            <p className="text-xs text-muted-foreground mt-2">Showing 200 of {rows.length}. Use Show all to expand.</p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

export function SitemapInventory({
  sitemap = [],
  restApi = [],
  external = [],
  filters,
  restSummary,
  apiSpecs,
  assetId,
}: {
  sitemap?: SitemapNode[];
  restApi?: SitemapNode[];
  external?: SitemapNode[];
  filters?: Record<string, number>;
  restSummary?: Record<string, any>;
  apiSpecs?: Array<Record<string, any>>;
  assetId?: number;
}) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState<Set<FilterKey>>(new Set());

  const toggle = (key: FilterKey) => {
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const apply = (rows: SitemapNode[]) => {
    const q = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (!matchesFilters(row, active)) return false;
      if (!q) return true;
      return (
        row.path.toLowerCase().includes(q) ||
        row.url.toLowerCase().includes(q) ||
        (row.host || '').toLowerCase().includes(q)
      );
    });
  };

  const sitemapRows = useMemo(() => apply(sitemap), [sitemap, query, active]);
  const externalRows = useMemo(() => apply(external), [external, query, active]);

  const total = sitemap.length + restApi.length + external.length;
  if (total === 0) return null;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sitemap paths…"
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          {FILTERS.map((f) => (
            <Button
              key={f.key}
              size="sm"
              variant={active.has(f.key) ? 'default' : 'outline'}
              className="h-8"
              onClick={() => toggle(f.key)}
            >
              {f.label}
              {typeof filters?.[f.key] === 'number' && (
                <Badge variant="secondary" className="ml-1.5 h-5 px-1.5 text-[10px]">
                  {filters[f.key]}
                </Badge>
              )}
            </Button>
          ))}
        </div>
      </div>

      <SitemapTable title="Sitemap" count={sitemapRows.length} rows={sitemapRows} />
      <RestApiTable rows={restApi} summary={restSummary} specs={apiSpecs} assetId={assetId} />
      <SitemapTable title="External URLs" count={externalRows.length} rows={externalRows} />
    </div>
  );
}
