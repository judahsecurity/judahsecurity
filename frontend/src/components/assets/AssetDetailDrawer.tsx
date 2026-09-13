'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Activity,
  AlertTriangle,
  Building2,
  Calendar,
  CheckCircle2,
  Clock3,
  Cloud,
  Code2,
  ExternalLink,
  FileCode2,
  FileText,
  Fingerprint,
  Globe2,
  History,
  KeyRound,
  Layers3,
  Loader2,
  MapPin,
  Network,
  Radar,
  Save,
  Server,
  ShieldAlert,
  StickyNote,
  Tag,
} from 'lucide-react';

import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { SitemapInventory } from '@/components/assets/SitemapInventory';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type Technology = {
  name: string;
  version?: string;
  categories?: string[];
};

type PortService = {
  id?: number;
  port: number;
  protocol?: string;
  service?: string;
  product?: string;
  version?: string;
  state?: string;
  verified?: boolean;
  is_risky?: boolean;
};

type AssetDetail = {
  id: number;
  value: string;
  name?: string;
  asset_type?: string;
  status?: string;
  description?: string;
  organization_name?: string;
  organization_id?: number;
  root_domain?: string;
  ip_address?: string;
  ip_addresses?: string[];
  http_status?: number;
  http_title?: string;
  live_url?: string;
  is_live?: boolean;
  in_scope?: boolean;
  is_owned?: boolean;
  is_monitored?: boolean;
  risk_score?: number;
  criticality?: string;
  vulnerability_count?: number;
  critical_vuln_count?: number;
  high_vuln_count?: number;
  open_ports_count?: number;
  risky_ports_count?: number;
  technologies?: Technology[];
  port_services?: PortService[];
  endpoints?: string[];
  parameters?: string[];
  js_files?: string[];
  tags?: string[];
  metadata_?: Record<string, any>;
  dns_records?: Record<string, any>;
  discovery_source?: string;
  discovery_chain?: Array<Record<string, any>>;
  association_reason?: string;
  association_confidence?: number;
  first_seen?: string;
  last_seen?: string;
  created_at?: string;
  updated_at?: string;
  last_scan_name?: string;
  last_scan_date?: string;
  hosting_type?: string;
  hosting_provider?: string;
  country?: string;
  city?: string;
  asn?: string;
};

type Finding = {
  id: number;
  name?: string;
  title?: string;
  severity?: string;
  status?: string;
  first_detected?: string;
  last_detected?: string;
};

type AppStructure = {
  summary?: Record<string, any>;
  sitemap?: any[];
  rest_api_endpoints?: any[];
  external_urls?: any[];
  parameters?: string[];
  urls?: string[];
  paths?: string[];
  js_files?: string[];
  rest_summary?: Record<string, any>;
  api_specs?: Array<Record<string, any>>;
  sitemap_filters?: Record<string, number>;
};

type Props = {
  assetId: number | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAssetChanged?: () => void;
};

const severityClass: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

function Stat({ label, value, icon: Icon, tone = 'text-primary' }: { label: string; value: string | number; icon: any; tone?: string }) {
  return (
    <Card className="bg-card/70">
      <CardContent className="flex items-center gap-3 p-4">
        <div className="rounded-lg bg-muted p-2"><Icon className={`h-4 w-4 ${tone}`} /></div>
        <div>
          <div className="text-xl font-semibold tabular-nums">{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="text-sm break-words">{children || '—'}</div>
    </div>
  );
}

function EmptyState({ icon: Icon, title, description }: { icon: any; title: string; description: string }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center">
      <Icon className="mb-3 h-8 w-8 text-muted-foreground" />
      <div className="font-medium">{title}</div>
      <div className="mt-1 max-w-md text-sm text-muted-foreground">{description}</div>
    </div>
  );
}

export function AssetDetailDrawer({ assetId, open, onOpenChange, onAssetChanged }: Props) {
  const router = useRouter();
  const { toast } = useToast();
  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [appStructure, setAppStructure] = useState<AppStructure | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [appLoading, setAppLoading] = useState(false);
  const [noteDraft, setNoteDraft] = useState('');
  const [savingNote, setSavingNote] = useState(false);

  useEffect(() => {
    if (!open || !assetId) return;
    let cancelled = false;
    setLoading(true);
    setAsset(null);
    setFindings([]);
    setAppStructure(null);
    setActiveTab('overview');

    Promise.all([
      api.getAsset(assetId),
      api.getVulnerabilitiesForAsset(assetId, { limit: 50 }).catch(() => []),
    ])
      .then(([assetData, findingData]) => {
        if (cancelled) return;
        const nextAsset = assetData as AssetDetail;
        setAsset(nextAsset);
        setNoteDraft(nextAsset.description || '');
        setFindings(Array.isArray(findingData) ? findingData : findingData?.items || []);
      })
      .catch(() => {
        if (!cancelled) {
          toast({ title: 'Could not load asset', description: 'The asset details request failed.', variant: 'destructive' });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [assetId, open, toast]);

  useEffect(() => {
    if (activeTab !== 'app-surface' || !assetId || appStructure || appLoading) return;
    setAppLoading(true);
    api.getAppStructureByAsset(assetId)
      .then((data) => setAppStructure(data))
      .catch(() => setAppStructure({}))
      .finally(() => setAppLoading(false));
  }, [activeTab, appLoading, appStructure, assetId]);

  const appSummary = useMemo(() => {
    const summary = appStructure?.summary || {};
    return {
      endpoints: summary.total_api_endpoints ?? appStructure?.rest_api_endpoints?.length ?? asset?.endpoints?.length ?? 0,
      parameters: summary.total_parameters ?? appStructure?.parameters?.length ?? asset?.parameters?.length ?? 0,
      paths: summary.total_paths ?? appStructure?.paths?.length ?? 0,
      javascript: summary.total_js_files ?? appStructure?.js_files?.length ?? asset?.js_files?.length ?? 0,
    };
  }, [appStructure, asset]);

  const saveNote = async () => {
    if (!assetId) return;
    setSavingNote(true);
    try {
      await api.request(`/assets/${assetId}/investigate`, { method: 'POST', params: { notes: noteDraft } });
      setAsset((current) => current ? { ...current, description: noteDraft } : current);
      onAssetChanged?.();
      toast({ title: 'Note saved', description: 'Investigation notes were updated.' });
    } catch {
      toast({ title: 'Could not save note', description: 'The investigation note was not updated.', variant: 'destructive' });
    } finally {
      setSavingNote(false);
    }
  };

  const lastSeen = asset?.last_seen || asset?.updated_at || asset?.created_at;
  const firstSeen = asset?.first_seen || asset?.created_at;
  const live = Boolean(asset?.is_live);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-[94vw] max-w-none overflow-y-auto p-0 sm:max-w-[1100px]">
        {loading || !asset ? (
          <div className="flex h-full items-center justify-center">
            <Loader2 className="h-7 w-7 animate-spin text-primary" />
          </div>
        ) : (
          <>
            <SheetHeader className="sticky top-0 z-20 border-b bg-background/95 px-6 py-5 pr-14 backdrop-blur">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <Badge className={live ? 'border-green-500/30 bg-green-500/15 text-green-400' : 'border-muted bg-muted text-muted-foreground'}>
                      {live ? 'Live' : asset.status || 'Not live'}
                    </Badge>
                    <Badge variant="outline">{asset.asset_type?.replaceAll('_', ' ') || 'asset'}</Badge>
                    {asset.in_scope === false && <Badge variant="destructive">Out of scope</Badge>}
                  </div>
                  <SheetTitle className="truncate font-mono text-xl">{asset.value || asset.name}</SheetTitle>
                  <SheetDescription className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1">
                    {asset.organization_name && <span className="inline-flex items-center gap-1"><Building2 className="h-3.5 w-3.5" />{asset.organization_name}</span>}
                    {lastSeen && <span className="inline-flex items-center gap-1"><Clock3 className="h-3.5 w-3.5" />Last seen {formatDate(lastSeen)}</span>}
                  </SheetDescription>
                </div>
                <Button variant="outline" onClick={() => router.push(`/assets/${asset.id}`)}>
                  Open full details <ExternalLink className="ml-2 h-4 w-4" />
                </Button>
              </div>
            </SheetHeader>

            <Tabs value={activeTab} onValueChange={setActiveTab} className="px-6 py-5">
              <div className="overflow-x-auto pb-1">
                <TabsList className="h-auto min-w-max justify-start">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="app-surface">App Surface</TabsTrigger>
                  <TabsTrigger value="findings">Findings</TabsTrigger>
                  <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
                  <TabsTrigger value="discovery">Discovery</TabsTrigger>
                  <TabsTrigger value="notes">Notes</TabsTrigger>
                  <TabsTrigger value="activity">Activity</TabsTrigger>
                  <TabsTrigger value="ownership">Ownership</TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value="overview" className="mt-5 space-y-5">
                <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                  <Stat label="Risk score" value={asset.risk_score ?? 0} icon={ShieldAlert} tone="text-orange-400" />
                  <Stat label="Open findings" value={asset.vulnerability_count ?? findings.length} icon={AlertTriangle} tone="text-red-400" />
                  <Stat label="Open ports" value={asset.open_ports_count ?? asset.port_services?.length ?? 0} icon={Network} tone="text-cyan-400" />
                  <Stat label="Technologies" value={asset.technologies?.length ?? 0} icon={Layers3} tone="text-purple-400" />
                </div>

                <Card>
                  <CardHeader><CardTitle className="text-base">Asset identity</CardTitle></CardHeader>
                  <CardContent className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
                    <Field label="Asset">{asset.value}</Field>
                    <Field label="IP address">{asset.ip_addresses?.join(', ') || asset.ip_address}</Field>
                    <Field label="HTTP">{asset.http_status ? `${asset.http_status}${asset.http_title ? ` · ${asset.http_title}` : ''}` : '—'}</Field>
                    <Field label="Root domain">{asset.root_domain}</Field>
                    <Field label="First seen">{firstSeen ? formatDate(firstSeen) : '—'}</Field>
                    <Field label="Last seen">{lastSeen ? formatDate(lastSeen) : '—'}</Field>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Technologies</CardTitle>
                    <CardDescription>Software and frameworks detected on this asset.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {asset.technologies?.length ? (
                      <div className="flex flex-wrap gap-2">
                        {asset.technologies.map((technology, index) => (
                          <Badge key={`${technology.name}-${index}`} variant="outline" className="gap-1.5 py-1.5">
                            {technology.name}{technology.version && <span className="text-muted-foreground">v{technology.version}</span>}
                          </Badge>
                        ))}
                      </div>
                    ) : <EmptyState icon={Fingerprint} title="No technologies detected" description="Run technology detection to fingerprint this asset." />}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="app-surface" className="mt-5 space-y-5">
                {appLoading ? (
                  <div className="flex min-h-64 items-center justify-center"><Loader2 className="h-6 w-6 animate-spin" /></div>
                ) : (
                  <>
                    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                      <Stat label="API endpoints" value={appSummary.endpoints} icon={Code2} tone="text-cyan-400" />
                      <Stat label="Parameters" value={appSummary.parameters} icon={KeyRound} tone="text-orange-400" />
                      <Stat label="Paths" value={appSummary.paths} icon={Globe2} tone="text-blue-400" />
                      <Stat label="JavaScript files" value={appSummary.javascript} icon={FileCode2} tone="text-yellow-400" />
                    </div>

                    <SitemapInventory
                      sitemap={appStructure?.sitemap || []}
                      restApi={appStructure?.rest_api_endpoints || []}
                      external={appStructure?.external_urls || []}
                      restSummary={appStructure?.rest_summary}
                      apiSpecs={appStructure?.api_specs}
                      assetId={asset.id}
                      filters={{
                        secrets: appStructure?.summary?.secrets_count || 0,
                        login: appStructure?.summary?.login_count || 0,
                        sso: appStructure?.summary?.sso_count || 0,
                        screenshots: appStructure?.summary?.screenshot_count || 0,
                        response: appStructure?.sitemap_filters?.with_response || 0,
                      }}
                    />

                    {(appStructure?.parameters?.length || asset.parameters?.length) ? (
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-base">Discovered parameters</CardTitle>
                          <CardDescription>Parameter names collected from crawling, archives and JavaScript analysis.</CardDescription>
                        </CardHeader>
                        <CardContent className="flex max-h-64 flex-wrap gap-2 overflow-y-auto">
                          {(appStructure?.parameters || asset.parameters || []).map((parameter, index) => (
                            <Badge key={`${parameter}-${index}`} variant="outline" className="font-mono text-xs">{parameter}</Badge>
                          ))}
                        </CardContent>
                      </Card>
                    ) : appSummary.endpoints === 0 ? (
                      <EmptyState icon={Code2} title="No application structure discovered" description="Run Katana, ParamSpider or JavaScript reconnaissance to collect endpoints and parameters." />
                    ) : null}
                  </>
                )}
              </TabsContent>

              <TabsContent value="findings" className="mt-5">
                {findings.length ? (
                  <Card>
                    <CardHeader><CardTitle className="text-base">Findings ({findings.length})</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      {findings.map((finding) => (
                        <div key={finding.id} className="flex items-center justify-between gap-4 rounded-lg border p-3">
                          <div className="min-w-0">
                            <div className="truncate font-medium">{finding.title || finding.name || `Finding ${finding.id}`}</div>
                            <div className="mt-1 text-xs text-muted-foreground">{finding.status || 'open'}{finding.last_detected ? ` · Last detected ${formatDate(finding.last_detected)}` : ''}</div>
                          </div>
                          <Badge variant="outline" className={severityClass[finding.severity?.toLowerCase() || '']}>{finding.severity || 'unknown'}</Badge>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ) : <EmptyState icon={CheckCircle2} title="No findings" description="No security findings are currently associated with this asset." />}
              </TabsContent>

              <TabsContent value="infrastructure" className="mt-5 space-y-5">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Open ports and services</CardTitle>
                    <CardDescription>Network services observed on this asset.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {asset.port_services?.length ? (
                      <div className="overflow-x-auto rounded-md border">
                        <Table>
                          <TableHeader><TableRow><TableHead>Port</TableHead><TableHead>Protocol</TableHead><TableHead>Service</TableHead><TableHead>Product</TableHead><TableHead>State</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {asset.port_services.map((port, index) => (
                              <TableRow key={port.id || `${port.port}-${index}`}>
                                <TableCell className="font-mono font-medium">{port.port}</TableCell>
                                <TableCell className="uppercase text-muted-foreground">{port.protocol || 'tcp'}</TableCell>
                                <TableCell>{port.service || '—'}</TableCell>
                                <TableCell>{port.product || '—'}{port.version && <span className="ml-2 text-xs text-muted-foreground">{port.version}</span>}</TableCell>
                                <TableCell><Badge variant="outline" className={port.is_risky ? 'border-red-500/40 text-red-400' : ''}>{port.state || 'open'}</Badge></TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    ) : <EmptyState icon={Server} title="No open ports detected" description="Run a port scan to enumerate services on this asset." />}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-base">Hosting and location</CardTitle></CardHeader>
                  <CardContent className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
                    <Field label="Hosting type">{asset.hosting_type}</Field>
                    <Field label="Provider">{asset.hosting_provider}</Field>
                    <Field label="ASN">{asset.asn}</Field>
                    <Field label="Location">{[asset.city, asset.country].filter(Boolean).join(', ')}</Field>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="discovery" className="mt-5 space-y-5">
                <Card>
                  <CardHeader><CardTitle className="text-base">Discovery context</CardTitle></CardHeader>
                  <CardContent className="grid gap-5 sm:grid-cols-2">
                    <Field label="Source">{asset.discovery_source}</Field>
                    <Field label="Root domain">{asset.root_domain}</Field>
                    <Field label="Association reason">{asset.association_reason}</Field>
                    <Field label="Confidence">{asset.association_confidence != null ? `${Math.round(asset.association_confidence * (asset.association_confidence <= 1 ? 100 : 1))}%` : '—'}</Field>
                  </CardContent>
                </Card>
                {asset.discovery_chain?.length ? (
                  <Card>
                    <CardHeader><CardTitle className="text-base">Discovery path</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      {asset.discovery_chain.map((step, index) => (
                        <div key={index} className="flex gap-3 rounded-lg border p-3">
                          <Radar className="mt-0.5 h-4 w-4 text-primary" />
                          <div className="text-sm">{step.description || step.value || step.source || JSON.stringify(step)}</div>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ) : null}
              </TabsContent>

              <TabsContent value="notes" className="mt-5">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base"><StickyNote className="h-4 w-4" />Investigation notes</CardTitle>
                    <CardDescription>Capture analyst context, ownership details and follow-up information.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <Textarea value={noteDraft} onChange={(event) => setNoteDraft(event.target.value)} placeholder="Add investigation notes…" className="min-h-40" />
                    <div className="flex justify-end">
                      <Button onClick={saveNote} disabled={savingNote || noteDraft === (asset.description || '')}>
                        {savingNote ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}Save note
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="activity" className="mt-5">
                <Card>
                  <CardHeader><CardTitle className="flex items-center gap-2 text-base"><History className="h-4 w-4" />Asset activity</CardTitle></CardHeader>
                  <CardContent className="space-y-3">
                    {asset.last_scan_date && (
                      <div className="flex gap-3 rounded-lg border p-3"><Activity className="mt-0.5 h-4 w-4 text-primary" /><div><div className="text-sm font-medium">{asset.last_scan_name || 'Security scan'}</div><div className="text-xs text-muted-foreground">{formatDate(asset.last_scan_date)}</div></div></div>
                    )}
                    {lastSeen && <div className="flex gap-3 rounded-lg border p-3"><Clock3 className="mt-0.5 h-4 w-4 text-blue-400" /><div><div className="text-sm font-medium">Last observed</div><div className="text-xs text-muted-foreground">{formatDate(lastSeen)}</div></div></div>}
                    {firstSeen && <div className="flex gap-3 rounded-lg border p-3"><Calendar className="mt-0.5 h-4 w-4 text-green-400" /><div><div className="text-sm font-medium">First discovered</div><div className="text-xs text-muted-foreground">{formatDate(firstSeen)}</div></div></div>}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="ownership" className="mt-5 space-y-5">
                <div className="grid gap-3 sm:grid-cols-3">
                  <Stat label="Owned" value={asset.is_owned ? 'Yes' : 'Unverified'} icon={Fingerprint} tone={asset.is_owned ? 'text-green-400' : 'text-yellow-400'} />
                  <Stat label="In scope" value={asset.in_scope === false ? 'No' : 'Yes'} icon={ShieldAlert} tone={asset.in_scope === false ? 'text-red-400' : 'text-green-400'} />
                  <Stat label="Monitored" value={asset.is_monitored === false ? 'No' : 'Yes'} icon={Radar} tone="text-blue-400" />
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Affiliation evidence</CardTitle>
                    <CardDescription>Why this asset is associated with the organization.</CardDescription>
                  </CardHeader>
                  <CardContent className="grid gap-5 sm:grid-cols-2">
                    <Field label="Organization">{asset.organization_name || asset.organization_id}</Field>
                    <Field label="Confidence">{asset.association_confidence != null ? `${Math.round(asset.association_confidence * (asset.association_confidence <= 1 ? 100 : 1))}%` : 'Not evaluated'}</Field>
                    <div className="sm:col-span-2"><Field label="Evidence">{asset.association_reason || 'No affiliation evidence has been recorded yet.'}</Field></div>
                    {asset.tags?.length ? <div className="sm:col-span-2"><Field label="Tags"><span className="flex flex-wrap gap-2">{asset.tags.map((tag) => <Badge key={tag} variant="secondary"><Tag className="mr-1 h-3 w-3" />{tag}</Badge>)}</span></Field></div> : null}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
