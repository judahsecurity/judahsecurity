'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import dynamic from 'next/dynamic';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Globe,
  Shield,
  AlertTriangle,
  Camera,
  Activity,
  TrendingUp,
  TrendingDown,
  ArrowRight,
  RefreshCw,
  Network,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Zap,
  BarChart3,
  AlertCircle,
  Flame,
  Sparkles,
} from 'lucide-react';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import Link from 'next/link';
import { useToast } from '@/hooks/use-toast';

const WorldMap = dynamic(
  () => import('@/components/map/WorldMap').then((m) => m.WorldMap),
  {
    ssr: false,
    loading: () => (
      <div className="flex items-center justify-center h-[420px] text-muted-foreground text-sm">
        Loading map…
      </div>
    ),
  }
);

const PrioritizationFunnelCard = dynamic(
  () =>
    import('@/components/dashboard/PrioritizationFunnelCard').then(
      (m) => m.PrioritizationFunnelCard
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-[420px] rounded-lg border border-orange-500/20 bg-card animate-pulse" />
    ),
  }
);

type FindingsGroupBy =
  | 'severity'
  | 'status'
  | 'organization'
  | 'country'
  | 'asset_type'
  | 'root_domain';

const FINDINGS_GROUP_OPTIONS: { value: FindingsGroupBy; label: string }[] = [
  { value: 'severity', label: 'Severity' },
  { value: 'status', label: 'Status' },
  { value: 'organization', label: 'Organization' },
  { value: 'country', label: 'Country' },
  { value: 'asset_type', label: 'Asset type' },
  { value: 'root_domain', label: 'Root domain' },
];

const GROUP_BAR_COLORS = [
  'bg-red-600',
  'bg-orange-500',
  'bg-yellow-500',
  'bg-green-500',
  'bg-blue-500',
  'bg-purple-500',
  'bg-cyan-500',
  'bg-pink-500',
];

interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;  // Excludes info
  total_all_vulnerabilities: number;  // Includes info
  info_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_organizations: number;
  recent_scans: number;
}

interface NetblockStats {
  total_netblocks: number;
  owned_netblocks: number;
  in_scope_netblocks: number;
  total_ips: number;
  owned_ips: number;
  in_scope_ips: number;
  scanned_netblocks: number;
  unscanned_netblocks: number;
}

interface RemediationStats {
  period_days: number;
  new_findings: number;
  resolved_findings: number;
  resolution_rate: number;
  avg_resolution_time_days: number | null;
  mttr_days: number | null;
  open_critical: number;
  open_high: number;
  overdue_count: number;
}

interface DelphiPriorityFinding {
  vulnerability_id: number;
  cve_id: string;
  title: string | null;
  severity: string;
  asset_value: string | null;
  priority: 'critical' | 'high' | 'medium' | 'low' | 'none';
  priority_reason?: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  on_kev: boolean;
  ransomware: boolean;
}

interface DelphiStatus {
  enabled: boolean;
  kev_entries: number;
  epss_entries: number;
  epss_score_date?: string | null;
  refresh_hours: number;
  last_loaded?: string | null;
}

interface ExposureStats {
  total_exposure_score: number;
  assets_with_vulnerabilities: number;
  total_assets: number;
  exposure_percentage: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_vulnerable_assets: Array<{
    asset_id: number;
    asset_name: string;
    asset_value: string;
    vulnerability_count: number;
    asset_type: string;
  }>;
  exposure_trend: 'increasing' | 'decreasing' | 'stable';
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [netblockStats, setNetblockStats] = useState<NetblockStats | null>(null);
  const [remediationStats, setRemediationStats] = useState<RemediationStats | null>(null);
  const [exposureStats, setExposureStats] = useState<ExposureStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [mapLoading, setMapLoading] = useState(true);
  const [recentVulns, setRecentVulns] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [delphiPriorities, setDelphiPriorities] = useState<DelphiPriorityFinding[]>([]);
  const [delphiStatus, setDelphiStatus] = useState<DelphiStatus | null>(null);
  const [findingsGroupBy, setFindingsGroupBy] = useState<FindingsGroupBy>('severity');
  const [findingsGroups, setFindingsGroups] = useState<Array<{ key: string; label: string; count: number }>>([]);
  const [groupsLoading, setGroupsLoading] = useState(false);
  const { toast } = useToast();

  const syncFindingsGroups = useCallback((vulnSummary: any, groupBy: FindingsGroupBy) => {
    if (Array.isArray(vulnSummary.groups) && vulnSummary.groups.length > 0) {
      setFindingsGroups(vulnSummary.groups);
      return;
    }
    if (groupBy === 'severity' && vulnSummary.by_severity) {
      setFindingsGroups(
        ['critical', 'high', 'medium', 'low'].map((k) => ({
          key: k,
          label: k.charAt(0).toUpperCase() + k.slice(1),
          count: vulnSummary.by_severity[k] || 0,
        }))
      );
      return;
    }
    setFindingsGroups([]);
  }, []);

  const fetchFindingsGrouped = useCallback(async (groupBy: FindingsGroupBy) => {
    setGroupsLoading(true);
    try {
      const vulnSummary = await api.getVulnerabilitiesSummary(undefined, groupBy);
      setStats((prev) => ({
        total_assets: prev?.total_assets || 0,
        total_organizations: prev?.total_organizations || 0,
        recent_scans: prev?.recent_scans || 0,
        total_vulnerabilities: vulnSummary.total || 0,
        total_all_vulnerabilities: vulnSummary.total_all || vulnSummary.total || 0,
        info_count: vulnSummary.info_count || vulnSummary.by_severity?.info || 0,
        critical_count: vulnSummary.by_severity?.critical || 0,
        high_count: vulnSummary.by_severity?.high || 0,
        medium_count: vulnSummary.by_severity?.medium || 0,
        low_count: vulnSummary.by_severity?.low || 0,
      }));
      syncFindingsGroups(vulnSummary, groupBy);
    } catch (error) {
      console.error('Failed to fetch grouped findings summary:', error);
    } finally {
      setGroupsLoading(false);
    }
  }, [syncFindingsGroups]);

  const fetchDashboardData = useCallback(async () => {
    setLoading(true);
    setMapLoading(true);
    try {
      // Fast path: aggregates first so cards paint without waiting on the map payload
      const [vulnSummary, assetSummary, orgs, vulns, nbSummary, remediationData, exposureData, delphiPrios, delphiStat] =
        await Promise.all([
          api.getVulnerabilitiesSummary(undefined, findingsGroupBy),
          api.getAssetsSummary(),
          api.getOrganizations({ limit: 100 }),
          api.getVulnerabilities({ limit: 5 }),
          api.getNetblockSummary().catch(() => null),
          api.getRemediationEfficiency(30).catch(() => null),
          api.getVulnerabilityExposure().catch(() => null),
          api.getDelphiPriorities(10, false).catch(() => []),
          api.getDelphiStatus().catch(() => null),
        ]);

      setStats({
        total_assets: assetSummary.total || 0,
        total_organizations: Array.isArray(orgs) ? orgs.length : 0,
        recent_scans: 0,
        total_vulnerabilities: vulnSummary.total || 0,
        total_all_vulnerabilities: vulnSummary.total_all || vulnSummary.total || 0,
        info_count: vulnSummary.info_count || vulnSummary.by_severity?.info || 0,
        critical_count: vulnSummary.by_severity?.critical || 0,
        high_count: vulnSummary.by_severity?.high || 0,
        medium_count: vulnSummary.by_severity?.medium || 0,
        low_count: vulnSummary.by_severity?.low || 0,
      });
      syncFindingsGroups(vulnSummary, findingsGroupBy);

      if (nbSummary) setNetblockStats(nbSummary);
      if (remediationData) setRemediationStats(remediationData);
      if (exposureData) setExposureStats(exposureData);
      setRecentVulns(vulns.items || vulns || []);
      setDelphiPriorities(Array.isArray(delphiPrios) ? delphiPrios : []);
      setDelphiStatus(delphiStat);
      setLoading(false);

      // Slow path: lean geo markers (does not block stats)
      try {
        const geoAssetsData = await api.getGeoAssets({ limit: 5000 });
        setAssets(geoAssetsData.items || []);
      } catch (error) {
        console.error('Failed to fetch geo assets:', error);
        setAssets([]);
      } finally {
        setMapLoading(false);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setLoading(false);
      setMapLoading(false);
    }
  }, [syncFindingsGroups, findingsGroupBy]);

  // Transform lean geo assets for WorldMap
  const mapAssets = useMemo(() => {
    return assets
      .filter((a: any) => {
        const lat = a.latitude;
        const lng = a.longitude;
        const hasValidLat = lat !== null && lat !== undefined && lat !== '' && !isNaN(parseFloat(lat));
        const hasValidLng = lng !== null && lng !== undefined && lng !== '' && !isNaN(parseFloat(lng));
        return hasValidLat && hasValidLng;
      })
      .map((a: any) => {
        const maxSeverity: 'critical' | 'high' | 'medium' | 'low' | null =
          (a.critical_vuln_count ?? 0) > 0 ? 'critical' :
          (a.high_vuln_count ?? 0) > 0 ? 'high' :
          (a.medium_vuln_count ?? 0) > 0 ? 'medium' :
          (a.low_vuln_count ?? 0) > 0 ? 'low' : null;

        return {
          id: a.id,
          value: a.name || a.value || '',
          type: a.asset_type?.toLowerCase() || 'subdomain',
          findingsCount: a.vulnerability_count || 0,
          maxSeverity,
          openPortsCount: a.open_ports_count ?? 0,
          riskyPortsCount: a.risky_ports_count ?? 0,
          openPorts: [],
          dnsThreat: a.dns_threat ?? a.metadata_?.dns_threat_listed ?? false,
          urlhausMalicious: a.urlhaus_malicious ?? a.metadata_?.urlhaus_malicious ?? false,
          geoLocation: {
            latitude: parseFloat(a.latitude),
            longitude: parseFloat(a.longitude),
            city: a.city,
            country: a.country,
            countryCode: a.country_code,
          },
        };
      });
  }, [assets]);

  useEffect(() => {
    fetchDashboardData();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- initial load only; refresh button re-runs with current group
  }, []);

  const breakdownItems = useMemo(() => {
    if (findingsGroupBy === 'severity' && (!findingsGroups.length || findingsGroups.every((g) => ['critical', 'high', 'medium', 'low'].includes(g.key)))) {
      return [
        { label: 'Critical', count: stats?.critical_count || 0, color: 'bg-red-600' },
        { label: 'High', count: stats?.high_count || 0, color: 'bg-orange-500' },
        { label: 'Medium', count: stats?.medium_count || 0, color: 'bg-yellow-500' },
        { label: 'Low', count: stats?.low_count || 0, color: 'bg-green-500' },
      ];
    }
    return findingsGroups.map((g, i) => ({
      label: g.label || g.key,
      count: g.count || 0,
      color: GROUP_BAR_COLORS[i % GROUP_BAR_COLORS.length],
    }));
  }, [findingsGroupBy, findingsGroups, stats]);

  const statCards = [
    {
      title: 'Total Assets',
      value: stats?.total_assets || 0,
      icon: Globe,
      color: 'text-blue-500',
      bgColor: 'bg-blue-500/10',
      href: '/assets',
    },
    {
      title: 'Findings',
      value: stats?.total_vulnerabilities || 0,
      icon: Shield,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      href: '/findings',
    },
    {
      title: 'Critical Issues',
      value: stats?.critical_count || 0,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-600/10',
      href: '/findings?severity=critical',
    },
    {
      title: 'Organizations',
      value: stats?.total_organizations || 0,
      icon: Activity,
      color: 'text-green-500',
      bgColor: 'bg-green-500/10',
      href: '/organizations',
    },
  ];

  return (
    <MainLayout>
      <Header title="Dashboard" subtitle="Overview of your attack surface" />

      <div className="p-6 space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {statCards.map((stat) => (
            <Link key={stat.title} href={stat.href}>
              <Card className="hover:border-primary/50 transition-colors cursor-pointer">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{stat.title}</p>
                      <p className="text-3xl font-bold mt-1">
                        {loading ? '...' : formatNumber(stat.value)}
                      </p>
                    </div>
                    <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                      <stat.icon className={`h-6 w-6 ${stat.color}`} />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>

        {/* World Map */}
        <Card>
          <CardContent className="pt-6">
            {mapLoading ? (
              <div className="text-center py-12 text-muted-foreground">
                <RefreshCw className="h-8 w-8 mx-auto mb-4 opacity-50 animate-spin" />
                <p>Loading map markers…</p>
              </div>
            ) : mapAssets.length > 0 ? (
              <WorldMap 
                assets={mapAssets} 
                onAssetClick={(asset) => {
                  toast({
                    title: asset.value,
                    description: `${asset.geoLocation?.city || 'Unknown'}, ${asset.geoLocation?.country || 'Unknown'} · ${asset.findingsCount || 0} findings`,
                  });
                }} 
              />
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No assets with geo-location data yet</p>
                <p className="text-sm mt-2">Run a DNS Resolution scan to resolve IPs and geo-locate assets</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Prioritization value — live scanner → Delphi → OPES funnel */}
        <PrioritizationFunnelCard />

        {/* Findings Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle className="text-lg">Findings Breakdown</CardTitle>
              <div className="flex items-center gap-2">
                <Select
                  value={findingsGroupBy}
                  onValueChange={(value) => {
                    const next = value as FindingsGroupBy;
                    setFindingsGroupBy(next);
                    fetchFindingsGrouped(next);
                  }}
                >
                  <SelectTrigger className="h-8 w-[150px]">
                    <SelectValue placeholder="Group by" />
                  </SelectTrigger>
                  <SelectContent>
                    {FINDINGS_GROUP_OPTIONS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button variant="ghost" size="icon" onClick={fetchDashboardData}>
                  <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {(loading || groupsLoading) && breakdownItems.length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-6">Loading…</p>
                ) : (
                  breakdownItems.map((item) => {
                    const total = Math.max(
                      breakdownItems.reduce((sum, row) => sum + row.count, 0),
                      1
                    );
                    const percentage = (item.count / total) * 100;
                    return (
                      <div key={item.label} className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground truncate pr-2">{item.label}</span>
                          <span className="font-medium shrink-0">{item.count}</span>
                        </div>
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full ${item.color} rounded-full transition-all duration-500`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                )}
                {/* Info count shown separately when grouping by severity */}
                {findingsGroupBy === 'severity' && stats?.info_count && stats.info_count > 0 && (
                  <div className="pt-2 border-t border-muted">
                    <div className="flex items-center justify-between text-sm text-muted-foreground">
                      <span>Informational (not counted as findings)</span>
                      <span>{stats.info_count}</span>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Recent Findings</CardTitle>
              <Link href="/findings">
                <Button variant="ghost" size="sm">
                  View All <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {recentVulns.length === 0 ? (
                  <p className="text-muted-foreground text-sm text-center py-8">
                    No findings found. Run a scan to discover issues.
                  </p>
                ) : (
                  recentVulns.slice(0, 5).map((vuln: any, index: number) => (
                    <div
                      key={vuln.id || index}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {vuln.name || vuln.template_id || 'Unknown'}
                        </p>
                        <p className="text-xs text-muted-foreground truncate">
                          {vuln.host || vuln.target || 'Unknown target'}
                        </p>
                      </div>
                      <Badge
                        variant={
                          vuln.severity?.toLowerCase() === 'critical'
                            ? 'critical'
                            : vuln.severity?.toLowerCase() === 'high'
                            ? 'high'
                            : vuln.severity?.toLowerCase() === 'medium'
                            ? 'medium'
                            : 'low'
                        }
                      >
                        {vuln.severity || 'Unknown'}
                      </Badge>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Delphi Priorities (CISA KEV + FIRST EPSS) */}
        <Card className="border-purple-500/20">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Sparkles className="h-5 w-5 text-purple-400" />
                Delphi Priorities
              </CardTitle>
              <p className="text-sm text-muted-foreground mt-1">
                What to fix next — CISA KEV first, then FIRST EPSS exploit-prediction
                {delphiStatus && delphiStatus.kev_entries > 0 && (
                  <>
                    {' '}· {delphiStatus.kev_entries.toLocaleString()} KEV entries
                    {delphiStatus.epss_entries > 0 && `, ${delphiStatus.epss_entries.toLocaleString()} EPSS scored`}
                  </>
                )}
              </p>
            </div>
            <Link href="/findings">
              <Button variant="ghost" size="sm">
                Open Findings <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            {loading ? (
              <p className="text-sm text-muted-foreground text-center py-6">Loading…</p>
            ) : delphiPriorities.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground">
                <Sparkles className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p className="text-sm">
                  No Delphi-prioritised findings yet.
                </p>
                <p className="text-xs mt-1">
                  Run a Nuclei scan to ingest CVEs — Delphi auto-enriches them with KEV + EPSS.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {delphiPriorities.slice(0, 8).map((p) => (
                  <Link
                    key={p.vulnerability_id}
                    href={`/findings`}
                    className="flex items-center justify-between gap-3 p-3 rounded-lg bg-muted/40 hover:bg-muted transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      {p.ransomware ? (
                        <Flame className="h-4 w-4 text-red-400 shrink-0" />
                      ) : p.on_kev ? (
                        <Flame className="h-4 w-4 text-red-500/80 shrink-0" />
                      ) : (
                        <TrendingUp className="h-4 w-4 text-purple-400 shrink-0" />
                      )}
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">
                          <span className="font-mono text-primary">{p.cve_id}</span>
                          {p.title && <span className="text-muted-foreground"> · {p.title}</span>}
                        </p>
                        <p className="text-xs text-muted-foreground truncate">
                          {p.asset_value || 'unknown asset'}
                          {p.priority_reason && <> — {p.priority_reason}</>}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {p.on_kev && (
                        <Badge
                          variant="outline"
                          className={
                            p.ransomware
                              ? 'bg-red-600/20 text-red-300 border-red-600/40 text-[10px]'
                              : 'bg-red-500/15 text-red-400 border-red-500/30 text-[10px]'
                          }
                        >
                          {p.ransomware ? 'KEV · Ransomware' : 'CISA KEV'}
                        </Badge>
                      )}
                      {p.epss_percentile != null && (
                        <Badge
                          variant="outline"
                          className="bg-purple-500/10 text-purple-300 border-purple-500/30 text-[10px]"
                        >
                          EPSS {(p.epss_percentile * 100).toFixed(0)}%
                        </Badge>
                      )}
                      <Badge
                        variant={
                          p.priority === 'critical'
                            ? 'critical'
                            : p.priority === 'high'
                            ? 'high'
                            : p.priority === 'medium'
                            ? 'medium'
                            : 'low'
                        }
                        className="text-[10px]"
                      >
                        {p.priority}
                      </Badge>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Remediation Efficiency & Vulnerability Exposure */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Remediation Efficiency */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Zap className="h-5 w-5 text-green-500" />
                  Remediation Efficiency
                </CardTitle>
                <p className="text-sm text-muted-foreground mt-1">Last 30 days</p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <AlertCircle className="h-4 w-4 text-orange-500" />
                    <span className="text-sm text-muted-foreground">New Findings</span>
                  </div>
                  <p className="text-2xl font-bold">{remediationStats?.new_findings || 0}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Resolved</span>
                  </div>
                  <p className="text-2xl font-bold">{remediationStats?.resolved_findings || 0}</p>
                </div>
              </div>
              
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Resolution Rate</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-green-500 rounded-full transition-all duration-500"
                        style={{ width: `${Math.min(remediationStats?.resolution_rate || 0, 100)}%` }}
                      />
                    </div>
                    <span className="font-medium text-sm">{remediationStats?.resolution_rate || 0}%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">MTTR (Mean Time to Remediate)</span>
                  <span className="font-medium">
                    {remediationStats?.mttr_days != null 
                      ? `${remediationStats.mttr_days} days`
                      : '—'}
                  </span>
                </div>
                
                <div className="pt-3 border-t border-muted flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="text-center">
                      <Badge variant="critical" className="mb-1">Critical</Badge>
                      <p className="text-lg font-bold">{remediationStats?.open_critical || 0}</p>
                    </div>
                    <div className="text-center">
                      <Badge variant="high" className="mb-1">High</Badge>
                      <p className="text-lg font-bold">{remediationStats?.open_high || 0}</p>
                    </div>
                  </div>
                  {(remediationStats?.overdue_count || 0) > 0 && (
                    <div className="flex items-center gap-2 text-red-500">
                      <Clock className="h-4 w-4" />
                      <span className="text-sm font-medium">{remediationStats?.overdue_count} overdue</span>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Vulnerability Exposure */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Target className="h-5 w-5 text-red-500" />
                  Vulnerability Exposure
                </CardTitle>
                <p className="text-sm text-muted-foreground mt-1">Current attack surface risk</p>
              </div>
              <div className="flex items-center gap-2">
                {exposureStats?.exposure_trend === 'increasing' && (
                  <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                    <TrendingUp className="h-3 w-3 mr-1" /> Increasing
                  </Badge>
                )}
                {exposureStats?.exposure_trend === 'decreasing' && (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                    <TrendingDown className="h-3 w-3 mr-1" /> Decreasing
                  </Badge>
                )}
                {exposureStats?.exposure_trend === 'stable' && (
                  <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                    Stable
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold text-red-500">{exposureStats?.total_exposure_score || 0}</p>
                  <p className="text-xs text-muted-foreground">Exposure Score</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold">{exposureStats?.assets_with_vulnerabilities || 0}</p>
                  <p className="text-xs text-muted-foreground">Vulnerable Assets</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold">{exposureStats?.exposure_percentage || 0}%</p>
                  <p className="text-xs text-muted-foreground">Asset Exposure</p>
                </div>
              </div>
              
              {/* Severity Distribution — each label shares flex width with its color segment */}
              <div className="mb-4">
                <p className="text-sm text-muted-foreground mb-2">Open Vulnerabilities by Severity</p>
                <div className="flex gap-1.5">
                  {(
                    [
                      {
                        key: 'critical',
                        label: 'Critical',
                        color: 'bg-red-600',
                        count: exposureStats?.severity_distribution?.critical || 0,
                      },
                      {
                        key: 'high',
                        label: 'High',
                        color: 'bg-orange-500',
                        count: exposureStats?.severity_distribution?.high || 0,
                      },
                      {
                        key: 'medium',
                        label: 'Medium',
                        color: 'bg-yellow-500',
                        count: exposureStats?.severity_distribution?.medium || 0,
                      },
                      {
                        key: 'low',
                        label: 'Low',
                        color: 'bg-green-500',
                        count: exposureStats?.severity_distribution?.low || 0,
                      },
                    ] as const
                  ).map((seg) => (
                    <div
                      key={seg.key}
                      className="min-w-0 flex flex-col gap-1"
                      style={{ flexGrow: Math.max(seg.count, 1), flexBasis: 0 }}
                      title={`${seg.label}: ${seg.count}`}
                    >
                      <div className={`h-4 rounded ${seg.color}`} />
                      <span className="text-[10px] sm:text-xs text-muted-foreground truncate leading-tight">
                        {seg.label}: {seg.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Vulnerable Assets */}
              {exposureStats?.top_vulnerable_assets && exposureStats.top_vulnerable_assets.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Most Vulnerable Assets</p>
                  <div className="space-y-2">
                    {exposureStats.top_vulnerable_assets.slice(0, 5).map((asset) => (
                      <Link 
                        key={asset.asset_id} 
                        href={`/assets/${asset.asset_id}`}
                        className="flex items-center justify-between p-2 rounded bg-muted/50 hover:bg-muted transition-colors"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Globe className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-sm truncate">{asset.asset_name}</span>
                        </div>
                        <Badge variant="destructive" className="flex-shrink-0">
                          {asset.vulnerability_count}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Scan Coverage */}
        {netblockStats && (netblockStats.total_netblocks > 0 || netblockStats.total_ips > 0) && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <Network className="h-5 w-5" />
                Scan Coverage
              </CardTitle>
              <Link href="/netblocks">
                <Button variant="ghost" size="sm">
                  Manage CIDR Blocks <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Network className="h-4 w-4 text-primary" />
                    <span className="text-sm text-muted-foreground">CIDR Ranges</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.total_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Owned</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.owned_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className="h-4 w-4 text-blue-500" />
                    <span className="text-sm text-muted-foreground">In Scope</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.in_scope_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Globe className="h-4 w-4 text-purple-500" />
                    <span className="text-sm text-muted-foreground">Total IPs</span>
                  </div>
                  <p className="text-2xl font-bold">
                    {netblockStats.total_ips >= 1000000
                      ? `${(netblockStats.total_ips / 1000000).toFixed(1)}M`
                      : netblockStats.total_ips >= 1000
                      ? `${(netblockStats.total_ips / 1000).toFixed(1)}K`
                      : netblockStats.total_ips}
                  </p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Activity className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Scanned</span>
                  </div>
                  <p className="text-2xl font-bold">
                    {netblockStats.scanned_netblocks}/{netblockStats.total_netblocks}
                  </p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <XCircle className="h-4 w-4 text-orange-500" />
                    <span className="text-sm text-muted-foreground">Pending</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.unscanned_netblocks}</p>
                </div>
              </div>
              
              {/* Scan Progress Bar */}
              {netblockStats.total_netblocks > 0 && (
                <div className="mt-4">
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-muted-foreground">Scan Progress</span>
                    <span className="font-medium">
                      {Math.round((netblockStats.scanned_netblocks / netblockStats.total_netblocks) * 100)}%
                    </span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full transition-all duration-500"
                      style={{
                        width: `${(netblockStats.scanned_netblocks / netblockStats.total_netblocks) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Link href="/organizations">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Activity className="h-5 w-5" />
                  <span>New Organization</span>
                </Button>
              </Link>
              <Link href="/scans">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Shield className="h-5 w-5" />
                  <span>Run Scan</span>
                </Button>
              </Link>
              <Link href="/discovery">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Globe className="h-5 w-5" />
                  <span>Asset Discovery</span>
                </Button>
              </Link>
              <Link href="/screenshots">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Camera className="h-5 w-5" />
                  <span>Screenshots</span>
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}














