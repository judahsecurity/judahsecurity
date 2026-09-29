'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  GraphVisualization,
  GraphStats,
  GraphNode,
  GraphData,
} from '@/components/graph/GraphVisualization';
import { ThreatExposureCard } from '@/components/graph/ThreatExposureCard';
import { VulnerabilityExposureView } from '@/components/graph/VulnerabilityExposureView';
import {
  RefreshCw,
  GitBranch,
  Database,
  AlertTriangle,
  Search,
  Target,
  Route,
  Shield,
  CheckCircle,
  XCircle,
  Loader2,
  Layers,
  Cpu,
  Network,
  Server,
  ExternalLink,
  Lock,
  Globe,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface GraphStatus {
  connected: boolean;
  enabled: boolean;
  uri?: string;
  node_count?: number;
  relationship_count?: number;
}

interface Organization {
  id: number;
  name: string;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  asset_type: string;
}

export default function GraphPage() {
  const [status, setStatus] = useState<GraphStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [highlightPath, setHighlightPath] = useState<string[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('all');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [attackPathSource, setAttackPathSource] = useState<string>('');
  const [attackPathTarget, setAttackPathTarget] = useState<string>('');
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState('explorer');
  const [attackSurface, setAttackSurface] = useState<any>(null);
  const [techGrouping, setTechGrouping] = useState<any>(null);
  const [portGrouping, setPortGrouping] = useState<any>(null);
  const [attackSurfaceLoading, setAttackSurfaceLoading] = useState(false);
  const [discoverySources, setDiscoverySources] = useState<any[]>([]);
  const [discoveryGraphData, setDiscoveryGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const assetRequestId = useRef(0);
  const surfaceRequestId = useRef(0);
  const relationshipRequestId = useRef(0);
  const discoveryRequestId = useRef(0);
  const pathRequestId = useRef(0);
  const { toast } = useToast();

  const changeOrganization = (orgId: string) => {
    assetRequestId.current += 1;
    surfaceRequestId.current += 1;
    relationshipRequestId.current += 1;
    discoveryRequestId.current += 1;
    pathRequestId.current += 1;
    setSelectedOrg(orgId);
    setSelectedAssetId('');
    setSelectedNode(null);
    setGraphData({ nodes: [], links: [] });
    setDiscoveryGraphData({ nodes: [], links: [] });
    setHighlightPath([]);
    setAttackPaths([]);
    setAttackPathSource('');
    setAttackPathTarget('');
    setAttackSurface(null);
    setTechGrouping(null);
    setPortGrouping(null);
    setDiscoverySources([]);
    setAssets([]);
    setGraphLoading(false);
    setDiscoveryLoading(false);
    setAttackSurfaceLoading(false);
  };

  // Fetch graph status
  const fetchStatus = async () => {
    try {
      const data = await api.getGraphStatus();
      setStatus(data);
    } catch (error) {
      console.error('Failed to fetch graph status:', error);
      setStatus({ connected: false, enabled: false });
    } finally {
      setLoading(false);
    }
  };

  // Fetch organizations
  const fetchOrganizations = async () => {
    try {
      const data = await api.getOrganizations();
      setOrganizations(data);
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    }
  };

  // Fetch assets for dropdown
  const fetchAssets = async () => {
    const requestId = ++assetRequestId.current;
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const data = await api.getAssets({ 
        organization_id: orgId, 
        limit: 500,
        asset_type: 'domain'
      });
      if (requestId === assetRequestId.current) {
        setAssets(data.items || data || []);
      }
    } catch (error) {
      console.error('Failed to fetch assets:', error);
    }
  };

  // Sync graph data
  const handleSync = async () => {
    const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
    if (!orgId) return;
    setSyncing(true);
    try {
      const result = await api.syncGraph(orgId);
      if (result.error) throw new Error(result.error);
      toast({
        title: 'Graph Synced',
        description: `Synced ${result.assets_synced || 0} assets to Neo4j`,
      });
      await fetchStatus();
      const assetsRes = await api.getAssets({ organization_id: orgId, limit: 500 }).catch(() => ({ items: [] }));
      const assetsList = assetsRes?.items ?? assetsRes ?? [];
      setAssets(Array.isArray(assetsList) ? assetsList : []);
      if (selectedAssetId) {
        await loadAssetRelationships(parseInt(selectedAssetId));
        setActiveTab('explorer');
      } else {
        const first = Array.isArray(assetsList) ? assetsList[0] : undefined;
        if (first?.id != null) {
          setSelectedAssetId(String(first.id));
          await loadAssetRelationships(first.id);
          setActiveTab('explorer');
        }
      }
    } catch (error: any) {
      toast({
        title: 'Sync Failed',
        description: error?.response?.data?.detail || error?.message || 'Failed to sync graph data',
        variant: 'destructive',
      });
    } finally {
      setSyncing(false);
    }
  };

  // Load asset relationships
  const loadAssetRelationships = async (assetId: number) => {
    const requestId = ++relationshipRequestId.current;
    setGraphLoading(true);
    setHighlightPath([]);
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const data = await api.getAssetRelationships(assetId, 3, orgId);
      
      // Transform to graph format
      const nodes: GraphNode[] = data.nodes?.map((n: any) => ({
        id: n.id || n.element_id,
        label: graphNodeLabel(n),
        type: mapNeo4jLabelsToType(n.labels, n.properties?.asset_type),
        properties: n.properties,
      })) || [];
      
      const links = data.relationships?.map((r: any) => ({
        source: r.start_node || r.source,
        target: r.end_node || r.target,
        type: r.type,
        properties: r.properties,
      })) || [];
      
      if (requestId === relationshipRequestId.current) setGraphData({ nodes, links });
    } catch (error: any) {
      if (requestId === relationshipRequestId.current) {
        toast({
          title: 'Failed to load relationships',
          description: error?.response?.data?.detail || 'Could not fetch asset relationships',
          variant: 'destructive',
        });
        setGraphData({ nodes: [], links: [] });
      }
    } finally {
      if (requestId === relationshipRequestId.current) setGraphLoading(false);
    }
  };

  // Find attack paths
  const findAttackPaths = async () => {
    if (!attackPathSource || !attackPathTarget) {
      toast({
        title: 'Select Assets',
        description: 'Please select both source and target assets',
        variant: 'destructive',
      });
      return;
    }

    const requestId = ++pathRequestId.current;
    setGraphLoading(true);
    try {
      const data = await api.getAttackPaths({
        source_id: parseInt(attackPathSource),
        target_id: parseInt(attackPathTarget),
        organization_id: selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined,
        max_paths: 5,
      });
      if (requestId !== pathRequestId.current) return;
      
      setAttackPaths(data.paths || []);
      
      // Highlight first path if available
      if (data.paths && data.paths.length > 0) {
        const pathNodeIds = data.paths[0].nodes?.map((n: any) => n.id || n.element_id) || [];
        setHighlightPath(pathNodeIds);
        
        // Also update graph data to show the path
        const nodes: GraphNode[] = data.paths[0].nodes?.map((n: any) => ({
          id: n.id || n.element_id,
          label: graphNodeLabel(n),
          type: mapNeo4jLabelsToType(n.labels, n.properties?.asset_type),
          properties: n.properties,
        })) || [];
        
        const links = data.paths[0].relationships?.map((r: any) => ({
          source: r.start_node || r.source,
          target: r.end_node || r.target,
          type: r.type,
        })) || [];
        
        setGraphData({ nodes, links });
      }
      
      toast({
        title: 'Attack Paths Found',
        description: `Found ${data.paths?.length || 0} potential attack paths`,
      });
    } catch (error: any) {
      if (requestId !== pathRequestId.current) return;
      toast({
        title: 'Search Failed',
        description: error?.response?.data?.detail || 'Could not find attack paths',
        variant: 'destructive',
      });
    } finally {
      if (requestId === pathRequestId.current) setGraphLoading(false);
    }
  };

  // Fetch attack surface data (with fallback to PostgreSQL if Neo4j unavailable)
  const fetchAttackSurface = async () => {
    const requestId = ++surfaceRequestId.current;
    setAttackSurfaceLoading(true);
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      // If Neo4j is not connected, use PostgreSQL fallback
      const useFallback = !status?.connected;
      const [overview, techData, portData] = await Promise.all([
        api.getAttackSurfaceOverview(orgId, useFallback),
        api.getAssetsByTechnology({ organization_id: orgId }, useFallback),
        api.getAssetsByPort({ organization_id: orgId }, useFallback),
      ]);
      if (requestId === surfaceRequestId.current) {
        setAttackSurface(overview);
        setTechGrouping(techData);
        setPortGrouping(portData);
      }
    } catch (error) {
      console.error('Failed to fetch attack surface:', error);
      if (requestId === surfaceRequestId.current) {
        toast({
          title: 'Error loading attack surface',
          description: 'Failed to fetch grouping data. Try syncing the graph first.',
          variant: 'destructive',
        });
      }
    } finally {
      if (requestId === surfaceRequestId.current) setAttackSurfaceLoading(false);
    }
  };

  // Load discovery provenance for an asset
  const loadDiscoveryTree = async (assetId: number) => {
    const requestId = ++discoveryRequestId.current;
    setDiscoveryLoading(true);
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const data = await api.getDiscoveryTree(assetId, orgId);
      const nodes: GraphNode[] = (data.nodes || []).map((n: any) => ({
        id: n.id || n.element_id,
        label: graphNodeLabel(n),
        type: mapNeo4jLabelsToType(n.labels, n.properties?.asset_type),
        properties: n.properties,
      }));
      const links = (data.relationships || []).map((r: any) => ({
        source: r.start_node || r.source,
        target: r.end_node || r.target,
        type: r.type,
      }));
      if (requestId === discoveryRequestId.current) setDiscoveryGraphData({ nodes, links });
    } catch (error) {
      if (requestId === discoveryRequestId.current) console.error('Failed to load discovery tree:', error);
    } finally {
      if (requestId === discoveryRequestId.current) setDiscoveryLoading(false);
    }
  };

  // Load discovery sources summary
  const loadDiscoverySources = async () => {
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const data = await api.getDiscoverySources(orgId);
      setDiscoverySources(data.sources || []);
    } catch (error) {
      console.error('Failed to load discovery sources:', error);
    }
  };

  // Map Neo4j labels to our node types
  const graphNodeLabel = (node: any): string => {
    const properties = node.properties || {};
    return String(properties.value || properties.name || properties.url || properties.path ||
      properties.title || properties.display_name || properties.asn_number ||
      properties.package_name || properties.symbol_name || properties.sha ||
      properties.port || node.labels?.[0] || 'Unknown');
  };

  const mapNeo4jLabelsToType = (labels: string[] = [], assetType?: string): GraphNode['type'] => {
    const mapping: Record<string, GraphNode['type']> = {
      Domain: 'domain',
      Subdomain: 'subdomain',
      IP: 'ip',
      Port: 'port',
      Service: 'service',
      ServiceObservation: 'service_observation',
      Technology: 'technology',
      Vulnerability: 'vulnerability',
      CVE: 'cve',
      CWE: 'cwe',
      DiscoverySource: 'discovery_source',
      ASN: 'asn',
      HostingProvider: 'hosting_provider',
      Certificate: 'certificate',
      JSResource: 'script',
      Endpoint: 'endpoint',
      SourceFile: 'source_file',
      SourceRoute: 'source_route',
      CodeSymbol: 'code_symbol',
      PackageVersion: 'package',
      SourceCommit: 'source_commit',
      SourceRepository: 'source_repository',
      ChainFinding: 'memory',
    };
    // Asset also carries a more specific label, such as IP or Subdomain.
    for (const label of labels) {
      if (mapping[label]) return mapping[label];
    }
    if (assetType === 'SUBDOMAIN') return 'subdomain';
    if (assetType === 'IP_ADDRESS') return 'ip';
    if (assetType === 'PORT') return 'port';
    if (assetType === 'SERVICE') return 'service';
    if (assetType === 'URL' || assetType === 'API_ENDPOINT') return 'endpoint';
    return 'domain';
  };

  // Handle node click
  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
  };

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchOrganizations();
  }, []);

  // Fetch attack surface when tab changes or status is determined
  useEffect(() => {
    if (activeTab === 'attack-surface' && status !== null) {
      fetchAttackSurface();
    }
    if (activeTab === 'discovery' && status?.connected) {
      loadDiscoverySources();
    }
  }, [activeTab, status?.connected, selectedOrg]);

  // Fetch assets when org changes
  useEffect(() => {
    fetchAssets();
  }, [selectedOrg]);

  // Load relationships when asset is selected
  useEffect(() => {
    if (selectedAssetId) {
      loadAssetRelationships(parseInt(selectedAssetId));
    }
  }, [selectedAssetId]);

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-screen">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header 
        title="Asset Relationship Graph" 
        subtitle="Visualize connections between assets, vulnerabilities, and attack paths"
      />

      <div className="p-6 space-y-6">
        {/* Status Card */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Database className="h-5 w-5" />
                Neo4j Graph Database
              </CardTitle>
              <CardDescription>
                Relationship mapping for attack surface analysis
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant={status?.connected ? 'default' : 'destructive'}>
                {status?.connected ? (
                  <><CheckCircle className="h-3 w-3 mr-1" /> Connected</>
                ) : (
                  <><XCircle className="h-3 w-3 mr-1" /> Disconnected</>
                )}
              </Badge>
              <Button
                onClick={handleSync}
                disabled={syncing || !status?.connected || selectedOrg === 'all'}
                title={selectedOrg === 'all' ? 'Select an organization to sync (sync runs for one org at a time)' : undefined}
              >
                {syncing ? (
                  <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Syncing...</>
                ) : (
                  <><RefreshCw className="h-4 w-4 mr-2" /> Sync Data</>
                )}
              </Button>
            </div>
          </CardHeader>
          {status?.connected && (
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{status.node_count || 0}</div>
                  <div className="text-sm text-muted-foreground">Total Nodes</div>
                </div>
                <div className="p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{status.relationship_count || 0}</div>
                  <div className="text-sm text-muted-foreground">Relationships</div>
                </div>
              </div>
            </CardContent>
          )}
        </Card>

        {!status?.connected && (
          <Card className="border-yellow-500/50 bg-yellow-500/10">
            <CardContent className="pt-6">
              <div className="flex items-start gap-4">
                <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold text-yellow-500">Neo4j Not Connected (Using PostgreSQL)</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    The graph database is not connected. Attack Surface grouping still works using PostgreSQL.
                    For full graph visualization and attack path analysis, enable Neo4j:
                  </p>
                  <ol className="list-decimal list-inside text-sm text-muted-foreground mt-2 space-y-1">
                    <li>Set NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD environment variables</li>
                    <li>Start Neo4j with: <code className="bg-muted px-1 rounded">docker compose --profile graph up -d</code></li>
                    <li>Refresh this page, select an organization (not “All”), then click “Sync Data”</li>
                  </ol>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="attack-surface" className="flex items-center gap-2">
              <Layers className="h-4 w-4" />
              Attack Surface
            </TabsTrigger>
            {status?.connected && (
              <>
                <TabsTrigger value="discovery" className="flex items-center gap-2">
                  <Search className="h-4 w-4" />
                  Discovery
                </TabsTrigger>
                <TabsTrigger value="explorer" className="flex items-center gap-2">
                  <GitBranch className="h-4 w-4" />
                  Relationships
                </TabsTrigger>
                <TabsTrigger value="attack-paths" className="flex items-center gap-2">
                  <Route className="h-4 w-4" />
                  Attack Paths
                </TabsTrigger>
                <TabsTrigger value="impact" className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Vulnerability Impact
                </TabsTrigger>
              </>
            )}
          </TabsList>

            {/* Attack Surface Tab */}
            <TabsContent value="attack-surface" className="space-y-6">
              {/* Data-driven vulnerability exposure: sources → total (like threat exposure dashboards) */}
              <VulnerabilityExposureView />

              {attackSurfaceLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-8 w-8 animate-spin" />
                  <span className="ml-2 text-muted-foreground">Loading attack surface data...</span>
                </div>
              ) : (
                <>
                  {/* Threat exposure–style metric cards (glow circles + central value) */}
                  {attackSurface?.risk_distribution && (
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
                      <Card className="overflow-hidden">
                        <CardContent className="p-0">
                          <ThreatExposureCard
                            value={attackSurface.risk_distribution.total_assets ?? 0}
                            label="Total assets"
                            variant="info"
                            animate={true}
                          />
                        </CardContent>
                      </Card>
                      <Card className="overflow-hidden">
                        <CardContent className="p-0">
                          <ThreatExposureCard
                            value={attackSurface.risk_distribution.critical_risk ?? 0}
                            label="Critical risk"
                            variant="danger"
                            animate={false}
                          />
                        </CardContent>
                      </Card>
                      <Card className="overflow-hidden">
                        <CardContent className="p-0">
                          <ThreatExposureCard
                            value={attackSurface.risk_distribution.high_risk ?? 0}
                            label="High risk"
                            variant="warning"
                            animate={false}
                          />
                        </CardContent>
                      </Card>
                      <Card className="overflow-hidden">
                        <CardContent className="p-0">
                          <ThreatExposureCard
                            value={attackSurface.risk_distribution.medium_risk ?? 0}
                            label="Medium risk"
                            variant="neutral"
                            animate={false}
                          />
                        </CardContent>
                      </Card>
                      <Card className="overflow-hidden">
                        <CardContent className="p-0">
                          <ThreatExposureCard
                            value={attackSurface.risk_distribution.low_risk ?? 0}
                            label="Low risk"
                            variant="success"
                            animate={false}
                          />
                        </CardContent>
                      </Card>
                    </div>
                  )}

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Technology Grouping */}
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Cpu className="h-5 w-5 text-cyan-500" />
                            <CardTitle className="text-base">Technologies ({techGrouping?.total_technologies || 0})</CardTitle>
                          </div>
                        </div>
                        <CardDescription>Assets grouped by CMS, frameworks, and libraries</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {techGrouping?.technologies && techGrouping.technologies.length > 0 ? (
                          <div className="space-y-2 max-h-96 overflow-y-auto">
                            {techGrouping.technologies.map((tech: any, idx: number) => (
                              <div
                                key={idx}
                                className="p-3 bg-muted/50 rounded-lg hover:bg-muted transition-colors cursor-pointer"
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <span className="font-medium">{tech.technology}</span>
                                  <Badge variant="secondary">{tech.asset_count} assets</Badge>
                                </div>
                                {tech.categories && (
                                  <div className="text-xs text-muted-foreground mb-2">{tech.categories}</div>
                                )}
                                <div className="flex flex-wrap gap-1">
                                  {tech.assets?.slice(0, 5).map((asset: any, i: number) => (
                                    <Badge key={i} variant="outline" className="text-xs">
                                      {asset.value}
                                      {asset.has_login_portal && <Lock className="h-2 w-2 ml-1" />}
                                    </Badge>
                                  ))}
                                  {tech.assets?.length > 5 && (
                                    <Badge variant="outline" className="text-xs">
                                      +{tech.assets.length - 5} more
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center py-8 text-muted-foreground">
                            <Cpu className="h-8 w-8 mx-auto mb-2 opacity-50" />
                            <p>No technology data available</p>
                            <p className="text-xs">Sync data to populate</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    {/* Port Grouping */}
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Network className="h-5 w-5 text-amber-500" />
                            <CardTitle className="text-base">Open Ports ({portGrouping?.total_unique_ports || 0})</CardTitle>
                          </div>
                          {portGrouping?.risky_summary && (
                            <Badge variant="destructive" className="text-xs">
                              {portGrouping.risky_summary.risky_port_count} risky
                            </Badge>
                          )}
                        </div>
                        <CardDescription>Assets grouped by exposed ports and services</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {portGrouping?.ports && portGrouping.ports.length > 0 ? (
                          <div className="space-y-2 max-h-96 overflow-y-auto">
                            {portGrouping.ports.map((port: any, idx: number) => {
                              const isFiltered = port.state?.toLowerCase() === 'filtered' || port.verified_state?.toLowerCase() === 'filtered';
                              return (
                              <div
                                key={idx}
                                className={`p-3 rounded-lg hover:bg-muted transition-colors cursor-pointer ${
                                  isFiltered ? 'bg-yellow-500/10 border border-yellow-500/30' :
                                  port.is_risky ? 'bg-red-500/10 border border-red-500/30' : 'bg-muted/50'
                                }`}
                              >
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono font-bold">{port.port_number}</span>
                                    <span className="text-muted-foreground">/{port.protocol}</span>
                                    {port.service_name && (
                                      <Badge variant="outline" className="text-xs">{port.service_name}</Badge>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2">
                                    {isFiltered && (
                                      <AlertTriangle className="h-4 w-4 text-yellow-500" />
                                    )}
                                    {port.is_risky && !isFiltered && (
                                      <AlertTriangle className="h-4 w-4 text-red-500" />
                                    )}
                                    <Badge variant="secondary">{port.asset_count} assets</Badge>
                                  </div>
                                </div>
                                <div className="flex flex-wrap gap-1">
                                  {port.assets?.slice(0, 5).map((asset: any, i: number) => (
                                    <Badge key={i} variant="outline" className="text-xs font-mono">
                                      {asset.scanned_ip || asset.value}
                                    </Badge>
                                  ))}
                                  {port.assets?.length > 5 && (
                                    <Badge variant="outline" className="text-xs">
                                      +{port.assets.length - 5} more
                                    </Badge>
                                  )}
                                </div>
                              </div>
                              );
                            })}
                          </div>
                        ) : (
                          <div className="text-center py-8 text-muted-foreground">
                            <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
                            <p>No port data available</p>
                            <p className="text-xs">Run port scans to populate</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Entry Points */}
                    <Card>
                      <CardHeader>
                        <div className="flex items-center gap-2">
                          <Globe className="h-5 w-5 text-green-500" />
                          <CardTitle className="text-base">Entry Points</CardTitle>
                        </div>
                        <CardDescription>Live assets with open ports - potential attack entry points</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {attackSurface?.entry_points && attackSurface.entry_points.length > 0 ? (
                          <div className="space-y-2 max-h-80 overflow-y-auto">
                            {attackSurface.entry_points.map((entry: any, idx: number) => (
                              <div key={idx} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm">{entry.asset}</span>
                                  {entry.has_login && <Lock className="h-3 w-3 text-yellow-500" />}
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs">{entry.port_count} ports</Badge>
                                  {entry.critical_vulns > 0 && (
                                    <Badge variant="destructive" className="text-xs">
                                      {entry.critical_vulns} critical
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center py-6 text-muted-foreground">
                            <p>No entry points found</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    {/* High Value Targets */}
                    <Card>
                      <CardHeader>
                        <div className="flex items-center gap-2">
                          <Target className="h-5 w-5 text-red-500" />
                          <CardTitle className="text-base">High-Value Targets</CardTitle>
                        </div>
                        <CardDescription>Login portals and critical assets</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {attackSurface?.high_value_targets && attackSurface.high_value_targets.length > 0 ? (
                          <div className="space-y-2 max-h-80 overflow-y-auto">
                            {attackSurface.high_value_targets.map((target: any, idx: number) => (
                              <div key={idx} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm">{target.asset}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  {target.has_login && (
                                    <Badge className="text-xs bg-yellow-500/20 text-yellow-600 border-yellow-500/30">
                                      <Lock className="h-3 w-3 mr-1" />
                                      Login
                                    </Badge>
                                  )}
                                  {target.criticality === 'critical' && (
                                    <Badge variant="destructive" className="text-xs">Critical</Badge>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center py-6 text-muted-foreground">
                            <p>No high-value targets identified</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>

                  {/* Discovery Sources */}
                  {attackSurface?.discovery_sources && attackSurface.discovery_sources.length > 0 && (
                    <Card>
                      <CardHeader>
                        <div className="flex items-center gap-2">
                          <Search className="h-5 w-5" />
                          <CardTitle className="text-base">Discovery Sources</CardTitle>
                        </div>
                        <CardDescription>How assets were discovered</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-wrap gap-3">
                          {attackSurface.discovery_sources.map((source: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-2 p-2 bg-muted/50 rounded">
                              <span className="capitalize">{source.source?.replace(/_/g, ' ') || 'Unknown'}</span>
                              <Badge variant="secondary">{source.count}</Badge>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </>
              )}
            </TabsContent>

            {/* Discovery Provenance Tab (requires Neo4j) */}
            {status?.connected && (
            <TabsContent value="discovery" className="space-y-4">
              {/* Discovery source summary cards */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card className="lg:col-span-1">
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Search className="h-5 w-5 text-lime-500" />
                      <CardTitle className="text-base">Discovery Sources</CardTitle>
                    </div>
                    <CardDescription>How assets were found — registrar lookups, DNS enumeration, cert transparency</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {discoverySources.length > 0 ? (
                      <div className="space-y-2">
                        {discoverySources.map((src: any, i: number) => (
                          <div key={i} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                            <span className="text-sm">{src.display_name || src.source?.replace(/_/g, ' ')}</span>
                            <Badge variant="secondary">{src.asset_count} assets</Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-6 text-muted-foreground text-sm">
                        <Search className="h-6 w-6 mx-auto mb-2 opacity-40" />
                        Sync data to populate discovery sources
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-base">Asset Discovery Provenance</CardTitle>
                    <CardDescription>
                      Select an asset to visualize its discovery chain — registrar → domain → subdomain → IP → hosting provider → ASN
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex gap-4 mb-4">
                      <Select value={selectedOrg} onValueChange={changeOrganization}>
                        <SelectTrigger className="w-[180px]">
                          <SelectValue placeholder="Organization" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Organizations</SelectItem>
                          {organizations.map((org) => (
                            <SelectItem key={org.id} value={org.id.toString()}>{org.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Select
                        value={selectedAssetId}
                        onValueChange={(v) => {
                          setSelectedAssetId(v);
                          loadDiscoveryTree(parseInt(v));
                        }}
                      >
                        <SelectTrigger className="flex-1">
                          <SelectValue placeholder="Select an asset to trace..." />
                        </SelectTrigger>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id.toString()}>
                              {asset.value} ({asset.asset_type})
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Dashed-ring nodes (
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2.5 h-2.5 rounded-full border border-dashed border-lime-500 bg-lime-500/40" />
                        Discovery source
                      </span>,{' '}
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2.5 h-2.5 rounded-full border border-dashed border-teal-500 bg-teal-500/40" />
                        ASN
                      </span>,{' '}
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2.5 h-2.5 rounded-full border border-dashed border-indigo-500 bg-indigo-500/40" />
                        Hosting provider
                      </span>,{' '}
                      <span className="inline-flex items-center gap-1">
                        <span className="inline-block w-2.5 h-2.5 rounded-full border border-dashed border-pink-500 bg-pink-500/40" />
                        Certificate
                      </span>
                      ) represent provenance context, not scanned infrastructure.
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Discovery graph canvas */}
              <Card>
                <CardContent className="p-0">
                  <GraphVisualization
                    data={discoveryGraphData}
                    onNodeClick={handleNodeClick}
                    selectedNodeId={selectedNode?.id}
                    highlightPath={[]}
                    loading={discoveryLoading}
                    height={560}
                  />
                </CardContent>
              </Card>

              {/* Selected node details in discovery context */}
              {selectedNode && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: selectedNode.type === 'discovery_source' ? '#84cc16' : selectedNode.type === 'asn' ? '#14b8a6' : selectedNode.type === 'hosting_provider' ? '#6366f1' : selectedNode.type === 'certificate' ? '#ec4899' : '#6b7280' }} />
                      {selectedNode.label}
                      <Badge variant="outline" className="capitalize ml-1 text-xs">{selectedNode.type.replace('_', ' ')}</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                      {selectedNode.properties && Object.entries(selectedNode.properties)
                        .filter(([, v]) => v !== null && v !== undefined && String(v).trim() !== '')
                        .slice(0, 12)
                        .map(([key, value]) => (
                          <div key={key} className="bg-muted/50 rounded p-2">
                            <div className="text-xs text-muted-foreground mb-0.5">{key.replace(/_/g, ' ')}</div>
                            <div className="font-medium truncate">{String(value)}</div>
                          </div>
                        ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>
            )}

            {/* Relationship Explorer Tab (requires Neo4j) */}
            {status?.connected && (
            <TabsContent value="explorer" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Select Asset to Explore</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-4">
                    <Select value={selectedOrg} onValueChange={changeOrganization}>
                      <SelectTrigger className="w-[200px]">
                        <SelectValue placeholder="All Organizations" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Organizations</SelectItem>
                        {organizations.map((org) => (
                          <SelectItem key={org.id} value={org.id.toString()}>
                            {org.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <Select value={selectedAssetId} onValueChange={setSelectedAssetId}>
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Select an asset to explore..." />
                      </SelectTrigger>
                      <SelectContent>
                        {assets.map((asset) => (
                          <SelectItem key={asset.id} value={asset.id.toString()}>
                            {asset.value} ({asset.asset_type})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                {/* Graph Visualization */}
                <Card className="lg:col-span-3">
                  <CardContent className="p-0">
                    <GraphVisualization
                      data={graphData}
                      onNodeClick={handleNodeClick}
                      selectedNodeId={selectedNode?.id}
                      highlightPath={highlightPath}
                      loading={graphLoading}
                      height={600}
                    />
                  </CardContent>
                </Card>

                {/* Selected Node Details */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Node Details</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {selectedNode ? (
                      <div className="space-y-4">
                        <div>
                          <div className="text-sm text-muted-foreground">Label</div>
                          <div className="font-medium break-all">{selectedNode.label}</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground">Type</div>
                          <Badge variant="outline" className="capitalize">
                            {selectedNode.type}
                          </Badge>
                        </div>
                        {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                          <div>
                            <div className="text-sm text-muted-foreground mb-2">Properties</div>
                            <div className="space-y-2 text-sm">
                              {Object.entries(selectedNode.properties).map(([key, value]) => (
                                <div key={key} className="flex justify-between">
                                  <span className="text-muted-foreground">{key}</span>
                                  <span className="font-medium truncate max-w-[150px]">
                                    {String(value)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center text-muted-foreground py-8">
                        <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p>Click a node to view details</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            )}

            {/* Attack Paths Tab (requires Neo4j) */}
            {status?.connected && (
            <TabsContent value="attack-paths" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Find Attack Paths</CardTitle>
                  <CardDescription>
                    Discover potential attack paths between assets
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-4 items-end">
                    <div className="flex-1">
                      <label className="text-sm text-muted-foreground mb-2 block">
                        Source Asset (Entry Point)
                      </label>
                      <Select value={attackPathSource} onValueChange={setAttackPathSource}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select source asset..." />
                        </SelectTrigger>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id.toString()}>
                              {asset.value}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex-1">
                      <label className="text-sm text-muted-foreground mb-2 block">
                        Target Asset (Goal)
                      </label>
                      <Select value={attackPathTarget} onValueChange={setAttackPathTarget}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select target asset..." />
                        </SelectTrigger>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id.toString()}>
                              {asset.value}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <Button onClick={findAttackPaths} disabled={graphLoading}>
                      {graphLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <><Search className="h-4 w-4 mr-2" /> Find Paths</>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {attackPaths.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">
                      Found {attackPaths.length} Attack Path{attackPaths.length > 1 ? 's' : ''}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {attackPaths.map((path, index) => (
                        <div
                          key={index}
                          className="p-3 bg-muted/50 rounded-lg cursor-pointer hover:bg-muted"
                          onClick={() => {
                            const pathNodeIds = path.nodes?.map((n: any) => n.id || n.element_id) || [];
                            setHighlightPath(pathNodeIds);
                          }}
                        >
                          <div className="flex items-center gap-2 text-sm">
                            <Badge variant="outline">Path {index + 1}</Badge>
                            <span className="text-muted-foreground">
                              {path.nodes?.length || 0} nodes, {path.relationships?.length || 0} hops
                            </span>
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground flex items-center gap-1 flex-wrap">
                            {path.nodes?.map((node: any, i: number) => (
                              <span key={i} className="flex items-center gap-1">
                                <Badge variant="secondary" className="text-xs">
                                  {node.properties?.value || node.labels?.[0] || 'Unknown'}
                                </Badge>
                                {i < (path.nodes?.length || 0) - 1 && <span>→</span>}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardContent className="p-0">
                  <GraphVisualization
                    data={graphData}
                    onNodeClick={handleNodeClick}
                    selectedNodeId={selectedNode?.id}
                    highlightPath={highlightPath}
                    loading={graphLoading}
                    height={500}
                  />
                </CardContent>
              </Card>
            </TabsContent>
            )}

            {/* Vulnerability Impact Tab (requires Neo4j) */}
            {status?.connected && (
            <TabsContent value="impact" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Vulnerability Impact Analysis</CardTitle>
                  <CardDescription>
                    See which assets are affected by a vulnerability and understand the blast radius
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    Select a vulnerability from the Findings page to analyze its impact across your attack surface.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-0">
                  <GraphVisualization
                    data={graphData}
                    onNodeClick={handleNodeClick}
                    selectedNodeId={selectedNode?.id}
                    highlightPath={highlightPath}
                    loading={graphLoading}
                    height={500}
                  />
                </CardContent>
              </Card>
            </TabsContent>
            )}
          </Tabs>
      </div>
    </MainLayout>
  );
}
