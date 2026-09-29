'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Target,
  AlertTriangle,
  Globe,
  Server,
  Shield,
  Cpu,
  Network,
  Search,
  Route,
  GitBranch,
} from 'lucide-react';

// Dynamically import ForceGraph2D to avoid SSR issues
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center">
      <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  ),
});

export interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'ip' | 'port' | 'service' | 'service_observation' | 'technology' | 'vulnerability' | 'cve' | 'cwe' | 'discovery_source' | 'asn' | 'hosting_provider' | 'certificate' | 'script' | 'endpoint' | 'source_file' | 'source_route' | 'code_symbol' | 'package' | 'source_commit' | 'source_repository' | 'memory';
  properties?: Record<string, any>;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
  properties?: Record<string, any>;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

interface GraphVisualizationProps {
  data: GraphData;
  onNodeClick?: (node: GraphNode) => void;
  onNodeHover?: (node: GraphNode | null) => void;
  selectedNodeId?: string | null;
  highlightPath?: string[];
  loading?: boolean;
  height?: number;
}

// Node colors by type
const NODE_COLORS: Record<string, string> = {
  // Technical topology
  domain: '#3b82f6',          // blue
  subdomain: '#60a5fa',       // light blue
  ip: '#8b5cf6',              // purple
  port: '#f59e0b',            // amber
  service: '#10b981',         // emerald
  technology: '#06b6d4',      // cyan
  vulnerability: '#ef4444',   // red
  cve: '#dc2626',             // dark red
  cwe: '#f97316',             // orange
  // Discovery provenance layer
  discovery_source: '#84cc16', // lime green
  asn: '#14b8a6',             // teal
  hosting_provider: '#6366f1', // indigo
  certificate: '#ec4899',     // pink
  service_observation: '#34d399',
  script: '#facc15',
  endpoint: '#fb923c',
  source_file: '#38bdf8',
  source_route: '#2dd4bf',
  code_symbol: '#a78bfa',
  package: '#c084fc',
  source_commit: '#94a3b8',
  source_repository: '#64748b',
  memory: '#f472b6',
};

// Node sizes by type (relative importance in the graph)
const NODE_SIZES: Record<string, number> = {
  domain: 10,
  subdomain: 7,
  ip: 8,
  port: 5,
  service: 5,
  technology: 7,
  vulnerability: 9,
  cve: 8,
  cwe: 7,
  discovery_source: 12,  // larger — anchor nodes in provenance view
  asn: 11,
  hosting_provider: 11,
  certificate: 9,
  service_observation: 5,
  script: 8,
  endpoint: 7,
  source_file: 8,
  source_route: 7,
  code_symbol: 5,
  package: 6,
  source_commit: 9,
  source_repository: 10,
  memory: 8,
};

// Node icons by type
const NODE_ICONS: Record<string, React.ElementType> = {
  domain: Globe,
  subdomain: Globe,
  ip: Server,
  port: Network,
  service: Cpu,
  technology: Cpu,
  vulnerability: AlertTriangle,
  cve: Shield,
  cwe: AlertTriangle,
  discovery_source: Search,
  asn: Network,
  hosting_provider: Server,
  certificate: Shield,
  service_observation: Server,
  script: Cpu,
  endpoint: Network,
  source_file: Cpu,
  source_route: Route,
  code_symbol: Cpu,
  package: Cpu,
  source_commit: GitBranch,
  source_repository: GitBranch,
  memory: Shield,
};

export function GraphVisualization({
  data,
  onNodeClick,
  onNodeHover,
  selectedNodeId,
  highlightPath = [],
  loading = false,
  height = 600,
}: GraphVisualizationProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height });
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: height,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [height]);

  // Node paint function
  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = 12 / globalScale;
      const nodeSize = (NODE_SIZES[node.type] || 8);
      const color = NODE_COLORS[node.type] || '#6b7280';

      const isSelected = selectedNodeId === node.id;
      const isHighlighted = highlightPath.includes(node.id);
      const isHovered = hoveredNode?.id === node.id;
      const isVulnerable = node.type === 'vulnerability' || node.type === 'cve';

      // Glow for highlighted / vulnerable / selected nodes
      if (isSelected || isHighlighted || isVulnerable) {
        ctx.shadowColor = color;
        ctx.shadowBlur = isSelected ? 20 : isVulnerable ? 10 : 14;
      }

      // Draw node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeSize, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Draw ring for discovery-layer nodes (dashed outer ring)
      const isProvenance = ['discovery_source', 'asn', 'hosting_provider', 'certificate'].includes(node.type);
      if (isProvenance) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeSize + 3 / globalScale, 0, 2 * Math.PI);
        ctx.strokeStyle = color;
        ctx.lineWidth = 1 / globalScale;
        ctx.setLineDash([3 / globalScale, 2 / globalScale]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Solid border for selected/hovered nodes
      if (isSelected || isHovered) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeSize + 2 / globalScale, 0, 2 * Math.PI);
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      // Draw label (only when zoomed in enough)
      if (globalScale > 0.6) {
        ctx.font = `${fontSize}px Sans-Serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#e5e7eb';
        const maxLength = 22;
        const displayLabel = label.length > maxLength ? label.substring(0, maxLength) + '…' : label;
        ctx.fillText(displayLabel, node.x, node.y + nodeSize + fontSize);
      }
    },
    [selectedNodeId, highlightPath, hoveredNode]
  );

  // Link paint function
  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      
      const isHighlighted = highlightPath.includes(sourceId) && highlightPath.includes(targetId);
      
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);
      
      ctx.strokeStyle = isHighlighted ? '#ef4444' : '#4b5563';
      ctx.lineWidth = isHighlighted ? 2 / globalScale : 1 / globalScale;
      ctx.stroke();
    },
    [highlightPath]
  );

  // Zoom controls
  const handleZoomIn = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom * 1.3, 300);
    }
  };

  const handleZoomOut = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom / 1.3, 300);
    }
  };

  const handleFitToScreen = () => {
    if (graphRef.current) {
      graphRef.current.zoomToFit(400, 50);
    }
  };

  const handleCenterOnNode = (nodeId: string) => {
    if (graphRef.current) {
      const node = data.nodes.find(n => n.id === nodeId);
      if (node && node.x !== undefined && node.y !== undefined) {
        graphRef.current.centerAt(node.x, node.y, 500);
        graphRef.current.zoom(2, 500);
      }
    }
  };

  // Center on selected node when it changes
  useEffect(() => {
    if (selectedNodeId) {
      handleCenterOnNode(selectedNodeId);
    }
  }, [selectedNodeId]);

  return (
    <div className="relative" ref={containerRef}>
      {/* Controls */}
      <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
        <Button
          variant="secondary"
          size="icon"
          onClick={handleZoomIn}
          className="bg-background/80 backdrop-blur"
        >
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          onClick={handleZoomOut}
          className="bg-background/80 backdrop-blur"
        >
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          onClick={handleFitToScreen}
          className="bg-background/80 backdrop-blur"
        >
          <Maximize2 className="h-4 w-4" />
        </Button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 bg-background/80 backdrop-blur rounded-lg p-3 max-w-[260px] max-h-48 overflow-y-auto">
        <div className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wide">Legend</div>
        <div className="mb-2">
          <div className="text-xs text-muted-foreground mb-1">Infrastructure</div>
          <div className="grid grid-cols-3 gap-x-3 gap-y-1 text-xs">
            {(['domain', 'subdomain', 'ip', 'port', 'service', 'technology'] as const).map((type) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: NODE_COLORS[type] }} />
                <span className="capitalize truncate">{type}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="mb-2">
          <div className="text-xs text-muted-foreground mb-1">Vulnerabilities</div>
          <div className="grid grid-cols-3 gap-x-3 gap-y-1 text-xs">
            {(['vulnerability', 'cve', 'cwe'] as const).map((type) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: NODE_COLORS[type] }} />
                <span className="capitalize truncate">{type}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground mb-1">Discovery Provenance</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            {(['discovery_source', 'asn', 'hosting_provider', 'certificate'] as const).map((type) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full border border-dashed flex-shrink-0" style={{ backgroundColor: NODE_COLORS[type], borderColor: NODE_COLORS[type] }} />
                <span className="capitalize truncate">{type.replace('_', ' ')}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-2">
          <div className="text-xs text-muted-foreground mb-1">Web, Code &amp; Memory</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            {(['script', 'endpoint', 'source_file', 'source_route', 'package', 'memory'] as const).map((type) => (
              <div key={type} className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: NODE_COLORS[type] }} />
                <span className="capitalize truncate">{type.replace('_', ' ')}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Hovered node info */}
      {hoveredNode && (
        <div className="absolute top-4 left-4 z-10 bg-background/95 backdrop-blur rounded-lg p-3 max-w-xs">
          <div className="flex items-center gap-2 mb-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: NODE_COLORS[hoveredNode.type] }}
            />
            <span className="font-medium text-sm">{hoveredNode.label}</span>
          </div>
          <Badge variant="outline" className="text-xs capitalize">
            {hoveredNode.type}
          </Badge>
          {hoveredNode.properties && Object.keys(hoveredNode.properties).length > 0 && (
            <div className="mt-2 text-xs text-muted-foreground space-y-1">
              {Object.entries(hoveredNode.properties).slice(0, 5).map(([key, value]) => (
                <div key={key}>
                  <span className="font-medium">{key}:</span> {String(value).substring(0, 50)}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Loading overlay */}
      {loading && (
        <div className="absolute inset-0 bg-background/50 flex items-center justify-center z-20">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
        </div>
      )}

      {/* Graph */}
      {data.nodes.length > 0 ? (
        <ForceGraph2D
          ref={graphRef}
          graphData={data}
          width={dimensions.width}
          height={dimensions.height}
          nodeCanvasObject={paintNode}
          linkCanvasObject={paintLink}
          nodeLabel={() => ''}
          onNodeClick={(node: any) => onNodeClick?.(node as GraphNode)}
          onNodeHover={(node: any) => {
            setHoveredNode(node as GraphNode | null);
            onNodeHover?.(node as GraphNode | null);
          }}
          cooldownTicks={100}
          onEngineStop={() => graphRef.current?.zoomToFit(400, 50)}
          enableNodeDrag={true}
          backgroundColor="transparent"
        />
      ) : (
        <div
          className="flex items-center justify-center text-muted-foreground"
          style={{ height: dimensions.height }}
        >
          <div className="text-center">
            <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No graph data available</p>
            <p className="text-sm mt-2">Sync data from PostgreSQL to Neo4j first</p>
          </div>
        </div>
      )}
    </div>
  );
}

// Stats card for graph overview
interface GraphStatsProps {
  stats: {
    total_nodes: number;
    total_relationships: number;
    node_types: Record<string, number>;
    relationship_types: Record<string, number>;
  };
}

export function GraphStats({ stats }: GraphStatsProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{stats.total_nodes}</div>
          <div className="text-sm text-muted-foreground">Total Nodes</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{stats.total_relationships}</div>
          <div className="text-sm text-muted-foreground">Relationships</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{Object.keys(stats.node_types).length}</div>
          <div className="text-sm text-muted-foreground">Node Types</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{Object.keys(stats.relationship_types).length}</div>
          <div className="text-sm text-muted-foreground">Relationship Types</div>
        </CardContent>
      </Card>
    </div>
  );
}
