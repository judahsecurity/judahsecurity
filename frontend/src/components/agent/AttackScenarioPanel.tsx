'use client';

import { useCallback, useEffect, useRef, useState, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ZoomIn, ZoomOut, Maximize2, ChevronRight, ChevronDown,
  CheckCircle, XCircle, AlertTriangle, Target, Loader2,
  Shield, Crosshair, Eye, ChevronLeft,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { TrustBoundaryMap, TRUST_COLORS } from './TrustBoundaryMap';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  ),
});

export interface ScenarioNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
  x?: number;
  y?: number;
}

export interface ScenarioEdge {
  source: string;
  target: string;
  type: string;
}

export interface AttackPath {
  assets?: string[];
  relationships?: string[];
  target_cve?: string;
  severity?: string;
  nodes?: { properties?: { value?: string }; labels?: string[] }[];
}

export interface ChainData {
  nodes: ScenarioNode[];
  edges: ScenarioEdge[];
  meta?: {
    session_id?: string;
    objective?: string;
    status?: string;
    step_count?: number;
    final_phase?: string;
  };
  attack_paths?: AttackPath[];
}

interface AttackScenarioPanelProps {
  chainData: ChainData | null;
  loading?: boolean;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

const NODE_COLORS: Record<string, string> = {
  chain: TRUST_COLORS.blue,
  step: TRUST_COLORS.purple,
  finding: TRUST_COLORS.green,
  finding_info: TRUST_COLORS.blue,
  finding_low: TRUST_COLORS.green,
  finding_medium: TRUST_COLORS.yellow,
  finding_high: TRUST_COLORS.orange,
  finding_critical: TRUST_COLORS.red,
  failure: TRUST_COLORS.red,
};

/** Phase → HF-inspired trust colors */
const PHASE_COLORS: Record<string, string> = {
  informational: TRUST_COLORS.green,
  reconnaissance: TRUST_COLORS.green,
  enumeration: TRUST_COLORS.gray,
  vulnerability_analysis: TRUST_COLORS.orange,
  exploitation: TRUST_COLORS.yellow,
  post_exploitation: TRUST_COLORS.purple,
  reporting: TRUST_COLORS.pink,
};

function stageColorForPhase(phase?: string): string {
  return PHASE_COLORS[(phase || '').toLowerCase()] || TRUST_COLORS.gray;
}

type ViewMode = 'map' | 'timeline' | 'graph';

export function AttackScenarioPanel({
  chainData,
  loading = false,
  collapsed = false,
  onToggleCollapse,
}: AttackScenarioPanelProps) {
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 400, height: 300 });
  const [selectedNode, setSelectedNode] = useState<ScenarioNode | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('map');
  const [hoveredNode, setHoveredNode] = useState<ScenarioNode | null>(null);

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: Math.max(280, containerRef.current.clientHeight || 300),
        });
      }
    };
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [collapsed, viewMode]);

  const graphData = useMemo(() => {
    if (!chainData) return { nodes: [], links: [] };
    return {
      nodes: chainData.nodes.map((n) => ({ ...n })),
      links: chainData.edges.map((e) => ({ ...e })),
    };
  }, [chainData]);

  const steps = useMemo(() => {
    if (!chainData) return [];
    return chainData.nodes
      .filter((n) => n.type !== 'chain' && !n.type.startsWith('finding'))
      .sort((a, b) => (a.properties?.iteration || 0) - (b.properties?.iteration || 0));
  }, [chainData]);

  const findings = useMemo(() => {
    if (!chainData) return [];
    return chainData.nodes.filter((n) => n.type.startsWith('finding'));
  }, [chainData]);

  const phases = useMemo(() => {
    const seen = setWithOrder(
      steps.map((s) => s.properties?.phase).filter((p): p is string => !!p)
    );
    return seen;
  }, [steps]);

  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = 10 / globalScale;
      const isSelected = selectedNode?.id === node.id;
      const isHovered = hoveredNode?.id === node.id;
      const color = node.type.startsWith('finding')
        ? NODE_COLORS[node.type] || NODE_COLORS.finding
        : stageColorForPhase(node.properties?.phase);

      let nodeSize = 6;
      if (node.type === 'chain') nodeSize = 10;
      if (node.type.startsWith('finding_critical') || node.type.startsWith('finding_high')) nodeSize = 8;

      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeSize, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      if (isSelected || isHovered) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 14;
      }
      ctx.fill();
      ctx.shadowBlur = 0;

      if (isSelected || isHovered) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5 / globalScale;
        ctx.stroke();
      }

      ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#d1d5db';
      const maxLen = 18;
      const display = label.length > maxLen ? label.substring(0, maxLen) + '...' : label;
      ctx.fillText(display, node.x, node.y + nodeSize + fontSize);
    },
    [selectedNode, hoveredNode]
  );

  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);
      const isProduced = link.type === 'PRODUCED';
      ctx.strokeStyle = isProduced ? TRUST_COLORS.red : '#4b5563';
      ctx.lineWidth = (isProduced ? 1.5 : 0.8) / globalScale;
      ctx.stroke();

      const dx = link.target.x - link.source.x;
      const dy = link.target.y - link.source.y;
      const angle = Math.atan2(dy, dx);
      const arrowLen = 4 / globalScale;
      const tx = link.target.x - Math.cos(angle) * 8;
      const ty = link.target.y - Math.sin(angle) * 8;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(tx - arrowLen * Math.cos(angle - Math.PI / 6), ty - arrowLen * Math.sin(angle - Math.PI / 6));
      ctx.lineTo(tx - arrowLen * Math.cos(angle + Math.PI / 6), ty - arrowLen * Math.sin(angle + Math.PI / 6));
      ctx.closePath();
      ctx.fillStyle = ctx.strokeStyle;
      ctx.fill();
    },
    []
  );

  const handleFitToScreen = () => {
    if (graphRef.current) graphRef.current.zoomToFit(300, 30);
  };

  if (collapsed) {
    return (
      <div className="w-10 shrink-0">
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggleCollapse}
          className="h-full w-10 p-0 flex flex-col items-center gap-1 text-muted-foreground hover:text-foreground"
          title="Show Attack Scenario"
        >
          <ChevronLeft className="h-4 w-4" />
          <span className="text-[10px]" style={{ writingMode: 'vertical-lr' }}>
            Attack Scenario
          </span>
        </Button>
      </div>
    );
  }

  const isEmpty = !chainData || chainData.nodes.length === 0;
  const isRunning = chainData?.meta?.status === 'running';

  return (
    <Card
      className={cn(
        'shrink-0 flex flex-col max-h-[calc(100vh-200px)] overflow-hidden border-border/60 bg-card transition-[width] duration-300',
        viewMode === 'map' ? 'w-[560px]' : 'w-[460px]'
      )}
    >
      <CardHeader className="pb-2 px-3 pt-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Crosshair className="h-4 w-4" style={{ color: TRUST_COLORS.orange }} />
            Attack Scenario
          </CardTitle>
          <div className="flex items-center gap-1">
            {chainData?.meta?.status && (
              <Badge
                variant="outline"
                className={cn(
                  'text-[10px] font-mono uppercase tracking-wide',
                  isRunning
                    ? 'text-amber-400 border-amber-400/60'
                    : 'text-emerald-400 border-emerald-400/60'
                )}
              >
                {chainData.meta.status}
              </Badge>
            )}
            <div className="flex border rounded-md overflow-hidden">
              {([
                ['map', 'Map'],
                ['timeline', 'Timeline'],
                ['graph', 'Force'],
              ] as const).map(([mode, label]) => (
                <Button
                  key={mode}
                  variant={viewMode === mode ? 'secondary' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode(mode)}
                  className="h-6 px-2 rounded-none text-[10px]"
                >
                  {label}
                </Button>
              ))}
            </div>
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onToggleCollapse}>
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
        {chainData?.meta?.objective && (
          <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2">
            {chainData.meta.objective}
          </p>
        )}
        {viewMode === 'map' && !isEmpty && (
          <p className="text-[10px] font-mono text-muted-foreground/80 mt-1">
            Attack chain across trust boundaries · nodes ignite as the agent reaches them
          </p>
        )}
      </CardHeader>

      <CardContent className="p-0 flex-1 overflow-hidden flex flex-col">
        {!isEmpty && (
          <div className="flex gap-3 px-3 py-1.5 border-b text-[10px] text-muted-foreground font-mono">
            <span className="flex items-center gap-1">
              <Target className="h-3 w-3" /> {steps.length} steps
            </span>
            <span className="flex items-center gap-1">
              <Shield className="h-3 w-3 text-emerald-500" /> {findings.length} findings
            </span>
            <span className="flex items-center gap-1">
              <Eye className="h-3 w-3" /> {phases.length} phases
            </span>
          </div>
        )}

        {isEmpty && !loading && (
          <div className="flex-1 flex items-center justify-center text-muted-foreground p-6">
            <div className="text-center">
              <Crosshair className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-xs">No attack scenario yet</p>
              <p className="text-[10px] mt-1 font-mono text-muted-foreground/70">
                chain map builds as the agent tests
              </p>
            </div>
          </div>
        )}

        {loading && isEmpty && (
          <div className="flex-1 flex items-center justify-center p-6">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {/* HF-style trust-boundary attack chain map */}
        {viewMode === 'map' && !isEmpty && (
          <div className="flex-1 min-h-0 flex flex-col">
            <TrustBoundaryMap
              steps={steps}
              findings={findings}
              isRunning={isRunning}
              className="flex-1 min-h-[360px]"
            />
            {chainData?.attack_paths && chainData.attack_paths.length > 0 && (
              <div className="border-t px-3 py-2 max-h-[120px] overflow-y-auto space-y-1.5 bg-[#070b12]">
                <p className="text-[10px] font-mono tracking-[0.14em] font-semibold" style={{ color: TRUST_COLORS.blue }}>
                  GRAPH PATHS · asset topology
                </p>
                {chainData.attack_paths.map((path, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border px-2 py-1.5 text-[10px]"
                    style={{ borderColor: `${TRUST_COLORS.blue}55`, background: 'rgba(2,6,23,0.7)' }}
                  >
                    <div className="flex items-center gap-1 mb-1">
                      <span className="font-mono" style={{ color: TRUST_COLORS.blue }}>PATH {idx + 1}</span>
                      {path.target_cve && (
                        <Badge variant="outline" className="text-[9px] text-rose-400 border-rose-400/50">
                          {path.target_cve}
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-1 font-mono text-slate-300">
                      {(path.assets || path.nodes?.map((n) => n.properties?.value || '?') || []).map(
                        (asset, ai, arr) => (
                          <span key={ai} className="flex items-center gap-1">
                            <span
                              className="rounded border px-1.5 py-0.5"
                              style={{
                                borderColor: `${TRUST_COLORS.blue}66`,
                                background: `${TRUST_COLORS.blue}18`,
                              }}
                            >
                              {String(asset)}
                            </span>
                            {ai < arr.length - 1 && <span className="text-slate-500">→</span>}
                          </span>
                        )
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Force graph (secondary) */}
        {viewMode === 'graph' && !isEmpty && (
          <div className="relative flex-1 min-h-[300px]" ref={containerRef}
            style={{
              backgroundColor: '#070b12',
              backgroundImage:
                'linear-gradient(rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.06) 1px, transparent 1px)',
              backgroundSize: '24px 24px',
            }}
          >
            <div className="absolute top-2 right-2 z-10 flex gap-1">
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() * 1.3, 300)}>
                <ZoomIn className="h-3 w-3" />
              </Button>
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() / 1.3, 300)}>
                <ZoomOut className="h-3 w-3" />
              </Button>
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={handleFitToScreen}>
                <Maximize2 className="h-3 w-3" />
              </Button>
            </div>
            {graphData.nodes.length > 0 && (
              <ForceGraph2D
                ref={graphRef}
                graphData={graphData}
                width={dimensions.width}
                height={dimensions.height}
                nodeCanvasObject={paintNode}
                linkCanvasObject={paintLink}
                nodeLabel={() => ''}
                onNodeClick={(node: any) => setSelectedNode(node)}
                onNodeHover={(node: any) => setHoveredNode(node)}
                cooldownTicks={80}
                onEngineStop={() => graphRef.current?.zoomToFit(300, 30)}
                enableNodeDrag={true}
                backgroundColor="rgba(0,0,0,0)"
                dagMode="td"
                dagLevelDistance={40}
              />
            )}
          </div>
        )}

        {/* Timeline view */}
        {viewMode === 'timeline' && !isEmpty && (
          <div className="flex-1 overflow-y-auto">
            <div className="px-3 py-2 space-y-0.5">
              {steps.map((step, idx) => {
                const props = step.properties || {};
                const isSuccess = props.success === true;
                const isFail = props.success === false;
                const stepFindings = (props.findings || []).filter((f: any) => f.type);
                const stepFailures = (props.failures || []).filter((f: any) => f.tool);
                const isExpanded = selectedNode?.id === step.id;

                return (
                  <div key={step.id}>
                    <div
                      className={`flex items-start gap-2 rounded-md px-2 py-1.5 cursor-pointer transition-colors hover:bg-muted/60 ${isExpanded ? 'bg-muted' : ''}`}
                      onClick={() => setSelectedNode(isExpanded ? null : step)}
                    >
                      <div className="flex flex-col items-center pt-0.5 shrink-0">
                        <div
                          className="w-2 h-2 rounded-full border-2"
                          style={{
                            borderColor: PHASE_COLORS[props.phase] || '#6b7280',
                            backgroundColor: isSuccess ? (PHASE_COLORS[props.phase] || '#6b7280') : 'transparent',
                          }}
                        />
                        {idx < steps.length - 1 && (
                          <div className="w-px h-full min-h-[16px] bg-border mt-0.5" />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          {isSuccess && <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />}
                          {isFail && <XCircle className="h-3 w-3 text-red-500 shrink-0" />}
                          {!isSuccess && !isFail && <Loader2 className="h-3 w-3 text-muted-foreground shrink-0 animate-spin" />}
                          <code className="text-[11px] font-medium truncate">{step.label}</code>
                          <Badge variant="outline" className="text-[9px] ml-auto shrink-0" style={{ color: PHASE_COLORS[props.phase] || '#6b7280', borderColor: PHASE_COLORS[props.phase] || '#6b7280' }}>
                            {(props.phase || '').replace(/_/g, ' ')}
                          </Badge>
                        </div>
                        {props.thought && (
                          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">
                            {props.thought}
                          </p>
                        )}
                        {stepFindings.length > 0 && (
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            {stepFindings.map((f: any, fi: number) => (
                              <Badge key={fi} variant="outline" className={`text-[9px] ${f.severity === 'critical' || f.severity === 'high' ? 'text-red-500 border-red-500' : 'text-emerald-500 border-emerald-500'}`}>
                                <AlertTriangle className="h-2.5 w-2.5 mr-0.5" /> {f.type}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      {isExpanded ? <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground mt-0.5" /> : <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground mt-0.5" />}
                    </div>

                    {isExpanded && (
                      <div className="ml-6 pl-2 border-l border-border mb-1 space-y-1">
                        {props.tool_args && (
                          <div className="text-[10px]">
                            <span className="text-muted-foreground font-medium">Args: </span>
                            <code className="text-[10px] bg-muted px-1 rounded break-all">{typeof props.tool_args === 'string' ? props.tool_args : JSON.stringify(props.tool_args)}</code>
                          </div>
                        )}
                        {props.output_summary && (
                          <div className="text-[10px]">
                            <span className="text-muted-foreground font-medium">Output: </span>
                            <span className="text-muted-foreground">{props.output_summary}</span>
                          </div>
                        )}
                        {stepFindings.map((f: any, fi: number) => (
                          <div key={fi} className="text-[10px] bg-red-500/5 border border-red-500/20 rounded p-1.5">
                            <span className="font-medium text-red-500">[{f.severity}] {f.type}: </span>
                            <span className="text-muted-foreground">{f.description}</span>
                          </div>
                        ))}
                        {stepFailures.map((f: any, fi: number) => (
                          <div key={fi} className="text-[10px] bg-amber-500/5 border border-amber-500/20 rounded p-1.5">
                            <span className="font-medium text-amber-500">Lesson: </span>
                            <span className="text-muted-foreground">{f.lesson || f.error}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {findings.length > 0 && (
                <div className="pt-2 border-t mt-2">
                  <p className="text-[10px] font-medium text-muted-foreground mb-1">Findings ({findings.length})</p>
                  {findings.map((f) => (
                    <div key={f.id} className="text-[10px] flex items-center gap-1 py-0.5">
                      <AlertTriangle className={`h-3 w-3 shrink-0 ${f.type.includes('critical') || f.type.includes('high') ? 'text-red-500' : 'text-emerald-500'}`} />
                      <span className="truncate">{f.label}</span>
                    </div>
                  ))}
                </div>
              )}

              {chainData?.attack_paths && chainData.attack_paths.length > 0 && (
                <div className="pt-2 border-t mt-2">
                  <p className="text-[10px] font-medium text-muted-foreground mb-1 flex items-center gap-1">
                    <Shield className="h-3 w-3" /> Attack Paths from Graph ({chainData.attack_paths.length})
                  </p>
                  {chainData.attack_paths.map((path, idx) => (
                    <div key={idx} className="text-[10px] bg-muted/50 rounded p-1.5 mb-1">
                      <div className="flex items-center gap-1 mb-0.5">
                        <Badge variant="outline" className="text-[9px]">Path {idx + 1}</Badge>
                        {path.target_cve && (
                          <Badge variant="outline" className="text-[9px] text-red-500 border-red-500">{path.target_cve}</Badge>
                        )}
                        {path.severity && (
                          <Badge variant="outline" className={`text-[9px] ${path.severity === 'critical' || path.severity === 'high' ? 'text-red-500 border-red-500' : 'text-amber-500 border-amber-500'}`}>{path.severity}</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-0.5 flex-wrap">
                        {(path.assets || path.nodes?.map((n) => n.properties?.value || n.labels?.[0] || '?') || []).map((asset, ai) => (
                          <span key={ai} className="flex items-center gap-0.5">
                            <Badge variant="secondary" className="text-[9px]">{typeof asset === 'string' ? asset : String(asset)}</Badge>
                            {ai < ((path.assets || path.nodes || []).length - 1) && <span className="text-muted-foreground">→</span>}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function setWithOrder(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    if (!seen.has(item)) {
      seen.add(item);
      out.push(item);
    }
  }
  return out;
}
