'use client';

import { useEffect, useMemo, useState } from 'react';
import { Pause, Play, RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

/** Minimal step/finding shape used by the map (avoids circular imports). */
export interface MapScenarioNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
}

/** HF-inspired trust-boundary palette */
export const TRUST_COLORS = {
  green: '#34d399',
  gray: '#94a3b8',
  orange: '#fb923c',
  yellow: '#fbbf24',
  red: '#f87171',
  salmon: '#fb7185',
  purple: '#c084fc',
  pink: '#f472b6',
  blue: '#60a5fa',
  bg: '#070b12',
} as const;

type ZoneId = 'external' | 'surface' | 'target' | 'perimeter' | 'internal';

interface MapNode {
  id: string;
  zone: ZoneId;
  x: number;
  y: number;
  w: number;
  h: number;
  tag: string;
  title: string;
  sub: string;
  color: string;
  /** fraction 0–1 when this node ignites */
  frac: number;
  phases: string[];
}

interface MapEdge {
  id: string;
  d: string;
  color: string;
  dst: number;
  label?: string;
  lx?: number;
  ly?: number;
}

interface MapZone {
  id: ZoneId;
  x: number;
  y: number;
  w: number;
  h: number;
  color: string;
  label: string;
  keys: string[];
}

const ZONES: MapZone[] = [
  {
    id: 'external',
    x: 16,
    y: 44,
    w: 200,
    h: 108,
    color: TRUST_COLORS.green,
    label: 'External · internet',
    keys: ['n1', 'n2'],
  },
  {
    id: 'surface',
    x: 228,
    y: 44,
    w: 148,
    h: 108,
    color: TRUST_COLORS.gray,
    label: 'Attack surface',
    keys: ['n3'],
  },
  {
    id: 'target',
    x: 388,
    y: 40,
    w: 168,
    h: 116,
    color: TRUST_COLORS.orange,
    label: 'Target · probed',
    keys: ['n4'],
  },
  {
    id: 'perimeter',
    x: 388,
    y: 200,
    w: 168,
    h: 100,
    color: TRUST_COLORS.yellow,
    label: 'Perimeter breach',
    keys: ['n5'],
  },
  {
    id: 'internal',
    x: 16,
    y: 340,
    w: 540,
    h: 108,
    color: TRUST_COLORS.red,
    label: 'Impact · blast radius',
    keys: ['n6', 'n7', 'n8'],
  },
];

const NODES: MapNode[] = [
  {
    id: 'n1',
    zone: 'external',
    x: 28,
    y: 68,
    w: 84,
    h: 64,
    tag: 'START',
    title: 'Agent',
    sub: 'objective set',
    color: TRUST_COLORS.green,
    frac: 0,
    phases: ['informational'],
  },
  {
    id: 'n2',
    zone: 'external',
    x: 122,
    y: 68,
    w: 82,
    h: 64,
    tag: 'RECON',
    title: 'Discovery',
    sub: 'DNS · assets',
    color: TRUST_COLORS.green,
    frac: 0.08,
    phases: ['reconnaissance'],
  },
  {
    id: 'n3',
    zone: 'surface',
    x: 242,
    y: 68,
    w: 120,
    h: 64,
    tag: 'SURFACE',
    title: 'Open services',
    sub: 'ports · tech',
    color: TRUST_COLORS.gray,
    frac: 0.2,
    phases: ['enumeration'],
  },
  {
    id: 'n4',
    zone: 'target',
    x: 402,
    y: 64,
    w: 140,
    h: 72,
    tag: 'PROBE',
    title: 'Weak points',
    sub: 'vuln analysis',
    color: TRUST_COLORS.orange,
    frac: 0.38,
    phases: ['vulnerability_analysis'],
  },
  {
    id: 'n5',
    zone: 'perimeter',
    x: 402,
    y: 222,
    w: 140,
    h: 60,
    tag: 'VALIDATE',
    title: 'Exploit proof',
    sub: 'confirmed access',
    color: TRUST_COLORS.yellow,
    frac: 0.58,
    phases: ['exploitation'],
  },
  {
    id: 'n6',
    zone: 'internal',
    x: 28,
    y: 368,
    w: 150,
    h: 60,
    tag: 'PIVOT',
    title: 'Post-exploit',
    sub: 'session · creds',
    color: TRUST_COLORS.salmon,
    frac: 0.72,
    phases: ['post_exploitation'],
  },
  {
    id: 'n7',
    zone: 'internal',
    x: 198,
    y: 368,
    w: 160,
    h: 60,
    tag: 'LATERAL',
    title: 'Internal path',
    sub: 'adjacent assets',
    color: TRUST_COLORS.purple,
    frac: 0.84,
    phases: ['post_exploitation'],
  },
  {
    id: 'n8',
    zone: 'internal',
    x: 378,
    y: 368,
    w: 160,
    h: 60,
    tag: 'FINDINGS',
    title: 'Crown jewels',
    sub: 'impact recorded',
    color: TRUST_COLORS.pink,
    frac: 0.94,
    phases: ['reporting'],
  },
];

const EDGES: MapEdge[] = [
  {
    id: 'e1',
    d: 'M112,100 L122,100',
    color: TRUST_COLORS.green,
    dst: 0.08,
    label: 'scope',
    lx: 117,
    ly: 92,
  },
  {
    id: 'e2',
    d: 'M204,100 L242,100',
    color: TRUST_COLORS.gray,
    dst: 0.2,
  },
  {
    id: 'e3',
    d: 'M362,100 L402,100',
    color: TRUST_COLORS.orange,
    dst: 0.38,
    label: 'probe',
    lx: 382,
    ly: 92,
  },
  {
    id: 'e4',
    d: 'M472,136 L472,222',
    color: TRUST_COLORS.orange,
    dst: 0.58,
  },
  {
    id: 'e5',
    d: 'M402,252 C280,280 180,320 103,368',
    color: TRUST_COLORS.salmon,
    dst: 0.72,
  },
  {
    id: 'e6',
    d: 'M472,282 C460,320 360,348 278,368',
    color: TRUST_COLORS.purple,
    dst: 0.84,
  },
  {
    id: 'e7',
    d: 'M358,398 L378,398',
    color: TRUST_COLORS.pink,
    dst: 0.94,
    label: 'impact',
    lx: 368,
    ly: 390,
  },
];

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function phaseProgress(steps: MapScenarioNode[], findingsCount: number): number {
  if (!steps.length && !findingsCount) return 0;
  const order = [
    'informational',
    'reconnaissance',
    'enumeration',
    'vulnerability_analysis',
    'exploitation',
    'post_exploitation',
    'reporting',
  ];
  let maxIdx = -1;
  for (const step of steps) {
    const p = (step.properties?.phase || '').toLowerCase();
    const idx = order.indexOf(p);
    if (idx > maxIdx) maxIdx = idx;
  }
  if (findingsCount > 0) maxIdx = Math.max(maxIdx, order.indexOf('reporting'));
  if (maxIdx < 0) return steps.length ? 0.12 : 0;
  return clamp((maxIdx + 1) / order.length, 0.05, 1);
}

function nodeLiveFromSteps(node: MapNode, steps: MapScenarioNode[], findingsCount: number): boolean {
  if (node.id === 'n1') return steps.length > 0 || findingsCount > 0;
  if (node.id === 'n8') return findingsCount > 0 || steps.some((s) => s.properties?.phase === 'reporting');
  if (node.id === 'n7') {
    return steps.some(
      (s) =>
        s.properties?.phase === 'post_exploitation' &&
        (String(s.label || '').toLowerCase().includes('lateral') ||
          String(s.properties?.thought || '').toLowerCase().includes('lateral') ||
          steps.filter((x) => x.properties?.phase === 'post_exploitation').length > 1)
    );
  }
  return steps.some((s) => node.phases.includes((s.properties?.phase || '').toLowerCase()));
}

interface TrustBoundaryMapProps {
  steps: MapScenarioNode[];
  findings: MapScenarioNode[];
  isRunning?: boolean;
  className?: string;
}

export function TrustBoundaryMap({
  steps,
  findings,
  isRunning = false,
  className,
}: TrustBoundaryMapProps) {
  const autoT = useMemo(
    () => phaseProgress(steps, findings.length),
    [steps, findings.length]
  );

  const [playing, setPlaying] = useState(false);
  const [scrub, setScrub] = useState(1); // 1 = live tip
  const [manual, setManual] = useState(false);

  // Follow live progress unless user is scrubbing
  useEffect(() => {
    if (!manual) setScrub(1);
  }, [autoT, manual]);

  const t = scrub * autoT;

  useEffect(() => {
    if (!playing) return;
    setManual(true);
    let raf = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const dt = (now - last) / 1000;
      last = now;
      setScrub((prev) => {
        const next = prev + dt * 0.35;
        if (next >= 1) {
          setPlaying(false);
          return 1;
        }
        return next;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing]);

  const liveById = useMemo(() => {
    const map: Record<string, boolean> = {};
    for (const n of NODES) {
      // Progressive reveal by scrub + actual chain evidence
      const evidenced = nodeLiveFromSteps(n, steps, findings.length);
      map[n.id] = evidenced && t >= n.frac - 0.001;
    }
    return map;
  }, [steps, findings.length, t]);

  const frontier = useMemo(() => {
    let id = 'n1';
    for (const n of NODES) {
      if (liveById[n.id]) id = n.id;
    }
    return id;
  }, [liveById]);

  const frontierCenter = useMemo(() => {
    const n = NODES.find((x) => x.id === frontier) || NODES[0];
    return { cx: n.x + n.w / 2, cy: n.y + n.h / 2 };
  }, [frontier]);

  const edgeLens = useMemo(() => {
    // Approximate path lengths for dash animation (good enough for UX)
    const lens: Record<string, number> = {};
    for (const e of EDGES) {
      if (e.d.includes('C')) lens[e.id] = 180;
      else if (e.d.includes('L') && e.d.split('L').length > 2) lens[e.id] = 90;
      else lens[e.id] = 48;
    }
    lens.e4 = 86;
    lens.e5 = 220;
    lens.e6 = 200;
    return lens;
  }, []);

  const stepHint = useMemo(() => {
    if (!steps.length) return 'awaiting first action';
    const last = steps[steps.length - 1];
    const phase = (last.properties?.phase || 'recon').replace(/_/g, ' ');
    return `${phase} · ${last.label}`;
  }, [steps]);

  return (
    <div className={cn('flex flex-col h-full min-h-0', className)}>
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
        <Button
          variant="secondary"
          size="icon"
          className="h-7 w-7"
          onClick={() => {
            setManual(true);
            if (scrub >= 1) setScrub(0);
            setPlaying((p) => !p);
          }}
          title={playing ? 'Pause' : 'Play replay'}
        >
          {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={() => {
            setPlaying(false);
            setManual(false);
            setScrub(1);
          }}
          title="Jump to live tip"
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </Button>
        <input
          type="range"
          min={0}
          max={1}
          step={0.01}
          value={scrub}
          onChange={(e) => {
            setPlaying(false);
            setManual(true);
            setScrub(Number(e.target.value));
          }}
          className="flex-1 h-1 accent-orange-400 cursor-pointer"
          aria-label="Attack chain scrubber"
        />
        <span className="text-[10px] font-mono text-slate-400 tabular-nums w-10 text-right">
          {Math.round(t * 100)}%
        </span>
      </div>

      <div
        className="flex-1 overflow-auto relative"
        style={{
          backgroundColor: TRUST_COLORS.bg,
          backgroundImage:
            'linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)',
          backgroundSize: '20px 20px',
        }}
      >
        <svg
          viewBox="0 0 572 460"
          className="w-full h-auto min-w-[480px]"
          role="img"
          aria-label="Attack chain across trust boundaries"
        >
          <defs>
            <filter id="nodeGlow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Stage captions */}
          <text x="20" y="28" fill={TRUST_COLORS.green} fontSize="9" fontFamily="ui-monospace, Menlo, monospace" fontWeight="600" letterSpacing="0.08em">
            STAGE 1 · mapping the surface
          </text>
          <text x="556" y="188" textAnchor="end" fill={TRUST_COLORS.orange} fontSize="9" fontFamily="ui-monospace, Menlo, monospace" fontWeight="600" letterSpacing="0.06em">
            STAGE 2 · proving impact
          </text>
          <text x="556" y="202" textAnchor="end" fill={TRUST_COLORS.blue} fontSize="8" fontFamily="ui-monospace, Menlo, monospace">
            findings feed the blast radius
          </text>

          {/* Zones */}
          {ZONES.map((z) => {
            const hot = z.keys.some((k) => liveById[k]);
            return (
              <g key={z.id} opacity={hot ? 1 : 0.35}>
                <rect
                  x={z.x}
                  y={z.y}
                  width={z.w}
                  height={z.h}
                  rx={12}
                  fill={hot ? `${z.color}14` : 'rgba(15,23,42,0.55)'}
                  stroke={hot ? z.color : `${z.color}55`}
                  strokeWidth={hot ? 1.4 : 1}
                  style={{
                    filter: hot ? `drop-shadow(0 0 10px ${z.color}55)` : undefined,
                  }}
                />
                <text
                  x={z.x + 10}
                  y={z.y + 14}
                  fill={z.color}
                  fontSize="8"
                  fontFamily="ui-monospace, Menlo, monospace"
                  fontWeight="600"
                  letterSpacing="0.04em"
                >
                  {z.label}
                </text>
              </g>
            );
          })}

          {/* Edges: base + lit */}
          {EDGES.map((e) => {
            const len = edgeLens[e.id] || 60;
            const window = Math.min(0.06, e.dst || 0.06);
            const prog = clamp((t - (e.dst - window)) / window, 0, 1);
            const lit = prog > 0;
            return (
              <g key={e.id}>
                <path
                  d={e.d}
                  fill="none"
                  stroke="rgba(148,163,184,0.22)"
                  strokeWidth={1.5}
                  strokeLinecap="round"
                />
                <path
                  d={e.d}
                  fill="none"
                  stroke={e.color}
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeDasharray={len}
                  strokeDashoffset={len * (1 - prog)}
                  opacity={lit ? 0.95 : 0}
                  style={{
                    filter: lit ? `drop-shadow(0 0 4px ${e.color})` : undefined,
                    transition: playing ? 'none' : 'stroke-dashoffset 0.35s ease-out',
                  }}
                />
                {e.label && (
                  <text
                    x={e.lx}
                    y={e.ly}
                    textAnchor="middle"
                    fill={prog > 0.5 ? e.color : '#64748b'}
                    fontSize="8"
                    fontFamily="ui-monospace, Menlo, monospace"
                    fontWeight="600"
                  >
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* Read-back dashed loop (cosmetic, HF-style) */}
          <path
            d="M472,222 L472,136"
            fill="none"
            stroke={TRUST_COLORS.blue}
            strokeWidth={1.2}
            strokeDasharray="4 4"
            opacity={liveById.n5 ? 0.55 : 0.15}
          />

          {/* Nodes */}
          {NODES.map((n) => {
            const live = liveById[n.id];
            const isFrontier = frontier === n.id && live;
            return (
              <g key={n.id} opacity={live ? 1 : 0.28}>
                <rect
                  x={n.x}
                  y={n.y}
                  width={n.w}
                  height={n.h}
                  rx={10}
                  fill="rgba(2,6,23,0.88)"
                  stroke={n.color}
                  strokeWidth={isFrontier ? 2 : 1.2}
                  style={{
                    filter: live ? `drop-shadow(0 0 8px ${n.color}66)` : undefined,
                  }}
                />
                <text
                  x={n.x + 10}
                  y={n.y + 16}
                  fill={n.color}
                  fontSize="7"
                  fontFamily="ui-monospace, Menlo, monospace"
                  fontWeight="700"
                  letterSpacing="0.08em"
                >
                  {n.tag}
                </text>
                <text
                  x={n.x + 10}
                  y={n.y + 34}
                  fill="#f1f5f9"
                  fontSize="11"
                  fontFamily="ui-sans-serif, system-ui, sans-serif"
                  fontWeight="600"
                >
                  {n.title}
                </text>
                <text
                  x={n.x + 10}
                  y={n.y + 50}
                  fill="#94a3b8"
                  fontSize="8"
                  fontFamily="ui-monospace, Menlo, monospace"
                >
                  {n.sub}
                </text>
              </g>
            );
          })}

          {/* Agent packet on frontier */}
          {(steps.length > 0 || findings.length > 0) && (
            <g>
              <circle
                cx={frontierCenter.cx}
                cy={frontierCenter.cy}
                r={10}
                fill={TRUST_COLORS.orange}
                opacity={0.25}
                style={{ transition: 'cx 0.45s cubic-bezier(.5,0,.2,1), cy 0.45s cubic-bezier(.5,0,.2,1)' }}
              >
                {isRunning && (
                  <animate attributeName="r" values="8;14;8" dur="1.6s" repeatCount="indefinite" />
                )}
              </circle>
              <circle
                cx={frontierCenter.cx}
                cy={frontierCenter.cy}
                r={4}
                fill="#fff"
                style={{
                  transition: 'cx 0.45s cubic-bezier(.5,0,.2,1), cy 0.45s cubic-bezier(.5,0,.2,1)',
                  filter: 'drop-shadow(0 0 6px rgba(255,255,255,0.8))',
                }}
              />
            </g>
          )}
        </svg>
      </div>

      <div className="px-3 py-2 border-t border-white/5 flex items-center justify-between gap-2">
        <p className="text-[10px] font-mono text-slate-400 truncate">{stepHint}</p>
        <p className="text-[10px] font-mono text-slate-500 shrink-0">
          {findings.length} findings · {steps.length} steps
        </p>
      </div>
    </div>
  );
}
