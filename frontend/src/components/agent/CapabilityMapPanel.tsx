'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ChevronDown, ChevronUp, Compass, Lock, Unlock } from 'lucide-react';

export type HuntQueueItem = {
  priority?: string;
  hunt?: string;
  why?: string;
  evidence?: string;
};

export type CapabilityMapState = {
  quality_score?: number;
  ready_for_attack?: boolean;
  capabilities?: string[];
  ranked_hunt_queue?: HuntQueueItem[];
  authenticated?: boolean | null;
  api_sample_count?: number;
  pages_visited?: string[];
};

type Props = {
  map: CapabilityMapState | null;
  authSession?: { authenticated?: boolean | null; cookie_count?: number; target?: string } | null;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
};

export function CapabilityMapPanel({
  map,
  authSession,
  collapsed = false,
  onToggleCollapse,
}: Props) {
  if (!map) return null;

  const score = typeof map.quality_score === 'number' ? map.quality_score : 0;
  const queue = map.ranked_hunt_queue || [];
  const caps = map.capabilities || [];
  const authed = map.authenticated ?? authSession?.authenticated;

  return (
    <Card className="border-border/60 bg-card/40">
      <CardHeader className="py-3 px-4 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Compass className="h-4 w-4 text-primary" />
          Application capability map
        </CardTitle>
        <div className="flex items-center gap-2">
          <Badge variant={map.ready_for_attack ? 'default' : 'outline'} className="text-[10px]">
            {map.ready_for_attack ? 'ready' : 'thin'}
          </Badge>
          <Badge variant="outline" className="text-[10px] font-mono">
            q={score.toFixed(2)}
          </Badge>
          {onToggleCollapse && (
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onToggleCollapse}>
              {collapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
            </Button>
          )}
        </div>
      </CardHeader>
      {!collapsed && (
        <CardContent className="px-4 pb-4 pt-0 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1">
              {authed ? (
                <Lock className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Unlock className="h-3.5 w-3.5" />
              )}
              {authed ? 'authenticated session' : 'unauthenticated'}
            </span>
            {typeof authSession?.cookie_count === 'number' && (
              <span>· {authSession.cookie_count} cookies</span>
            )}
            {typeof map.api_sample_count === 'number' && map.api_sample_count > 0 && (
              <span>· {map.api_sample_count} replay samples</span>
            )}
          </div>

          {caps.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {caps.map((c) => (
                <Badge key={c} variant="secondary" className="text-[10px] font-normal">
                  {c}
                </Badge>
              ))}
            </div>
          )}

          {queue.length > 0 ? (
            <div className="space-y-1.5">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-semibold">
                Hunt queue
              </p>
              <ol className="space-y-1.5">
                {queue.slice(0, 8).map((h, i) => (
                  <li
                    key={`${h.hunt}-${i}`}
                    className="rounded-md border border-border/50 bg-muted/20 px-2.5 py-1.5 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-muted-foreground">{i + 1}.</span>
                      <Badge
                        variant="outline"
                        className={
                          h.priority === 'high'
                            ? 'text-[10px] border-amber-500/40 text-amber-300'
                            : 'text-[10px]'
                        }
                      >
                        {h.priority || 'med'}
                      </Badge>
                      <span className="font-medium">{h.hunt}</span>
                    </div>
                    {h.why && (
                      <p className="mt-0.5 pl-5 text-muted-foreground leading-snug">{h.why}</p>
                    )}
                  </li>
                ))}
              </ol>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Run execute_deep_crawl to browse the app and fill this map.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}
