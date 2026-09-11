import { Activity, CalendarClock, CircleDot, ExternalLink, FileCode2, Loader2 } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import { isSafeTimelineReference, timelineEventLabel, timelineEventTone } from '@/lib/threat-intel-timeline.mjs';

export interface IntelTimelineEvent {
  id: string;
  kind: string;
  category: string;
  timestamp: string;
  title: string;
  description?: string | null;
  source: { id: string; label: string; url?: string | null };
  deadline: boolean;
  scope: 'global' | 'organization';
  metadata: {
    template_id?: string;
    template_name?: string;
    cve_id?: string;
    version?: string;
    content_digest?: string;
    provider?: string;
    reference?: string;
    known_ransomware_use?: string;
  };
}

const TONE_CLASS = {
  deadline: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  detected: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300',
  detection: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  exploitation: 'border-red-500/40 bg-red-500/10 text-red-300',
  neutral: 'border-border bg-muted/20 text-muted-foreground',
};

function EventIcon({ event }: { event: IntelTimelineEvent }) {
  if (event.deadline) return <CalendarClock className="h-3.5 w-3.5" />;
  if (event.category === 'asset_detected') return <Activity className="h-3.5 w-3.5" />;
  if (event.category.startsWith('detection_')) return <FileCode2 className="h-3.5 w-3.5" />;
  return <CircleDot className="h-3.5 w-3.5" />;
}

function EventList({ events }: { events: IntelTimelineEvent[] }) {
  if (!events.length) {
    return <p className="py-4 text-xs text-muted-foreground">No trustworthy dated events are available yet.</p>;
  }
  return (
    <div className="space-y-2 pt-3">
      {events.map(event => {
        const tone = timelineEventTone(event);
        const reference = event.metadata?.reference || event.source.url || '';
        return (
          <div key={event.id} className={cn('rounded-md border p-2.5', TONE_CLASS[tone])}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 font-medium text-xs">
                  <EventIcon event={event} />
                  <span>{timelineEventLabel(event)}</span>
                </div>
                {event.description && <p className="mt-1 text-xs text-muted-foreground leading-relaxed">{event.description}</p>}
              </div>
              <time className="shrink-0 text-[11px] text-muted-foreground" dateTime={event.timestamp}>
                {new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(event.timestamp))}
              </time>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <Badge variant="outline" className="text-[10px]">{event.source.label}</Badge>
              {event.scope === 'organization' && <Badge variant="outline" className="text-[10px]">Your organization</Badge>}
              {event.metadata?.template_id && <code className="text-[10px] text-muted-foreground">{event.metadata.template_id}</code>}
              {event.metadata?.version && <span className="text-[10px] text-muted-foreground">v {event.metadata.version}</span>}
              {isSafeTimelineReference(reference) && (
                <a href={reference} target={reference.startsWith('http') ? '_blank' : undefined}
                  rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-[10px] hover:underline">
                  Source <ExternalLink className="h-2.5 w-2.5" />
                </a>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function IntelTimeline({ updates, timeline, loading }: {
  updates: IntelTimelineEvent[];
  timeline: IntelTimelineEvent[];
  loading: boolean;
}) {
  return (
    <div className="rounded-lg border border-border p-3">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Exploitation Timeline</p>
        {loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
      </div>
      <Tabs defaultValue="updates">
        <TabsList className="h-8">
          <TabsTrigger value="updates" className="text-xs">Intel Updates</TabsTrigger>
          <TabsTrigger value="timeline" className="text-xs">Chronological</TabsTrigger>
        </TabsList>
        <TabsContent value="updates">
          <EventList events={updates.slice(0, 8)} />
          {updates.length > 8 && <p className="pt-1 text-[10px] text-muted-foreground">Showing the 8 newest of {updates.length} updates.</p>}
        </TabsContent>
        <TabsContent value="timeline"><EventList events={timeline} /></TabsContent>
      </Tabs>
    </div>
  );
}
