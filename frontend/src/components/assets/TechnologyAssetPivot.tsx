'use client';

import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Cpu, Loader2, MonitorUp } from 'lucide-react';

import { api } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type TechnologyAsset = {
  id: number;
  value: string;
  is_live?: boolean;
  risk_score?: number;
  has_login_portal?: boolean;
};

type TechnologyGroup = {
  technology: string;
  categories?: string[];
  cpe?: string;
  asset_count: number;
  assets?: TechnologyAsset[];
};

export function TechnologyAssetPivot({
  organizationId,
  search,
  liveFilter,
  onSelectAsset,
}: {
  organizationId?: number;
  search: string;
  liveFilter: string;
  onSelectAsset: (assetId: number) => void;
}) {
  const [groups, setGroups] = useState<TechnologyGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.getAssetsByTechnology({ organization_id: organizationId })
      .then((data) => {
        if (!cancelled) setGroups(data?.technologies || []);
      })
      .catch(() => {
        if (!cancelled) setGroups([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [organizationId]);

  const visibleGroups = useMemo(() => {
    const query = search.trim().toLowerCase();
    return groups
      .map((group) => {
        const assets = (group.assets || []).filter((asset) => {
          const matchesLive = liveFilter === 'all' || (liveFilter === 'live' ? asset.is_live : !asset.is_live);
          const matchesSearch = !query || group.technology.toLowerCase().includes(query) || asset.value.toLowerCase().includes(query);
          return matchesLive && matchesSearch;
        });
        return { ...group, assets };
      })
      .filter((group) => group.assets.length > 0 || (!query && liveFilter === 'all'));
  }, [groups, liveFilter, search]);

  const toggle = (technology: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(technology)) next.delete(technology);
      else next.add(technology);
      return next;
    });
  };

  if (loading) {
    return <div className="flex min-h-64 items-center justify-center"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>;
  }

  if (!visibleGroups.length) {
    return (
      <Card>
        <CardContent className="flex min-h-64 flex-col items-center justify-center text-center">
          <Cpu className="mb-3 h-9 w-9 text-muted-foreground" />
          <div className="font-medium">No technologies detected</div>
          <div className="mt-1 text-sm text-muted-foreground">Run technology detection or adjust the current filters.</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Technology</TableHead>
            <TableHead>Category</TableHead>
            <TableHead className="text-right">Matching assets</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visibleGroups.map((group) => {
            const isExpanded = expanded.has(group.technology);
            return [
              <TableRow key={group.technology} className="cursor-pointer" onClick={() => toggle(group.technology)}>
                <TableCell>
                  <div className="flex items-center gap-2 font-medium">
                    {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    <Cpu className="h-4 w-4 text-purple-400" />
                    {group.technology}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {(group.categories || []).slice(0, 3).map((category) => <Badge key={category} variant="secondary">{category}</Badge>)}
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono">{group.assets.length || group.asset_count}</TableCell>
              </TableRow>,
              isExpanded ? (
                <TableRow key={`${group.technology}-assets`} className="hover:bg-transparent">
                  <TableCell colSpan={3} className="bg-muted/20 p-4">
                    <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                      {group.assets.map((asset) => (
                        <Button
                          key={asset.id}
                          variant="outline"
                          className="h-auto justify-between gap-3 px-3 py-2 text-left"
                          onClick={(event) => {
                            event.stopPropagation();
                            onSelectAsset(asset.id);
                          }}
                        >
                          <span className="min-w-0 truncate font-mono text-xs">{asset.value}</span>
                          <span className="flex shrink-0 items-center gap-1.5">
                            {asset.has_login_portal && <MonitorUp className="h-3.5 w-3.5 text-blue-400" />}
                            <span className={`h-2 w-2 rounded-full ${asset.is_live ? 'bg-green-400' : 'bg-muted-foreground'}`} />
                          </span>
                        </Button>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ) : null,
            ];
          })}
        </TableBody>
      </Table>
    </Card>
  );
}
