'use client';

import { useCallback, useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Bot,
  Check,
  Loader2,
  RefreshCw,
  ShieldOff,
  X,
  AlertTriangle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface ValidationCoverage {
  open: number;
  validated: number;
  pending: number;
}

interface SignalBreakdown {
  validator_hosts?: number;
  manual_hosts?: number;
  analyst_feedback?: number;
  hosts?: string[];
}

interface Suppression {
  id: number;
  template_id: string;
  detected_by: string | null;
  status: 'recommended' | 'approved' | 'dismissed';
  host_count: number;
  threshold: number;
  signal_breakdown: SignalBreakdown;
  validation_coverage?: ValidationCoverage;
  first_flagged_at: string | null;
  last_evaluated_at: string | null;
  approved_at: string | null;
}

const STATUS_STYLES: Record<string, string> = {
  recommended: 'bg-amber-100 text-amber-800 border-amber-200',
  approved: 'bg-red-100 text-red-800 border-red-200',
  dismissed: 'bg-slate-100 text-slate-600 border-slate-200',
};

export default function DetectionPatternsPage() {
  const { toast } = useToast();
  const [rows, setRows] = useState<Suppression[]>([]);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('recommended');
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, any> = { include_coverage: true };
      if (statusFilter !== 'all') params.status = statusFilter;
      const data = await api.getDetectionSuppressions(params);
      setRows(Array.isArray(data) ? data : []);
    } catch (err: any) {
      toast({ title: 'Failed to load detection patterns', description: err?.message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [statusFilter, toast]);

  useEffect(() => { load(); }, [load]);

  const handleEvaluate = async () => {
    setEvaluating(true);
    try {
      const resp = await api.evaluateDetectionPatterns();
      toast({
        title: 'Patterns re-evaluated',
        description: `${resp?.recommendations?.length ?? 0} template(s) flagged for review.`,
      });
      await load();
    } catch (err: any) {
      toast({ title: 'Evaluation failed', description: err?.message, variant: 'destructive' });
    } finally {
      setEvaluating(false);
    }
  };

  const handleApprove = async (s: Suppression) => {
    setBusyId(s.id);
    try {
      await api.approveDetectionSuppression(s.id);
      toast({
        title: 'Suppression approved',
        description: `Future ${s.template_id} matches will be auto-marked false positive.`,
      });
      await load();
    } catch (err: any) {
      toast({ title: 'Approve failed', description: err?.message, variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  };

  const handleDismiss = async (s: Suppression) => {
    setBusyId(s.id);
    try {
      await api.dismissDetectionSuppression(s.id);
      toast({ title: 'Recommendation dismissed', description: s.template_id });
      await load();
    } catch (err: any) {
      toast({ title: 'Dismiss failed', description: err?.message, variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  };

  const handleSendToValidator = async (s: Suppression) => {
    setBusyId(s.id);
    try {
      const resp = await api.validateSuppressionSample(s.id);
      toast({
        title: resp?.queued ? 'Sent to validator agent' : 'Nothing to validate',
        description: resp?.message,
      });
      await load();
    } catch (err: any) {
      toast({ title: 'Failed to queue validation', description: err?.message, variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  };

  return (
    <MainLayout>
      <Header
        title="Detection Patterns"
        subtitle="Recurring false positives grouped by detection template — review and suppress with analyst approval"
      />

      <div className="p-6 space-y-6">
        <div className="flex flex-wrap items-center gap-4">
          <Tabs value={statusFilter} onValueChange={setStatusFilter}>
            <TabsList>
              <TabsTrigger value="recommended">Recommended</TabsTrigger>
              <TabsTrigger value="approved">Approved</TabsTrigger>
              <TabsTrigger value="dismissed">Dismissed</TabsTrigger>
              <TabsTrigger value="all">All</TabsTrigger>
            </TabsList>
          </Tabs>

          <Button
            size="sm"
            variant="outline"
            onClick={handleEvaluate}
            disabled={evaluating}
            className="gap-1.5 h-9 ml-auto"
          >
            {evaluating ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Re-evaluate patterns
          </Button>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldOff className="h-4 w-4" />
              Suppression {statusFilter === 'all' ? 'rules' : statusFilter}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12 text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading…
              </div>
            ) : rows.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <ShieldOff className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-sm">No {statusFilter === 'all' ? '' : statusFilter} detection patterns.</p>
                <p className="text-xs mt-1">Patterns appear once false positives span multiple hosts.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Template</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-center">Hosts</TableHead>
                    <TableHead>Signals</TableHead>
                    <TableHead>Validator coverage</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map(s => {
                    const cov = s.validation_coverage;
                    const bd = s.signal_breakdown || {};
                    const isBusy = busyId === s.id;
                    return (
                      <TableRow key={s.id}>
                        <TableCell>
                          <div className="font-mono text-sm">{s.template_id}</div>
                          <div className="text-xs text-muted-foreground">{s.detected_by || 'nuclei'}</div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={cn('capitalize', STATUS_STYLES[s.status])}>
                            {s.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-center">
                          <span className="font-semibold">{s.host_count}</span>
                          <span className="text-xs text-muted-foreground"> / {s.threshold}</span>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 text-xs">
                            {!!bd.validator_hosts && (
                              <Badge variant="secondary" className="gap-1">
                                <Bot className="h-3 w-3" /> {bd.validator_hosts} validator
                              </Badge>
                            )}
                            {!!bd.analyst_feedback && (
                              <Badge variant="secondary">{bd.analyst_feedback} analyst</Badge>
                            )}
                            {!!bd.manual_hosts && (
                              <Badge variant="secondary">{bd.manual_hosts} manual FP</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          {cov ? (
                            <div className="text-xs">
                              <span className="font-medium">{cov.validated}</span>
                              <span className="text-muted-foreground"> / {cov.open} validated</span>
                              {cov.pending > 0 && (
                                <div className="text-amber-600 flex items-center gap-1 mt-0.5">
                                  <AlertTriangle className="h-3 w-3" /> {cov.pending} unvalidated
                                </div>
                              )}
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <Button
                              size="sm"
                              variant="outline"
                              className="gap-1 h-8"
                              disabled={isBusy || !cov || cov.pending === 0}
                              onClick={() => handleSendToValidator(s)}
                              title="Send unvalidated findings to the validator agent"
                            >
                              {isBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Bot className="h-3.5 w-3.5" />}
                              Validate
                            </Button>
                            {s.status !== 'approved' && (
                              <Button
                                size="sm"
                                className="gap-1 h-8 bg-red-600 hover:bg-red-700"
                                disabled={isBusy}
                                onClick={() => handleApprove(s)}
                                title="Approve — future matches auto-marked false positive"
                              >
                                <Check className="h-3.5 w-3.5" /> Approve
                              </Button>
                            )}
                            {s.status !== 'dismissed' && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="gap-1 h-8"
                                disabled={isBusy}
                                onClick={() => handleDismiss(s)}
                              >
                                <X className="h-3.5 w-3.5" /> Dismiss
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
