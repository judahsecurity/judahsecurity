'use client';

import { Suspense, useCallback, useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  AlertCircle,
  CheckCircle2,
  Code2,
  FileCode,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Sparkles,
  Trash2,
  XCircle,
  Play,
  Pause,
  Eye,
  Bot,
  Upload,
  Tag,
  Clock,
  Zap,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Template {
  id: number;
  organization_id: number;
  template_id: string;
  name: string;
  description: string | null;
  template_yaml: string;
  cve_ids: string[];
  severity: string | null;
  tags: string[];
  template_type: string | null;
  source: 'manual' | 'ai_generated';
  ai_model: string | null;
  status: 'draft' | 'active' | 'disabled';
  validated: boolean;
  times_matched: number;
  last_run_at: string | null;
  last_match_at: string | null;
  created_at: string;
}

// ── Style helpers ─────────────────────────────────────────────────────────────

const STATUS_STYLE: Record<string, string> = {
  active: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  draft: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  disabled: 'bg-muted text-muted-foreground border-border',
};

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-muted text-muted-foreground border-border',
};

function StatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={cn('text-xs capitalize', STATUS_STYLE[status] ?? STATUS_STYLE.draft)}>
      {status === 'active' && <CheckCircle2 className="h-3 w-3 mr-1" />}
      {status === 'draft' && <Clock className="h-3 w-3 mr-1" />}
      {status === 'disabled' && <XCircle className="h-3 w-3 mr-1" />}
      {status}
    </Badge>
  );
}

function SourceBadge({ source }: { source: string }) {
  if (source === 'ai_generated') {
    return (
      <Badge variant="outline" className="bg-purple-500/15 text-purple-400 border-purple-500/30 gap-1 text-xs">
        <Bot className="h-3 w-3" />AI Generated
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="bg-blue-500/15 text-blue-400 border-blue-500/30 gap-1 text-xs">
      <Upload className="h-3 w-3" />Manual
    </Badge>
  );
}

// ── YAML viewer ───────────────────────────────────────────────────────────────

function YAMLViewer({ yaml }: { yaml: string }) {
  return (
    <pre className="text-xs font-mono bg-black/40 border border-border rounded-lg p-4 overflow-auto max-h-96 text-green-300 leading-relaxed whitespace-pre-wrap">
      {yaml}
    </pre>
  );
}

// ── AI Generate dialog ────────────────────────────────────────────────────────

function GenerateDialog({
  open,
  onClose,
  organizationId,
  prefillCveId,
  onGenerated,
}: {
  open: boolean;
  onClose: () => void;
  organizationId: number | null;
  prefillCveId?: string;
  onGenerated: (t: Template) => void;
}) {
  const { toast } = useToast();
  const [generating, setGenerating] = useState(false);
  const [cveId, setCveId] = useState(prefillCveId || '');
  const [description, setDescription] = useState('');
  const [affectedUrl, setAffectedUrl] = useState('');
  const [product, setProduct] = useState('');
  const [evidence, setEvidence] = useState('');

  useEffect(() => { if (prefillCveId) setCveId(prefillCveId); }, [prefillCveId]);

  const handleGenerate = async (force = false) => {
    if (!organizationId) return;
    if (!cveId.trim() && !description.trim()) {
      toast({ title: 'Provide a CVE ID or vulnerability description', variant: 'destructive' });
      return;
    }
    setGenerating(true);
    try {
      const resp = await api.post('/nuclei-templates/generate', {
        organization_id: organizationId,
        cve_id: cveId.trim() || undefined,
        vulnerability_description: description.trim() || undefined,
        affected_url: affectedUrl.trim() || undefined,
        affected_product: product.trim() || undefined,
        detection_evidence: evidence.trim() || undefined,
        force,
      });
      toast({ title: 'Template generated', description: 'Saved as draft — review YAML before activating.' });
      onGenerated(resp.data);
      onClose();
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      // 409: a template already exists for this CVE — offer to generate anyway.
      if (err?.response?.status === 409 && detail?.error === 'template_already_exists') {
        const proceed = window.confirm(
          `${detail.message}\n\nGenerate a custom (secondary) template anyway?`
        );
        if (proceed) {
          setGenerating(false);
          return handleGenerate(true);
        }
        toast({ title: 'Template already exists', description: detail.message });
      } else {
        const msg = typeof detail === 'string' ? detail : (detail?.message || err.message);
        toast({ title: 'Generation failed', description: msg, variant: 'destructive' });
      }
    } finally {
      setGenerating(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-purple-400" />
            Generate Nuclei Template with AI
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 text-sm">
          <p className="text-muted-foreground text-xs">
            The AI will generate a Nuclei YAML detection template. Provide a CVE ID for automatic context enrichment, or describe the vulnerability manually. Generated templates are saved as <strong>draft</strong> — review before activating.
          </p>

          <div className="space-y-1">
            <Label>CVE ID <span className="text-muted-foreground">(recommended)</span></Label>
            <Input
              placeholder="CVE-2024-12345"
              value={cveId}
              onChange={e => setCveId(e.target.value.toUpperCase())}
            />
            <p className="text-xs text-muted-foreground">Will fetch vulnerability context from ProjectDiscovery automatically</p>
          </div>

          <div className="flex items-center gap-2">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs text-muted-foreground">or describe manually</span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <div className="space-y-1">
            <Label>Vulnerability Description</Label>
            <Textarea
              placeholder="Describe the vulnerability: what endpoint is affected, how it's triggered, what a vulnerable response looks like..."
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={4}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Affected URL Pattern</Label>
              <Input placeholder="/actuator/env" value={affectedUrl} onChange={e => setAffectedUrl(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Affected Product</Label>
              <Input placeholder="Spring Boot, Apache Tomcat..." value={product} onChange={e => setProduct(e.target.value)} />
            </div>
          </div>

          <div className="space-y-1">
            <Label>Detection Evidence <span className="text-muted-foreground">(response snippet, error message)</span></Label>
            <Textarea
              placeholder="Paste a response body snippet or error message from a vulnerable target..."
              value={evidence}
              onChange={e => setEvidence(e.target.value)}
              rows={3}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={generating}>Cancel</Button>
          <Button
            onClick={() => handleGenerate()}
            disabled={generating || (!cveId.trim() && !description.trim())}
            className="gap-2 bg-purple-600 hover:bg-purple-700"
          >
            {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
            {generating ? 'Generating…' : 'Generate Template'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Template detail dialog ────────────────────────────────────────────────────

function TemplateDetail({
  template,
  open,
  onClose,
  onStatusChange,
  onDelete,
}: {
  template: Template | null;
  open: boolean;
  onClose: () => void;
  onStatusChange: (id: number, status: string) => void;
  onDelete: (id: number) => void;
}) {
  const { toast } = useToast();
  const [deleting, setDeleting] = useState(false);
  const [toggling, setToggling] = useState(false);

  if (!template) return null;

  const handleActivate = async (skipValidation = false) => {
    setToggling(true);
    try {
      await api.post(
        `/nuclei-templates/${template.id}/activate`,
        null,
        { params: skipValidation ? { skip_validation: true } : undefined },
      );
      toast({ title: 'Template activated' });
      onStatusChange(template.id, 'active');
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      // 422: nuclei -validate rejected the template — show why + offer override.
      if (err?.response?.status === 422 && detail?.error === 'template_validation_failed') {
        const proceed = window.confirm(
          `${detail.message}\n\n${detail.validation_output || ''}\n\nActivate anyway (skip validation)?`
        );
        if (proceed) {
          setToggling(false);
          return handleActivate(true);
        }
        toast({ title: 'Validation failed', description: detail.message, variant: 'destructive' });
      } else {
        const msg = typeof detail === 'string' ? detail : (detail?.message || 'Failed to activate');
        toast({ title: 'Failed to activate', description: msg, variant: 'destructive' });
      }
    } finally { setToggling(false); }
  };

  const handleDisable = async () => {
    setToggling(true);
    try {
      await api.post(`/nuclei-templates/${template.id}/disable`);
      toast({ title: 'Template disabled' });
      onStatusChange(template.id, 'disabled');
    } catch {
      toast({ title: 'Failed to disable', variant: 'destructive' });
    } finally { setToggling(false); }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/nuclei-templates/${template.id}`);
      toast({ title: 'Template deleted' });
      onDelete(template.id);
      onClose();
    } catch {
      toast({ title: 'Failed to delete', variant: 'destructive' });
    } finally { setDeleting(false); }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <FileCode className="h-4 w-4 text-primary" />
            <code className="text-sm">{template.template_id}</code>
            <StatusBadge status={template.status} />
            <SourceBadge source={template.source} />
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          <p className="font-medium">{template.name}</p>
          {template.description && (
            <p className="text-muted-foreground leading-relaxed">{template.description}</p>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div>
              <p className="text-xs text-muted-foreground mb-1">Severity</p>
              {template.severity ? (
                <Badge variant="outline" className={cn('text-xs uppercase', SEVERITY_STYLE[template.severity] ?? '')}>
                  {template.severity}
                </Badge>
              ) : <span className="text-muted-foreground">—</span>}
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Matches</p>
              <p className="font-semibold">{template.times_matched}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Validated</p>
              {template.validated
                ? <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                : <span className="text-xs text-muted-foreground">Pending review</span>}
            </div>
          </div>

          {template.cve_ids.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground mb-1">CVEs</p>
              <div className="flex flex-wrap gap-1">
                {template.cve_ids.map(c => (
                  <Badge key={c} variant="outline" className="text-xs font-mono text-primary border-primary/30">
                    {c}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {template.tags.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground mb-1">Tags</p>
              <div className="flex flex-wrap gap-1">
                {template.tags.map(t => (
                  <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                ))}
              </div>
            </div>
          )}

          {template.source === 'ai_generated' && (
            <div className="flex items-center gap-2 p-2 rounded border border-purple-500/20 bg-purple-500/5 text-xs text-purple-400">
              <AlertCircle className="h-3.5 w-3.5 shrink-0" />
              AI-generated — review YAML carefully and test against a known-vulnerable target before activating.
              {template.ai_model && <span className="ml-auto text-muted-foreground">Model: {template.ai_model}</span>}
            </div>
          )}

          <div className="space-y-2">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Template YAML</p>
            <YAMLViewer yaml={template.template_yaml} />
          </div>
        </div>

        <DialogFooter className="flex justify-between">
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive gap-1"
            onClick={handleDelete}
            disabled={deleting}
          >
            {deleting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
            Delete
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>Close</Button>
            {template.status !== 'active' && (
              <Button size="sm" onClick={() => handleActivate()} disabled={toggling} className="gap-1 bg-emerald-600 hover:bg-emerald-700">
                {toggling ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                Activate
              </Button>
            )}
            {template.status === 'active' && (
              <Button size="sm" variant="outline" onClick={handleDisable} disabled={toggling} className="gap-1">
                {toggling ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Pause className="h-3.5 w-3.5" />}
                Disable
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Detection Gap type ────────────────────────────────────────────────────────

interface DetectionGap {
  cve_id: string;
  title: string;
  severity: string;
  asset_count: number;
  finding_id: number;
  cvss_score: number | null;
  is_kev: boolean;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, unknown: 5 };

// ── Detection Gaps tab ────────────────────────────────────────────────────────

function DetectionGapsTab({
  selectedOrg,
  templates,
  templatesLoading,
  onGenerate,
}: {
  selectedOrg: number | null;
  templates: Template[];
  templatesLoading: boolean;
  onGenerate: (cveId: string) => void;
}) {
  const { toast } = useToast();
  const [gaps, setGaps] = useState<DetectionGap[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');

  const coveredCves = new Set(templates.flatMap(t => t.cve_ids.map(c => c.toUpperCase())));

  const loadGaps = useCallback(async () => {
    if (!selectedOrg) return;
    setLoading(true);
    try {
      // API enforces limit <= 100; page through to build the full CVE set.
      const pageSize = 100;
      const vulns: any[] = [];
      for (let skip = 0; ; skip += pageSize) {
        const resp = await api.getVulnerabilities({
          organization_id: selectedOrg,
          skip,
          limit: pageSize,
        });
        const batch: any[] = Array.isArray(resp) ? resp : (resp as any).items ?? [];
        vulns.push(...batch);
        if (batch.length < pageSize) break;
      }
      const seen = new Set<string>();
      const found: DetectionGap[] = [];
      for (const v of vulns) {
        const cve = (v.cve_id || '').toUpperCase();
        if (!cve || seen.has(cve)) continue;
        seen.add(cve);
        if (coveredCves.has(cve)) continue;
        found.push({
          cve_id: cve,
          title: v.title || v.name || cve,
          severity: (v.severity || 'unknown').toLowerCase(),
          asset_count: 1,
          finding_id: v.id,
          cvss_score: v.cvss_score ?? null,
          is_kev: !!(v.metadata_?.delphi?.is_kev || v.delphi_is_kev),
        });
      }
      found.sort((a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
      );
      setGaps(found);
    } catch (err: any) {
      toast({ title: 'Failed to load detection gaps', description: err.message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [selectedOrg, coveredCves.size]);

  useEffect(() => { loadGaps(); }, [selectedOrg, templates.length]);

  const filtered = gaps.filter(g => {
    if (sevFilter !== 'all' && g.severity !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return g.cve_id.toLowerCase().includes(q) || g.title.toLowerCase().includes(q);
    }
    return true;
  });

  const gapStats = {
    total: gaps.length,
    critical: gaps.filter(g => g.severity === 'critical').length,
    high: gaps.filter(g => g.severity === 'high').length,
    kev: gaps.filter(g => g.is_kev).length,
  };

  if (!selectedOrg) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <p>Select an organization to see detection gaps.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Gaps', value: gapStats.total, color: 'text-primary', desc: 'CVEs with no detection template' },
          { label: 'Critical', value: gapStats.critical, color: 'text-red-400', desc: 'Critical severity gaps' },
          { label: 'High', value: gapStats.high, color: 'text-orange-400', desc: 'High severity gaps' },
          { label: 'On CISA KEV', value: gapStats.kev, color: 'text-yellow-400', desc: 'Known exploited with no detection' },
        ].map(s => (
          <Card key={s.label} className="border-border">
            <CardContent className="p-4">
              <p className={cn('text-2xl font-bold', s.color)}>{loading ? '—' : s.value}</p>
              <p className="text-sm font-medium mt-0.5">{s.label}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{s.desc}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48 max-w-72">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search CVE ID or title…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 h-9"
          />
        </div>

        <Select value={sevFilter} onValueChange={setSevFilter}>
          <SelectTrigger className="w-36 h-9">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Button variant="outline" size="sm" onClick={loadGaps} className="gap-1 h-9">
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
        </Button>
      </div>

      {/* Table */}
      <Card className="border-border">
        <CardContent className="p-0">
          {loading || templatesLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <CheckCircle2 className="h-10 w-10 mb-3 opacity-30 text-emerald-400" />
              <p className="font-medium">No detection gaps found</p>
              <p className="text-sm mt-1">
                {gaps.length === 0
                  ? 'All CVEs in your findings have detection templates — great coverage!'
                  : 'No gaps match your current filters.'}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead>CVE</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-20">CVSS</TableHead>
                  <TableHead className="w-24">KEV</TableHead>
                  <TableHead className="w-52 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(g => (
                  <TableRow key={g.cve_id} className="border-border hover:bg-muted/30">
                    <TableCell>
                      <span className="font-mono text-xs font-semibold text-primary">{g.cve_id}</span>
                    </TableCell>

                    <TableCell>
                      <span className="text-sm line-clamp-1">{g.title}</span>
                    </TableCell>

                    <TableCell>
                      <Badge variant="outline" className={cn('text-xs uppercase', SEVERITY_STYLE[g.severity] ?? '')}>
                        {g.severity}
                      </Badge>
                    </TableCell>

                    <TableCell>
                      <span className="text-sm">{g.cvss_score != null ? g.cvss_score.toFixed(1) : '—'}</span>
                    </TableCell>

                    <TableCell>
                      {g.is_kev ? (
                        <Badge variant="outline" className="bg-yellow-500/15 text-yellow-400 border-yellow-500/30 text-xs gap-1">
                          <Zap className="h-3 w-3" />KEV
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>

                    <TableCell className="text-right">
                      <div className="flex gap-2 justify-end">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs gap-1"
                                onClick={() =>
                                  window.open(
                                    `https://nuclei.projectdiscovery.io/nuclei-templates/?q=${encodeURIComponent(g.cve_id)}`,
                                    '_blank'
                                  )
                                }
                              >
                                <Search className="h-3 w-3" />
                                Community
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Search community Nuclei templates for this CVE</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>

                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                size="sm"
                                className="h-7 text-xs gap-1 bg-purple-600 hover:bg-purple-700"
                                onClick={() => onGenerate(g.cve_id)}
                              >
                                <Sparkles className="h-3 w-3" />
                                Generate
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Generate a Nuclei template with AI for this CVE</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

function DetectionCoveragePageContent() {
  const { toast } = useToast();
  const searchParams = useSearchParams();
  const [orgs, setOrgs] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<number | null>(null);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [showGenerate, setShowGenerate] = useState(false);
  const [generatePrefill, setGeneratePrefill] = useState<string | undefined>();
  const [selected, setSelected] = useState<Template | null>(null);
  const [activeTab, setActiveTab] = useState('gaps');
  const autoOpenedRef = useRef(false);

  useEffect(() => {
    api.getOrganizations().then((data: any[]) => {
      setOrgs(data);
      if (data.length > 0) setSelectedOrg(data[0].id);
    });
    const generateCve = searchParams.get('generate');
    if (generateCve && !autoOpenedRef.current) {
      autoOpenedRef.current = true;
      setGeneratePrefill(generateCve.toUpperCase());
      setShowGenerate(true);
    }
  }, []);

  const loadTemplates = useCallback(async () => {
    if (!selectedOrg) return;
    setTemplatesLoading(true);
    try {
      const params: Record<string, string> = { organization_id: String(selectedOrg) };
      if (statusFilter !== 'all') params.status = statusFilter;
      if (sourceFilter !== 'all') params.source = sourceFilter;
      const resp = await api.get('/nuclei-templates', params);
      setTemplates(resp.data);
    } catch (err: any) {
      toast({ title: 'Failed to load templates', description: err.message, variant: 'destructive' });
    } finally {
      setTemplatesLoading(false);
    }
  }, [selectedOrg, statusFilter, sourceFilter, toast]);

  useEffect(() => { loadTemplates(); }, [loadTemplates]);

  const filtered = templates.filter(t => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      t.template_id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.cve_ids.some(c => c.toLowerCase().includes(q)) ||
      t.tags.some(tag => tag.toLowerCase().includes(q))
    );
  });

  const stats = {
    total: templates.length,
    active: templates.filter(t => t.status === 'active').length,
    draft: templates.filter(t => t.status === 'draft').length,
    aiGenerated: templates.filter(t => t.source === 'ai_generated').length,
    matches: templates.reduce((sum, t) => sum + t.times_matched, 0),
  };

  const handleStatusChange = (id: number, status: string) => {
    setTemplates(prev => prev.map(t => t.id === id ? { ...t, status: status as Template['status'] } : t));
    if (selected?.id === id) setSelected(prev => prev ? { ...prev, status: status as Template['status'] } : prev);
  };

  const handleDelete = (id: number) => {
    setTemplates(prev => prev.filter(t => t.id !== id));
  };

  const handleGenerated = (t: Template) => {
    setTemplates(prev => [t, ...prev]);
    setActiveTab('templates');
  };

  const handleGenerateForCve = (cveId: string) => {
    setGeneratePrefill(cveId);
    setShowGenerate(true);
  };

  return (
    <MainLayout>
      <Header
        title="Detection Coverage"
        subtitle="Identify undetected CVEs in your environment and generate Nuclei templates"
      />

      <div className="p-6 space-y-6">

        {/* Org selector */}
        <div className="flex flex-wrap items-center gap-4">
          <Select
            value={selectedOrg ? String(selectedOrg) : ''}
            onValueChange={v => setSelectedOrg(Number(v))}
          >
            <SelectTrigger className="w-52 h-9">
              <SelectValue placeholder="Select org" />
            </SelectTrigger>
            <SelectContent>
              {orgs.map(o => (
                <SelectItem key={o.id} value={String(o.id)}>{o.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            size="sm"
            onClick={() => setShowGenerate(true)}
            disabled={!selectedOrg}
            className="gap-1.5 h-9 bg-purple-600 hover:bg-purple-700 ml-auto"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Generate Template with AI
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full max-w-xs grid-cols-2">
            <TabsTrigger value="gaps" className="gap-1.5">
              <AlertCircle className="h-3.5 w-3.5" />
              Detection Gaps
            </TabsTrigger>
            <TabsTrigger value="templates" className="gap-1.5">
              <FileCode className="h-3.5 w-3.5" />
              My Templates
              {stats.active > 0 && (
                <Badge variant="secondary" className="ml-1 text-xs h-4 px-1">{stats.active}</Badge>
              )}
            </TabsTrigger>
          </TabsList>

          {/* ── Detection Gaps tab ── */}
          <TabsContent value="gaps" className="mt-5">
            <DetectionGapsTab
              selectedOrg={selectedOrg}
              templates={templates}
              templatesLoading={templatesLoading}
              onGenerate={handleGenerateForCve}
            />
          </TabsContent>

          {/* ── My Templates tab ── */}
          <TabsContent value="templates" className="mt-5">
            <div className="space-y-5">
              {/* Stats */}
              <div className="flex gap-5">
                {[
                  { label: 'Active', value: stats.active, color: 'text-emerald-400' },
                  { label: 'Draft', value: stats.draft, color: 'text-yellow-400' },
                  { label: 'AI Generated', value: stats.aiGenerated, color: 'text-purple-400' },
                  { label: 'Total Matches', value: stats.matches, color: 'text-primary' },
                ].map(s => (
                  <div key={s.label} className="text-center">
                    <p className={cn('text-xl font-bold', s.color)}>{s.value}</p>
                    <p className="text-xs text-muted-foreground">{s.label}</p>
                  </div>
                ))}
              </div>

              {/* Toolbar */}
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-48 max-w-72">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search ID, CVE, tag…"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="pl-8 h-9"
                  />
                </div>

                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-32 h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="draft">Draft</SelectItem>
                    <SelectItem value="disabled">Disabled</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={sourceFilter} onValueChange={setSourceFilter}>
                  <SelectTrigger className="w-40 h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Sources</SelectItem>
                    <SelectItem value="ai_generated">AI Generated</SelectItem>
                    <SelectItem value="manual">Manual</SelectItem>
                  </SelectContent>
                </Select>

                <Button variant="outline" size="sm" onClick={() => loadTemplates()} className="gap-1 h-9">
                  <RefreshCw className={cn('h-3.5 w-3.5', templatesLoading && 'animate-spin')} />
                </Button>
              </div>

              {/* Table */}
              <Card className="border-border">
                <CardContent className="p-0">
                  {templatesLoading ? (
                    <div className="flex items-center justify-center py-16">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : filtered.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                      <FileCode className="h-10 w-10 mb-3 opacity-30" />
                      <p className="font-medium">No templates found</p>
                      <p className="text-sm mt-1">Use "Generate with AI" to create your first detection template</p>
                    </div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow className="border-border hover:bg-transparent">
                          <TableHead>Template ID</TableHead>
                          <TableHead>CVEs</TableHead>
                          <TableHead className="w-24">Severity</TableHead>
                          <TableHead className="w-28">Source</TableHead>
                          <TableHead className="w-24">Status</TableHead>
                          <TableHead className="w-20">Matches</TableHead>
                          <TableHead className="w-28">Created</TableHead>
                          <TableHead className="w-20" />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filtered.map(t => (
                          <TableRow
                            key={t.id}
                            className="border-border cursor-pointer hover:bg-muted/30"
                            onClick={() => setSelected(t)}
                          >
                            <TableCell>
                              <div className="space-y-0.5">
                                <p className="font-mono text-xs font-semibold text-primary">{t.template_id}</p>
                                <p className="text-xs text-muted-foreground line-clamp-1">{t.name}</p>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {t.cve_ids.slice(0, 2).map(c => (
                                  <Badge key={c} variant="outline" className="text-xs font-mono text-primary border-primary/30">{c}</Badge>
                                ))}
                                {t.cve_ids.length > 2 && (
                                  <Badge variant="secondary" className="text-xs">+{t.cve_ids.length - 2}</Badge>
                                )}
                                {t.cve_ids.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
                              </div>
                            </TableCell>
                            <TableCell>
                              {t.severity ? (
                                <Badge variant="outline" className={cn('text-xs uppercase', SEVERITY_STYLE[t.severity] ?? '')}>
                                  {t.severity}
                                </Badge>
                              ) : <span className="text-muted-foreground text-xs">—</span>}
                            </TableCell>
                            <TableCell><SourceBadge source={t.source} /></TableCell>
                            <TableCell><StatusBadge status={t.status} /></TableCell>
                            <TableCell><span className="text-sm font-semibold">{t.times_matched}</span></TableCell>
                            <TableCell>
                              <span className="text-xs text-muted-foreground">
                                {t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}
                              </span>
                            </TableCell>
                            <TableCell>
                              <Button variant="ghost" size="icon" className="h-7 w-7">
                                <Eye className="h-3.5 w-3.5" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>

      <GenerateDialog
        open={showGenerate}
        onClose={() => { setShowGenerate(false); setGeneratePrefill(undefined); }}
        organizationId={selectedOrg}
        prefillCveId={generatePrefill}
        onGenerated={handleGenerated}
      />

      <TemplateDetail
        template={selected}
        open={!!selected}
        onClose={() => setSelected(null)}
        onStatusChange={handleStatusChange}
        onDelete={handleDelete}
      />
    </MainLayout>
  );
}

export default function DetectionCoveragePage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-background" />}>
      <DetectionCoveragePageContent />
    </Suspense>
  );
}
