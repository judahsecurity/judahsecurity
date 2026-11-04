'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
  Loader2,
  CheckCircle2,
  XCircle,
  Plug,
  Trash2,
  RefreshCw,
  AlertCircle,
  Settings2,
  KanbanSquare,
  Download,
  Plus,
  Pencil,
} from 'lucide-react';
import {
  api,
  getApiErrorMessage,
  type AzureDevOpsAuthMethod,
  type AzureDevOpsCloseAs,
  type AzureDevOpsIntegration,
  type AzureDevOpsIntegrationCreate,
  type AzureDevOpsProject,
  type AzureDevOpsSeverity,
  type AzureDevOpsTemplate,
  type AzureDevOpsTemplateCreate,
  type AzureDevOpsTestResult,
  type AzureDevOpsWorkItemType,
} from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

const ADO_URL_PREFIX = 'https://dev.azure.com/';

const SEVERITY_OPTIONS: { value: AzureDevOpsSeverity; label: string; short: string }[] = [
  { value: 'critical', label: 'Critical only', short: 'Critical' },
  { value: 'high', label: 'High and above', short: 'High+' },
  { value: 'medium', label: 'Medium and above', short: 'Medium+' },
  { value: 'low', label: 'Low and above', short: 'Low+' },
  { value: 'info', label: 'All severities (Info and above)', short: 'Info+' },
];

const CLOSE_AS: { value: AzureDevOpsCloseAs; label: string }[] = [
  { value: 'resolved', label: 'Resolved' },
  { value: 'mitigated', label: 'Mitigated' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'accepted', label: 'Risk accepted' },
];

const SEVERITY_MAPPING: [string, string][] = [
  ['Critical', '1 - Critical'],
  ['High', '2 - High'],
  ['Medium', '3 - Medium'],
  ['Low / Info', '4 - Low'],
];

const SECRET_UNCHANGED = '•••••• (unchanged)';

function splitList(value: string): string[] {
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

function validateOrgUrl(url: string): string | null {
  const trimmed = url.trim();
  if (!trimmed) return 'Organization URL is required.';
  if (/visualstudio\.com/i.test(trimmed)) {
    return 'Legacy *.visualstudio.com URLs are not supported. Use https://dev.azure.com/<organization>.';
  }
  if (!trimmed.toLowerCase().startsWith(ADO_URL_PREFIX) || trimmed.length <= ADO_URL_PREFIX.length) {
    return 'Organization URL must start with https://dev.azure.com/ (legacy visualstudio.com URLs are not supported).';
  }
  return null;
}

// ── Connection form ──────────────────────────────────────────────────────────

interface ConnectionFormState {
  organization_url: string;
  auth_method: AzureDevOpsAuthMethod;
  pat: string;
  tenant_id: string;
  client_id: string;
  client_secret: string;
  sync_enabled: boolean;
  remote_closed_states: string;
  accept_close_as: AzureDevOpsCloseAs;
  close_state: string;
  reopen_state: string;
  notify_severity_change: boolean;
}

const defaultConnectionForm: ConnectionFormState = {
  organization_url: '',
  auth_method: 'entra_id',
  pat: '',
  tenant_id: '',
  client_id: '',
  client_secret: '',
  sync_enabled: true,
  remote_closed_states: 'Closed, Resolved, Done',
  accept_close_as: 'resolved',
  close_state: '',
  reopen_state: '',
  notify_severity_change: true,
};

function formFromIntegration(integration: AzureDevOpsIntegration): ConnectionFormState {
  return {
    organization_url: integration.organization_url,
    auth_method: integration.auth_method === 'pat' ? 'pat' : 'entra_id',
    pat: '',
    tenant_id: integration.tenant_id || '',
    client_id: integration.client_id || '',
    client_secret: '',
    sync_enabled: integration.sync_enabled,
    remote_closed_states: (integration.remote_closed_states || []).join(', '),
    accept_close_as: (CLOSE_AS.some((o) => o.value === integration.accept_close_as)
      ? integration.accept_close_as
      : 'resolved') as AzureDevOpsCloseAs,
    close_state: integration.close_state || '',
    reopen_state: integration.reopen_state || '',
    notify_severity_change: integration.notify_severity_change,
  };
}

// ── Template form ────────────────────────────────────────────────────────────

interface TemplateFormState {
  name: string;
  project: string;
  work_item_type: string;
  area_path: string;
  iteration_path: string;
  extra_tags: string;
  auto_create_enabled: boolean;
  auto_create_min_severity: AzureDevOpsSeverity;
  is_active: boolean;
}

const defaultTemplateForm: TemplateFormState = {
  name: '',
  project: '',
  work_item_type: 'Bug',
  area_path: '',
  iteration_path: '',
  extra_tags: '',
  auto_create_enabled: false,
  auto_create_min_severity: 'high',
  is_active: true,
};

function templateFormFrom(t: AzureDevOpsTemplate): TemplateFormState {
  return {
    name: t.name,
    project: t.project,
    work_item_type: t.work_item_type,
    area_path: t.area_path || '',
    iteration_path: t.iteration_path || '',
    extra_tags: (t.extra_tags || []).join(', '),
    auto_create_enabled: t.auto_create_enabled,
    auto_create_min_severity: (SEVERITY_OPTIONS.some((o) => o.value === t.auto_create_min_severity)
      ? t.auto_create_min_severity
      : 'high') as AzureDevOpsSeverity,
    is_active: t.is_active,
  };
}

function severityShort(value?: string | null): string {
  return SEVERITY_OPTIONS.find((o) => o.value === value)?.short || (value ? `${value}+` : '');
}

function AdoLogo({ size = 'md' }: { size?: 'sm' | 'md' }) {
  return (
    <div className={cn(
      'rounded-lg bg-[#0078D4] flex items-center justify-center shrink-0',
      size === 'md' ? 'w-10 h-10' : 'w-6 h-6 rounded',
    )}>
      <KanbanSquare className={cn('text-white', size === 'md' ? 'w-5 h-5' : 'w-4 h-4')} />
    </div>
  );
}

function SwitchRow({
  checked,
  onChange,
  title,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  title: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <p className="text-sm font-medium">{title}</p>
        {description && <p className="text-xs text-muted-foreground">{description}</p>}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} disabled={disabled} className="shrink-0" />
    </div>
  );
}

export function AzureDevOpsSection({ selectedOrgId }: { selectedOrgId?: number }) {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<AzureDevOpsIntegration | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [form, setForm] = useState<ConnectionFormState>(defaultConnectionForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [pulling, setPulling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testResult, setTestResult] = useState<AzureDevOpsTestResult | null>(null);

  // Templates
  const [templates, setTemplates] = useState<AzureDevOpsTemplate[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<AzureDevOpsTemplate | null>(null);
  const [templateForm, setTemplateForm] = useState<TemplateFormState>(defaultTemplateForm);
  const [templateSaving, setTemplateSaving] = useState(false);
  const [templateToDelete, setTemplateToDelete] = useState<AzureDevOpsTemplate | null>(null);
  const [templateDeleting, setTemplateDeleting] = useState(false);
  const [projects, setProjects] = useState<AzureDevOpsProject[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(false);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [workItemTypes, setWorkItemTypes] = useState<AzureDevOpsWorkItemType[]>([]);
  const [typesLoading, setTypesLoading] = useState(false);

  useEffect(() => {
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId]);

  async function load() {
    setLoading(true);
    try {
      const data = await api.getAzureDevOpsIntegration(selectedOrgId);
      setIntegration(data);
      loadTemplates();
    } catch {
      setIntegration(null);
      setTemplates([]);
    } finally {
      setLoading(false);
    }
  }

  async function loadTemplates() {
    setTemplatesLoading(true);
    try {
      setTemplates(await api.getAzureDevOpsTemplates(selectedOrgId));
    } catch (err) {
      setTemplates([]);
      toast({ title: 'Could not load work item templates', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setTemplatesLoading(false);
    }
  }

  // ── Connection handlers ──────────────────────────────────────────────────

  function openSetup() {
    setForm(integration ? formFromIntegration(integration) : defaultConnectionForm);
    setTestResult(null);
    setSetupOpen(true);
  }

  function buildPayload(): AzureDevOpsIntegrationCreate {
    const payload: AzureDevOpsIntegrationCreate = {
      organization_url: form.organization_url.trim().replace(/\/+$/, ''),
      auth_method: form.auth_method,
      sync_enabled: form.sync_enabled,
      remote_closed_states: splitList(form.remote_closed_states),
      accept_close_as: form.accept_close_as,
      close_state: form.close_state.trim() || null,
      reopen_state: form.reopen_state.trim() || null,
      notify_severity_change: form.notify_severity_change,
    };
    if (form.auth_method === 'pat') {
      if (form.pat) payload.pat = form.pat;
    } else {
      payload.tenant_id = form.tenant_id.trim();
      payload.client_id = form.client_id.trim();
      if (form.client_secret) payload.client_secret = form.client_secret;
    }
    return payload;
  }

  async function handleSave() {
    const urlError = validateOrgUrl(form.organization_url);
    if (urlError) {
      toast({ title: urlError, variant: 'destructive' });
      return;
    }
    // A secret is only optional when editing and the same auth method already has one stored.
    const sameMethod = integration && integration.auth_method === form.auth_method;
    if (form.auth_method === 'pat') {
      if (!form.pat && !(sameMethod && integration?.has_pat)) {
        toast({ title: 'Personal Access Token is required.', variant: 'destructive' });
        return;
      }
    } else {
      if (!form.tenant_id.trim() || !form.client_id.trim()) {
        toast({ title: 'Tenant ID and Client ID are required.', variant: 'destructive' });
        return;
      }
      if (!form.client_secret && !(sameMethod && integration?.has_client_secret)) {
        toast({ title: 'Client secret is required.', variant: 'destructive' });
        return;
      }
    }
    if (form.sync_enabled && splitList(form.remote_closed_states).length === 0) {
      toast({ title: 'Enter at least one closed state to sync.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      const payload = buildPayload();
      if (integration) {
        await api.updateAzureDevOpsIntegration(payload, selectedOrgId);
        toast({ title: 'Azure DevOps integration updated.' });
      } else {
        await api.createAzureDevOpsIntegration(payload, selectedOrgId);
        toast({ title: 'Azure DevOps connected.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testAzureDevOpsConnection(selectedOrgId);
      setTestResult(result);
      await load();
    } catch (err) {
      setTestResult({ ok: false, message: getApiErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  }

  async function handlePull() {
    setPulling(true);
    try {
      const result = await api.pullAzureDevOpsWorkItems(selectedOrgId);
      toast({
        title: result.ok ? 'Pull complete' : 'Pull finished with errors',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Pull failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setPulling(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await api.deleteAzureDevOpsIntegration(selectedOrgId);
      setIntegration(null);
      setTemplates([]);
      setTestResult(null);
      setDeleteOpen(false);
      toast({ title: 'Azure DevOps integration removed.' });
    } catch (err) {
      toast({ title: 'Failed to remove', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setDeleting(false);
    }
  }

  // ── Template handlers ────────────────────────────────────────────────────

  async function loadProjects() {
    setProjectsLoading(true);
    setProjectsError(null);
    try {
      const data = await api.getAzureDevOpsProjects(selectedOrgId);
      setProjects(data.projects || []);
    } catch (err) {
      setProjects([]);
      setProjectsError(getApiErrorMessage(err, 'Could not load projects'));
    } finally {
      setProjectsLoading(false);
    }
  }

  async function loadWorkItemTypes(project: string) {
    setWorkItemTypes([]);
    if (!project) return;
    setTypesLoading(true);
    try {
      const data = await api.getAzureDevOpsWorkItemTypes(project, selectedOrgId);
      setWorkItemTypes(data.work_item_types || []);
    } catch (err) {
      toast({ title: 'Could not load work item types', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setTypesLoading(false);
    }
  }

  function openTemplate(t: AzureDevOpsTemplate | null) {
    setEditingTemplate(t);
    setTemplateForm(t ? templateFormFrom(t) : defaultTemplateForm);
    setWorkItemTypes([]);
    setTemplateOpen(true);
    loadProjects();
    if (t?.project) loadWorkItemTypes(t.project);
  }

  function handleProjectChange(project: string) {
    setTemplateForm((f) => ({ ...f, project, work_item_type: '' }));
    loadWorkItemTypes(project);
  }

  async function handleSaveTemplate() {
    if (!templateForm.name.trim()) {
      toast({ title: 'Template name is required.', variant: 'destructive' });
      return;
    }
    if (!templateForm.project) {
      toast({ title: 'Choose a project.', variant: 'destructive' });
      return;
    }
    if (!templateForm.work_item_type) {
      toast({ title: 'Choose a work item type.', variant: 'destructive' });
      return;
    }
    const payload: AzureDevOpsTemplateCreate = {
      name: templateForm.name.trim(),
      project: templateForm.project,
      work_item_type: templateForm.work_item_type,
      area_path: templateForm.area_path.trim() || null,
      iteration_path: templateForm.iteration_path.trim() || null,
      extra_tags: splitList(templateForm.extra_tags),
      auto_create_enabled: templateForm.auto_create_enabled,
      auto_create_min_severity: templateForm.auto_create_min_severity,
      is_active: templateForm.is_active,
    };
    setTemplateSaving(true);
    try {
      if (editingTemplate) {
        await api.updateAzureDevOpsTemplate(editingTemplate.id, payload, selectedOrgId);
        toast({ title: 'Template updated.' });
      } else {
        await api.createAzureDevOpsTemplate(payload, selectedOrgId);
        toast({ title: 'Template created.' });
      }
      setTemplateOpen(false);
      await loadTemplates();
    } catch (err) {
      toast({ title: 'Failed to save template', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setTemplateSaving(false);
    }
  }

  async function handleDeleteTemplate() {
    if (!templateToDelete) return;
    setTemplateDeleting(true);
    try {
      await api.deleteAzureDevOpsTemplate(templateToDelete.id, selectedOrgId);
      setTemplates((prev) => prev.filter((t) => t.id !== templateToDelete.id));
      setTemplateToDelete(null);
      toast({ title: 'Template deleted.' });
    } catch (err) {
      toast({ title: 'Failed to delete template', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setTemplateDeleting(false);
    }
  }

  const isEdit = !!integration;
  const urlError = form.organization_url.trim() ? validateOrgUrl(form.organization_url) : null;
  const authBadge = integration?.auth_method === 'pat' ? 'Personal Access Token' : 'Entra ID service principal';
  // When editing, a stored secret can be kept only if the auth method has not changed.
  const keepPat = isEdit && integration?.auth_method === 'pat' && integration.has_pat;
  const keepClientSecret = isEdit && integration?.auth_method === 'entra_id' && integration.has_client_secret;
  // Make sure the selected project/type stay selectable even before the lists load.
  const projectOptions = templateForm.project && !projects.some((p) => p.name === templateForm.project)
    ? [{ id: `current-${templateForm.project}`, name: templateForm.project }, ...projects]
    : projects;
  const typeOptions = templateForm.work_item_type && !workItemTypes.some((t) => t.name === templateForm.work_item_type)
    ? [{ name: templateForm.work_item_type }, ...workItemTypes]
    : workItemTypes;

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <AdoLogo />
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Azure DevOps Work Items</CardTitle>
          <CardDescription className="text-sm">
            Create Azure DevOps work items from findings, by hand or by severity, and sync their closed state back.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integration ? (
            <Badge variant="outline" className={cn(
              integration.is_active && integration.last_test_ok !== false
                ? 'bg-green-500/10 text-green-400 border-green-500/30'
                : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
            )}>
              {integration.is_active && integration.last_test_ok !== false
                ? <><CheckCircle2 className="h-3 w-3 mr-1" />Connected</>
                : <><AlertCircle className="h-3 w-3 mr-1" />Check config</>}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {integration ? (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div className="sm:col-span-2">
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Organization</p>
                <p className="font-mono text-xs break-all">{integration.organization_url}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auth</p>
                <Badge variant="outline" className="text-xs">{authBadge}</Badge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Closed-state sync</p>
                <p className="text-xs">
                  {integration.sync_enabled
                    ? <span className="text-green-400">
                        Enabled — {(integration.remote_closed_states || []).join(', ') || 'no states'} →{' '}
                        {CLOSE_AS.find((o) => o.value === integration.accept_close_as)?.label || integration.accept_close_as}
                      </span>
                    : <span className="text-muted-foreground">Disabled</span>}
                </p>
              </div>
            </div>

            {integration.last_tested_at && (
              <p className="text-xs text-muted-foreground">
                Last tested: {new Date(integration.last_tested_at).toLocaleString()}{' '}
                {integration.last_test_ok === true && <span className="text-green-400">— OK</span>}
                {integration.last_test_ok === false && <span className="text-red-400">— Failed</span>}
              </p>
            )}
            {integration.last_pull_at && (
              <p className="text-xs text-muted-foreground">
                Last pull: {new Date(integration.last_pull_at).toLocaleString()}
              </p>
            )}
            {integration.last_error && (
              <p className="text-xs text-red-400 break-words">{integration.last_error}</p>
            )}

            {testResult && (
              <div className={cn(
                'flex items-start gap-2 rounded-lg border p-3 text-sm',
                testResult.ok ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300',
              )}>
                {testResult.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 shrink-0" />}
                <span>
                  {testResult.message}
                  {testResult.ok && testResult.project_count != null && ` (${testResult.project_count} project${testResult.project_count === 1 ? '' : 's'} visible)`}
                </span>
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-1">
              <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
                {testing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                Test connection
              </Button>
              <Button size="sm" variant="outline" onClick={handlePull} disabled={pulling}>
                {pulling ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                Pull now
              </Button>
              <Button size="sm" variant="outline" onClick={openSetup}>
                <Settings2 className="h-4 w-4 mr-2" />Edit
              </Button>
              <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="h-4 w-4 mr-2" />Remove
              </Button>
            </div>

            {/* Templates */}
            <div className="border-t border-border pt-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-medium">Work item templates</p>
                  <p className="text-xs text-muted-foreground">
                    Where work items go (project, type, area, iteration). Templates with auto-create on file work items for new findings at or above their threshold.
                  </p>
                </div>
                <Button size="sm" variant="outline" onClick={() => openTemplate(null)} className="shrink-0">
                  <Plus className="h-4 w-4 mr-2" />Add template
                </Button>
              </div>

              {templatesLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />Loading templates…
                </div>
              ) : templates.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No templates yet. You can still create work items from a finding by picking a project and type.
                </p>
              ) : (
                <div className="rounded-md border border-border overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Project</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Auto-create</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead className="w-[1%]" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {templates.map((t) => (
                        <TableRow key={t.id}>
                          <TableCell className="font-medium">{t.name}</TableCell>
                          <TableCell className="text-xs">{t.project}</TableCell>
                          <TableCell className="text-xs">{t.work_item_type}</TableCell>
                          <TableCell>
                            {t.auto_create_enabled ? (
                              <Badge variant="outline" className="bg-[#0078D4]/10 text-[#4FA3E8] border-[#0078D4]/30 text-[10px]">
                                Auto: {severityShort(t.auto_create_min_severity)}
                              </Badge>
                            ) : (
                              <span className="text-xs text-muted-foreground">Manual</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {t.is_active ? (
                              <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30 text-[10px]">Active</Badge>
                            ) : (
                              <Badge variant="outline" className="text-muted-foreground text-[10px]">Inactive</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openTemplate(t)} title="Edit template">
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button size="icon" variant="ghost" className="h-7 w-7 text-red-400 hover:text-red-300" onClick={() => setTemplateToDelete(t)} title="Delete template">
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}

              <div className="rounded-md border border-border bg-muted/20 p-3">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">Severity mapping</p>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                  {SEVERITY_MAPPING.map(([from, to]) => (
                    <span key={from}>
                      {from} <span className="text-muted-foreground">→</span> <span className="font-mono">{to}</span>
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect an Azure DevOps organization with an Entra ID service principal or a Personal Access Token.
            </p>
            <Button onClick={openSetup} disabled={loading}>
              <Plug className="h-4 w-4 mr-2" />Set up Azure DevOps
            </Button>
          </div>
        )}
      </CardContent>

      {/* Connection setup dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AdoLogo size="sm" />
              {isEdit ? 'Edit Azure DevOps Integration' : 'Connect Azure DevOps'}
            </DialogTitle>
            <DialogDescription>
              The connection is validated against Azure DevOps when you save.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 py-2">
            {/* Organization */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Organization URL</label>
              <Input
                placeholder="https://dev.azure.com/your-organization"
                value={form.organization_url}
                onChange={(e) => setForm((f) => ({ ...f, organization_url: e.target.value }))}
              />
              {urlError ? (
                <p className="text-xs text-red-400">{urlError}</p>
              ) : (
                <p className="text-xs text-muted-foreground">
                  Must start with https://dev.azure.com/. Legacy visualstudio.com URLs are not supported.
                </p>
              )}
            </div>

            {/* Authentication */}
            <div className="space-y-3">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Authentication</p>
              {form.auth_method === 'entra_id' ? (
                <>
                  <p className="text-sm font-medium">Entra ID service principal (recommended)</p>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Tenant ID</label>
                    <Input
                      placeholder="00000000-0000-0000-0000-000000000000"
                      value={form.tenant_id}
                      onChange={(e) => setForm((f) => ({ ...f, tenant_id: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Client (Application) ID</label>
                    <Input
                      placeholder="00000000-0000-0000-0000-000000000000"
                      value={form.client_id}
                      onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Client secret</label>
                    <Input
                      type="password"
                      autoComplete="new-password"
                      placeholder={keepClientSecret ? SECRET_UNCHANGED : 'Client secret value'}
                      value={form.client_secret}
                      onChange={(e) => setForm((f) => ({ ...f, client_secret: e.target.value }))}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Add the service principal under Organization Settings &gt; Users with Basic access, then use Manage access to add it to each target project as Project Contributors.
                  </p>
                  <button
                    type="button"
                    onClick={() => setForm((f) => ({ ...f, auth_method: 'pat' }))}
                    className="text-xs text-primary hover:underline"
                  >
                    Use a Personal Access Token instead
                  </button>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium">Personal Access Token</p>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">PAT</label>
                    <Input
                      type="password"
                      autoComplete="new-password"
                      placeholder={keepPat ? SECRET_UNCHANGED : 'Personal Access Token'}
                      value={form.pat}
                      onChange={(e) => setForm((f) => ({ ...f, pat: e.target.value }))}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">Requires Work Items (Read &amp; Write) scope.</p>
                  <button
                    type="button"
                    onClick={() => setForm((f) => ({ ...f, auth_method: 'entra_id' }))}
                    className="text-xs text-primary hover:underline"
                  >
                    Use an Entra ID service principal instead (recommended)
                  </button>
                </>
              )}
            </div>

            {/* Sync */}
            <div className="space-y-4 border-t border-border pt-4">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Sync</p>
              <SwitchRow
                checked={form.sync_enabled}
                onChange={(v) => setForm((f) => ({ ...f, sync_enabled: v }))}
                title="Sync closed state back from Azure DevOps"
                description="When a linked work item reaches one of the closed states, the finding is closed in the platform."
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Closed states</label>
                  <Input
                    value={form.remote_closed_states}
                    onChange={(e) => setForm((f) => ({ ...f, remote_closed_states: e.target.value }))}
                    disabled={!form.sync_enabled}
                    placeholder="Closed, Resolved, Done"
                  />
                  <p className="text-[11px] text-muted-foreground">Comma-separated</p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Mark finding as</label>
                  <Select
                    value={form.accept_close_as}
                    onValueChange={(v) => setForm((f) => ({ ...f, accept_close_as: v as AzureDevOpsCloseAs }))}
                    disabled={!form.sync_enabled}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {CLOSE_AS.map((o) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Close state</label>
                  <Input
                    value={form.close_state}
                    onChange={(e) => setForm((f) => ({ ...f, close_state: e.target.value }))}
                    placeholder="e.g. Closed"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Optional: state to set on the work item when the finding is closed in the platform, e.g. Closed
                  </p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Reopen state</label>
                  <Input
                    value={form.reopen_state}
                    onChange={(e) => setForm((f) => ({ ...f, reopen_state: e.target.value }))}
                    placeholder="e.g. Active"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Optional: state to set on the work item when the finding is reopened in the platform, e.g. Active
                  </p>
                </div>
              </div>
              <SwitchRow
                checked={form.notify_severity_change}
                onChange={(v) => setForm((f) => ({ ...f, notify_severity_change: v }))}
                title="Comment on severity changes"
                description="Add a comment to linked work items when a finding's severity changes."
              />
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !!urlError}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {isEdit ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Remove integration dialog */}
      <Dialog open={deleteOpen} onOpenChange={(v) => { if (!deleting) setDeleteOpen(v); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove Azure DevOps
            </DialogTitle>
            <DialogDescription>
              This removes the stored credentials, templates and work item links in the platform. Work items already created in Azure DevOps are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={deleting}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Template add / edit dialog */}
      <Dialog open={templateOpen} onOpenChange={(v) => { if (!templateSaving) setTemplateOpen(v); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AdoLogo size="sm" />
              {editingTemplate ? 'Edit work item template' : 'Add work item template'}
            </DialogTitle>
            <DialogDescription>
              Choose where work items are filed and whether new findings create them automatically.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Name</label>
              <Input
                placeholder="e.g. Platform team bugs"
                value={templateForm.name}
                onChange={(e) => setTemplateForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium">Project</label>
                <button
                  type="button"
                  onClick={loadProjects}
                  disabled={projectsLoading}
                  className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
                >
                  {projectsLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                  Reload
                </button>
              </div>
              <Select
                value={templateForm.project || undefined}
                onValueChange={handleProjectChange}
                disabled={projectsLoading && projectOptions.length === 0}
              >
                <SelectTrigger>
                  <SelectValue placeholder={projectsLoading ? 'Loading projects…' : 'Select a project'} />
                </SelectTrigger>
                <SelectContent>
                  {projectOptions.map((p) => (
                    <SelectItem key={p.id} value={p.name}>{p.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {projectsError ? (
                <p className="text-xs text-red-400">{projectsError}</p>
              ) : !projectsLoading && projects.length === 0 ? (
                <p className="text-xs text-yellow-400">
                  No projects found. In Azure DevOps go to Organization Settings &gt; Users, open Manage access for the service principal or PAT user, and add it to each project as Project Contributors.
                </p>
              ) : null}
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">Work item type</label>
              <Select
                value={templateForm.work_item_type || undefined}
                onValueChange={(v) => setTemplateForm((f) => ({ ...f, work_item_type: v }))}
                disabled={!templateForm.project}
              >
                <SelectTrigger>
                  <SelectValue placeholder={
                    !templateForm.project ? 'Choose a project first' : typesLoading ? 'Loading types…' : 'Select a type'
                  } />
                </SelectTrigger>
                <SelectContent>
                  {typeOptions.map((t) => (
                    <SelectItem key={t.name} value={t.name}>{t.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Area path <span className="text-muted-foreground font-normal">(optional)</span></label>
                <Input
                  placeholder={templateForm.project ? `${templateForm.project}\\Team` : 'Project\\Team'}
                  value={templateForm.area_path}
                  onChange={(e) => setTemplateForm((f) => ({ ...f, area_path: e.target.value }))}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Iteration path <span className="text-muted-foreground font-normal">(optional)</span></label>
                <Input
                  placeholder={templateForm.project ? `${templateForm.project}\\Sprint 1` : 'Project\\Sprint 1'}
                  value={templateForm.iteration_path}
                  onChange={(e) => setTemplateForm((f) => ({ ...f, iteration_path: e.target.value }))}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">Extra tags <span className="text-muted-foreground font-normal">(optional)</span></label>
              <Input
                placeholder="security, asm"
                value={templateForm.extra_tags}
                onChange={(e) => setTemplateForm((f) => ({ ...f, extra_tags: e.target.value }))}
              />
              <p className="text-[11px] text-muted-foreground">Comma-separated</p>
            </div>

            <div className="space-y-3 border-t border-border pt-4">
              <SwitchRow
                checked={templateForm.auto_create_enabled}
                onChange={(v) => setTemplateForm((f) => ({ ...f, auto_create_enabled: v }))}
                title="Auto-create work items"
                description="New findings at or above the threshold get a work item from this template automatically."
              />
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Minimum severity</label>
                <Select
                  value={templateForm.auto_create_min_severity}
                  onValueChange={(v) => setTemplateForm((f) => ({ ...f, auto_create_min_severity: v as AzureDevOpsSeverity }))}
                  disabled={!templateForm.auto_create_enabled}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <SwitchRow
                checked={templateForm.is_active}
                onChange={(v) => setTemplateForm((f) => ({ ...f, is_active: v }))}
                title="Active"
                description="Inactive templates are hidden from the finding dialog and never auto-create."
              />
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setTemplateOpen(false)} disabled={templateSaving}>Cancel</Button>
            <Button onClick={handleSaveTemplate} disabled={templateSaving}>
              {templateSaving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {editingTemplate ? 'Save template' : 'Add template'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Template delete dialog */}
      <Dialog open={!!templateToDelete} onOpenChange={(v) => { if (!v && !templateDeleting) setTemplateToDelete(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Delete template
            </DialogTitle>
            <DialogDescription>
              Delete &ldquo;{templateToDelete?.name}&rdquo;? Work items already created from it stay linked to their findings.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setTemplateToDelete(null)} disabled={templateDeleting}>Cancel</Button>
            <Button variant="destructive" onClick={handleDeleteTemplate} disabled={templateDeleting}>
              {templateDeleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
