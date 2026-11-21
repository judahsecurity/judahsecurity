'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Bookmark, Download, FileSpreadsheet, Loader2, Pencil, Trash2, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { api, getApiErrorMessage, type AssetImportResult, type SavedListView } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

export type AssetViewFilters = { search?: string; asset_type?: string; status?: string; organization?: string };

function download(data: BlobPart, filename: string, type: string) {
  const url = window.URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export function AssetInventoryToolbar({
  organizationId, filters, onApplyView, onImported,
}: {
  organizationId?: number;
  filters: AssetViewFilters;
  onApplyView: (filters: AssetViewFilters) => void;
  onImported: () => void;
}) {
  const { toast } = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [views, setViews] = useState<SavedListView[]>([]);
  const [saveOpen, setSaveOpen] = useState(false);
  const [viewName, setViewName] = useState('');
  const [viewShared, setViewShared] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'skip' | 'update'>('skip');
  const [preview, setPreview] = useState<AssetImportResult | null>(null);
  const [busy, setBusy] = useState(false);

  const loadViews = useCallback(() => {
    api.getSavedViews('assets').then(setViews).catch(() => setViews([]));
  }, []);
  useEffect(() => { loadViews(); }, [loadViews]);

  const exportAs = async (format: 'csv' | 'xlsx') => {
    try {
      const data = await api.exportAssetInventory({
        format,
        organization_id: organizationId,
        asset_type: filters.asset_type,
        search: filters.search,
      });
      download(data, `assets.${format}`, format === 'csv' ? 'text/csv'
        : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    } catch (error) {
      toast({ title: 'Export failed', description: getApiErrorMessage(error, 'Export failed'), variant: 'destructive' });
    }
  };

  const runImport = async (dryRun: boolean) => {
    if (!file) return;
    setBusy(true);
    try {
      const result = await api.importAssetInventory(file, { organization_id: organizationId, mode, dry_run: dryRun });
      if (dryRun) {
        setPreview(result);
      } else {
        toast({ title: 'Import complete', description: `${result.created} created, ${result.updated} updated, ${result.skipped} skipped, ${result.invalid} invalid` });
        setFile(null);
        setPreview(null);
        onImported();
      }
    } catch (error) {
      toast({ title: 'Import failed', description: getApiErrorMessage(error, 'Import failed'), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const saveView = async () => {
    try {
      await api.createSavedView({ page: 'assets', name: viewName.trim(), filters, shared: viewShared });
      setSaveOpen(false);
      setViewName('');
      loadViews();
    } catch (error) {
      toast({ title: 'Could not save view', description: getApiErrorMessage(error, 'Save failed'), variant: 'destructive' });
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm"><Bookmark className="h-4 w-4 mr-1" /> Views</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-64">
          {!views.length && <DropdownMenuItem disabled>No saved views</DropdownMenuItem>}
          {views.map((view) => (
            <DropdownMenuItem key={view.id} className="flex justify-between"
                              onSelect={() => onApplyView(view.filters as AssetViewFilters)}>
              <span className="truncate">{view.name}{view.shared ? ' · shared' : ''}</span>
              {view.mine && (
                <Trash2 className="h-3.5 w-3.5 text-muted-foreground" aria-label={`Delete ${view.name}`}
                        onClick={async (e) => { e.stopPropagation(); await api.deleteSavedView(view.id); loadViews(); }} />
              )}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setSaveOpen(true)}>Save current filters…</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm"><Download className="h-4 w-4 mr-1" /> Export</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem onSelect={() => exportAs('csv')}>CSV</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => exportAs('xlsx')}>Excel (.xlsx)</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
        <Upload className="h-4 w-4 mr-1" /> Import
      </Button>
      <input ref={fileRef} type="file" accept=".csv,.xlsx" className="hidden"
             onChange={(e) => { const f = e.target.files?.[0] || null; setFile(f); setPreview(null); e.target.value = ''; }} />

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save view</DialogTitle>
            <DialogDescription>Saves the current search and filters.</DialogDescription>
          </DialogHeader>
          <Label htmlFor="view-name">Name</Label>
          <Input id="view-name" value={viewName} maxLength={80} onChange={(e) => setViewName(e.target.value)} />
          <label className="flex items-center gap-2 text-sm"><Switch checked={viewShared} onCheckedChange={setViewShared} /> Share with my organization</label>
          <DialogFooter><Button onClick={saveView} disabled={!viewName.trim()}>Save</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!file} onOpenChange={(open) => { if (!open) { setFile(null); setPreview(null); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><FileSpreadsheet className="h-5 w-5" /> Import {file?.name}</DialogTitle>
            <DialogDescription>
              Needs a <code>value</code> column; <code>asset_type</code>, name, description, tags (; separated),
              criticality, in_scope and is_monitored are optional. Up to 10,000 rows.{' '}
              <a className="underline" href="#" onClick={async (e) => { e.preventDefault(); download(await api.getAssetImportTemplate(), 'asset_import_template.csv', 'text/csv'); }}>Download template</a>
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Existing assets</Label>
            <Select value={mode} onValueChange={(v) => { setMode(v as 'skip' | 'update'); setPreview(null); }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="skip">Leave unchanged (only add new)</SelectItem>
                <SelectItem value="update">Update name, description, tags, criticality, scope</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {preview && (
            <div className="text-sm space-y-1">
              <p>Preview: {preview.created} new, {preview.updated} updated, {preview.skipped} skipped, {preview.invalid} invalid.</p>
              {preview.errors.slice(0, 8).map((err) => (
                <p key={err.line} className="text-xs text-red-500">Line {err.line}: {err.error}</p>
              ))}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => runImport(true)} disabled={busy}>Preview</Button>
            <Button onClick={() => runImport(false)} disabled={busy || !preview}>
              {busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />} Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function BulkEditButton({ assetIds, organizationId, onDone }: {
  assetIds: number[]; organizationId?: number; onDone: () => void;
}) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [criticality, setCriticality] = useState('unchanged');
  const [addTags, setAddTags] = useState('');
  const [removeTags, setRemoveTags] = useState('');
  const [busy, setBusy] = useState(false);

  const apply = async () => {
    setBusy(true);
    try {
      const split = (text: string) => text.split(/[,;]/).map((t) => t.trim()).filter(Boolean);
      const result = await api.bulkUpdateAssets({
        organization_id: organizationId,
        asset_ids: assetIds,
        changes: {
          ...(criticality !== 'unchanged' ? { criticality } : {}),
          add_tags: split(addTags),
          remove_tags: split(removeTags),
        },
      });
      toast({ title: 'Assets updated', description: `${result.updated} asset(s) changed` });
      setOpen(false);
      onDone();
    } catch (error) {
      toast({ title: 'Update failed', description: getApiErrorMessage(error, 'Bulk update failed'), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}><Pencil className="h-4 w-4 mr-1" /> Edit Fields</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit {assetIds.length} asset(s)</DialogTitle>
            <DialogDescription>Only the fields you change are applied.</DialogDescription>
          </DialogHeader>
          <Label>Criticality</Label>
          <Select value={criticality} onValueChange={setCriticality}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {['unchanged', 'low', 'medium', 'high', 'critical'].map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
          <Label htmlFor="add-tags">Add tags</Label>
          <Input id="add-tags" value={addTags} onChange={(e) => setAddTags(e.target.value)} placeholder="prod, customer-facing" />
          <Label htmlFor="remove-tags">Remove tags</Label>
          <Input id="remove-tags" value={removeTags} onChange={(e) => setRemoveTags(e.target.value)} />
          <DialogFooter>
            <Button onClick={apply} disabled={busy || (criticality === 'unchanged' && !addTags.trim() && !removeTags.trim())}>
              {busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />} Apply
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
