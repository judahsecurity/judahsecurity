'use client';

import { useEffect, useState } from 'react';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import {
  api, getApiErrorMessage, type CensysFieldMappingRule, type CensysIntegration,
  type CensysMappingCatalog, type CensysSampleFields,
} from '@/lib/api';

const ENTITIES = ['host', 'domain', 'subdomain', 'certificate', 'risk'];

export function CensysFieldMappingDialog({
  integration, open, onOpenChange, onSaved,
}: {
  integration: CensysIntegration | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<CensysMappingCatalog | null>(null);
  const [rules, setRules] = useState<CensysFieldMappingRule[]>([]);
  const [sampleEntity, setSampleEntity] = useState('host');
  const [samples, setSamples] = useState<Record<string, CensysSampleFields>>({});
  const [loadingSample, setLoadingSample] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !integration) return;
    setRules(integration.field_mappings || []);
    setSamples({});
    api.getCensysMappingCatalog().then(setCatalog).catch((err) => {
      toast({ title: 'Could not load mapping fields', description: getApiErrorMessage(err), variant: 'destructive' });
    });
  }, [open, integration, toast]);

  function changeRule(index: number, patch: Partial<CensysFieldMappingRule>) {
    setRules(current => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule));
  }

  async function loadSample() {
    if (!integration) return;
    setLoadingSample(true);
    try {
      const sample = await api.getCensysSampleFields(integration.id, sampleEntity);
      setSamples(current => ({ ...current, [sampleEntity]: sample }));
      if (!sample.fields.length) toast({ title: `No ${sampleEntity} sample available in this workspace.` });
    } catch (err) {
      toast({ title: 'Could not read Censys sample', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setLoadingSample(false);
    }
  }

  async function save() {
    if (!integration) return;
    setSaving(true);
    try {
      await api.updateCensysMappings(integration.id, rules);
      toast({ title: 'Censys field mappings saved', description: 'They will apply on the next sync.' });
      onOpenChange(false);
      onSaved();
    } catch (err) {
      toast({ title: 'Could not save mappings', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(value) => { if (!saving) onOpenChange(value); }}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Censys ASM field mapping</DialogTitle>
          <DialogDescription>
            Map fields from {integration?.workspace_name} into Judah assets and findings. Identity and organization
            stay fixed. Use custom metadata for fields Judah does not have yet.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="rounded-lg border border-border p-3 space-y-2">
            <p className="text-sm font-medium">Inspect a live Censys sample</p>
            <div className="flex flex-wrap gap-2">
              <Select value={sampleEntity} onValueChange={setSampleEntity}>
                <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
                <SelectContent>{ENTITIES.map(e => <SelectItem key={e} value={e}>{e}</SelectItem>)}</SelectContent>
              </Select>
              <Button variant="outline" onClick={loadSample} disabled={loadingSample}>
                {loadingSample && <Loader2 className="h-4 w-4 animate-spin mr-2" />}Load sample fields
              </Button>
            </div>
            {samples[sampleEntity]?.fields.length ? (
              <div className="max-h-32 overflow-y-auto text-xs text-muted-foreground space-y-1">
                {samples[sampleEntity].fields.map(field => (
                  <div key={field.path}><code>{field.path}</code> <span>({field.type})</span> — {field.example}</div>
                ))}
              </div>
            ) : null}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Mapping rules</p>
                <p className="text-xs text-muted-foreground">Source paths may use dots and list indexes, such as services[0].port.</p>
              </div>
              <Button size="sm" variant="outline" disabled={!catalog || rules.length >= 50}
                onClick={() => setRules(current => [...current, { entity: 'host', source_path: '', target: 'operating_system' }])}>
                <Plus className="h-4 w-4 mr-1" />Add mapping
              </Button>
            </div>
            {!rules.length && <p className="text-sm text-muted-foreground rounded-lg border border-dashed p-4">No extra mappings yet. Judah still imports basic Censys asset and risk identities.</p>}
            {ENTITIES.map(entity => (
              <datalist key={entity} id={`censys-fields-${entity}`}>
                {(samples[entity]?.fields || []).map(field => <option key={field.path} value={field.path} />)}
              </datalist>
            ))}
            {rules.map((rule, index) => {
              const targets = catalog?.entities[rule.entity] || {};
              const custom = rule.target.startsWith('custom.');
              return (
                <div key={index} className="grid grid-cols-1 md:grid-cols-[130px_1fr_180px_32px] gap-2 items-start rounded-lg border border-border p-2">
                  <Select value={rule.entity} onValueChange={(entity) => changeRule(index, { entity, target: Object.keys(catalog?.entities[entity] || {})[0] || '' })}>
                    <SelectTrigger aria-label={`Entity for rule ${index + 1}`}><SelectValue /></SelectTrigger>
                    <SelectContent>{ENTITIES.map(e => <SelectItem key={e} value={e}>{e}</SelectItem>)}</SelectContent>
                  </Select>
                  <div>
                    <Input aria-label={`Censys source path for rule ${index + 1}`} list={`censys-fields-${rule.entity}`} placeholder="Censys source path" value={rule.source_path}
                      onChange={e => changeRule(index, { source_path: e.target.value })} />
                  </div>
                  <div className="space-y-1">
                    <Select value={custom ? '__custom' : rule.target} onValueChange={(target) => changeRule(index, { target: target === '__custom' ? 'custom.field' : target })}>
                      <SelectTrigger aria-label={`Judah target for rule ${index + 1}`}><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {Object.entries(targets).map(([target, kind]) => <SelectItem key={target} value={target}>{target} ({kind})</SelectItem>)}
                        <SelectItem value="__custom">Custom metadata</SelectItem>
                      </SelectContent>
                    </Select>
                    {custom && <Input aria-label={`Custom metadata key for rule ${index + 1}`} placeholder="Field name" value={rule.target.slice(7)}
                      onChange={e => changeRule(index, { target: `custom.${e.target.value}` })} />}
                  </div>
                  <Button size="icon" variant="ghost" aria-label={`Remove rule ${index + 1}`} onClick={() => setRules(current => current.filter((_, i) => i !== index))}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              );
            })}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>Cancel</Button>
          <Button onClick={save} disabled={saving || !catalog}>{saving && <Loader2 className="h-4 w-4 animate-spin mr-2" />}Save mappings</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
