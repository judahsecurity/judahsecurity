'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface Props {
  open: boolean;
  organizationId: number;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}

const DEFAULT_PYTHON = `import os
from pathlib import Path

inp = Path(os.environ["WORKFLOW_IN"])
out = Path(os.environ["WORKFLOW_OUT"])
# Read first .txt in inputs and echo hosts
lines = []
for p in sorted(inp.glob("*.txt")):
    lines.extend(p.read_text().splitlines())
(out / "hosts.txt").write_text("\\n".join(x for x in lines if x.strip()) + "\\n")
print(f"wrote {len(lines)} lines")
`;

export function ScriptEditor({ open, organizationId, onOpenChange, onCreated }: Props) {
  const { toast } = useToast();
  const [name, setName] = useState('Normalize hosts');
  const [language, setLanguage] = useState('python');
  const [source, setSource] = useState(DEFAULT_PYTHON);
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!organizationId) return;
    setSaving(true);
    try {
      await api.createWorkflowScript({
        name,
        language,
        source,
        organization_id: organizationId,
        input_ports: [{ name: 'hosts', type: 'FILE_LIST' }],
        output_ports: [{ name: 'hosts', type: 'FILE_LIST' }],
      });
      toast({ title: 'Script created' });
      onCreated();
      onOpenChange(false);
    } catch (e: any) {
      toast({ title: 'Failed to create script', description: e?.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>New workflow script</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label>Language</Label>
            <Select value={language} onValueChange={setLanguage}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="python">Python</SelectItem>
                <SelectItem value="bash">Bash</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>Source</Label>
            <textarea
              className="w-full h-64 rounded-md border border-border bg-background p-3 font-mono text-xs"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={save} disabled={saving}>
            Save script
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
