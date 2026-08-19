'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { Rocket } from 'lucide-react';

import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

type Playbook = { id: string; name: string; description: string };

interface LaunchAssessmentDialogProps {
  /** Prefill the target field (e.g. from an asset row). */
  defaultTarget?: string;
  /** Prefill the playbook selection. Use "custom" for a free-form objective. */
  defaultPlaybookId?: string;
  /** Custom trigger element. Defaults to a "Launch assessment" button. */
  trigger?: React.ReactNode;
}

const CUSTOM = 'custom';

/**
 * Reusable launcher for an Aegis engagement. Collects a playbook (or a
 * free-form objective), a target, and a run mode, then deep-links to the
 * agent chat with `autostart=1` so the run begins and streams immediately.
 */
export function LaunchAssessmentDialog({
  defaultTarget = '',
  defaultPlaybookId = CUSTOM,
  trigger,
}: LaunchAssessmentDialogProps) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [playbooks, setPlaybooks] = React.useState<Playbook[]>([]);
  const [playbookId, setPlaybookId] = React.useState(defaultPlaybookId);
  const [target, setTarget] = React.useState(defaultTarget);
  const [question, setQuestion] = React.useState('');
  const [mode, setMode] = React.useState<'assist' | 'agent'>('agent');

  React.useEffect(() => {
    if (!open) return;
    setTarget(defaultTarget);
    setPlaybookId(defaultPlaybookId);
    api.getAgentPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }, [open, defaultTarget, defaultPlaybookId]);

  const isCustom = playbookId === CUSTOM;
  const selected = playbooks.find((p) => p.id === playbookId);
  const canLaunch = isCustom
    ? question.trim().length > 0 || target.trim().length > 0
    : target.trim().length > 0 || Boolean(selected);

  const launch = () => {
    const params = new URLSearchParams();
    if (target.trim()) params.set('target', target.trim());
    if (!isCustom) params.set('playbook', playbookId);
    if (isCustom && question.trim()) params.set('question', question.trim());
    params.set('mode', mode);
    params.set('autostart', '1');
    setOpen(false);
    router.push(`/agent?${params.toString()}`);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button>
            <Rocket className="mr-2 h-4 w-4" />
            Launch assessment
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Launch assessment</DialogTitle>
          <DialogDescription>
            Point Aegis at a target. Pick a playbook for a structured run, or choose
            &quot;Custom objective&quot; to let the agent decide everything.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="launch-playbook">Playbook</Label>
            <Select value={playbookId} onValueChange={setPlaybookId}>
              <SelectTrigger id="launch-playbook">
                <SelectValue placeholder="Choose a playbook" />
              </SelectTrigger>
              <SelectContent className="max-h-72">
                <SelectItem value={CUSTOM}>Custom objective (agent decides)</SelectItem>
                {playbooks.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!isCustom && selected?.description && (
              <p className="text-xs text-muted-foreground">{selected.description}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="launch-target">Target</Label>
            <Input
              id="launch-target"
              placeholder="https://app.example.com  ·  host  ·  repo path"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>

          {isCustom && (
            <div className="space-y-2">
              <Label htmlFor="launch-objective">Objective</Label>
              <Textarea
                id="launch-objective"
                placeholder="e.g. Find IDORs and broken object-level auth in the /api/orders endpoints."
                rows={3}
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
              />
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="launch-mode">Mode</Label>
            <Select value={mode} onValueChange={(v) => setMode(v as 'assist' | 'agent')}>
              <SelectTrigger id="launch-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="agent">Autonomous (agent)</SelectItem>
                <SelectItem value="assist">Step-by-step (assist)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={launch} disabled={!canLaunch}>
            <Rocket className="mr-2 h-4 w-4" />
            Launch
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default LaunchAssessmentDialog;
