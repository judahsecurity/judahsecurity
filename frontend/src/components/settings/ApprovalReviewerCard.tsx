'use client';

import { useEffect, useState } from 'react';
import { Bot, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

export function ApprovalReviewerCard({ orgId }: { orgId: number | null }) {
  const { toast } = useToast();
  const [loaded, setLoaded] = useState(false);
  const [aiReviewer, setAiReviewer] = useState(false);
  const [tools, setTools] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!orgId) return;
    setLoaded(false);
    api.getProjectSettings(orgId, 'agent')
      .then((data) => {
        setAiReviewer(data.tool_confirmation_reviewer === 'ai');
        setTools((data.ai_reviewer_tools || []).join(', '));
      })
      .catch(() => undefined)
      .finally(() => setLoaded(true));
  }, [orgId]);

  const save = async () => {
    if (!orgId) return;
    setSaving(true);
    try {
      await api.updateProjectSettingsModule(orgId, 'agent', {
        tool_confirmation_reviewer: aiReviewer ? 'ai' : 'human',
        ai_reviewer_tools: tools.split(/[\s,]+/).filter(Boolean),
      });
      toast({ title: 'Saved', description: 'Approval reviewer updated' });
    } catch (error) {
      toast({ title: 'Error', description: getApiErrorMessage(error, 'Failed to save'), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Bot className="h-5 w-5" /> AI Approval Reviewer</CardTitle>
        <CardDescription>
          Let a small model approve routine scanner calls that need approval, so runs don&apos;t stall.
          It can only approve or pass to a person — never deny. Rules-of-Engagement approvals, pilots and
          risky tools (sqlmap, intruder, custom code, masscan, new scans, MCP) always go to a person.
          Every AI decision is in the Audit Log.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!loaded ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <p className="font-medium">Use the AI reviewer</p>
              <Switch checked={aiReviewer} onCheckedChange={setAiReviewer} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ai-tools">Tools it may approve (optional)</Label>
              <Input id="ai-tools" value={tools} onChange={(e) => setTools(e.target.value)}
                     placeholder="Default: nuclei, naabu, nmap, ffuf, katana, nikto, testssl, …" />
            </div>
            <Button onClick={save} disabled={saving || !orgId}>
              {saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />} Save Reviewer Settings
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}
