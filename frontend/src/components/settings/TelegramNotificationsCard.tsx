'use client';

import { useEffect, useState } from 'react';
import { Bell, Loader2, Send } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function TelegramNotificationsCard({ orgId }: { orgId: number | null }) {
  const { toast } = useToast();
  const [loaded, setLoaded] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [chatIds, setChatIds] = useState('');
  const [notifyFindings, setNotifyFindings] = useState(true);
  const [notifyRuns, setNotifyRuns] = useState(true);
  const [minSeverity, setMinSeverity] = useState('high');
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);

  useEffect(() => {
    if (!orgId) return;
    setLoaded(false);
    api.getProjectSettings(orgId, 'notifications')
      .then((data) => {
        setEnabled(Boolean(data.telegram_enabled));
        setChatIds((data.telegram_chat_ids || []).join(', '));
        setNotifyFindings(data.notify_findings ?? true);
        setNotifyRuns(data.notify_run_finished ?? true);
        setMinSeverity(data.min_severity || 'high');
      })
      .catch(() => undefined)
      .finally(() => setLoaded(true));
  }, [orgId]);

  const save = async () => {
    if (!orgId) return;
    setBusy('save');
    try {
      const data = await api.updateProjectSettingsModule(orgId, 'notifications', {
        telegram_enabled: enabled,
        telegram_chat_ids: chatIds,
        notify_findings: notifyFindings,
        notify_run_finished: notifyRuns,
        min_severity: minSeverity,
      });
      setChatIds((data.telegram_chat_ids || []).join(', '));
      toast({ title: 'Saved', description: 'Notification settings updated' });
    } catch (error) {
      toast({ title: 'Error', description: getApiErrorMessage(error, 'Failed to save notification settings'), variant: 'destructive' });
    } finally {
      setBusy(null);
    }
  };

  const sendTest = async () => {
    if (!orgId) return;
    setBusy('test');
    try {
      const { results } = await api.sendTestNotification(orgId);
      const failed = Object.entries(results).filter(([, status]) => status !== 'sent');
      toast(failed.length
        ? { title: 'Some chats failed', description: failed.map(([id, why]) => `${id}: ${why}`).join('; '), variant: 'destructive' }
        : { title: 'Test sent', description: `Delivered to ${Object.keys(results).length} chat(s)` });
    } catch (error) {
      toast({ title: 'Test failed', description: getApiErrorMessage(error, 'Could not send a test message'), variant: 'destructive' });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bell className="h-5 w-5" />
          Telegram Notifications
        </CardTitle>
        <CardDescription>
          Send a short summary to Telegram when an agent run ends or the agent files a finding.
          Messages contain the title, severity and asset only, never evidence. Admins only.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {!loaded ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading settings…
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Enable Telegram</p>
                <p className="text-sm text-muted-foreground">Requires TELEGRAM_BOT_TOKEN on the server.</p>
              </div>
              <Switch checked={enabled} onCheckedChange={setEnabled} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="tg-chats">Chat IDs</Label>
              <Input id="tg-chats" value={chatIds} onChange={(e) => setChatIds(e.target.value)}
                     placeholder="-1001234567890, @your_channel" />
              <p className="text-xs text-muted-foreground">
                Add the bot to a group or channel, send it a message, then use that chat&apos;s numeric ID
                (groups start with -100). Up to 10, comma separated.
              </p>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-medium">New findings</p>
              <Switch checked={notifyFindings} onCheckedChange={setNotifyFindings} />
            </div>
            <div className="space-y-2">
              <Label>Minimum finding severity</Label>
              <Select value={minSeverity} onValueChange={setMinSeverity}>
                <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between">
              <p className="font-medium">Agent run finished</p>
              <Switch checked={notifyRuns} onCheckedChange={setNotifyRuns} />
            </div>
            <div className="flex gap-2 pt-4 border-t">
              <Button onClick={save} disabled={busy !== null || !orgId}>
                {busy === 'save' ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Save Notification Settings
              </Button>
              <Button variant="outline" onClick={sendTest} disabled={busy !== null || !orgId}>
                {busy === 'test' ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Send className="h-4 w-4 mr-2" />}
                Send test message
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
