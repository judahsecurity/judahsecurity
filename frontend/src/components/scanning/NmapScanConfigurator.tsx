'use client';

import { useEffect, useMemo, useState } from 'react';
import { api, NmapProfile, NmapProfileConfig } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertTriangle, Save, Trash2, Terminal } from 'lucide-react';

interface NmapOption {
  value: string;
  label: string;
  description: string;
}

interface TimingOption {
  value: number;
  label: string;
  description: string;
}

interface NseGroup {
  group: string;
  scripts: NmapOption[];
}

interface PortList {
  name: string;
  description?: string;
  ports_string: string;
  port_count: number;
}

export const DEFAULT_NMAP_CONFIG: NmapProfileConfig = {
  nmap_scan_type: '-sT',
  timing: 4,
  service_detection: true,
  os_detection: false,
  nse_scripts: [],
  ports: null,
};

/** Techniques that need raw sockets (root) — surfaced as a warning, not a block. */
const ROOT_TECHNIQUES = new Set(['-sS', '-sU', '-sA', '-sN', '-sF', '-sX']);

/**
 * Client-side mirror of PortScannerService.build_nmap_command_preview so the
 * preview updates instantly. The backend re-validates before running, so this
 * is advisory display only.
 */
function buildCommandPreview(cfg: NmapProfileConfig, validTechniques: Set<string>): string {
  const scanType = validTechniques.size === 0 || validTechniques.has(cfg.nmap_scan_type)
    ? cfg.nmap_scan_type
    : '-sT';
  const timing = Math.max(0, Math.min(5, Number.isFinite(cfg.timing) ? cfg.timing : 4));
  const parts = ['nmap', scanType, `-T${timing}`, '-Pn'];
  const ports = (cfg.ports || '').trim();
  if (ports && ports !== '-' && ports !== 'all') {
    parts.push('-p', ports);
  } else if (ports === '-' || ports === 'all') {
    parts.push('-p', '1-65535');
  }
  if (cfg.service_detection) parts.push('-sV');
  if (cfg.os_detection) parts.push('-O');
  if (cfg.nse_scripts.length > 0) parts.push('--script', cfg.nse_scripts.join(','));
  parts.push('<targets>');
  return parts.join(' ');
}

interface Props {
  value: NmapProfileConfig;
  onChange: (config: NmapProfileConfig) => void;
}

export function NmapScanConfigurator({ value, onChange }: Props) {
  const { toast } = useToast();
  const [techniques, setTechniques] = useState<NmapOption[]>([]);
  const [timings, setTimings] = useState<TimingOption[]>([]);
  const [nseGroups, setNseGroups] = useState<NseGroup[]>([]);
  const [portLists, setPortLists] = useState<PortList[]>([]);
  const [profiles, setProfiles] = useState<NmapProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('');
  const [profileName, setProfileName] = useState('');
  const [customScripts, setCustomScripts] = useState('');
  const [saving, setSaving] = useState(false);

  const validTechniques = useMemo(
    () => new Set(techniques.map((t) => t.value)),
    [techniques]
  );

  const loadProfiles = async () => {
    try {
      setProfiles(await api.getNmapProfiles());
    } catch {
      /* profiles are optional; ignore load failures */
    }
  };

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [options, lists] = await Promise.all([
          api.getNmapOptions(),
          api.getPortLists().catch(() => []),
        ]);
        if (!active) return;
        setTechniques(options.scan_techniques);
        setTimings(options.timing_templates);
        setNseGroups(options.nse_catalog);
        setPortLists(lists as PortList[]);
      } catch {
        toast({
          title: 'Could not load nmap options',
          description: 'Using built-in defaults. Check that the backend is reachable.',
          variant: 'destructive',
        });
      }
      await loadProfiles();
    })();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const update = (patch: Partial<NmapProfileConfig>) => {
    onChange({ ...value, ...patch });
    setSelectedProfile(''); // any manual edit detaches from the loaded profile
  };

  const toggleScript = (script: string, checked: boolean) => {
    const set = new Set(value.nse_scripts);
    if (checked) set.add(script);
    else set.delete(script);
    update({ nse_scripts: Array.from(set) });
  };

  const applyCustomScripts = () => {
    const extra = customScripts
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (extra.length === 0) return;
    update({ nse_scripts: Array.from(new Set([...value.nse_scripts, ...extra])) });
    setCustomScripts('');
  };

  const loadProfile = (name: string) => {
    const profile = profiles.find((p) => p.name === name);
    if (!profile) return;
    onChange({ ...DEFAULT_NMAP_CONFIG, ...profile.config });
    setSelectedProfile(name);
  };

  const handleSaveProfile = async () => {
    const name = profileName.trim();
    if (!name) {
      toast({ title: 'Name required', description: 'Enter a name to save this profile.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      await api.saveNmapProfile({ name, config: value });
      toast({ title: 'Profile saved', description: `"${name}" is now reusable.` });
      setProfileName('');
      await loadProfiles();
      setSelectedProfile(name);
    } catch (error: any) {
      toast({
        title: 'Could not save profile',
        description: error?.response?.data?.detail || 'Save failed.',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteProfile = async (name: string) => {
    try {
      await api.deleteNmapProfile(name);
      toast({ title: 'Profile deleted', description: `"${name}" removed.` });
      if (selectedProfile === name) setSelectedProfile('');
      await loadProfiles();
    } catch (error: any) {
      toast({
        title: 'Could not delete profile',
        description: error?.response?.data?.detail || 'Delete failed.',
        variant: 'destructive',
      });
    }
  };

  const commandPreview = useMemo(
    () => buildCommandPreview(value, validTechniques),
    [value, validTechniques]
  );

  const needsRoot = ROOT_TECHNIQUES.has(value.nmap_scan_type) || value.os_detection;
  const selectedProfileObj = profiles.find((p) => p.name === selectedProfile);

  return (
    <div className="space-y-4 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
      <div className="flex items-center gap-2">
        <Terminal className="h-4 w-4 text-emerald-400" />
        <p className="text-sm font-medium">Custom Nmap Configuration</p>
      </div>

      {/* Saved profiles */}
      {profiles.length > 0 && (
        <div className="space-y-2">
          <Label>Start from a saved profile</Label>
          <div className="flex items-center gap-2">
            <Select value={selectedProfile} onValueChange={loadProfile}>
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Select a profile to load…" />
              </SelectTrigger>
              <SelectContent>
                {profiles.map((p) => (
                  <SelectItem key={p.name} value={p.name}>
                    <div className="flex flex-col">
                      <span>
                        {p.name}
                        {p.is_default && <span className="ml-2 text-xs text-muted-foreground">(built-in)</span>}
                      </span>
                      {p.description && (
                        <span className="text-xs text-muted-foreground">{p.description}</span>
                      )}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedProfileObj && !selectedProfileObj.is_default && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="text-red-500 hover:text-red-600 hover:bg-red-500/10"
                onClick={() => handleDeleteProfile(selectedProfileObj.name)}
                title="Delete profile"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      )}

      {/* Technique + timing */}
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-2">
          <Label>Scan technique</Label>
          <Select value={value.nmap_scan_type} onValueChange={(v) => update({ nmap_scan_type: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {techniques.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  <div className="flex flex-col">
                    <span className="font-mono">{t.value}</span>
                    <span className="text-xs text-muted-foreground">{t.description}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Timing template</Label>
          <Select
            value={String(value.timing)}
            onValueChange={(v) => update({ timing: parseInt(v, 10) })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {timings.map((t) => (
                <SelectItem key={t.value} value={String(t.value)}>
                  <div className="flex flex-col">
                    <span>{t.label}</span>
                    <span className="text-xs text-muted-foreground">{t.description}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Detection toggles */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-center justify-between rounded-md border p-3">
          <div>
            <Label className="cursor-pointer">Service / version detection</Label>
            <p className="text-xs text-muted-foreground font-mono">-sV</p>
          </div>
          <Switch
            checked={value.service_detection}
            onCheckedChange={(c) => update({ service_detection: c })}
          />
        </div>
        <div className="flex items-center justify-between rounded-md border p-3">
          <div>
            <Label className="cursor-pointer">OS detection</Label>
            <p className="text-xs text-muted-foreground font-mono">-O (needs root)</p>
          </div>
          <Switch
            checked={value.os_detection}
            onCheckedChange={(c) => update({ os_detection: c })}
          />
        </div>
      </div>

      {/* Ports */}
      <div className="space-y-2">
        <Label>Ports</Label>
        <div className="flex items-center gap-2">
          <Select
            value=""
            onValueChange={(v) => {
              const list = portLists.find((l) => l.name === v);
              if (list) update({ ports: list.ports_string });
            }}
          >
            <SelectTrigger className="w-[200px]">
              <SelectValue placeholder="Use a preset…" />
            </SelectTrigger>
            <SelectContent>
              {portLists.map((l) => (
                <SelectItem key={l.name} value={l.name}>
                  {l.name} ({l.port_count})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            className="flex-1 font-mono"
            placeholder="80,443,8080 or 1-1000 or - for all"
            value={value.ports || ''}
            onChange={(e) => update({ ports: e.target.value || null })}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Pick a preset to fill the box, then edit freely. Leave empty for nmap's top ports.
        </p>
      </div>

      {/* NSE scripts */}
      <div className="space-y-2">
        <Label>NSE scripts</Label>
        <div className="space-y-3">
          {nseGroups.map((group) => (
            <div key={group.group} className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground">{group.group}</p>
              <div className="grid grid-cols-2 gap-2">
                {group.scripts.map((s) => (
                  <div key={s.value} className="flex items-start space-x-2">
                    <Checkbox
                      id={`nse-${s.value}`}
                      checked={value.nse_scripts.includes(s.value)}
                      onCheckedChange={(c) => toggleScript(s.value, !!c)}
                    />
                    <label htmlFor={`nse-${s.value}`} className="cursor-pointer">
                      <span className="text-sm font-mono">{s.label}</span>
                      <span className="block text-xs text-muted-foreground">{s.description}</span>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Input
            className="flex-1 font-mono"
            placeholder="Add custom scripts, comma-separated (e.g. http-enum,smb-vuln*)"
            value={customScripts}
            onChange={(e) => setCustomScripts(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                applyCustomScripts();
              }
            }}
          />
          <Button type="button" variant="outline" size="sm" onClick={applyCustomScripts}>
            Add
          </Button>
        </div>
        {value.nse_scripts.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {value.nse_scripts.map((s) => (
              <Badge
                key={s}
                variant="secondary"
                className="cursor-pointer font-mono"
                onClick={() => toggleScript(s, false)}
                title="Click to remove"
              >
                {s} ✕
              </Badge>
            ))}
          </div>
        )}
      </div>

      {/* Root warning */}
      {needsRoot && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5">
          <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
          <p className="text-xs text-muted-foreground">
            SYN/UDP/ACK techniques and OS detection need raw-socket (root) privileges on the scanner.
            If the scanner runs unprivileged, nmap falls back to a TCP connect scan.
          </p>
        </div>
      )}

      {/* Command preview */}
      <div className="space-y-1">
        <Label>Command preview</Label>
        <div className="rounded-md border bg-background p-3 font-mono text-xs overflow-x-auto">
          <code className="text-emerald-400 whitespace-nowrap">{commandPreview}</code>
        </div>
      </div>

      {/* Save as profile */}
      <div className="flex items-center gap-2 border-t pt-3">
        <Input
          className="flex-1"
          placeholder="Save this configuration as… (profile name)"
          value={profileName}
          onChange={(e) => setProfileName(e.target.value)}
        />
        <Button type="button" variant="outline" size="sm" onClick={handleSaveProfile} disabled={saving}>
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving…' : 'Save profile'}
        </Button>
      </div>
    </div>
  );
}
