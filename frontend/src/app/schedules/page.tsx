'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  CalendarClock,
  Play,
  Pause,
  Plus,
  RefreshCw,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Trash2,
  History,
  Pencil,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import { ScanNavTabs } from '@/components/scanning/ScanNavTabs';

interface ScanSchedule {
  id: number;
  name: string;
  description?: string;
  organization_id: number;
  scan_type: string;
  targets: string[];
  label_ids: number[];
  config: Record<string, any>;
  frequency: string;
  run_at_hour: number;
  run_on_day?: number;
  is_enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  run_count: number;
  consecutive_failures: number;
  last_error?: string;
  created_at: string;
}

interface ScanType {
  name: string;
  description: string;
  default_config: Record<string, any>;
}

const FREQUENCY_OPTIONS = [
  { value: 'every_15_minutes', label: 'Every 15 Minutes' },
  { value: 'every_30_minutes', label: 'Every 30 Minutes' },
  { value: 'hourly', label: 'Hourly' },
  { value: 'every_2_hours', label: 'Every 2 Hours' },
  { value: 'every_4_hours', label: 'Every 4 Hours' },
  { value: 'every_6_hours', label: 'Every 6 Hours' },
  { value: 'every_12_hours', label: 'Every 12 Hours' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
];

const DAY_OPTIONS = [
  { value: '0', label: 'Monday' },
  { value: '1', label: 'Tuesday' },
  { value: '2', label: 'Wednesday' },
  { value: '3', label: 'Thursday' },
  { value: '4', label: 'Friday' },
  { value: '5', label: 'Saturday' },
  { value: '6', label: 'Sunday' },
];

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [scanTypes, setScanTypes] = useState<Record<string, ScanType>>({});
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<ScanSchedule | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    organization_id: '',
    scan_type: 'critical_ports',
    frequency: 'daily',
    run_at_hour: '2',
    run_on_day: '0',
    targets: '',
    is_enabled: true,
    autonomous_followup: false,
  });
  const [editFormData, setEditFormData] = useState({
    name: '',
    description: '',
    scan_type: '',
    frequency: '',
    run_at_hour: '2',
    run_on_day: '0',
    targets: '',
    is_enabled: true,
    autonomous_followup: false,
  });
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [schedulesData, typesData, orgsData] = await Promise.all([
        api.request('/scan-schedules/'),
        api.request('/scan-schedules/scan-types'),
        api.getOrganizations(),
      ]);

      setSchedules(schedulesData || []);
      setScanTypes(typesData || {});
      setOrganizations(orgsData || []);
      
      if (orgsData.length > 0 && !formData.organization_id) {
        setFormData(prev => ({ ...prev, organization_id: orgsData[0].id.toString() }));
      }
    } catch (error) {
      console.error('Failed to fetch data:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch schedules',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateSchedule = async () => {
    if (!formData.organization_id || !formData.name) {
      toast({
        title: 'Error',
        description: 'Please fill in all required fields',
        variant: 'destructive',
      });
      return;
    }

    setSubmitting(true);
    try {
      const targets = formData.targets
        .split('\n')
        .map((t) => t.trim())
        .filter((t) => t);

      await api.request('/scan-schedules/', {
        method: 'POST',
        body: JSON.stringify({
          name: formData.name,
          description: formData.description,
          organization_id: parseInt(formData.organization_id),
          scan_type: formData.scan_type,
          frequency: formData.frequency,
          run_at_hour: parseInt(formData.run_at_hour),
          run_on_day: formData.frequency === 'weekly' ? parseInt(formData.run_on_day) : undefined,
          targets: targets.length > 0 ? targets : undefined,
          is_enabled: formData.is_enabled,
          config: formData.scan_type === 'tester_process' ? {
            ...(scanTypes.tester_process?.default_config || {}),
            autonomous_followup: formData.autonomous_followup,
          } : undefined,
        }),
      });

      toast({
        title: 'Schedule Created',
        description: 'The scan schedule has been created successfully.',
      });

      setCreateDialogOpen(false);
      setFormData({
        name: '',
        description: '',
        organization_id: formData.organization_id,
        scan_type: 'critical_ports',
        frequency: 'daily',
        run_at_hour: '2',
        run_on_day: '0',
        targets: '',
        is_enabled: true,
        autonomous_followup: false,
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create schedule',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggle = async (scheduleId: number) => {
    try {
      await api.request(`/scan-schedules/${scheduleId}/toggle`, {
        method: 'POST',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to toggle schedule',
        variant: 'destructive',
      });
    }
  };

  const handleTrigger = async (scheduleId: number) => {
    try {
      const result = await api.triggerScanSchedule(scheduleId);
      toast({
        title: 'Scan Triggered',
        description: result.total_ips 
          ? `Scan queued with ${result.total_ips.toLocaleString()} IPs from ${result.targets_count} targets`
          : `Scan queued with ${result.targets_count} targets`,
      });
      fetchData();
    } catch (error: any) {
      console.error('Trigger error:', error);
      toast({
        title: 'Error',
        description: error.response?.data?.detail || error.message || 'Failed to trigger scan',
        variant: 'destructive',
      });
    }
  };

  const handleDelete = async (scheduleId: number) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return;
    
    try {
      await api.request(`/scan-schedules/${scheduleId}`, {
        method: 'DELETE',
      });
      toast({
        title: 'Schedule Deleted',
        description: 'The schedule has been deleted.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to delete schedule',
        variant: 'destructive',
      });
    }
  };

  const handleEditSchedule = (schedule: ScanSchedule) => {
    setEditingSchedule(schedule);
    setEditFormData({
      name: schedule.name,
      description: schedule.description || '',
      scan_type: schedule.scan_type,
      frequency: schedule.frequency,
      run_at_hour: schedule.run_at_hour.toString(),
      run_on_day: schedule.run_on_day?.toString() || '0',
      targets: schedule.targets?.join('\n') || '',
      is_enabled: schedule.is_enabled,
      autonomous_followup: schedule.config?.autonomous_followup === true,
    });
    setEditDialogOpen(true);
  };

  const handleUpdateSchedule = async () => {
    if (!editingSchedule) return;

    setSubmitting(true);
    try {
      const targets = editFormData.targets
        .split('\n')
        .map((t) => t.trim())
        .filter((t) => t);

      await api.request(`/scan-schedules/${editingSchedule.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: editFormData.name,
          description: editFormData.description || undefined,
          scan_type: editFormData.scan_type,
          frequency: editFormData.frequency,
          run_at_hour: parseInt(editFormData.run_at_hour),
          run_on_day: editFormData.frequency === 'weekly' ? parseInt(editFormData.run_on_day) : undefined,
          targets: targets.length > 0 ? targets : [],
          is_enabled: editFormData.is_enabled,
          config: editFormData.scan_type === 'tester_process' ? {
            ...(editingSchedule.config || scanTypes.tester_process?.default_config || {}),
            autonomous_followup: editFormData.autonomous_followup,
          } : undefined,
        }),
      });

      toast({
        title: 'Schedule Updated',
        description: 'The scan schedule has been updated successfully.',
      });

      setEditDialogOpen(false);
      setEditingSchedule(null);
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to update schedule',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const getFrequencyLabel = (freq: string) => {
    return FREQUENCY_OPTIONS.find(f => f.value === freq)?.label || freq;
  };

  const getScanTypeLabel = (type: string) => {
    return scanTypes[type]?.name || type;
  };

  return (
    <MainLayout>
      <Header title="Scanning" subtitle="Manage scans and schedules" />
      <ScanNavTabs />

      <div className="p-6 space-y-6">
        {/* Header Actions */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="outline" size="sm" onClick={fetchData}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                New Schedule
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create Scan Schedule</DialogTitle>
                <DialogDescription>
                  Set up a recurring scan for continuous monitoring.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Schedule Name *</Label>
                  <Input
                    placeholder="e.g., Daily Critical Port Monitor"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Description</Label>
                  <Input
                    placeholder="Optional description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Organization *</Label>
                  <Select
                    value={formData.organization_id}
                    onValueChange={(value) => setFormData({ ...formData, organization_id: value })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
                      {organizations.map((org) => (
                        <SelectItem key={org.id} value={org.id.toString()}>
                          {org.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Scan Type *</Label>
                  <Select
                    value={formData.scan_type}
                    onValueChange={(value) => setFormData({ ...formData, scan_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(scanTypes).map(([key, type]) => (
                        <SelectItem key={key} value={key}>
                          <div className="flex flex-col">
                            <span>{type.name}</span>
                            <span className="text-xs text-muted-foreground">{type.description}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {formData.scan_type === 'critical_ports' && (
                    <p className="text-xs text-muted-foreground flex items-center gap-1">
                      <Shield className="h-3 w-3" />
                      Monitors databases, remote access, file sharing, and container ports
                    </p>
                  )}
                </div>

                {formData.scan_type === 'tester_process' && (
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={formData.autonomous_followup}
                        onCheckedChange={(checked) => setFormData({ ...formData, autonomous_followup: checked })}
                      />
                      <Label>Continue partial hunts automatically</Label>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Up to 3 turns per target, with time and reported model spend limits.
                    </p>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Frequency *</Label>
                    <Select
                      value={formData.frequency}
                      onValueChange={(value) => setFormData({ ...formData, frequency: value })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {FREQUENCY_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Run At (Hour, UTC)</Label>
                    <Select
                      value={formData.run_at_hour}
                      onValueChange={(value) => setFormData({ ...formData, run_at_hour: value })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Array.from({ length: 24 }, (_, i) => (
                          <SelectItem key={i} value={i.toString()}>
                            {i.toString().padStart(2, '0')}:00
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {formData.frequency === 'weekly' && (
                  <div className="space-y-2">
                    <Label>Day of Week</Label>
                    <Select
                      value={formData.run_on_day}
                      onValueChange={(value) => setFormData({ ...formData, run_on_day: value })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {DAY_OPTIONS.map((opt) => (
                          <SelectItem key={opt.value} value={opt.value}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                <div className="space-y-2">
                  <Label>Targets (optional, one per line)</Label>
                  <textarea
                    className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    placeholder="192.168.1.0/24&#10;10.0.0.1&#10;example.com"
                    value={formData.targets}
                    onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave empty to automatically scan <span className="font-medium text-primary">all discovered assets</span> including:
                  </p>
                  <ul className="text-xs text-muted-foreground list-disc list-inside pl-2 space-y-0.5">
                    <li>Domains and subdomains from discovery</li>
                    <li>IP addresses and ranges</li>
                    <li>CIDR blocks from WhoisXML netblocks</li>
                  </ul>
                </div>

                <div className="flex items-center gap-2">
                  <Switch
                    checked={formData.is_enabled}
                    onCheckedChange={(checked) => setFormData({ ...formData, is_enabled: checked })}
                  />
                  <Label>Enable schedule immediately</Label>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateSchedule} disabled={submitting}>
                  {submitting ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create Schedule
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Critical Port Monitoring Card */}
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-400" />
              Critical Port Monitoring
            </CardTitle>
            <CardDescription>
              Automatically monitor for exposed critical ports that are common attack vectors
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <p className="font-medium text-red-400">Remote Access</p>
                <p className="text-muted-foreground">SSH, RDP, VNC, Telnet</p>
              </div>
              <div>
                <p className="font-medium text-orange-400">Databases</p>
                <p className="text-muted-foreground">MySQL, PostgreSQL, MongoDB, Redis</p>
              </div>
              <div>
                <p className="font-medium text-yellow-400">File Sharing</p>
                <p className="text-muted-foreground">SMB, FTP, NFS</p>
              </div>
              <div>
                <p className="font-medium text-purple-400">Containers</p>
                <p className="text-muted-foreground">Docker, Kubernetes APIs</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Schedules Table */}
        <Card>
          <CardHeader>
            <CardTitle>Scheduled Scans</CardTitle>
            <CardDescription>
              {schedules.length} schedule{schedules.length !== 1 ? 's' : ''} configured
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Frequency</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Next Run</TableHead>
                  <TableHead>Last Run</TableHead>
                  <TableHead>Runs</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8">
                      <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                    </TableCell>
                  </TableRow>
                ) : schedules.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                      No schedules configured. Create one to start continuous monitoring.
                    </TableCell>
                  </TableRow>
                ) : (
                  schedules.map((schedule) => (
                    <TableRow key={schedule.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{schedule.name}</p>
                          {schedule.description && (
                            <p className="text-xs text-muted-foreground">{schedule.description}</p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={schedule.scan_type === 'critical_ports' ? 'default' : 'secondary'}>
                          {getScanTypeLabel(schedule.scan_type)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {getFrequencyLabel(schedule.frequency)}
                          <span className="text-muted-foreground text-xs">
                            @ {schedule.run_at_hour.toString().padStart(2, '0')}:00
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {schedule.is_enabled ? (
                          schedule.consecutive_failures > 0 ? (
                            <div className="space-y-1">
                              <Badge variant="destructive">
                                <AlertTriangle className="h-3 w-3 mr-1" />
                                {schedule.consecutive_failures} failures
                              </Badge>
                              {schedule.last_error && (
                                <p className="text-xs text-red-400 max-w-[200px] truncate" title={schedule.last_error}>
                                  {schedule.last_error}
                                </p>
                              )}
                            </div>
                          ) : (
                            <Badge className="bg-green-500/20 text-green-400">
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Active
                            </Badge>
                          )
                        ) : (
                          <Badge variant="secondary">
                            <Pause className="h-3 w-3 mr-1" />
                            Paused
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {schedule.next_run_at ? formatDate(schedule.next_run_at) : '—'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {schedule.last_run_at ? formatDate(schedule.last_run_at) : 'Never'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{schedule.run_count}</Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleTrigger(schedule.id)}
                            title="Run now"
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEditSchedule(schedule)}
                            title="Edit schedule"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleToggle(schedule.id)}
                            title={schedule.is_enabled ? 'Pause' : 'Resume'}
                          >
                            {schedule.is_enabled ? (
                              <Pause className="h-4 w-4" />
                            ) : (
                              <Play className="h-4 w-4 text-green-400" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(schedule.id)}
                            className="text-red-400 hover:text-red-500"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Edit Schedule Dialog */}
        <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Edit Scan Schedule</DialogTitle>
              <DialogDescription>
                Update the schedule configuration.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Schedule Name *</Label>
                <Input
                  placeholder="e.g., Daily Critical Port Monitor"
                  value={editFormData.name}
                  onChange={(e) => setEditFormData({ ...editFormData, name: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label>Description</Label>
                <Input
                  placeholder="Optional description"
                  value={editFormData.description}
                  onChange={(e) => setEditFormData({ ...editFormData, description: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label>Scan Type *</Label>
                <Select
                  value={editFormData.scan_type}
                  onValueChange={(value) => setEditFormData({ ...editFormData, scan_type: value })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(scanTypes).map(([key, type]) => (
                      <SelectItem key={key} value={key}>
                        <div className="flex flex-col">
                          <span>{type.name}</span>
                          <span className="text-xs text-muted-foreground">{type.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {editFormData.scan_type === 'tester_process' && (
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={editFormData.autonomous_followup}
                      onCheckedChange={(checked) => setEditFormData({ ...editFormData, autonomous_followup: checked })}
                    />
                    <Label>Continue partial hunts automatically</Label>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Up to 3 turns per target, with time and reported model spend limits.
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Frequency *</Label>
                  <Select
                    value={editFormData.frequency}
                    onValueChange={(value) => setEditFormData({ ...editFormData, frequency: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FREQUENCY_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Run At (Hour, UTC)</Label>
                  <Select
                    value={editFormData.run_at_hour}
                    onValueChange={(value) => setEditFormData({ ...editFormData, run_at_hour: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Array.from({ length: 24 }, (_, i) => (
                        <SelectItem key={i} value={i.toString()}>
                          {i.toString().padStart(2, '0')}:00
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {editFormData.frequency === 'weekly' && (
                <div className="space-y-2">
                  <Label>Day of Week</Label>
                  <Select
                    value={editFormData.run_on_day}
                    onValueChange={(value) => setEditFormData({ ...editFormData, run_on_day: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DAY_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <div className="space-y-2">
                <Label>Targets (optional, one per line)</Label>
                <textarea
                  className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  placeholder="192.168.1.0/24&#10;10.0.0.1&#10;example.com"
                  value={editFormData.targets}
                  onChange={(e) => setEditFormData({ ...editFormData, targets: e.target.value })}
                />
                <p className="text-xs text-muted-foreground">
                  Leave empty to automatically scan <span className="font-medium text-primary">all in-scope assets</span>
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Switch
                  checked={editFormData.is_enabled}
                  onCheckedChange={(checked) => setEditFormData({ ...editFormData, is_enabled: checked })}
                />
                <Label>Schedule enabled</Label>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setEditDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleUpdateSchedule} disabled={submitting}>
                {submitting ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Pencil className="h-4 w-4 mr-2" />
                )}
                Save Changes
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}

