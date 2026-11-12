'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  CheckCircle,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Terminal,
  Copy,
  ExternalLink,
  Shield,
  Zap,
  Target,
  Users,
  BookOpen,
  CheckSquare,
  AlertCircle,
  Info,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ActiveCampaignsCard, type ActiveCampaignsData } from './ActiveCampaignsCard';

interface RemediationStep {
  order: number;
  title: string;
  description: string;
  command?: string;
  code_snippet?: string;
  notes?: string;
  is_sufficient?: boolean;  // If true, completing this step alone resolves the finding
  is_required?: boolean;    // If false, this step is optional/recommended
  is_alternative?: boolean; // If true, this is an alternative to other steps
  alternative_group?: string; // Group name for mutually exclusive alternatives
}

interface VerificationStep {
  order: number;
  description: string;
  expected_result: string;
  command?: string;
  automated: boolean;
}

interface RemediationPlaybook {
  id: string;
  title: string;
  summary: string;
  priority: string;
  effort: string;
  estimated_time: string;
  required_access: string[];
  steps: RemediationStep[];
  verification: VerificationStep[];
  impact_if_not_fixed: string;
  common_mistakes: string[];
  references: string[];
  related_cwe?: string;
  related_cve: string[];
  tags: string[];
}

/** CWE (MITRE) info for remediation guidance */
export interface CweInfo {
  id: string;
  name: string;
  description?: string;
  mitigations?: Array<{
    description: string;
    phase?: string;
    strategy?: string;
    effectiveness?: string;
  }>;
  url?: string;
}

interface RemediationPanelProps {
  playbook?: RemediationPlaybook;
  fallbackRemediation?: string;
  /** CWE details from MITRE (from /remediation/for-finding or /remediation/cwe/{id}) */
  cwe?: CweInfo | null;
  /** CWE ID when cwe object not loaded (e.g. for lazy load) */
  cweId?: string | null;
  /** Active exploitation campaigns naming this finding's CVE or exposed product */
  activeCampaigns?: ActiveCampaignsData | null;
  className?: string;
}

const priorityConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  critical: {
    color: 'bg-red-600/20 text-red-400 border-red-600/30',
    icon: <AlertCircle className="h-4 w-4" />,
    label: 'Fix Immediately',
  },
  high: {
    color: 'bg-orange-600/20 text-orange-400 border-orange-600/30',
    icon: <AlertTriangle className="h-4 w-4" />,
    label: 'Fix Within 24-48 Hours',
  },
  medium: {
    color: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30',
    icon: <Clock className="h-4 w-4" />,
    label: 'Fix Within 1-2 Weeks',
  },
  low: {
    color: 'bg-green-600/20 text-green-400 border-green-600/30',
    icon: <Info className="h-4 w-4" />,
    label: 'Fix When Convenient',
  },
  informational: {
    color: 'bg-blue-600/20 text-blue-400 border-blue-600/30',
    icon: <BookOpen className="h-4 w-4" />,
    label: 'Awareness Only',
  },
};

const effortConfig: Record<string, { color: string; label: string }> = {
  minimal: { color: 'bg-green-600/20 text-green-400', label: '< 30 min' },
  low: { color: 'bg-green-600/20 text-green-400', label: '1-2 hours' },
  medium: { color: 'bg-yellow-600/20 text-yellow-400', label: 'Half to full day' },
  high: { color: 'bg-orange-600/20 text-orange-400', label: 'Multiple days' },
  significant: { color: 'bg-red-600/20 text-red-400', label: 'Week+' },
};

const accessConfig: Record<string, string> = {
  read_only: 'Read Only',
  operator: 'Operator',
  admin: 'Admin',
  infrastructure: 'Infrastructure',
  security_team: 'Security Team',
};

export function RemediationPanel({
  playbook,
  fallbackRemediation,
  cwe,
  cweId,
  activeCampaigns,
  className,
}: RemediationPanelProps) {
  const hasCampaigns = (activeCampaigns?.campaigns?.length ?? 0) > 0;
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([1]));
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const [showVerification, setShowVerification] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  const toggleStep = (order: number) => {
    const newExpanded = new Set(expandedSteps);
    if (newExpanded.has(order)) {
      newExpanded.delete(order);
    } else {
      newExpanded.add(order);
    }
    setExpandedSteps(newExpanded);
  };

  const toggleCompleted = (order: number) => {
    const newCompleted = new Set(completedSteps);
    if (newCompleted.has(order)) {
      newCompleted.delete(order);
    } else {
      newCompleted.add(order);
    }
    setCompletedSteps(newCompleted);
  };

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCommand(id);
      setTimeout(() => setCopiedCommand(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // If no playbook, show fallback remediation and optional CWE guidance
  if (!playbook) {
    if (!fallbackRemediation && !cwe && !cweId && !hasCampaigns) {
      return (
        <Card className={cn("border-muted", className)}>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No remediation guidance available for this finding.</p>
            <p className="text-sm mt-2">Check the references for more information.</p>
          </CardContent>
        </Card>
      );
    }

    return (
      <div className={cn("space-y-4", className)}>
        <ActiveCampaignsCard data={activeCampaigns} />
        {fallbackRemediation && (
          <Card className="border-muted">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-400" />
                Remediation Guidance
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground whitespace-pre-wrap">{fallbackRemediation}</p>
            </CardContent>
          </Card>
        )}
        {(cwe || cweId) && <CweGuidanceCard cwe={cwe} cweId={cweId} />}
      </div>
    );
  }

  const priority = priorityConfig[playbook.priority] || priorityConfig.medium;
  const effort = effortConfig[playbook.effort] || effortConfig.medium;
  
  // Count required steps vs optional
  const requiredSteps = playbook.steps.filter(s => s.is_required !== false);
  const sufficientSteps = playbook.steps.filter(s => s.is_sufficient);
  
  // Check if any sufficient step is completed (finding can be resolved)
  const canResolve = sufficientSteps.some(s => completedSteps.has(s.order));
  
  // Progress is based on completing at least one sufficient step, or all required steps
  const progressPercent = canResolve 
    ? 100 
    : (completedSteps.size / requiredSteps.length) * 100;

  return (
    <div className={cn("space-y-4", className)}>
      <ActiveCampaignsCard data={activeCampaigns} />
      {/* Header with Priority and Effort */}
      <Card className="border-muted">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-400" />
                {playbook.title}
              </CardTitle>
              <p className="text-sm text-muted-foreground mt-1">{playbook.summary}</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="flex items-center gap-2">
              <div className={cn("p-2 rounded-lg", priority.color)}>
                {priority.icon}
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Priority</p>
                <p className="text-sm font-medium capitalize">{playbook.priority}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <div className={cn("p-2 rounded-lg", effort.color)}>
                <Clock className="h-4 w-4" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Effort</p>
                <p className="text-sm font-medium">{playbook.estimated_time}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-purple-600/20 text-purple-400">
                <Target className="h-4 w-4" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Steps</p>
                <p className="text-sm font-medium">{playbook.steps.length} steps</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400">
                <Users className="h-4 w-4" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Access Needed</p>
                <p className="text-sm font-medium">
                  {playbook.required_access.map(a => accessConfig[a] || a).join(', ')}
                </p>
              </div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">Progress</span>
              <span className="text-muted-foreground">
                {completedSteps.size} of {playbook.steps.length} steps complete
                {sufficientSteps.length > 0 && (
                  <span className="ml-2 text-cyan-400">
                    ({sufficientSteps.length} sufficient option{sufficientSteps.length > 1 ? 's' : ''})
                  </span>
                )}
              </span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div 
                className={cn(
                  "h-full transition-all duration-300",
                  canResolve ? "bg-green-500" : "bg-yellow-500"
                )}
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            
            {/* Ready to Resolve Indicator */}
            {canResolve && (
              <div className="flex items-center gap-2 p-2 bg-green-600/20 border border-green-600/30 rounded-lg mt-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-sm text-green-400 font-medium">
                  Ready to resolve - a sufficient remediation step has been completed
                </span>
              </div>
            )}
            
            {/* Legend for step types */}
            {sufficientSteps.length > 0 && (
              <div className="flex flex-wrap gap-3 text-xs text-muted-foreground mt-2">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-cyan-500" />
                  Sufficient alone
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-gray-500" />
                  Optional
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-yellow-500" />
                  Required
                </span>
              </div>
            )}
          </div>

          {/* Priority Warning */}
          <div className={cn("mt-4 p-3 rounded-lg border", priority.color)}>
            <div className="flex items-start gap-2">
              {priority.icon}
              <div>
                <p className="text-sm font-medium">{priority.label}</p>
                <p className="text-xs mt-1 opacity-80">{playbook.impact_if_not_fixed}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Remediation Steps */}
      <Card className="border-muted">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-400" />
            Remediation Steps
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {playbook.steps.map((step, index) => {
            // Check if this step is an alternative (show OR divider)
            const prevStep = index > 0 ? playbook.steps[index - 1] : null;
            const showOrDivider = step.is_alternative && prevStep?.alternative_group === step.alternative_group;
            
            return (
              <div key={step.order}>
                {/* OR Divider for alternatives */}
                {showOrDivider && (
                  <div className="flex items-center gap-2 py-2">
                    <div className="flex-1 h-px bg-cyan-600/30" />
                    <span className="text-xs font-medium text-cyan-400 px-2">OR</span>
                    <div className="flex-1 h-px bg-cyan-600/30" />
                  </div>
                )}
                
                <div 
                  className={cn(
                    "border rounded-lg overflow-hidden transition-all",
                    completedSteps.has(step.order) ? "border-green-600/50 bg-green-600/5" : 
                    step.is_sufficient ? "border-cyan-600/30" : "border-muted"
                  )}
                >
                  <div 
                    className="flex items-center gap-3 p-3 cursor-pointer hover:bg-muted/50"
                    onClick={() => toggleStep(step.order)}
                  >
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleCompleted(step.order);
                      }}
                      className={cn(
                        "flex-shrink-0 w-6 h-6 rounded-full border-2 flex items-center justify-center transition-colors",
                        completedSteps.has(step.order) 
                          ? "bg-green-600 border-green-600 text-white" 
                          : step.is_sufficient 
                            ? "border-cyan-500 hover:border-green-500"
                            : "border-muted-foreground hover:border-green-500"
                      )}
                    >
                      {completedSteps.has(step.order) && <CheckCircle className="h-4 w-4" />}
                    </button>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className={cn(
                          "font-medium text-sm",
                          completedSteps.has(step.order) && "line-through text-muted-foreground"
                        )}>
                          {step.order}. {step.title}
                        </p>
                        {/* Step type badges */}
                        {step.is_sufficient && (
                          <Badge className="text-xs bg-cyan-600/20 text-cyan-400 border-cyan-600/30">
                            Sufficient
                          </Badge>
                        )}
                        {step.is_required === false && !step.is_sufficient && (
                          <Badge variant="outline" className="text-xs text-muted-foreground">
                            Optional
                          </Badge>
                        )}
                      </div>
                    </div>
                    
                    {expandedSteps.has(step.order) ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
              
              {expandedSteps.has(step.order) && (
                <div className="px-3 pb-3 pl-12 space-y-3">
                  <p className="text-sm text-muted-foreground">{step.description}</p>
                  
                  {step.command && (
                    <div className="relative">
                      <div className="flex items-center justify-between bg-secondary/50 rounded-t-lg px-3 py-1.5 border-b border-muted">
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <Terminal className="h-3 w-3" />
                          Command
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs"
                          onClick={() => copyToClipboard(step.command!, `step-${step.order}`)}
                        >
                          {copiedCommand === `step-${step.order}` ? (
                            <CheckCircle className="h-3 w-3 mr-1 text-green-400" />
                          ) : (
                            <Copy className="h-3 w-3 mr-1" />
                          )}
                          {copiedCommand === `step-${step.order}` ? 'Copied!' : 'Copy'}
                        </Button>
                      </div>
                      <pre className="bg-secondary/50 rounded-b-lg p-3 overflow-x-auto text-xs font-mono whitespace-pre-wrap">
                        {step.command}
                      </pre>
                    </div>
                  )}
                  
                  {step.code_snippet && (
                    <div className="relative">
                      <div className="flex items-center justify-between bg-secondary/50 rounded-t-lg px-3 py-1.5 border-b border-muted">
                        <span className="text-xs text-muted-foreground">Code Example</span>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs"
                          onClick={() => copyToClipboard(step.code_snippet!, `code-${step.order}`)}
                        >
                          {copiedCommand === `code-${step.order}` ? (
                            <CheckCircle className="h-3 w-3 mr-1 text-green-400" />
                          ) : (
                            <Copy className="h-3 w-3 mr-1" />
                          )}
                          Copy
                        </Button>
                      </div>
                      <pre className="bg-secondary/50 rounded-b-lg p-3 overflow-x-auto text-xs font-mono whitespace-pre-wrap">
                        {step.code_snippet}
                      </pre>
                    </div>
                  )}
                  
                  {step.notes && (
                    <div className="flex items-start gap-2 p-2 bg-yellow-600/10 border border-yellow-600/30 rounded-lg">
                      <AlertTriangle className="h-4 w-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                      <p className="text-xs text-yellow-400">{step.notes}</p>
                    </div>
                  )}
                </div>
              )}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Verification Steps */}
      <Card className="border-muted">
        <CardHeader className="pb-2">
          <button 
            onClick={() => setShowVerification(!showVerification)}
            className="flex items-center justify-between w-full"
          >
            <CardTitle className="text-base flex items-center gap-2">
              <CheckSquare className="h-4 w-4 text-blue-400" />
              Verification Steps
              <Badge variant="outline" className="ml-2 text-xs">
                {playbook.verification.length}
              </Badge>
            </CardTitle>
            {showVerification ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
        </CardHeader>
        
        {showVerification && (
          <CardContent className="space-y-3">
            {playbook.verification.map((v) => (
              <div key={v.order} className="border border-muted rounded-lg p-3 space-y-2">
                <div className="flex items-start justify-between">
                  <p className="text-sm font-medium">{v.order}. {v.description}</p>
                  {v.automated && (
                    <Badge className="bg-blue-600/20 text-blue-400 border-blue-600/30 text-xs">
                      Auto-verified
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  <span className="font-medium">Expected:</span> {v.expected_result}
                </p>
                {v.command && (
                  <div className="flex items-center gap-2">
                    <code className="text-xs bg-secondary/50 px-2 py-1 rounded flex-1 overflow-x-auto">
                      {v.command}
                    </code>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={() => copyToClipboard(v.command!, `verify-${v.order}`)}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        )}
      </Card>

      {/* Common Mistakes & References */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Common Mistakes */}
        {playbook.common_mistakes.length > 0 && (
          <Card className="border-muted">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                Common Mistakes
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {playbook.common_mistakes.map((mistake, i) => (
                  <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                    <span className="text-orange-400 mt-1">•</span>
                    {mistake}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}

        {/* References */}
        {playbook.references.length > 0 && (
          <Card className="border-muted">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <BookOpen className="h-4 w-4 text-blue-400" />
                References
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {playbook.references.map((ref, i) => (
                  <li key={i}>
                    <a 
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1 break-all"
                    >
                      <ExternalLink className="h-3 w-3 flex-shrink-0" />
                      {ref.replace('https://', '').replace('http://', '')}
                    </a>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>

      {/* CWE guidance from MITRE (Averlon-style recommendations) */}
      {(cwe || cweId) && (
        <CweGuidanceCard cwe={cwe} cweId={cweId} />
      )}

      {/* Tags and CWE/CVE */}
      <div className="flex flex-wrap gap-2">
        {playbook.related_cwe && (
          <Badge variant="outline" className="text-xs">
            {playbook.related_cwe}
          </Badge>
        )}
        {playbook.related_cve.map((cve) => (
          <Badge key={cve} variant="outline" className="text-xs text-red-400 border-red-400/30">
            {cve}
          </Badge>
        ))}
        {playbook.tags.map((tag) => (
          <Badge key={tag} variant="outline" className="text-xs">
            {tag}
          </Badge>
        ))}
      </div>
    </div>
  );
}

/** Card showing CWE description and potential mitigations from MITRE (remediation recommendations). */
function CweGuidanceCard({ cwe, cweId }: { cwe?: CweInfo | null; cweId?: string | null }) {
  const id = cwe?.id || cweId;
  const url = cwe?.url || (id ? `https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html` : undefined);

  if (!id && !cwe) return null;

  return (
    <Card className="border-muted border-cyan-600/20 bg-cyan-600/5">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-cyan-400" />
          CWE guidance (MITRE)
          {id && (
            <Badge variant="outline" className="text-xs font-mono">
              {id}
            </Badge>
          )}
        </CardTitle>
        {cwe?.name && (
          <p className="text-sm text-muted-foreground font-medium">{cwe.name}</p>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {cwe?.description && (
          <p className="text-sm text-muted-foreground">{cwe.description}</p>
        )}
        {cwe?.mitigations && cwe.mitigations.length > 0 && (
          <div>
            <p className="text-xs font-medium text-cyan-400 mb-2">Potential mitigations</p>
            <ul className="space-y-2">
              {cwe.mitigations.map((m, i) => (
                <li key={i} className="text-sm text-muted-foreground flex flex-col gap-0.5 pl-2 border-l-2 border-cyan-600/30">
                  <span>{m.description}</span>
                  {(m.phase || m.effectiveness) && (
                    <span className="text-xs text-muted-foreground/80">
                      {[m.phase, m.effectiveness].filter(Boolean).join(' · ')}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {url && (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <ExternalLink className="h-3 w-3" />
            View on CWE.mitre.org
          </a>
        )}
      </CardContent>
    </Card>
  );
}
