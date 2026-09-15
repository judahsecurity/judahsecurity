package schema

import "time"

// EvidenceFreshness describes whether an observation can safely be used for
// the current contextual assessment. Missing, stale, failed, and unsupported
// collection remain unknown; they are never interpreted as a mitigating fact.
type EvidenceFreshness string

const (
	EvidenceFresh       EvidenceFreshness = "fresh"
	EvidenceStale       EvidenceFreshness = "stale"
	EvidenceError       EvidenceFreshness = "error"
	EvidenceUnsupported EvidenceFreshness = "unsupported"
	EvidenceUnknown     EvidenceFreshness = "unknown"
)

// EvidenceObservation records where an asset-specific signal came from and
// the scope/time for which it is valid.
type EvidenceObservation struct {
	SignalPath  string            `json:"signal_path"`
	Value       string            `json:"value,omitempty"`
	Source      string            `json:"source,omitempty"`
	Scope       string            `json:"scope,omitempty"`
	CollectedBy string            `json:"collected_by,omitempty"`
	ObservedAt  FlexTime          `json:"observed_at,omitempty"`
	ValidUntil  FlexTime          `json:"valid_until,omitempty"`
	Freshness   EvidenceFreshness `json:"freshness"`
	Error       string            `json:"error,omitempty"`
	Reference   string            `json:"reference,omitempty"`
}

// FreshnessAt returns the usable state of an observation at assessment time.
func (e EvidenceObservation) FreshnessAt(now time.Time) EvidenceFreshness {
	if e.Freshness == EvidenceError || e.Freshness == EvidenceUnsupported {
		return e.Freshness
	}
	if e.ObservedAt.Time.IsZero() {
		return EvidenceUnknown
	}
	if e.Freshness == EvidenceStale || (!e.ValidUntil.Time.IsZero() && now.After(e.ValidUntil.Time)) {
		return EvidenceStale
	}
	if e.Freshness == EvidenceFresh {
		return EvidenceFresh
	}
	return EvidenceUnknown
}

// ComponentObservation deliberately separates component presence from runtime
// and reachability. A nil state means it was not established.
type ComponentObservation struct {
	Name              string                `json:"name"`
	Version           string                `json:"version,omitempty"`
	Installed         *bool                 `json:"installed,omitempty"`
	Enabled           *bool                 `json:"enabled,omitempty"`
	Used              *bool                 `json:"used,omitempty"`
	IdleOnDemand      *bool                 `json:"idle_on_demand,omitempty"`
	Executing         *bool                 `json:"executing,omitempty"`
	AttackerReachable *bool                 `json:"attacker_reachable,omitempty"`
	Evidence          []EvidenceObservation `json:"evidence,omitempty"`
}

type ExploitPath struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	PreconditionIDs     []string `json:"precondition_ids"`
	ResultingCapability string   `json:"resulting_capability,omitempty"`
}

// AttackTransition keeps network access separate from the capability needed
// to turn that access into attacker progress.
type AttackTransition struct {
	ID                  string `json:"id"`
	Description         string `json:"description,omitempty"`
	FromPosition        string `json:"from_position,omitempty"`
	Target              string `json:"target,omitempty"`
	AccessRequired      string `json:"access_required,omitempty"`
	CapabilityRequired  string `json:"capability_required,omitempty"`
	ResultingCapability string `json:"resulting_capability,omitempty"`
	AccessSignal        string `json:"access_signal,omitempty"`
	CapabilitySignal    string `json:"capability_signal,omitempty"`
}

type PathAssessment struct {
	Path              ExploitPath        `json:"path"`
	Status            PreconditionStatus `json:"status"`
	Reason            string             `json:"reason"`
	BlockingCondition string             `json:"blocking_condition,omitempty"`
}

type AttackTransitionAssessment struct {
	Transition       AttackTransition      `json:"transition"`
	AccessStatus     PreconditionStatus    `json:"access_status"`
	CapabilityStatus PreconditionStatus    `json:"capability_status"`
	Status           PreconditionStatus    `json:"status"`
	Reason           string                `json:"reason"`
	Evidence         []EvidenceObservation `json:"evidence,omitempty"`
}

type ContextualAssessmentState string

const (
	ContextConditionsMet       ContextualAssessmentState = "conditions_met"
	ContextNeedsEvidence       ContextualAssessmentState = "needs_evidence"
	ContextDocumentedPathBlock ContextualAssessmentState = "documented_path_blocked"
	ContextConditional         ContextualAssessmentState = "conditional"
)

// ContextualAssessment is strictly local to a finding and asset. Global EPSS,
// KEV, and campaign intelligence remains a separate input/output concern.
type ContextualAssessment struct {
	AssetID                  string                       `json:"asset_id,omitempty"`
	TenantID                 string                       `json:"tenant_id,omitempty"`
	AttackerStartingPosition string                       `json:"attacker_starting_position,omitempty"`
	AffectedComponent        string                       `json:"affected_component,omitempty"`
	RealisticWorkflow        string                       `json:"realistic_workflow,omitempty"`
	InputSource              string                       `json:"input_source,omitempty"`
	AttackerInfluence        string                       `json:"attacker_influence,omitempty"`
	ObservedAt               FlexTime                     `json:"observed_at,omitempty"`
	RequiredCapability       AttackerCapability           `json:"required_capability,omitempty"`
	ResultingCapability      string                       `json:"resulting_capability,omitempty"`
	State                    ContextualAssessmentState    `json:"state"`
	Summary                  string                       `json:"summary"`
	Components               []ComponentObservation       `json:"components,omitempty"`
	Preconditions            PreconditionEvalSet          `json:"preconditions,omitempty"`
	Paths                    []PathAssessment             `json:"paths,omitempty"`
	Transitions              []AttackTransitionAssessment `json:"transitions,omitempty"`
	MissingChecks            []string                     `json:"missing_checks,omitempty"`
}

// IntrinsicContext contains vulnerability-level structure which is evaluated
// against local evidence. It must not contain claims about a specific asset.
type IntrinsicContext struct {
	AttackerStartingPosition string             `json:"attacker_starting_position,omitempty"`
	AffectedComponent        string             `json:"affected_component,omitempty"`
	RealisticWorkflow        string             `json:"realistic_workflow,omitempty"`
	InputSource              string             `json:"input_source,omitempty"`
	AttackerInfluence        string             `json:"attacker_influence,omitempty"`
	ResultingCapability      string             `json:"resulting_capability,omitempty"`
	ExploitPaths             []ExploitPath      `json:"exploit_paths,omitempty"`
	Transitions              []AttackTransition `json:"transitions,omitempty"`
}
