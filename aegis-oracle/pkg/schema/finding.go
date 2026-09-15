package schema

import "time"

type FindingStatus string

const (
	StatusOpen       FindingStatus = "open"
	StatusVerifying  FindingStatus = "verifying"
	StatusSuppressed FindingStatus = "suppressed"
	StatusFixed      FindingStatus = "fixed"
	StatusSuperseded FindingStatus = "superseded"
)

// Finding is the unit of work surfaced to the ASM and ticketing systems.
// One per (CVE, Asset) pair. New findings are written for each
// re-evaluation; old ones are marked superseded for audit.
type Finding struct {
	ID                     string               `json:"finding_id"`
	CVEID                  string               `json:"cve_id"`
	AssetID                string               `json:"asset_id"`
	IntrinsicInputHash     string               `json:"intrinsic_input_hash"`
	AssetSignalsHash       string               `json:"asset_signals_hash"`
	EvaluatorVersion       string               `json:"evaluator_version"`
	PreconditionsEvaluated PreconditionEvalSet  `json:"preconditions_evaluated"`
	ContextualAssessment   ContextualAssessment `json:"contextual_assessment"`
	OPES                   OPESScore            `json:"opes"`
	CVSSReconciliation     CVSSReconciliation   `json:"cvss_reconciliation"`
	// AnalystBrief carries the plain-language vulnerability intelligence
	// written by Phase A — rendered in the UI as the first thing an analyst
	// reads when opening a finding.
	AnalystBrief AnalystBrief `json:"analyst_brief"`
	// AttackPathClass is the MITRE ATT&CK initial access technique category
	// for this finding — propagated from IntrinsicAnalysis for display and
	// filtering without requiring a separate intrinsic lookup.
	AttackPathClass AttackPathClass `json:"attack_path_class,omitempty"`
	// LateralMovementPotential describes the pivot/lateral movement value an
	// attacker gains from exploiting this finding. Propagated from Phase A.
	LateralMovementPotential LateralMovementPotential `json:"lateral_movement_potential,omitempty"`
	RecommendationText       string                   `json:"recommendation_text"`
	VerificationTasks        []VerificationTask       `json:"verification_tasks,omitempty"`
	Status                   FindingStatus            `json:"status"`
	CreatedAt                time.Time                `json:"created_at"`
	UpdatedAt                time.Time                `json:"updated_at"`
}

// VerificationTask is a work item generated when a precondition's status is
// Unknown. Resolving the task updates the asset signal and triggers
// re-evaluation of the finding.
type VerificationTask struct {
	ID                    string    `json:"id"`
	PreconditionID        string    `json:"precondition_id"`
	Summary               string    `json:"summary"`
	TaskKind              string    `json:"task_kind"` // 'container_inspect' | 'config_check' | 'nuclei_run' | 'manual'
	Command               string    `json:"command,omitempty"`
	ExpectedSignalPath    string    `json:"expected_signal_path"`
	ExpectedMatch         string    `json:"expected_match,omitempty"`
	ResolvesPreconditions []string  `json:"resolves"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
}
