package schema

type PreconditionSeverity string

const (
	// PreconditionBlocker means the exploit is impossible if this is unsatisfied.
	PreconditionBlocker PreconditionSeverity = "blocker"
	// PreconditionContributing makes exploitation easier or available, but
	// alternative paths may exist.
	PreconditionContributing PreconditionSeverity = "contributing"
)

type PreconditionStatus string

const (
	PreconditionSatisfied   PreconditionStatus = "satisfied"
	PreconditionUnsatisfied PreconditionStatus = "unsatisfied"
	PreconditionUnknown     PreconditionStatus = "unknown"
)

// Precondition is a structured, machine-verifiable fact required for
// exploitation. Authored by the intrinsic reasoner (LLM) per CVE, or
// curated in dev_patterns.
type Precondition struct {
	ID                 string               `json:"id" yaml:"id"`
	Description        string               `json:"description" yaml:"description"`
	VerificationSignal string               `json:"verification_signal" yaml:"verification_signal"`
	MatchKind          string               `json:"match_kind" yaml:"match_kind"` // 'regex' | 'equals' | 'contains' | 'version_lte' | 'present'
	MatchValue         string               `json:"match_value,omitempty" yaml:"match_value,omitempty"`
	VerificationMethod string               `json:"verification_method" yaml:"verification_method"`
	Severity           PreconditionSeverity `json:"severity" yaml:"severity"`
	// PathIDs scopes this prerequisite to one or more documented exploit
	// paths. A failed prerequisite blocks those paths, not every possible path.
	PathIDs []string `json:"path_ids,omitempty" yaml:"path_ids,omitempty"`
}

// PreconditionEval is the contextual reasoner's evaluation of a single
// precondition against a specific asset's signals.
type PreconditionEval struct {
	Precondition Precondition          `json:"precondition"`
	Status       PreconditionStatus    `json:"status"`
	Reason       string                `json:"reason"`
	SignalValue  string                `json:"signal_value,omitempty"`
	Evidence     []EvidenceObservation `json:"evidence,omitempty"`
}

// PreconditionEvalSet is a slice of evaluations with helpers for OPES
// scoring and override logic.
type PreconditionEvalSet []PreconditionEval

func (s PreconditionEvalSet) AnyBlocker(status PreconditionStatus) bool {
	for _, e := range s {
		if e.Precondition.Severity == PreconditionBlocker && e.Status == status {
			return true
		}
	}
	return false
}

func (s PreconditionEvalSet) CountBlockers(status PreconditionStatus) int {
	c := 0
	for _, e := range s {
		if e.Precondition.Severity == PreconditionBlocker && e.Status == status {
			c++
		}
	}
	return c
}

func (s PreconditionEvalSet) BlockerCount() int {
	c := 0
	for _, e := range s {
		if e.Precondition.Severity == PreconditionBlocker {
			c++
		}
	}
	return c
}
