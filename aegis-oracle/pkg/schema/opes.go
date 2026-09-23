package schema

// Priority is the action-oriented bucket assigned by OPES.
//
// "urgent" is intentionally excluded here — it is a manual-only override
// that analysts apply in the UI and cannot be emitted by the scoring engine.
type Priority string

const (
	PriorityCritical      Priority = "critical"
	PriorityHigh          Priority = "high"
	PriorityMedium        Priority = "medium"
	PriorityLow           Priority = "low"
	PriorityInformational Priority = "informational"
)

// OPESScore is the Oracle Practical Exploitability Score: a 0–10 number
// plus a priority bucket, computed deterministically from intrinsic
// analysis + asset signals. The LLM never emits this — math does, so the
// score is reproducible and auditable.
type OPESScore struct {
	Value            float64        `json:"score"`
	Category         Priority       `json:"category"`
	Label            string         `json:"label"`
	Confidence       Confidence     `json:"confidence"`
	Components       OPESComponents `json:"components"`
	TopContributors  []string       `json:"top_contributors"`
	Dampener         string         `json:"dampener,omitempty"`
	Override         string         `json:"override,omitempty"`
	EvaluatorVersion string         `json:"evaluator_version"`

	// RiskModel is the Likelihood × Impact breakdown computed from the same
	// inputs. It does not change Value or Category; it exists so reviewers
	// can see severity, discoverability and exploit practicality separately.
	RiskModel *RiskModelScore `json:"risk_model,omitempty"`
}

// RiskFactor is one 1–5 factor of the Likelihood × Impact risk model
// (Network Location may be 0), with the reason it received that score.
type RiskFactor struct {
	Score  int    `json:"score"`
	Rating string `json:"rating"`
	Reason string `json:"reason"`
}

// RiskFactors are the seven factors of the risk model.
//
// Impact: BusinessImpact, NetworkLocation, VulnerabilitySeverity.
// Likelihood: SkillLevel (5 = no skill needed), EaseOfDiscovery,
// EaseOfExploit, Awareness.
type RiskFactors struct {
	BusinessImpact        RiskFactor `json:"business_impact"`
	NetworkLocation       RiskFactor `json:"network_location"`
	VulnerabilitySeverity RiskFactor `json:"vulnerability_severity"`
	SkillLevel            RiskFactor `json:"skill_level"`
	EaseOfDiscovery       RiskFactor `json:"ease_of_discovery"`
	EaseOfExploit         RiskFactor `json:"ease_of_exploit"`
	Awareness             RiskFactor `json:"awareness"`
}

// Exploit realism tiers, from proven on this asset to blocked on this asset.
const (
	RealismConfirmed   = "confirmed"
	RealismLikely      = "likely"
	RealismUnverified  = "unverified"
	RealismConditional = "conditional"
	RealismBlocked     = "blocked"
)

// ExploitRealism is the asset-specific reality check on exploitability:
// an exploit existing somewhere does not mean it works here. Score is 1–5
// (5 = confirmed on this asset, 1 = known paths blocked on this asset).
// Blocked is not a safety claim: it covers the documented paths only.
type ExploitRealism struct {
	Score   int      `json:"score"`
	Tier    string   `json:"tier"`
	Reasons []string `json:"reasons"`
}

// RiskModelScore is Risk = Impact × Likelihood on a 0–25 scale.
//
// Severity, Discoverability and ExploitPracticality are the three headline
// questions the model answers: how bad is it, how easily is it found, and
// how practical is it to exploit in the real world (mean of skill level,
// ease of exploit and awareness, 1–5).
type RiskModelScore struct {
	Score               float64  `json:"score"`
	Level               Priority `json:"level"`
	Impact              float64  `json:"impact"`
	Likelihood          float64  `json:"likelihood"`
	Severity            int      `json:"severity"`
	Discoverability     int      `json:"discoverability"`
	ExploitPracticality float64  `json:"exploit_practicality"`
	// Realism answers "can the known exploit actually work against this
	// asset?" It caps Ease of Exploit and tool-driven Skill Level, and can
	// cap Likelihood; LikelihoodUncapped shows the value before that cap.
	Realism            *ExploitRealism `json:"exploit_realism,omitempty"`
	LikelihoodUncapped float64         `json:"likelihood_uncapped"`
	Factors            RiskFactors     `json:"factors"`
	Version            string          `json:"version"`
}

// OPESComponents are the six 0–10 sub-scores that combine into the final
// OPES value. Keeping them on the score lets reviewers see what drove it.
type OPESComponents struct {
	E float64 `json:"E"` // exploit difficulty (higher = harder); contributes inversely
	R float64 `json:"R"` // reachability (higher = more reachable)
	P float64 `json:"P"` // precondition satisfaction (higher = preconditions met)
	X float64 `json:"X"` // active exploitation evidence (higher = in-the-wild)
	C float64 `json:"C"` // asset criticality (higher = bigger blast radius)
	T float64 `json:"T"` // time pressure (higher = more urgent)
}
