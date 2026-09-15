package schema

type RemoteTriggerability string

const (
	TriggerYes         RemoteTriggerability = "yes"
	TriggerNo          RemoteTriggerability = "no"
	TriggerConditional RemoteTriggerability = "conditional"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// AttackPathClass describes the MITRE ATT&CK initial access technique category
// that best describes how an attacker reaches the vulnerable component. Used by
// OPES reachability to weight initial-access difficulty correctly — a
// phishing-delivered exploit (UI:R) behaves very differently in practice from
// a direct exploit against an internet-facing service.
type AttackPathClass string

const (
	// AttackPathExploitPublicFacing — T1190. Attacker directly exploits a
	// network-reachable service (web app, API, VPN gateway). No user
	// interaction required; automatable via scanner or Nuclei template.
	AttackPathExploitPublicFacing AttackPathClass = "exploit_public_facing"

	// AttackPathPhishingDelivery — T1566. Exploit is delivered via email
	// attachment, link, or document. Requires a human victim to trigger.
	// Maps to CVSS UI:R. Reduces automated-scan risk but very common in
	// targeted campaigns.
	AttackPathPhishingDelivery AttackPathClass = "phishing_delivery"

	// AttackPathLateralMovementRequired — T1021/T1550/T1570 family. Exploit
	// can only be reached from inside the network — attacker needs an
	// existing foothold on a different host. Most dangerous when the
	// vulnerable service is a high-value internal target (AD, secrets store).
	AttackPathLateralMovementRequired AttackPathClass = "lateral_movement_required"

	// AttackPathValidCredentials — T1078. Exploit requires stolen or guessed
	// credentials. Attack complexity depends entirely on credential hygiene
	// and MFA posture of the target.
	AttackPathValidCredentials AttackPathClass = "valid_credentials_required"

	// AttackPathSupplyChain — T1195. Vulnerability is introduced through a
	// compromised dependency, build system, or update mechanism. Victim
	// unknowingly installs the malicious component.
	AttackPathSupplyChain AttackPathClass = "supply_chain"

	// AttackPathUnknown — insufficient information to classify.
	AttackPathUnknown AttackPathClass = "unknown"
)

// LateralMovementPotential describes what an attacker gains in terms of
// lateral movement capability after exploiting this CVE. High potential means
// that compromising this asset gives an attacker keys to move through the
// network — credential theft, pivot access, or control of auth infrastructure.
type LateralMovementPotential string

const (
	// LateralMovementHigh — exploitation directly enables significant pivot:
	// credential theft (pass-the-hash, token forgery), domain controller
	// compromise, secrets manager access, or multi-homed gateway takeover.
	LateralMovementHigh LateralMovementPotential = "high"

	// LateralMovementMedium — some pivot capability, but limited in scope:
	// access to one adjacent segment, internal service enumeration, or
	// partial credential access.
	LateralMovementMedium LateralMovementPotential = "medium"

	// LateralMovementLow — exploitation gives access to a single isolated
	// service or data set. No meaningful path to other hosts or credentials.
	LateralMovementLow LateralMovementPotential = "low"
)

// Label returns analyst-facing prose for the attack path. Used in
// recommendation narratives and UI; keep in sync with reachabilityVerdict
// in internal/pipeline.
func (c AttackPathClass) Label() string {
	switch c {
	case AttackPathExploitPublicFacing:
		return "Direct exploitation of internet-facing service"
	case AttackPathPhishingDelivery:
		return "Phishing-delivered (requires user interaction)"
	case AttackPathLateralMovementRequired:
		return "Reachable only after attacker has internal foothold"
	case AttackPathValidCredentials:
		return "Requires valid credentials"
	case AttackPathSupplyChain:
		return "Supply-chain compromise"
	default:
		return "Attack path not classified"
	}
}

// Label returns analyst-facing prose for lateral-movement impact after exploit.
func (l LateralMovementPotential) Label() string {
	switch l {
	case LateralMovementHigh:
		return "High — exploitation enables credential theft or pivot to other hosts"
	case LateralMovementMedium:
		return "Medium — limited pivot to adjacent services"
	case LateralMovementLow:
		return "Low — contained to this asset"
	default:
		return ""
	}
}

// AttackerCapability captures the minimum capability an attacker must already
// possess to mount the exploit. Used by OPES difficulty and reachability.
type AttackerCapability string

const (
	AttackerUnauthenticatedNetwork AttackerCapability = "unauthenticated_network"
	AttackerAuthenticatedLowPriv   AttackerCapability = "authenticated_low_priv"
	AttackerAuthenticatedHighPriv  AttackerCapability = "authenticated_high_priv"
	AttackerLocalUser              AttackerCapability = "local_user"
	AttackerAdjacentNetwork        AttackerCapability = "adjacent_network"
	AttackerPhysical               AttackerCapability = "physical"
	AttackerCodeExecution          AttackerCapability = "code_execution_required"
)

type ExploitComplexity string

const (
	ComplexityLow    ExploitComplexity = "low"
	ComplexityMedium ExploitComplexity = "medium"
	ComplexityHigh   ExploitComplexity = "high"
)

// CVSSReconciliation is the LLM's judgment about which CVSS source to trust
// when sources disagree. Driven by the description, references, and PoC
// content. The corrected vector — not the NVD vector — flows into OPES.
type CVSSReconciliation struct {
	CorrectVector  string                   `json:"correct_vector"`
	CorrectScore   float64                  `json:"correct_score"`
	CorrectVersion string                   `json:"correct_version"`
	Rationale      string                   `json:"rationale"`
	Disagreements  []CVSSSourceDisagreement `json:"disagreements,omitempty"`
}

type CVSSSourceDisagreement struct {
	Source       string `json:"source"`
	TheirVector  string `json:"their_vector"`
	Disagreement string `json:"disagreement"`
}

// AnalystBrief is the plain-language vulnerability intelligence section of
// an IntrinsicAnalysis. It is written for the human analyst reading the
// finding — not for downstream scoring. All fields are 2–5 sentences of
// prose, jargon-free enough for a developer or security engineer who is
// not a specialist in the vulnerability class.
type AnalystBrief struct {
	// Title is a single-line human-readable vulnerability name in the form
	// "<Product/Component>: <Impact> via <Root Cause>" — e.g.
	// "Marimo: Pre-Auth Remote Code Execution via Terminal WebSocket Auth Bypass"
	// or "Node.js http-proxy: SSRF via Unchecked Host Header Forwarding".
	// Used as the heading in the UI so analysts can understand the finding
	// at a glance without reading the CVE description.
	Title string `json:"title"`

	// WhatIsIt describes the bug in plain English: what code path is
	// vulnerable, what the root cause is, and what class of weakness it
	// represents (e.g. "buffer overflow in the AEAD crypto interface").
	WhatIsIt string `json:"what_is_it"`

	// AttackScenario is a realistic step-by-step narrative of how an
	// attacker would actually exploit this — what they send, what happens
	// internally, and what they gain. Written for an analyst who needs to
	// understand the realistic threat, not a textbook description.
	AttackScenario string `json:"attack_scenario"`

	// AttackVectorSummary is a single sentence distillation of the attack
	// surface: who the attacker is, where they sit, and what access they
	// need before exploitation can begin.
	AttackVectorSummary string `json:"attack_vector_summary"`

	// RealWorldLikelihood assesses how likely real-world exploitation is,
	// going beyond CVSS. Considers attacker motivation, prevalence of
	// the vulnerable pattern in real codebases, tooling availability
	// (Metasploit, Nuclei, Shodan-visible surface), and whether the bug
	// requires specialist knowledge or is push-button exploitable.
	RealWorldLikelihood string `json:"real_world_likelihood"`

	// AffectedIf describes the specific development practices,
	// configurations, or deployment patterns that make a target
	// exploitable — e.g. "uses express-fileupload with parseNested:true"
	// or "runs with --allow-env flag". Concrete enough to let a dev
	// self-assess in 30 seconds.
	AffectedIf string `json:"affected_if"`

	// NotAffectedIf describes mitigating configurations or patterns that
	// exclude the risk — e.g. "WAF with OWASP ruleset blocks the payload",
	// "no user-controlled input reaches the sink", or "kernel version ≥
	// 6.15 has the patch applied". Empty if there are no known mitigations
	// short of patching.
	NotAffectedIf string `json:"not_affected_if,omitempty"`

	// ExploitabilityScore is a 1.0–5.0 practical exploitability rating that
	// answers "how easy is it for a real attacker to exploit this against a
	// typical deployment, right now?" It is NOT the same as CVSS severity —
	// it factors in attacker skill required, public tooling availability,
	// prevalence of the vulnerable pattern in real codebases, and active
	// exploitation evidence.
	//
	// 5 Push-Button  — Zero skill required; Metasploit/single-command exploit exists
	// 4 Opportunistic — Script-kiddie to mid-level; PoC + widespread pattern
	// 3 Moderate      — Experienced attacker; specific conditions required
	// 2 Targeted      — Specialist knowledge or local/adjacent-only access
	// 1 Theoretical   — Research-grade; no public exploit, complex preconditions
	ExploitabilityScore float64 `json:"exploitability_score"`

	// ExploitabilityTier is the named tier for ExploitabilityScore.
	// One of: "push_button" | "opportunistic" | "moderate" | "targeted" | "theoretical"
	ExploitabilityTier string `json:"exploitability_tier"`
}

// PatchBypass describes evidence that this CVE is a documented bypass of the
// fix applied for a predecessor vulnerability. When BypassConfirmed is true,
// defenders who applied the patch for PredecessorCVE may incorrectly believe
// they are protected — this is the highest-priority finding type.
//
// The LLM populates this when the advisory text, references, or CWE profile
// contains language such as "incomplete fix", "bypass of CVE-…", "regression",
// or "variant of". The OSV related[] alias list is pre-loaded into the prompt
// context so the model has signal beyond the description alone.
type PatchBypass struct {
	// PredecessorCVE is the CVE ID whose patch this CVE circumvents.
	// Empty string when no bypass is detected.
	PredecessorCVE string `json:"predecessor_cve,omitempty"`

	// BypassMechanism is a concise technical explanation of how the prior
	// patch failed to fully remediate the issue. E.g. "parse_url returns
	// false for triple-slash paths, skipping the is_string check".
	BypassMechanism string `json:"bypass_mechanism,omitempty"`

	// BypassConfirmed is true when the LLM has high confidence that this CVE
	// is an explicit, documented patch bypass (not a related-but-distinct vuln).
	BypassConfirmed bool `json:"bypass_confirmed"`

	// BypassSource is the reference URL that most clearly describes the bypass
	// relationship — typically the GHSA advisory or vendor security page.
	BypassSource string `json:"bypass_source,omitempty"`

	// BypassSummary is 1-2 sentences suitable for a warning callout in reports
	// and UI: "CVE-2026-45034 bypasses the phar:// wrapper check introduced in
	// 1.29.0 to fix CVE-2026-34084 by using three slashes after the scheme."
	BypassSummary string `json:"bypass_summary,omitempty"`
}

// IntrinsicAnalysis is the Phase A reasoner's structured output.
// Same input → same output (deterministic via prompt versioning + caching).
// Phase B and OPES consume this; humans audit it.
type IntrinsicAnalysis struct {
	CVEID                string               `json:"cve_id"`
	RemoteTriggerability RemoteTriggerability `json:"remote_triggerability"`
	ExploitComplexity    ExploitComplexity    `json:"exploit_complexity"`
	AttackerCapability   AttackerCapability   `json:"attacker_capability"`
	// AttackPathClass classifies the MITRE ATT&CK initial access technique
	// (T1190 direct exploit vs T1566 phishing vs lateral movement required
	// etc.). Consumed by OPES reachability to correctly weight the real-world
	// attack surface — a phishing-delivered exploit is not automatable the
	// same way a scanner-reachable service exploit is.
	AttackPathClass AttackPathClass `json:"attack_path_class"`
	// LateralMovementPotential describes what an attacker gains in terms of
	// pivot / lateral movement capability after successful exploitation.
	// High potential (credential stores, AD, pivot gateways) materially
	// increases the OPES criticality score above the asset's base value.
	LateralMovementPotential LateralMovementPotential `json:"lateral_movement_potential"`
	Preconditions            []Precondition           `json:"preconditions"`
	AttackerStartingPosition string                   `json:"attacker_starting_position,omitempty"`
	AffectedComponent        string                   `json:"affected_component,omitempty"`
	RealisticWorkflow        string                   `json:"realistic_workflow,omitempty"`
	InputSource              string                   `json:"input_source,omitempty"`
	AttackerInfluence        string                   `json:"attacker_influence,omitempty"`
	ResultingCapability      string                   `json:"resulting_capability,omitempty"`
	ExploitPaths             []ExploitPath            `json:"exploit_paths,omitempty"`
	Transitions              []AttackTransition       `json:"transitions,omitempty"`
	CVSSReconciliation       CVSSReconciliation       `json:"cvss_reconciliation"`
	AttackChainSummary       string                   `json:"attack_chain_summary"`
	// AnalystBrief is the human-readable vulnerability intelligence writeup
	// rendered in the UI to help analysts and developers understand the
	// vulnerability, attack vector, and real-world exploitation likelihood.
	AnalystBrief AnalystBrief `json:"analyst_brief"`
	// PatchBypass is populated when this CVE is a documented bypass of a
	// predecessor patch. When PatchBypass.BypassConfirmed is true, the finding
	// should be surfaced with maximum urgency — defenders holding the prior
	// patch believe they are protected but are not.
	PatchBypass      *PatchBypass `json:"patch_bypass,omitempty"`
	DetectionSignals []string     `json:"detection_signals,omitempty"`
	Rationale        string       `json:"rationale"`
	Confidence       Confidence   `json:"confidence"`

	PromptVersion string `json:"prompt_version,omitempty"`
	LLMModel      string `json:"llm_model,omitempty"`
}

func (a IntrinsicAnalysis) Context() IntrinsicContext {
	return IntrinsicContext{
		AttackerStartingPosition: a.AttackerStartingPosition,
		AffectedComponent:        a.AffectedComponent,
		RealisticWorkflow:        a.RealisticWorkflow,
		InputSource:              a.InputSource,
		AttackerInfluence:        a.AttackerInfluence,
		ResultingCapability:      a.ResultingCapability,
		ExploitPaths:             a.ExploitPaths,
		Transitions:              a.Transitions,
	}
}

func (a *IntrinsicAnalysis) ApplyContext(context IntrinsicContext) {
	if a == nil {
		return
	}
	a.AttackerStartingPosition = context.AttackerStartingPosition
	a.AffectedComponent = context.AffectedComponent
	a.RealisticWorkflow = context.RealisticWorkflow
	a.InputSource = context.InputSource
	a.AttackerInfluence = context.AttackerInfluence
	a.ResultingCapability = context.ResultingCapability
	a.ExploitPaths = context.ExploitPaths
	a.Transitions = context.Transitions
}
