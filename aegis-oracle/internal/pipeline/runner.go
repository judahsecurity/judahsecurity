// Package pipeline ties the phases together for a single CVE+Asset pair:
//
//  1. Load CVE from store (or accept one directly)
//  2. Fetch/cache intrinsic analysis (Phase A — LLM or cache)
//  3. Load asset from inventory
//  4. Evaluate preconditions against asset signals (Phase B — deterministic)
//  5. Compute OPES score
//  6. Build finding + verification tasks
//  7. Write finding to store (visible to ASM UI)
//
// The runner is intentionally single-CVE-single-asset. Concurrency and
// job dispatch live above this layer (queue workers call Run in goroutines).
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/internal/modules/reasoners/contextual"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Store is the persistence surface the runner needs.
type Store interface {
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
	GetAsset(ctx context.Context, assetID string) (*schema.Asset, error)
	GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error)
	UpsertIntrinsicAnalysis(ctx context.Context, cveID, inputHash string, a *schema.IntrinsicAnalysis, cost float64) error
	UpsertFinding(ctx context.Context, f *schema.Finding) error
}

// Runner executes the full analysis pipeline.
type Runner struct {
	store     Store
	intrinsic *intrinsic.Reasoner
	opesConf  opes.Config
}

// New constructs a Runner.
func New(store Store, intrinsicReasoner *intrinsic.Reasoner, opesConf opes.Config) *Runner {
	return &Runner{
		store:     store,
		intrinsic: intrinsicReasoner,
		opesConf:  opesConf.WithDefaults(),
	}
}

// RunResult is the output of a single pipeline execution.
type RunResult struct {
	Finding   *schema.Finding
	Cached    bool   // true if intrinsic analysis was served from cache
	LLMModel  string
	CostUSD   float64
	ElapsedMS int64
}

// Run executes the full pipeline for a (CVE, asset) pair.
// refs are pre-fetched reference texts passed to Phase A.
func (r *Runner) Run(ctx context.Context, cveID, assetID string, refs []intrinsic.ResolvedRef, exploitation schema.ExploitationEvidence) (*RunResult, error) {
	start := time.Now()

	cve, err := r.store.GetCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("get cve %s: %w", cveID, err)
	}
	if cve == nil {
		return nil, fmt.Errorf("cve %s not found", cveID)
	}

	asset, err := r.store.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("get asset %s: %w", assetID, err)
	}
	if asset == nil {
		return nil, fmt.Errorf("asset %s not found", assetID)
	}

	// Phase A — intrinsic analysis (LLM or cache).
	analysis, err := r.intrinsic.Analyze(ctx, cve, refs)
	if err != nil {
		return nil, fmt.Errorf("intrinsic analysis: %w", err)
	}

	// Phase B — contextual evaluation.
	preconditions := contextual.Evaluate(analysis, asset)

	// OPES scoring.
	score := opes.Compute(opes.Input{
		CVE:           cve,
		Intrinsic:     analysis,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, r.opesConf)

	// Build finding.
	finding := buildFinding(cve, asset, analysis, preconditions, score, exploitation)

	// Persist.
	if err := r.store.UpsertFinding(ctx, finding); err != nil {
		return nil, fmt.Errorf("upsert finding: %w", err)
	}

	return &RunResult{
		Finding:   finding,
		LLMModel:  analysis.LLMModel,
		ElapsedMS: time.Since(start).Milliseconds(),
	}, nil
}

// RunWithObjects is like Run but accepts pre-loaded CVE and asset objects,
// useful for the CLI and tests where objects are provided from JSON files.
func (r *Runner) RunWithObjects(
	ctx context.Context,
	cve *schema.CVE,
	asset *schema.Asset,
	refs []intrinsic.ResolvedRef,
	exploitation schema.ExploitationEvidence,
) (*RunResult, error) {
	start := time.Now()

	analysis, err := r.intrinsic.Analyze(ctx, cve, refs)
	if err != nil {
		return nil, fmt.Errorf("intrinsic analysis: %w", err)
	}

	preconditions := contextual.Evaluate(analysis, asset)

	score := opes.Compute(opes.Input{
		CVE:           cve,
		Intrinsic:     analysis,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, r.opesConf)

	finding := buildFinding(cve, asset, analysis, preconditions, score, exploitation)

	if r.store != nil {
		_ = r.store.UpsertFinding(ctx, finding)
	}

	return &RunResult{
		Finding:   finding,
		LLMModel:  analysis.LLMModel,
		ElapsedMS: time.Since(start).Milliseconds(),
	}, nil
}

// ─────────────────────────── internals ─────────────────────────────────

func buildFinding(
	cve *schema.CVE,
	asset *schema.Asset,
	analysis *schema.IntrinsicAnalysis,
	preconditions schema.PreconditionEvalSet,
	score schema.OPESScore,
	exploitation schema.ExploitationEvidence,
) *schema.Finding {
	signalsHash := hashSignals(asset.Signals)
	inputHash := shortHash(cve.ID + analysis.PromptVersion)

	f := &schema.Finding{
		ID:                     newFindingID(cve.ID, asset.ID, inputHash, signalsHash),
		CVEID:                  cve.ID,
		AssetID:                asset.ID,
		IntrinsicInputHash:     inputHash,
		AssetSignalsHash:       signalsHash,
		EvaluatorVersion:       opes.Version,
		PreconditionsEvaluated: preconditions,
		OPES:                   score,
		CVSSReconciliation:       analysis.CVSSReconciliation,
		AnalystBrief:             analysis.AnalystBrief,
		AttackPathClass:          analysis.AttackPathClass,
		LateralMovementPotential: analysis.LateralMovementPotential,
		RecommendationText:       buildRecommendation(cve, asset, analysis, score, preconditions, exploitation),
		Status:                 schema.StatusOpen,
		CreatedAt:              time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}

	// Attach verification tasks for unknown blocker preconditions.
	for _, e := range preconditions {
		if e.Status != schema.PreconditionUnknown {
			continue
		}
		kind := "manual"
		sig := e.Precondition.VerificationSignal
		if strings.HasPrefix(sig, "runtime_flags.") || strings.HasPrefix(sig, "container.") {
			kind = "container_inspect"
		}
		f.VerificationTasks = append(f.VerificationTasks, schema.VerificationTask{
			ID:                    "ver-" + f.ID[:8] + "-" + e.Precondition.ID,
			PreconditionID:        e.Precondition.ID,
			Summary:               "Verify: " + e.Precondition.Description,
			TaskKind:              kind,
			Command:               e.Precondition.VerificationMethod,
			ExpectedSignalPath:    e.Precondition.VerificationSignal,
			ExpectedMatch:         e.Precondition.MatchValue,
			ResolvesPreconditions: []string{e.Precondition.ID},
			Status:                "open",
			CreatedAt:             time.Now().UTC(),
		})
	}

	return f
}

// buildRecommendation produces the analyst-facing narrative attached to every
// finding. It is intentionally section-headed prose rather than terse one-liners
// so a CISO/analyst opening a single finding can answer:
//
//  1. How bad is this on this asset, right now?  (headline)
//  2. How would an attacker actually exploit it?  (attack path + brief)
//  3. Could it happen here?                       (reachability + preconditions)
//  4. Is it being exploited elsewhere?            (evidence summary)
//  5. What do we do next?                         (verification + patch)
//
// All inputs are already structured on the Finding; this function just renders
// them. Persisted into findings.recommendation_text and read by the UI.
func buildRecommendation(
	cve *schema.CVE,
	asset *schema.Asset,
	analysis *schema.IntrinsicAnalysis,
	score schema.OPESScore,
	preconditions schema.PreconditionEvalSet,
	exploitation schema.ExploitationEvidence,
) string {
	_ = cve // reserved for future per-CVE annotations (e.g. vendor priors)
	var sb strings.Builder

	// ── Headline ─────────────────────────────────────────────────────────
	fmt.Fprintf(&sb, "[%s] %s — OPES %.1f (confidence: %s)\n",
		score.Category, score.Label, score.Value, score.Confidence)

	switch score.Override {
	case "blocker_unsatisfied":
		sb.WriteString("Verdict: Not exploitable on this asset — a blocker precondition is confirmed unsatisfied. Safe to suppress.\n")
	case "unreachable":
		sb.WriteString("Verdict: Asset is isolated or unreachable by the required attacker class. Safe to suppress.\n")
	case "kev_floor":
		sb.WriteString("Verdict: CISA/VulnCheck KEV — confirmed exploited in the wild. Treat as P0 and patch on emergency cadence.\n")
	default:
		if score.Dampener != "" {
			fmt.Fprintf(&sb, "Verdict: %s\n", score.Dampener)
		}
	}

	// ── Attack path ─────────────────────────────────────────────────────
	if analysis.AttackPathClass != "" {
		sb.WriteString("\nATTACK PATH\n")
		fmt.Fprintf(&sb, "  %s\n", analysis.AttackPathClass.Label())
		if v := reachabilityVerdict(asset, analysis, score.Components.R); v != "" {
			fmt.Fprintf(&sb, "  Reachability: %s\n", v)
		}
		if l := analysis.LateralMovementPotential.Label(); l != "" {
			fmt.Fprintf(&sb, "  Lateral movement: %s\n", l)
		}
	}

	// ── Analyst brief quotes ────────────────────────────────────────────
	brief := analysis.AnalystBrief
	if v := strings.TrimSpace(brief.AttackVectorSummary); v != "" {
		sb.WriteString("\nWHAT AN ATTACKER WOULD DO\n  ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	if v := strings.TrimSpace(brief.RealWorldLikelihood); v != "" {
		sb.WriteString("\nREAL-WORLD LIKELIHOOD\n  ")
		sb.WriteString(truncateSentences(v, 3))
		sb.WriteString("\n")
	}
	if v := strings.TrimSpace(brief.AffectedIf); v != "" {
		sb.WriteString("\nAFFECTED IF\n  ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	if v := strings.TrimSpace(brief.NotAffectedIf); v != "" {
		sb.WriteString("\nNOT AFFECTED IF\n  ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}

	// ── Exploitation evidence summary ────────────────────────────────────
	if lines := summarizeExploitationEvidence(exploitation); len(lines) > 0 {
		sb.WriteString("\nEXPLOITATION EVIDENCE\n")
		for _, l := range lines {
			fmt.Fprintf(&sb, "  • %s\n", l)
		}
	}

	// ── Preconditions ────────────────────────────────────────────────────
	if len(preconditions) > 0 {
		sb.WriteString("\nPRECONDITIONS\n")
		for _, e := range preconditions {
			marker := preconditionMarker(e.Status)
			sevTag := ""
			if e.Precondition.Severity == schema.PreconditionBlocker {
				sevTag = " [blocker]"
			}
			fmt.Fprintf(&sb, "  %s %s%s — %s\n",
				marker, e.Precondition.ID, sevTag, e.Precondition.Description)
			if e.Status == schema.PreconditionUnknown && e.Precondition.VerificationMethod != "" {
				fmt.Fprintf(&sb, "      verify: %s\n", e.Precondition.VerificationMethod)
			}
		}
	}

	// ── CVSS reconciliation, only when sources disagreed ────────────────
	if len(analysis.CVSSReconciliation.Disagreements) > 0 {
		sb.WriteString("\nCVSS RECONCILIATION\n")
		fmt.Fprintf(&sb, "  Reconciled to %.1f (%s).\n",
			analysis.CVSSReconciliation.CorrectScore,
			analysis.CVSSReconciliation.CorrectVector,
		)
		if analysis.CVSSReconciliation.Rationale != "" {
			fmt.Fprintf(&sb, "  Rationale: %s\n", analysis.CVSSReconciliation.Rationale)
		}
		for _, d := range analysis.CVSSReconciliation.Disagreements {
			fmt.Fprintf(&sb, "  • %s disagrees (%s): %s\n",
				d.Source, d.TheirVector, d.Disagreement)
		}
	}

	// ── Phishing/UI:R control context — only relevant for human-mediated ─
	// CVEs where the real-world risk is bounded by environmental controls
	// rather than the bug itself. Surfacing this prevents overstating risk
	// for orgs with strong email security and understating it for orgs
	// without.
	if analysis.AttackPathClass == schema.AttackPathPhishingDelivery ||
		strings.Contains(analysis.CVSSReconciliation.CorrectVector, "UI:R") {
		sb.WriteString("\nCONTROL CONTEXT (USER-INTERACTION REQUIRED)\n")
		sb.WriteString("  This attack requires user interaction. Real-world risk is bounded by\n")
		sb.WriteString("  phishing controls (email sandboxing, attachment stripping, link rewriting),\n")
		sb.WriteString("  endpoint isolation (browser site isolation, app sandboxing, EDR), and user\n")
		sb.WriteString("  awareness. Treat as High where those controls are weak; Medium where mature.\n")
	}

	// ── Next steps ───────────────────────────────────────────────────────
	if next := nextSteps(score, preconditions); len(next) > 0 {
		sb.WriteString("\nNEXT STEPS\n")
		for _, n := range next {
			fmt.Fprintf(&sb, "  • %s\n", n)
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}

// reachabilityVerdict explains the R component in plain English. Returns ""
// when there is nothing meaningful to say (e.g. asset missing).
func reachabilityVerdict(asset *schema.Asset, analysis *schema.IntrinsicAnalysis, r float64) string {
	if asset == nil {
		return ""
	}
	if asset.Exposure == schema.ExposureIsolated {
		return "Asset is isolated — not reachable by any external attacker."
	}
	switch analysis.AttackPathClass {
	case schema.AttackPathExploitPublicFacing:
		if asset.Exposure == schema.ExposureInternet {
			return "Asset is internet-exposed and the vulnerable surface is directly reachable from the internet."
		}
		return "Vulnerable service is reachable on the internal network."
	case schema.AttackPathPhishingDelivery:
		return "Not directly reachable by scanners — exploit must be delivered to a human user via email, link, or document."
	case schema.AttackPathLateralMovementRequired:
		return "Reachable only after an attacker has compromised another host. Risk depends on adjacent-asset hygiene."
	case schema.AttackPathValidCredentials:
		return "Reachable, but exploitation requires valid credentials. Risk depends on credential hygiene and MFA posture."
	case schema.AttackPathSupplyChain:
		return "Reachability is determined by the compromised dependency or build pipeline, not by network position."
	}
	switch {
	case r >= 8:
		return "Highly reachable for the required attacker class."
	case r >= 5:
		return "Moderately reachable — some controls in place but not blocking."
	case r > 0:
		return "Limited reachability — significant controls or distance reduce exposure."
	}
	return ""
}

// summarizeExploitationEvidence converts the structured ExploitationEvidence
// into bullet lines that read like an incident-response briefing rather than
// a flag dump. Highest-signal items first.
func summarizeExploitationEvidence(e schema.ExploitationEvidence) []string {
	var out []string

	for _, src := range e.InKEVSources {
		switch src {
		case "cisa_kev":
			out = append(out, "CISA KEV — confirmed exploited; due-date applies to federal agencies")
		case "vulncheck_kev":
			out = append(out, "VulnCheck KEV — confirmed exploited (independent of CISA)")
		case "enisa_euvd_kev":
			out = append(out, "ENISA EUVD — EU-confirmed exploitation")
		}
	}
	if e.RansomwareAssociated || e.VulnCheckRansomwareCount > 0 {
		out = append(out, "Ransomware-associated — used by ransomware operators in observed incidents")
	}
	if e.VulnCheckBotnetCount > 0 {
		out = append(out, "Botnet-associated — used by automated mass-exploitation operators")
	}
	if e.BreachConfirmed {
		out = append(out, fmt.Sprintf("VCDB breach confirmation — caused %d documented breach(es)", e.BreachIncidentCount))
	}
	if e.ZeroDayConfirmed {
		out = append(out, "Google Project Zero — exploited as a 0day before a patch existed")
	}
	if e.VulnCheckReportedExploited {
		out = append(out, "VulnCheck — exploitation reported in the wild")
	}
	if e.VulnCheckThreatActorCount > 0 {
		out = append(out, fmt.Sprintf("Linked to %d known threat actor group(s)", e.VulnCheckThreatActorCount))
	}
	if e.VulnCheckWeaponized {
		out = append(out, "VulnCheck — validated weaponized exploit available")
	}
	if e.MetasploitAvailable {
		switch {
		case e.MetasploitModCount > 1:
			out = append(out, fmt.Sprintf("Metasploit — %d weaponized modules available (push-button)", e.MetasploitModCount))
		default:
			out = append(out, "Metasploit module available (push-button exploit)")
		}
	}
	if e.VulnCheckPublicExploit && e.VulnCheckExploitCount > 0 {
		out = append(out, fmt.Sprintf("VulnCheck — %d public exploit artifact(s) catalogued", e.VulnCheckExploitCount))
	}
	switch e.CISASSVCDecision {
	case "Immediate":
		out = append(out, "CISA SSVC: Immediate — patch on emergency cadence")
	case "Out-of-Cycle":
		out = append(out, "CISA SSVC: Out-of-Cycle — patch outside normal maintenance window")
	}
	if e.AttackerKBValue >= 4 {
		out = append(out, fmt.Sprintf("AttackerKB attacker_value %d/5 — practitioner community rates this highly valuable", e.AttackerKBValue))
	}
	if e.PublicPOCFound {
		src := "nomi-sec/PoC-in-GitHub and/or trickest/cve"
		switch {
		case e.PublicPOCCount > 1:
			out = append(out, fmt.Sprintf("Public PoC repos — %d GitHub PoC(s) indexed (%s)", e.PublicPOCCount, src))
		default:
			out = append(out, fmt.Sprintf("Public PoC repo indexed (%s)", src))
		}
	}
	if e.RecentPOCDays > 0 && e.RecentPOCDays <= 30 {
		out = append(out, fmt.Sprintf("Recent public PoC (≤%d days)", e.RecentPOCDays))
	}
	return out
}

// preconditionMarker returns a single-character status indicator. Avoids
// emoji to keep the output safe for consoles, tickets, and email clients.
func preconditionMarker(s schema.PreconditionStatus) string {
	switch s {
	case schema.PreconditionSatisfied:
		return "[+]"
	case schema.PreconditionUnsatisfied:
		return "[-]"
	case schema.PreconditionUnknown:
		return "[?]"
	default:
		return "[ ]"
	}
}

// nextSteps assembles concrete, asset-specific actions. Order: any open
// verification tasks first (analyst can act now), then patch/upgrade
// guidance.
func nextSteps(score schema.OPESScore, set schema.PreconditionEvalSet) []string {
	var steps []string
	for _, e := range set {
		if e.Status != schema.PreconditionUnknown {
			continue
		}
		if e.Precondition.VerificationMethod != "" {
			steps = append(steps, fmt.Sprintf(
				"Verify %s: %s",
				e.Precondition.ID, e.Precondition.VerificationMethod,
			))
		} else {
			steps = append(steps, fmt.Sprintf(
				"Manually verify precondition: %s",
				e.Precondition.Description,
			))
		}
	}
	switch score.Category {
	case schema.PriorityCritical:
		steps = append(steps, "Patch on emergency cadence; if no patch, apply vendor mitigations and isolate the asset until patched.")
	case schema.PriorityHigh:
		steps = append(steps, "Patch in the next change window; deploy compensating controls (WAF rule, network ACL) in the interim.")
	case schema.PriorityMedium:
		steps = append(steps, "Patch in routine maintenance; verify preconditions to confirm the conditional risk is real.")
	case schema.PriorityLow:
		steps = append(steps, "Verify outstanding preconditions before re-prioritizing; patch in routine cycle once verified.")
	case schema.PriorityInformational:
		steps = append(steps, "No urgent action; track for awareness and handle on routine patching cadence.")
	}
	return steps
}

// truncateSentences keeps the first n sentences of a string, preserving
// the original whitespace shape. Splits on '.', '!', '?' so it won't
// over-aggressively cut at decimal points or version numbers in the
// rare cases the LLM uses them mid-sentence — we accept that edge.
func truncateSentences(s string, n int) string {
	if n <= 0 {
		return s
	}
	count := 0
	for i, r := range s {
		if r == '.' || r == '!' || r == '?' {
			count++
			if count >= n {
				end := i + 1
				if end < len(s) {
					return strings.TrimSpace(s[:end])
				}
				return s
			}
		}
	}
	return s
}

func hashSignals(s schema.AssetSignals) string {
	b, _ := json.Marshal(s)
	return shortHash(string(b))
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func newFindingID(cveID, assetID, inputHash, signalsHash string) string {
	return shortHash(cveID + "|" + assetID + "|" + inputHash + "|" + signalsHash)
}
