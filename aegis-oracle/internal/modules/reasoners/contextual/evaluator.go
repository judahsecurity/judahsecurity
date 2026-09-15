// Package contextual implements Phase B: take an IntrinsicAnalysis and an
// Asset, evaluate each precondition against the asset's signals, and
// emit a PreconditionEvalSet usable by OPES.
//
// Phase B is rule-based and cheap. The LLM is not in the loop here —
// upstream Phase A produced structured preconditions with verification_signal
// paths, so resolving them is a deterministic signal lookup + match check.
//
// When a signal is missing the precondition is Unknown (not Unsatisfied).
// We never assume the absence of a signal means the precondition fails;
// that's how false-negative findings hide and how the bot would lose
// trust. The unknown-blocker dampener in OPES handles uncertainty.
package contextual

import (
	"regexp"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Evaluate walks the intrinsic preconditions and produces an evaluation
// per precondition against the asset's signals. The result feeds OPES.
//
// Match kinds:
//
//	regex       — match_value as Go regexp against signal value
//	equals      — case-insensitive string equality
//	contains    — case-insensitive substring
//	present     — signal exists and is non-empty (match_value ignored)
//	version_lte — string compare assuming semver-like tokens (best-effort)
func Evaluate(intrinsic *schema.IntrinsicAnalysis, asset *schema.Asset) schema.PreconditionEvalSet {
	return Assess(intrinsic, asset, time.Now()).Preconditions
}

// Assess evaluates the vulnerability's documented paths and transitions
// against fresh, attributable local evidence. Global threat intelligence is
// intentionally not accepted here.
func Assess(intrinsic *schema.IntrinsicAnalysis, asset *schema.Asset, assessedAt time.Time) schema.ContextualAssessment {
	if intrinsic == nil || asset == nil {
		return schema.ContextualAssessment{
			State:   schema.ContextNeedsEvidence,
			Summary: "asset or intrinsic vulnerability context is missing",
		}
	}
	out := make(schema.PreconditionEvalSet, 0, len(intrinsic.Preconditions))
	for _, p := range intrinsic.Preconditions {
		out = append(out, evaluateOne(p, asset, assessedAt))
	}

	context := intrinsic.Context()
	assessment := schema.ContextualAssessment{
		AssetID:                  asset.ID,
		TenantID:                 asset.TenantID,
		AttackerStartingPosition: context.AttackerStartingPosition,
		AffectedComponent:        context.AffectedComponent,
		RealisticWorkflow:        context.RealisticWorkflow,
		InputSource:              context.InputSource,
		AttackerInfluence:        context.AttackerInfluence,
		ObservedAt:               schema.FlexTime{Time: assessedAt},
		RequiredCapability:       intrinsic.AttackerCapability,
		ResultingCapability:      context.ResultingCapability,
		Components:               asset.Signals.Components,
		Preconditions:            out,
	}
	assessment.Paths = assessPaths(context.ExploitPaths, out)
	assessment.Transitions = assessTransitions(context.Transitions, asset, assessedAt)
	assessment.MissingChecks = missingChecks(out, assessment.Transitions)
	assessment.State, assessment.Summary = assessmentState(assessment.Paths, out, assessment.Transitions)
	return assessment
}

func evaluateOne(p schema.Precondition, asset *schema.Asset, assessedAt time.Time) schema.PreconditionEval {
	signalVal, evidence, present := asset.Signals.LookupWithEvidence(p.VerificationSignal)
	if !present {
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnknown,
			Reason:       "asset signal `" + p.VerificationSignal + "` not populated",
			Evidence:     evidence,
		}
	}
	if !hasFreshEvidence(evidence, assessedAt, asset.ID, signalVal) {
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnknown,
			Reason:       "signal is present but lacks fresh, attributable evidence",
			SignalValue:  signalVal,
			Evidence:     evidence,
		}
	}
	matched, supported, why := matches(p, signalVal)
	if !supported {
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnknown,
			Reason:       why,
			SignalValue:  signalVal,
			Evidence:     evidence,
		}
	}
	switch matched {
	case true:
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionSatisfied,
			Reason:       "signal matched: " + why,
			SignalValue:  signalVal,
			Evidence:     evidence,
		}
	default:
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnsatisfied,
			Reason:       "signal contradicts precondition: " + why,
			SignalValue:  signalVal,
			Evidence:     evidence,
		}
	}
}

func matches(p schema.Precondition, value string) (bool, bool, string) {
	switch p.MatchKind {
	case "regex":
		re, err := regexp.Compile(p.MatchValue)
		if err != nil {
			return false, false, "invalid regex: " + err.Error()
		}
		if re.MatchString(value) {
			return true, true, "matched regex /" + p.MatchValue + "/"
		}
		return false, true, "did not match regex /" + p.MatchValue + "/"
	case "equals":
		if strings.EqualFold(value, p.MatchValue) {
			return true, true, "equal to " + p.MatchValue
		}
		return false, true, "value " + value + " != " + p.MatchValue
	case "contains":
		if strings.Contains(strings.ToLower(value), strings.ToLower(p.MatchValue)) {
			return true, true, "contains " + p.MatchValue
		}
		return false, true, "does not contain " + p.MatchValue
	case "present":
		if value != "" {
			return true, true, "signal present"
		}
		return false, true, "signal empty"
	case "version_lte":
		if compareVersions(value, p.MatchValue) <= 0 {
			return true, true, "version " + value + " <= " + p.MatchValue
		}
		return false, true, "version " + value + " > " + p.MatchValue
	default:
		return false, false, "unsupported match_kind: " + p.MatchKind
	}
}

func hasFreshEvidence(evidence []schema.EvidenceObservation, assessedAt time.Time, scope, value string) bool {
	for _, observation := range evidence {
		scopeMatches := scope == "" || observation.Scope == scope
		valueMatches := observation.Value == "" || strings.EqualFold(observation.Value, value)
		if observation.FreshnessAt(assessedAt) == schema.EvidenceFresh && observation.Source != "" && scopeMatches && valueMatches {
			return true
		}
	}
	return false
}

func assessPaths(paths []schema.ExploitPath, evals schema.PreconditionEvalSet) []schema.PathAssessment {
	if len(paths) == 0 && len(evals) > 0 {
		ids := make([]string, 0, len(evals))
		for _, eval := range evals {
			ids = append(ids, eval.Precondition.ID)
		}
		paths = []schema.ExploitPath{{ID: "documented-path", Name: "Documented exploit path", PreconditionIDs: ids}}
	}

	results := make([]schema.PathAssessment, 0, len(paths))
	for _, path := range paths {
		result := schema.PathAssessment{Path: path, Status: schema.PreconditionSatisfied, Reason: "all documented prerequisites are met"}
		for _, prerequisiteID := range path.PreconditionIDs {
			eval, found := findEval(evals, prerequisiteID)
			if !found || eval.Status == schema.PreconditionUnknown {
				result.Status = schema.PreconditionUnknown
				result.Reason = "one or more prerequisites need evidence"
				continue
			}
			if eval.Status == schema.PreconditionUnsatisfied {
				result.Status = schema.PreconditionUnsatisfied
				result.Reason = "this documented path is blocked"
				result.BlockingCondition = eval.Precondition.Description
				break
			}
		}
		results = append(results, result)
	}
	return results
}

func findEval(evals schema.PreconditionEvalSet, id string) (schema.PreconditionEval, bool) {
	for _, eval := range evals {
		if eval.Precondition.ID == id {
			return eval, true
		}
	}
	return schema.PreconditionEval{}, false
}

func assessTransitions(transitions []schema.AttackTransition, asset *schema.Asset, assessedAt time.Time) []schema.AttackTransitionAssessment {
	results := make([]schema.AttackTransitionAssessment, 0, len(transitions))
	for _, transition := range transitions {
		access, accessEvidence := signalStatus(transition.AccessSignal, asset, assessedAt)
		capability, capabilityEvidence := signalStatus(transition.CapabilitySignal, asset, assessedAt)
		result := schema.AttackTransitionAssessment{
			Transition:       transition,
			AccessStatus:     access,
			CapabilityStatus: capability,
			Status:           schema.PreconditionUnknown,
			Reason:           "network access alone does not establish attacker progress",
			Evidence:         append(accessEvidence, capabilityEvidence...),
		}
		if access == schema.PreconditionUnsatisfied || capability == schema.PreconditionUnsatisfied {
			result.Status = schema.PreconditionUnsatisfied
			result.Reason = "a required access or capability condition is not met"
		} else if access == schema.PreconditionSatisfied && capability == schema.PreconditionSatisfied {
			result.Status = schema.PreconditionSatisfied
			result.Reason = "required access and attacker capability are both established"
		}
		results = append(results, result)
	}
	return results
}

func signalStatus(path string, asset *schema.Asset, assessedAt time.Time) (schema.PreconditionStatus, []schema.EvidenceObservation) {
	if path == "" {
		return schema.PreconditionUnknown, nil
	}
	value, evidence, present := asset.Signals.LookupWithEvidence(path)
	if !present || !hasFreshEvidence(evidence, assessedAt, asset.ID, value) {
		return schema.PreconditionUnknown, evidence
	}
	if strings.EqualFold(value, "false") || value == "0" || strings.EqualFold(value, "denied") {
		return schema.PreconditionUnsatisfied, evidence
	}
	return schema.PreconditionSatisfied, evidence
}

func missingChecks(evals schema.PreconditionEvalSet, transitions []schema.AttackTransitionAssessment) []string {
	checks := make([]string, 0)
	seen := make(map[string]bool)
	add := func(check string) {
		check = strings.TrimSpace(check)
		if check != "" && !seen[check] {
			seen[check] = true
			checks = append(checks, check)
		}
	}
	for _, eval := range evals {
		if eval.Status == schema.PreconditionUnknown {
			check := eval.Precondition.VerificationMethod
			if check == "" {
				check = "establish " + eval.Precondition.VerificationSignal
			}
			add(check)
		}
	}
	for _, transition := range transitions {
		if transition.AccessStatus == schema.PreconditionUnknown && transition.Transition.AccessSignal != "" {
			add("establish " + transition.Transition.AccessSignal)
		}
		if transition.CapabilityStatus == schema.PreconditionUnknown && transition.Transition.CapabilitySignal != "" {
			add("establish " + transition.Transition.CapabilitySignal)
		}
	}
	return checks
}

func assessmentState(paths []schema.PathAssessment, evals schema.PreconditionEvalSet, transitions []schema.AttackTransitionAssessment) (schema.ContextualAssessmentState, string) {
	if len(paths) == 0 && len(evals) == 0 {
		return schema.ContextNeedsEvidence, "no asset-specific exploit prerequisites have been evaluated"
	}
	met, blocked, unknown := 0, 0, 0
	for _, path := range paths {
		switch path.Status {
		case schema.PreconditionSatisfied:
			met++
		case schema.PreconditionUnsatisfied:
			blocked++
		default:
			unknown++
		}
	}
	if met > 0 {
		for _, transition := range transitions {
			if transition.Status == schema.PreconditionUnknown {
				return schema.ContextNeedsEvidence, "a documented path is locally plausible, but required attacker access or capability still needs evidence"
			}
			if transition.Status == schema.PreconditionUnsatisfied {
				return schema.ContextDocumentedPathBlock, "a required transition in the documented exploit chain is blocked; alternate paths are not ruled out"
			}
		}
		return schema.ContextConditionsMet, "at least one documented exploit path has all required conditions met"
	}
	if unknown > 0 {
		return schema.ContextNeedsEvidence, "additional asset evidence is required before exploitability can be determined"
	}
	if blocked > 0 {
		return schema.ContextDocumentedPathBlock, "all currently documented exploit paths are blocked; alternate paths are not ruled out"
	}
	return schema.ContextConditional, "asset-specific exploitability is conditional"
}

// compareVersions does a loose dotted-number comparison: "1.2.3" vs "1.2.10".
// Non-numeric tokens compare lexicographically. Returns -1 / 0 / 1.
//
// Good enough for the version_lte preconditions we expect (e.g. "node <=
// 24.10.0"); for serious version semantics, swap in github.com/Masterminds/semver
// behind this function.
func compareVersions(a, b string) int {
	ap := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bp := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ai, bi string
		if i < len(ap) {
			ai = ap[i]
		}
		if i < len(bp) {
			bi = bp[i]
		}
		if ai == bi {
			continue
		}
		ax, ok1 := atoi(ai)
		bx, ok2 := atoi(bi)
		if ok1 && ok2 {
			if ax < bx {
				return -1
			}
			return 1
		}
		if ai < bi {
			return -1
		}
		return 1
	}
	return 0
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
