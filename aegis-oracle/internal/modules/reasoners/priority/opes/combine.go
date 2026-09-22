package opes

import (
	"fmt"
	"math"
	"sort"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// combine takes the six component scores and produces the final OPESScore.
// Local prerequisites influence the P component and confidence, but never
// produce a universal "not exploitable" claim: an observation may only block
// one documented path, and alternate paths may exist. Likewise, isolation is
// not a permanent safety claim. Confirmed global exploitation can still apply
// the KEV floor independently of local evidence.
func combine(in Input, c schema.OPESComponents, cfg Config) schema.OPESScore {
	raw := cfg.Weights.X*c.X +
		cfg.Weights.P*c.P +
		cfg.Weights.R*c.R +
		cfg.Weights.E*(10-c.E) +
		cfg.Weights.C*c.C +
		cfg.Weights.T*c.T

	if c.X >= cfg.Dampeners.KEVFloorThreshold {
		if raw < cfg.Dampeners.KEVFloorScore {
			raw = cfg.Dampeners.KEVFloorScore
		}
		score := buildScore(raw, c, in, cfg)
		score.Category = schema.PriorityCritical
		score.Label = "Actively Exploited"
		score.Override = "kev_floor"
		return score
	}

	score := buildScore(raw, c, in, cfg)
	if unknown := in.Preconditions.CountBlockers(schema.PreconditionUnknown); unknown > 0 {
		score.Dampener = fmt.Sprintf(
			"Confidence reduced: %d required condition(s) need fresh asset evidence; score was not lowered for missing evidence",
			unknown,
		)
	}
	return score
}

func buildScore(raw float64, c schema.OPESComponents, in Input, cfg Config) schema.OPESScore {
	raw = clamp(raw, 0, 10)
	rounded := math.Round(raw*10) / 10
	cat, label := bucketize(rounded, cfg)
	return schema.OPESScore{
		Value:            rounded,
		Category:         cat,
		Label:            label,
		Confidence:       deriveConfidence(in),
		Components:       c,
		TopContributors:  explain(c, cfg),
		EvaluatorVersion: Version,
		RiskModel:        riskModel(in, cfg.RiskModel),
	}
}

func bucketize(v float64, cfg Config) (schema.Priority, string) {
	switch {
	case v >= cfg.Bucketing.Critical:
		return schema.PriorityCritical, "Critical - Actively Exploitable"
	case v >= cfg.Bucketing.High:
		return schema.PriorityHigh, "High - Likely Exploitable"
	case v >= cfg.Bucketing.Medium:
		return schema.PriorityMedium, "Medium - Conditionally Exploitable"
	case v >= cfg.Bucketing.Low:
		return schema.PriorityLow, "Low - Verification Required"
	default:
		return schema.PriorityInformational, "Informational - Limited Current Evidence"
	}
}

func deriveConfidence(in Input) schema.Confidence {
	if in.Intrinsic == nil {
		return schema.ConfidenceLow
	}
	if in.Preconditions.AnyBlocker(schema.PreconditionUnknown) {
		return schema.ConfidenceLow
	}
	if in.Intrinsic.Confidence == "" {
		return schema.ConfidenceMedium
	}
	return in.Intrinsic.Confidence
}

// explain ranks the components by their weighted contribution and returns
// human-readable lines for the top three. This is what shows up in
// findings.opes.top_contributors and feeds the recommendation paragraph.
func explain(c schema.OPESComponents, cfg Config) []string {
	type contrib struct {
		Name  string
		Code  string
		Value float64
		Raw   float64
	}
	contribs := []contrib{
		{Name: "Active exploitation evidence", Code: "X", Value: cfg.Weights.X * c.X, Raw: c.X},
		{Name: "Precondition satisfaction", Code: "P", Value: cfg.Weights.P * c.P, Raw: c.P},
		{Name: "Reachability", Code: "R", Value: cfg.Weights.R * c.R, Raw: c.R},
		{Name: "Exploit difficulty (inverted)", Code: "E", Value: cfg.Weights.E * (10 - c.E), Raw: c.E},
		{Name: "Asset criticality", Code: "C", Value: cfg.Weights.C * c.C, Raw: c.C},
		{Name: "Time pressure", Code: "T", Value: cfg.Weights.T * c.T, Raw: c.T},
	}
	// Rank by distance from neutral contribution (~1.5 if all weights equal).
	// This surfaces the most-influential factors regardless of direction.
	sort.Slice(contribs, func(i, j int) bool {
		return math.Abs(contribs[i].Value-1.5) > math.Abs(contribs[j].Value-1.5)
	})
	out := make([]string, 0, 3)
	for i := 0; i < 3 && i < len(contribs); i++ {
		out = append(out, fmt.Sprintf(
			"%s (%s=%.1f, contribution %+.2f)",
			contribs[i].Name, contribs[i].Code, contribs[i].Raw, contribs[i].Value,
		))
	}
	return out
}
