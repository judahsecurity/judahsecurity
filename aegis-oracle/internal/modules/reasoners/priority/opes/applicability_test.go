package opes

import (
	"strings"
	"testing"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestApplicabilityHeadlineDoesNotInferLocalExploitationFromPriority(t *testing.T) {
	for _, state := range []schema.ContextualAssessmentState{schema.ContextNeedsEvidence, schema.ContextDocumentedPathBlock, schema.ContextConditionsMet} {
		in := cve202555130Input()
		in.Contextual = &schema.ContextualAssessment{State: state}
		in.Exploitation.InKEVSources = []string{"cisa_kev"}
		score := Compute(in, DefaultConfig())
		label := score.Label
		if score.Category != schema.PriorityCritical || score.Override != "kev_floor" {
			t.Fatal("global intelligence should retain its priority floor")
		}
		if !strings.Contains(label, "Known exploitation reported") {
			t.Fatal(label)
		}
		if strings.Contains(label, "Actively Exploitable") {
			t.Fatal("global priority leaked into local conclusion: " + label)
		}
		if state == schema.ContextNeedsEvidence && score.Confidence != schema.ConfidenceLow {
			t.Fatal("unknown conditions must lower confidence")
		}
	}
}
