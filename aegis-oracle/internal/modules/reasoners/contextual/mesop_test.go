package contextual

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestMesopApplicabilityEvidence(t *testing.T) {
	data, err := os.ReadFile("../../../../examples/cve-2026-33057/intrinsic.json")
	if err != nil {
		t.Fatal(err)
	}
	var intrinsic schema.IntrinsicAnalysis
	if err := json.Unmarshal(data, &intrinsic); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, tc := range []struct {
		name      string
		values    map[string]string
		freshness schema.EvidenceFreshness
		scope     string
		expired   bool
		want      schema.ContextualAssessmentState
	}{
		{"version only", nil, schema.EvidenceFresh, "asm-1", false, schema.ContextNeedsEvidence},
		{"component only", map[string]string{"installed": "true"}, schema.EvidenceFresh, "asm-1", false, schema.ContextNeedsEvidence},
		{"all required facts", map[string]string{"installed": "true", "enabled": "true", "attacker_reachable": "true"}, schema.EvidenceFresh, "asm-1", false, schema.ContextConditionsMet},
		{"component absent", map[string]string{"installed": "false"}, schema.EvidenceFresh, "asm-1", false, schema.ContextDocumentedPathBlock},
		{"route disabled", map[string]string{"installed": "true", "enabled": "false"}, schema.EvidenceFresh, "asm-1", false, schema.ContextDocumentedPathBlock},
		{"expired absence", map[string]string{"installed": "false"}, schema.EvidenceFresh, "asm-1", true, schema.ContextNeedsEvidence},
		{"retracted absence", map[string]string{"installed": "false"}, schema.EvidenceUnknown, "asm-1", false, schema.ContextNeedsEvidence},
		{"wrong asset", map[string]string{"installed": "false"}, schema.EvidenceFresh, "asm-2", false, schema.ContextNeedsEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asset := &schema.Asset{ID: "asm-1", Exposure: schema.ExposureInternet, Signals: schema.AssetSignals{
				TechStack:       []schema.TechComponent{{Name: "mesop", Version: "1.2.2"}},
				ObservedSignals: map[string]schema.EvidenceObservation{},
			}}
			for property, value := range tc.values {
				path := "components.mesop_ai_sandbox." + property
				expiry := now.Add(time.Hour)
				if tc.expired {
					expiry = now.Add(-time.Minute)
				}
				asset.Signals.ObservedSignals[path] = schema.EvidenceObservation{
					SignalPath: path, Value: value, Source: "analyst:deployment_config", Scope: tc.scope,
					ObservedAt: schema.FlexTime{Time: now.Add(-time.Hour)}, ValidUntil: schema.FlexTime{Time: expiry}, Freshness: tc.freshness,
				}
			}
			assessment := Assess(&intrinsic, asset, now)
			if assessment.State != tc.want {
				t.Fatalf("got %s, want %s: %s", assessment.State, tc.want, assessment.Summary)
			}
			if tc.want == schema.ContextNeedsEvidence && len(assessment.MissingChecks) == 0 {
				t.Fatal("missing concrete verification tasks")
			}
		})
	}
}

func TestEmptyPathCannotEstablishApplicability(t *testing.T) {
	i := &schema.IntrinsicAnalysis{ExploitPaths: []schema.ExploitPath{{ID: "empty", Name: "Unknown route"}}}
	a := Assess(i, &schema.Asset{ID: "asm-1"}, time.Now())
	if a.State != schema.ContextNeedsEvidence || len(a.MissingChecks) == 0 {
		t.Fatalf("empty path treated as verified: %#v", a)
	}
}

func TestInvalidVersionCannotEstablishMitigation(t *testing.T) {
	p := schema.Precondition{MatchKind: "version_lte", MatchValue: "1.2.2"}
	_, supported, _ := matches(p, "unknown")
	if supported {
		t.Fatal("unparseable version must remain unknown")
	}
}

func TestTransitionBlockIsScopedToItsPath(t *testing.T) {
	now := time.Now()
	i := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{{ID: "input", VerificationSignal: "extra.input", MatchKind: "equals", MatchValue: "true"}},
		ExploitPaths:  []schema.ExploitPath{{ID: "http", PreconditionIDs: []string{"input"}}, {ID: "https", PreconditionIDs: []string{"input"}}},
		Transitions:   []schema.AttackTransition{{ID: "http-only", PathIDs: []string{"http"}, AccessSignal: "extra.http", CapabilitySignal: "extra.input"}},
	}
	asset := &schema.Asset{Signals: schema.AssetSignals{Extra: map[string]string{"input": "true", "http": "false"}, SignalEvidence: map[string][]schema.EvidenceObservation{
		"extra.input": {freshEvidence("extra.input", "true")}, "extra.http": {freshEvidence("extra.http", "false")},
	}}}
	a := Assess(i, asset, now.Add(time.Second))
	if a.State != schema.ContextConditionsMet || a.Paths[0].Status != schema.PreconditionUnsatisfied || a.Paths[1].Status != schema.PreconditionSatisfied {
		t.Fatalf("alternate path incorrectly blocked: %#v", a)
	}
}
