package contextual

import (
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestEvaluate_UnknownWhenSignalMissing(t *testing.T) {
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{
				ID:                 "node-permissions-active",
				VerificationSignal: "runtime_flags.node",
				MatchKind:          "regex",
				MatchValue:         "(--experimental-permissions|--permissions)",
				Severity:           schema.PreconditionBlocker,
			},
		},
	}
	asset := &schema.Asset{}
	out := Evaluate(intrinsic, asset)
	if len(out) != 1 {
		t.Fatalf("got %d evals", len(out))
	}
	if out[0].Status != schema.PreconditionUnknown {
		t.Errorf("expected Unknown, got %s", out[0].Status)
	}
}

func TestEvaluate_SatisfiedAndUnsatisfied(t *testing.T) {
	yes := true
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{
				ID:                 "tenant-runs-user-code",
				VerificationSignal: "tenant.runs_user_code",
				MatchKind:          "equals",
				MatchValue:         "true",
				Severity:           schema.PreconditionBlocker,
			},
			{
				ID:                 "auth-bypass-needed",
				VerificationSignal: "auth.required",
				MatchKind:          "equals",
				MatchValue:         "false",
				Severity:           schema.PreconditionContributing,
			},
		},
	}
	authReq := true
	asset := &schema.Asset{
		Signals: schema.AssetSignals{
			Tenant: &schema.TenantSignals{RunsUserCode: &yes},
			Auth:   &schema.AuthSignals{Required: &authReq},
			SignalEvidence: map[string][]schema.EvidenceObservation{
				"tenant.runs_user_code": {freshEvidence("tenant.runs_user_code", "true")},
				"auth.required":         {freshEvidence("auth.required", "true")},
			},
		},
	}
	out := Evaluate(intrinsic, asset)
	if out[0].Status != schema.PreconditionSatisfied {
		t.Errorf("first eval: expected Satisfied, got %s (%s)", out[0].Status, out[0].Reason)
	}
	if out[1].Status != schema.PreconditionUnsatisfied {
		t.Errorf("second eval: expected Unsatisfied, got %s (%s)", out[1].Status, out[1].Reason)
	}
}

func TestAssess_StaleAndUnsupportedEvidenceRemainUnknown(t *testing.T) {
	stale := freshEvidence("runtime_flags.service", "enabled")
	stale.ValidUntil = schema.FlexTime{Time: time.Now().Add(-time.Hour)}
	intrinsic := &schema.IntrinsicAnalysis{Preconditions: []schema.Precondition{
		{ID: "stale", VerificationSignal: "runtime_flags.service", MatchKind: "equals", MatchValue: "enabled"},
		{ID: "unsupported", VerificationSignal: "extra.mode", MatchKind: "custom", MatchValue: "on"},
	}}
	asset := &schema.Asset{Signals: schema.AssetSignals{
		RuntimeFlags: map[string]string{"service": "enabled"},
		Extra:        map[string]string{"mode": "on"},
		SignalEvidence: map[string][]schema.EvidenceObservation{
			"runtime_flags.service": {stale},
			"extra.mode":            {freshEvidence("extra.mode", "on")},
		},
	}}
	assessment := Assess(intrinsic, asset, time.Now())
	for _, eval := range assessment.Preconditions {
		if eval.Status != schema.PreconditionUnknown {
			t.Fatalf("%s: expected unknown, got %s", eval.Precondition.ID, eval.Status)
		}
	}
	if assessment.State != schema.ContextNeedsEvidence {
		t.Fatalf("expected needs_evidence, got %s", assessment.State)
	}
}

func TestAssess_AlternativePathsAreEvaluatedIndependently(t *testing.T) {
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{ID: "http", VerificationSignal: "extra.http_enabled", MatchKind: "equals", MatchValue: "true", PathIDs: []string{"http"}},
			{ID: "https", VerificationSignal: "extra.https_enabled", MatchKind: "equals", MatchValue: "true", PathIDs: []string{"https"}},
		},
		ExploitPaths: []schema.ExploitPath{
			{ID: "http", Name: "HTTP management path", PreconditionIDs: []string{"http"}},
			{ID: "https", Name: "HTTPS management path", PreconditionIDs: []string{"https"}},
		},
	}
	asset := &schema.Asset{Signals: schema.AssetSignals{
		Extra: map[string]string{"http_enabled": "false", "https_enabled": "true"},
		SignalEvidence: map[string][]schema.EvidenceObservation{
			"extra.http_enabled":  {freshEvidence("extra.http_enabled", "false")},
			"extra.https_enabled": {freshEvidence("extra.https_enabled", "true")},
		},
	}}
	assessment := Assess(intrinsic, asset, time.Now())
	if assessment.Paths[0].Status != schema.PreconditionUnsatisfied || assessment.Paths[1].Status != schema.PreconditionSatisfied {
		t.Fatalf("unexpected path statuses: %#v", assessment.Paths)
	}
	if assessment.State != schema.ContextConditionsMet {
		t.Fatalf("one blocked path must not hide a viable alternative: got %s", assessment.State)
	}
}

func TestAssess_IdleOnDemandComponentIsNotTreatedAsSafe(t *testing.T) {
	yes, no := true, false
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{ID: "installed", VerificationSignal: "components.aspnet.installed", MatchKind: "equals", MatchValue: "true"},
			{ID: "on-demand", VerificationSignal: "components.aspnet.idle_on_demand", MatchKind: "equals", MatchValue: "true"},
		},
	}
	evidence := []schema.EvidenceObservation{
		freshEvidence("components.aspnet.installed", "true"),
		freshEvidence("components.aspnet.idle_on_demand", "true"),
	}
	asset := &schema.Asset{Signals: schema.AssetSignals{Components: []schema.ComponentObservation{{
		Name: "aspnet", Installed: &yes, IdleOnDemand: &yes, Executing: &no, Evidence: evidence,
	}}}}
	assessment := Assess(intrinsic, asset, time.Now())
	if assessment.State != schema.ContextConditionsMet {
		t.Fatalf("idle-on-demand activation path must remain exploitable, got %s", assessment.State)
	}
}

func TestAssess_InstalledBrowserDoesNotProveAttackerReachableInput(t *testing.T) {
	yes := true
	intrinsic := &schema.IntrinsicAnalysis{Preconditions: []schema.Precondition{
		{ID: "installed", VerificationSignal: "components.browser.installed", MatchKind: "equals", MatchValue: "true"},
		{ID: "input", VerificationSignal: "components.browser.attacker_reachable", MatchKind: "equals", MatchValue: "true"},
	}}
	asset := &schema.Asset{Signals: schema.AssetSignals{Components: []schema.ComponentObservation{{
		Name: "browser", Installed: &yes, Evidence: []schema.EvidenceObservation{freshEvidence("components.browser.installed", "true")},
	}}}}
	assessment := Assess(intrinsic, asset, time.Now())
	if assessment.State != schema.ContextNeedsEvidence {
		t.Fatalf("installed-only browser must need input-path evidence, got %s", assessment.State)
	}
}

func TestAssess_SplunkForwarderDoesNotEstablishDeploymentServer(t *testing.T) {
	yes := true
	intrinsic := &schema.IntrinsicAnalysis{
		AffectedComponent: "Splunk deployment server",
		Preconditions: []schema.Precondition{{
			ID: "deployment-server", VerificationSignal: "components.splunkdeploymentserver.installed", MatchKind: "equals", MatchValue: "true",
		}},
	}
	asset := &schema.Asset{Signals: schema.AssetSignals{Components: []schema.ComponentObservation{{
		Name: "splunkuniversalforwarder", Installed: &yes,
		Evidence: []schema.EvidenceObservation{freshEvidence("components.splunkuniversalforwarder.installed", "true")},
	}}}}
	assessment := Assess(intrinsic, asset, time.Now())
	if assessment.State != schema.ContextNeedsEvidence || assessment.Preconditions[0].Status != schema.PreconditionUnknown {
		t.Fatalf("forwarder evidence must not be applied to deployment server: %#v", assessment)
	}
}

func TestAssess_AuthenticationBypassDoesNotProveHostExecution(t *testing.T) {
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{{ID: "auth-path", VerificationSignal: "extra.auth_bypass", MatchKind: "equals", MatchValue: "true"}},
		Transitions: []schema.AttackTransition{{
			ID: "auth-to-host", AccessSignal: "extra.auth_bypass", CapabilitySignal: "extra.host_code_execution",
		}},
	}
	asset := &schema.Asset{Signals: schema.AssetSignals{
		Extra: map[string]string{"auth_bypass": "true"},
		SignalEvidence: map[string][]schema.EvidenceObservation{
			"extra.auth_bypass": {freshEvidence("extra.auth_bypass", "true")},
		},
	}}
	assessment := Assess(intrinsic, asset, time.Now())
	if assessment.State != schema.ContextNeedsEvidence || assessment.Transitions[0].Status != schema.PreconditionUnknown {
		t.Fatalf("authentication progress must not imply host execution: %#v", assessment.Transitions[0])
	}
}

func TestAssess_NetworkAllowDoesNotEstablishExploitTransition(t *testing.T) {
	intrinsic := &schema.IntrinsicAnalysis{Transitions: []schema.AttackTransition{{
		ID: "edge-to-app", AccessSignal: "extra.f5_allows", CapabilitySignal: "extra.exploit_capability",
	}}}
	asset := &schema.Asset{Signals: schema.AssetSignals{
		Extra: map[string]string{"f5_allows": "true"},
		SignalEvidence: map[string][]schema.EvidenceObservation{
			"extra.f5_allows": {freshEvidence("extra.f5_allows", "true")},
		},
	}}
	assessment := Assess(intrinsic, asset, time.Now())
	transition := assessment.Transitions[0]
	if transition.AccessStatus != schema.PreconditionSatisfied || transition.Status != schema.PreconditionUnknown {
		t.Fatalf("allow rule must establish access only: %#v", transition)
	}
}

func freshEvidence(path, value string) schema.EvidenceObservation {
	now := time.Now()
	return schema.EvidenceObservation{
		SignalPath: path,
		Value:      value,
		Source:     "unit-test-connector",
		ObservedAt: schema.FlexTime{Time: now},
		ValidUntil: schema.FlexTime{Time: now.Add(time.Hour)},
		Freshness:  schema.EvidenceFresh,
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.10", -1},
		{"1.2.10", "1.2.3", 1},
		{"v24.10.0", "24.10.0", 0},
		{"24.10.1", "24.10.0", 1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		// Normalise to -1/0/1.
		if got > 0 {
			got = 1
		} else if got < 0 {
			got = -1
		}
		if got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
