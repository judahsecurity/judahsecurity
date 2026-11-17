package contextual

import (
	"strings"
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func regresshion() *schema.IntrinsicAnalysis {
	return &schema.IntrinsicAnalysis{Preconditions: []schema.Precondition{
		{ID: "sshd-running", VerificationSignal: "host.process.sshd.running", MatchKind: "equals", MatchValue: "true", Severity: schema.PreconditionBlocker},
		{ID: "logingracetime-nonzero", VerificationSignal: "host.sshd.logingracetime", MatchKind: "regex", MatchValue: "^[1-9][0-9]*$", Severity: schema.PreconditionBlocker},
	}}
}

func hostAsset(id string, host map[string]string, probeErr string) *schema.Asset {
	now := time.Now()
	obs := func(prefix string) []schema.EvidenceObservation {
		o := schema.EvidenceObservation{
			SignalPath: prefix, Source: "host_ssh_probe", Scope: id,
			ObservedAt: schema.FlexTime{Time: now}, ValidUntil: schema.FlexTime{Time: now.Add(time.Hour)},
			Freshness: schema.EvidenceFresh,
		}
		if probeErr != "" {
			o.Freshness, o.Error = schema.EvidenceError, probeErr
		}
		return []schema.EvidenceObservation{o}
	}
	ev := map[string][]schema.EvidenceObservation{}
	if probeErr != "" {
		ev["host.*"] = obs("host.*")
	} else {
		ev["host.process.*"] = obs("host.process.*")
		ev["host.sshd.*"] = obs("host.sshd.*")
	}
	return &schema.Asset{ID: id, Signals: schema.AssetSignals{Host: host, SignalEvidence: ev}}
}

func statuses(set schema.PreconditionEvalSet) map[string]schema.PreconditionEval {
	out := map[string]schema.PreconditionEval{}
	for _, e := range set {
		out[e.Precondition.ID] = e
	}
	return out
}

func TestHostPreconditions_Exploitable(t *testing.T) {
	a := hostAsset("lnx-web-12", map[string]string{"process.sshd.running": "true", "sshd.logingracetime": "120"}, "")
	res := Assess(regresshion(), a, time.Now())
	for id, e := range statuses(res.Preconditions) {
		if e.Status != schema.PreconditionSatisfied {
			t.Errorf("%s: got %s (%s)", id, e.Status, e.Reason)
		}
	}
	if res.State != schema.ContextConditionsMet {
		t.Errorf("state: got %s", res.State)
	}
}

func TestHostPreconditions_LoginGraceTimeZeroBlocks(t *testing.T) {
	a := hostAsset("lnx-web-07", map[string]string{"process.sshd.running": "true", "sshd.logingracetime": "0"}, "")
	res := Assess(regresshion(), a, time.Now())
	e := statuses(res.Preconditions)["logingracetime-nonzero"]
	if e.Status != schema.PreconditionUnsatisfied {
		t.Fatalf("got %s (%s)", e.Status, e.Reason)
	}
	if !strings.Contains(e.Reason, `"0"`) {
		t.Errorf("reason should show the observed value: %s", e.Reason)
	}
	if res.State != schema.ContextDocumentedPathBlock {
		t.Errorf("state: got %s", res.State)
	}
}

func TestHostPreconditions_UncheckableIsUnknownWithReason(t *testing.T) {
	a := hostAsset("lnx-web-03", nil, "ssh connect failed: timed out")
	res := Assess(regresshion(), a, time.Now())
	for id, e := range statuses(res.Preconditions) {
		if e.Status != schema.PreconditionUnknown {
			t.Errorf("%s: an unreachable host must stay unknown, got %s", id, e.Status)
		}
		if !strings.Contains(e.Reason, "could not check") || !strings.Contains(e.Reason, "timed out") {
			t.Errorf("%s: reason should say why: %s", id, e.Reason)
		}
	}
	if res.State != schema.ContextNeedsEvidence {
		t.Errorf("state: got %s", res.State)
	}
}

func TestHostPreconditions_EvidenceForAnotherAssetIsNotAccepted(t *testing.T) {
	a := hostAsset("lnx-web-12", map[string]string{"process.sshd.running": "true", "sshd.logingracetime": "0"}, "")
	a.ID = "some-other-asset"
	for id, e := range statuses(Evaluate(regresshion(), a)) {
		if e.Status != schema.PreconditionUnknown {
			t.Errorf("%s: evidence scoped to another asset must not count, got %s", id, e.Status)
		}
	}
}
