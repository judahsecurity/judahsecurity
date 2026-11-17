package schema

import "testing"

func TestLookupHostSignals(t *testing.T) {
	s := AssetSignals{Host: map[string]string{
		"sshd.logingracetime":    "0",
		"process._complete":      "true",
		"process.sshd.running":   "true",
		"package.openssh-server": "1:8.9p1-3ubuntu0.6",
	}}
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"host.sshd.logingracetime":     {"0", true},
		"host.SSHD.LoginGraceTime":     {"0", true},
		"host.process.sshd.running":    {"true", true},
		"host.process.nginx.running":   {"false", true}, // full list → absent means not running
		"host.package.openssh-server":  {"1:8.9p1-3ubuntu0.6", true},
		"host.package.nginx.installed": {"", false}, // package list not marked complete
		"host.sshd.permitrootlogin":    {"", false},
		"host.process..running":        {"", false},
	}
	for path, want := range cases {
		got, ok := s.Lookup(path)
		if got != want.want || ok != want.ok {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", path, got, ok, want.want, want.ok)
		}
	}
}

func TestLookupWithEvidenceUsesProbePrefix(t *testing.T) {
	s := AssetSignals{
		Host: map[string]string{"sshd.logingracetime": "120"},
		SignalEvidence: map[string][]EvidenceObservation{
			"host.sshd.*": {{SignalPath: "host.sshd.*", Source: "host_ssh_probe"}},
			"host.*":      {{SignalPath: "host.*", Source: "host_ssh_probe", Error: "unused"}},
		},
	}
	_, ev, ok := s.LookupWithEvidence("host.sshd.logingracetime")
	if !ok || len(ev) != 1 || ev[0].SignalPath != "host.sshd.*" {
		t.Fatalf("expected probe-level evidence, got ok=%v ev=%+v", ok, ev)
	}
	_, ev, ok = s.LookupWithEvidence("host.kernel.release")
	if ok || len(ev) != 1 || ev[0].SignalPath != "host.*" {
		t.Fatalf("expected run-level evidence for a missing key, got ok=%v ev=%+v", ok, ev)
	}
}

func TestVerificationTaskKind(t *testing.T) {
	for signal, want := range map[string]string{
		"host.sshd.logingracetime": "host_probe",
		"runtime_flags.node":       "container_inspect",
		"container.image":          "container_inspect",
		"tenant.runs_user_code":    "manual",
	} {
		if got := VerificationTaskKind(signal); got != want {
			t.Errorf("%s: got %s, want %s", signal, got, want)
		}
	}
}
