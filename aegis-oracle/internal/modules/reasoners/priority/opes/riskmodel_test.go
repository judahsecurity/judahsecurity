package opes

import (
	"math"
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func factors(bi, nl, vs, skill, disc, exploit, aware int) schema.RiskFactors {
	return schema.RiskFactors{
		BusinessImpact:        schema.RiskFactor{Score: bi},
		NetworkLocation:       schema.RiskFactor{Score: nl},
		VulnerabilitySeverity: schema.RiskFactor{Score: vs},
		SkillLevel:            schema.RiskFactor{Score: skill},
		EaseOfDiscovery:       schema.RiskFactor{Score: disc},
		EaseOfExploit:         schema.RiskFactor{Score: exploit},
		Awareness:             schema.RiskFactor{Score: aware},
	}
}

// TestRiskModel_WorkedExamples pins the arithmetic: factors 0–4,
// Impact = 0.2·BI + 0.1·NL + 0.7·VS, Likelihood = mean of four,
// Risk = (Impact/4)·(Likelihood/4)·100.
func TestRiskModel_WorkedExamples(t *testing.T) {
	cases := []struct {
		name               string
		f                  schema.RiskFactors
		impact, likelihood float64
		risk               float64
		level              schema.Priority
	}{
		{"company-hosted SQLi", factors(4, 4, 3, 2, 4, 4, 4), 3.3, 3.5, 72.19, schema.PriorityCritical},
		{"critical RCE on segmented network", factors(4, 0, 4, 4, 4, 4, 4), 3.6, 4.0, 90.0, schema.PriorityCritical},
		{"third-party-hosted XSS", factors(3, 2, 2, 3, 4, 3, 4), 2.2, 3.5, 48.13, schema.PriorityHigh},
		{"internal XSS in dev", factors(1, 1, 2, 2, 3, 3, 2), 1.7, 2.5, 26.56, schema.PriorityMedium},
		{"low-severity, hard to exploit", factors(1, 2, 1, 1, 2, 1, 4), 1.1, 2.0, 13.75, schema.PriorityLow},
		{"barely anything", factors(1, 0, 1, 1, 1, 0, 0), 0.9, 0.5, 2.81, schema.PriorityInformational},
		{"no likelihood means no risk", factors(4, 4, 4, 0, 0, 0, 0), 4.0, 0, 0, schema.PriorityInformational},
	}
	cfg := DefaultConfig().RiskModel
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scoreRiskFactors(tc.f, nil, cfg)
			if math.Abs(got.Impact-tc.impact) > 0.001 {
				t.Errorf("impact: got %.2f, want %.2f", got.Impact, tc.impact)
			}
			if math.Abs(got.Likelihood-tc.likelihood) > 0.001 {
				t.Errorf("likelihood: got %.2f, want %.2f", got.Likelihood, tc.likelihood)
			}
			if math.Abs(got.Score-tc.risk) > 0.011 {
				t.Errorf("risk: got %.2f, want %.2f", got.Score, tc.risk)
			}
			if got.Level != tc.level {
				t.Errorf("level: got %s, want %s", got.Level, tc.level)
			}
		})
	}

	// Blocked realism zeroes likelihood even when every factor is maxed.
	blocked := &schema.ExploitRealism{Tier: schema.RealismBlocked}
	if got := scoreRiskFactors(factors(4, 4, 4, 4, 4, 4, 4), blocked, cfg); got.Score != 0 || got.Level != schema.PriorityInformational {
		t.Errorf("blocked: got %.2f %s, want 0 informational", got.Score, got.Level)
	}
}

// TestRiskModel_DiscoverabilityOrdering: a vulnerability automated scanners
// can find is more likely to be exploited than one needing manual work.
func TestRiskModel_DiscoverabilityOrdering(t *testing.T) {
	cve := &schema.CVE{ID: "CVE-2099-0001"}
	nuclei := Input{CVE: &schema.CVE{ID: "CVE-2099-0001", NucleiTemplate: "cves/2099/CVE-2099-0001.yaml"}}
	remote := Input{CVE: cve, Exploitation: schema.ExploitationEvidence{AttackerDiscoverabilityTier: "remote_exploit"}}
	version := Input{CVE: cve, Exploitation: schema.ExploitationEvidence{AttackerDiscoverabilityTier: "version_detectable"}}
	manual := Input{CVE: cve}
	credentialed := Input{CVE: cve, Exploitation: schema.ExploitationEvidence{AttackerDiscoverabilityTier: "credentialed_only"}}

	want := []struct {
		name  string
		in    Input
		score int
	}{
		{"nuclei template", nuclei, 4},
		{"remote scanner signature", remote, 4},
		{"version fingerprint", version, 4},
		{"manual testing", manual, 3},
		{"credentialed only", credentialed, 2},
	}
	for _, w := range want {
		if got := discoveryFactor(w.in).Score; got != w.score {
			t.Errorf("%s: discovery got %d, want %d", w.name, got, w.score)
		}
	}

	// Same vuln, same asset: scanner-findable must score higher overall.
	base := func(in Input) Input {
		in.CVE.CVSSVectors = []schema.CVSSVector{{Version: "3.1", Score: 8.1}}
		in.Asset = &schema.Asset{Criticality: schema.CriticalityHigh, Exposure: schema.ExposureInternet}
		in.Now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		return in
	}
	hi := Compute(base(nuclei), DefaultConfig()).RiskModel
	lo := Compute(base(Input{CVE: &schema.CVE{ID: "CVE-2099-0001"},
		Exploitation: schema.ExploitationEvidence{AttackerDiscoverabilityTier: "credentialed_only"}}), DefaultConfig()).RiskModel
	if hi.Likelihood <= lo.Likelihood || hi.Score <= lo.Score {
		t.Errorf("scanner-findable should outrank credentialed-only: %.2f/%.2f vs %.2f/%.2f",
			hi.Likelihood, hi.Score, lo.Likelihood, lo.Score)
	}
}

// TestRiskModel_KEVMetasploitCompanyHosted: a KEV-listed critical RCE with a
// Metasploit module on company-owned internet-facing infrastructure.
func TestRiskModel_KEVMetasploitCompanyHosted(t *testing.T) {
	in := Input{
		CVE: &schema.CVE{ID: "CVE-2099-0002", NucleiTemplate: "x.yaml",
			CVSSVectors: []schema.CVSSVector{{Version: "3.1", Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
		Asset: &schema.Asset{
			Criticality: schema.CriticalityCritical,
			Exposure:    schema.ExposureInternet,
			Signals:     schema.AssetSignals{Extra: map[string]string{"hosting_type": "owned"}},
		},
		Exploitation: schema.ExploitationEvidence{InKEVSources: []string{"cisa_kev"}, MetasploitAvailable: true},
	}
	rm := Compute(in, DefaultConfig()).RiskModel
	f := rm.Factors
	if f.BusinessImpact.Score != 4 || f.NetworkLocation.Score != 4 || f.VulnerabilitySeverity.Score != 4 {
		t.Errorf("impact factors: %+v", f)
	}
	// Version match only: the Metasploit module is not yet shown to work
	// on this asset, so Ease of Exploit is held at 3 pending verification.
	if f.SkillLevel.Score != 4 || f.EaseOfDiscovery.Score != 4 || f.EaseOfExploit.Score != 3 || f.Awareness.Score != 4 {
		t.Errorf("likelihood factors: %+v", f)
	}
	if rm.Realism == nil || rm.Realism.Tier != schema.RealismUnverified {
		t.Errorf("realism: got %+v, want unverified", rm.Realism)
	}
	if rm.Level != schema.PriorityCritical {
		t.Errorf("level: got %s (%.2f), want critical", rm.Level, rm.Score)
	}
}

func TestRiskModel_NetworkLocationHosting(t *testing.T) {
	asset := func(exp schema.Exposure, hosting string) *schema.Asset {
		return &schema.Asset{Exposure: exp, Signals: schema.AssetSignals{Extra: map[string]string{"hosting_type": hosting}}}
	}
	cases := []struct {
		a    *schema.Asset
		want int
	}{
		{asset(schema.ExposureInternet, "owned"), 4},
		{asset(schema.ExposureInternet, "cloud"), 2},
		{asset(schema.ExposureInternet, "third_party"), 2},
		{asset(schema.ExposureInternet, ""), 4},
		{asset(schema.ExposureInternal, "owned"), 1},
		{asset(schema.ExposureIsolated, ""), 0},
	}
	for _, c := range cases {
		if got := networkLocationFactor(c.a).Score; got != c.want {
			t.Errorf("%s/%s: got %d, want %d", c.a.Exposure, c.a.Signals.Extra["hosting_type"], got, c.want)
		}
	}
}

// TestRiskModel_PracticalityCappedByMultiStagePath: a public exploit that
// needs a foothold first is not "easy" in the real world.
func TestRiskModel_PracticalityCappedByMultiStagePath(t *testing.T) {
	in := Input{
		CVE:          &schema.CVE{ID: "CVE-2099-0003"},
		Intrinsic:    &schema.IntrinsicAnalysis{AttackPathClass: schema.AttackPathLateralMovementRequired},
		Exploitation: schema.ExploitationEvidence{MetasploitAvailable: true},
	}
	if got := easeOfExploitFactor(in, exploitRealism(in)).Score; got != 2 {
		t.Errorf("ease of exploit: got %d, want 2 (multi-stage)", got)
	}
}

// TestRiskModel_SkillLevelFollowsExploitDifficulty: skill level reflects how
// hard the flaw is to exploit (OWASP threat-agent skill), lowered by exploit tooling.
func TestRiskModel_SkillLevelFollowsExploitDifficulty(t *testing.T) {
	withVector := func(v string) Input {
		return Input{CVE: &schema.CVE{ID: "CVE-2099-0004", CVSSVectors: []schema.CVSSVector{{Version: "3.1", Score: 8.0, Vector: v}}}}
	}
	intrinsic := func(capability schema.AttackerCapability, cx schema.ExploitComplexity, v string) Input {
		in := withVector(v)
		in.Intrinsic = &schema.IntrinsicAnalysis{AttackerCapability: capability, ExploitComplexity: cx}
		in.Intrinsic.CVSSReconciliation.CorrectVector = v
		return in
	}
	cases := []struct {
		name string
		in   Input
		want int
	}{
		{"unauth, AC:L, low complexity", intrinsic(schema.AttackerUnauthenticatedNetwork, schema.ComplexityLow, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 4},
		{"PR:N, AC:L from CVE vector", withVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 4},
		{"PR:L, AC:L", withVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 3},
		{"PR:N, AC:H", withVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"), 3},
		{"PR:H, AC:H, UI:R", withVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"), 1},
		{"code execution + high complexity", intrinsic(schema.AttackerCodeExecution, schema.ComplexityHigh, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"), 1},
	}
	for _, c := range cases {
		if got := skillLevelFactor(c.in, nil); got.Score != c.want {
			t.Errorf("%s: got %d (%s), want %d", c.name, got.Score, got.Reason, c.want)
		}
	}

	// Tooling lowers the skill bar: the same hard flaw with a Metasploit
	// module needs no technical skill, a public PoC only moderate skill.
	hard := withVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H")
	if got := skillLevelFactor(hard, nil).Score; got != 1 {
		t.Errorf("hard flaw without tooling: got %d, want 1", got)
	}
	armed := withVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H")
	armed.Exploitation.MetasploitAvailable = true
	if got := skillLevelFactor(armed, nil).Score; got != 4 {
		t.Errorf("hard flaw with Metasploit: got %d, want 4", got)
	}
	poc := withVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H")
	poc.Exploitation.PublicPOCFound = true
	if got := skillLevelFactor(poc, nil).Score; got != 2 {
		t.Errorf("hard flaw with PoC: got %d, want 2", got)
	}
	// Tooling never lowers the score of an already-easy flaw.
	easy := withVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	easy.Exploitation.PublicPOCFound = true
	if got := skillLevelFactor(easy, nil).Score; got != 4 {
		t.Errorf("easy flaw with PoC: got %d, want 4", got)
	}
	// Tooling can't remove a code-execution prerequisite.
	foothold := intrinsic(schema.AttackerCodeExecution, schema.ComplexityHigh, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H")
	foothold.Exploitation.MetasploitAvailable = true
	if got := skillLevelFactor(foothold, nil).Score; got != 2 {
		t.Errorf("code-exec prerequisite with Metasploit: got %d, want 2", got)
	}

	// A well-documented class never requires specialist skill.
	sqli := withVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
	sqli.CWEID = "CWE-89"
	if got := skillLevelFactor(sqli, nil).Score; got != 2 {
		t.Errorf("SQLi floor: got %d, want 2", got)
	}
}

func kevMetasploitInput() Input {
	return Input{
		CVE: &schema.CVE{ID: "CVE-2099-0005", CVSSVectors: []schema.CVSSVector{{Version: "3.1", Score: 9.8,
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, NucleiTemplate: "x.yaml"},
		Asset: &schema.Asset{Criticality: schema.CriticalityHigh, Exposure: schema.ExposureInternet},
		Exploitation: schema.ExploitationEvidence{
			InKEVSources: []string{"cisa_kev"}, MetasploitAvailable: true,
		},
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestRiskModel_ExploitRealism: a famous, weaponized exploit is only as
// likely as the evidence says it can work on this asset.
func TestRiskModel_ExploitRealism(t *testing.T) {
	blocker := func(status schema.PreconditionStatus) schema.PreconditionEvalSet {
		return schema.PreconditionEvalSet{{
			Precondition: schema.Precondition{ID: "mod_enabled", Description: "vulnerable module enabled", Severity: schema.PreconditionBlocker},
			Status:       status,
		}}
	}

	confirmed := kevMetasploitInput()
	confirmed.DetectionConfidence = schema.ExploitConfirmed

	likely := kevMetasploitInput()
	likely.DetectionConfidence = schema.EndpointConfirmed
	likely.Preconditions = blocker(schema.PreconditionSatisfied)

	unverified := kevMetasploitInput()
	unverified.DetectionConfidence = schema.VersionOnly

	conditional := kevMetasploitInput()
	conditional.Intrinsic = &schema.IntrinsicAnalysis{AttackPathClass: schema.AttackPathLateralMovementRequired}

	blocked := kevMetasploitInput()
	blocked.Preconditions = blocker(schema.PreconditionUnsatisfied)

	cases := []struct {
		name      string
		in        Input
		tier      string
		ease      int
		maxLikely float64
	}{
		{"confirmed", confirmed, schema.RealismConfirmed, 4, 4},
		{"likely", likely, schema.RealismLikely, 4, 4},
		{"unverified", unverified, schema.RealismUnverified, 3, 4},
		{"conditional", conditional, schema.RealismConditional, 2, 2.0},
		{"blocked", blocked, schema.RealismBlocked, 0, 0},
	}
	prev := 101.0
	for _, c := range cases {
		rm := Compute(c.in, DefaultConfig()).RiskModel
		if rm.Realism == nil || rm.Realism.Tier != c.tier {
			t.Errorf("%s: realism got %+v, want %s", c.name, rm.Realism, c.tier)
			continue
		}
		if rm.Factors.EaseOfExploit.Score != c.ease {
			t.Errorf("%s: ease of exploit got %d, want %d", c.name, rm.Factors.EaseOfExploit.Score, c.ease)
		}
		if rm.Likelihood > c.maxLikely {
			t.Errorf("%s: likelihood %.2f above cap %.2f", c.name, rm.Likelihood, c.maxLikely)
		}
		if rm.Score > prev {
			t.Errorf("%s: risk %.2f should not exceed the more realistic tier above it (%.2f)", c.name, rm.Score, prev)
		}
		prev = rm.Score
		t.Logf("%-11s risk %5.2f %-8s likelihood %.2f (uncapped %.2f) ease %d skill %d",
			c.name, rm.Score, rm.Level, rm.Likelihood, rm.LikelihoodUncapped, rm.Factors.EaseOfExploit.Score, rm.Factors.SkillLevel.Score)
	}

	// Blocked: a KEV + Metasploit bug has no likelihood on this asset
	// when its required condition is absent.
	if rm := Compute(blocked, DefaultConfig()).RiskModel; rm.Score != 0 || rm.Level != schema.PriorityInformational {
		t.Errorf("blocked KEV+Metasploit: got %.2f %s, want 0 informational", rm.Score, rm.Level)
	}
}

// TestRiskModel_RealismControlsInFront: auth or a WAF in front of an
// unauthenticated exploit makes it conditional, not direct.
func TestRiskModel_RealismControlsInFront(t *testing.T) {
	yes := true
	in := kevMetasploitInput()
	in.Intrinsic = &schema.IntrinsicAnalysis{AttackerCapability: schema.AttackerUnauthenticatedNetwork}
	in.Asset.Signals.Auth = &schema.AuthSignals{Required: &yes}
	if r := exploitRealism(in); r.Tier != schema.RealismConditional {
		t.Errorf("auth in front: got %s, want conditional", r.Tier)
	}
	in.Asset.Signals.Auth = nil
	in.Asset.Signals.Network = &schema.NetworkSignals{WAF: "cloudflare"}
	if r := exploitRealism(in); r.Tier != schema.RealismConditional {
		t.Errorf("WAF in front: got %s, want conditional", r.Tier)
	}
}

// TestRiskModel_NeedsAnalyst: factors scored on a default (no asset
// criticality, no hosting classification, no CVSS) are flagged for triage.
func TestRiskModel_NeedsAnalyst(t *testing.T) {
	in := Input{
		CVE:   &schema.CVE{ID: "CVE-2099-0006"},
		Asset: &schema.Asset{Exposure: schema.ExposureInternet},
	}
	rm := Compute(in, DefaultConfig()).RiskModel
	want := map[string]bool{"business_impact": true, "network_location": true, "vulnerability_severity": true, "skill_level": true}
	got := map[string]bool{}
	for _, k := range rm.NeedsAnalyst {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected %s in needs_analyst, got %v", k, rm.NeedsAnalyst)
		}
	}
	if rm.Factors.BusinessImpact.Source != schema.FactorAssumed {
		t.Errorf("business impact source: got %q", rm.Factors.BusinessImpact.Source)
	}

	// Fully evidenced input: nothing to fill in for the impact side.
	full := kevMetasploitInput()
	full.Asset.Criticality = schema.CriticalityCritical
	full.Asset.Signals.Extra = map[string]string{"hosting_type": "owned"}
	rm = Compute(full, DefaultConfig()).RiskModel
	for _, k := range rm.NeedsAnalyst {
		if k == "business_impact" || k == "network_location" || k == "vulnerability_severity" {
			t.Errorf("%s flagged despite evidence", k)
		}
	}
	if rm.Factors.VulnerabilitySeverity.Source != schema.FactorAuto {
		t.Errorf("severity source: got %q, want auto", rm.Factors.VulnerabilitySeverity.Source)
	}
}
