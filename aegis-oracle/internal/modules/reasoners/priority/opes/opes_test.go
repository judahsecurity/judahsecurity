package opes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// TestOPES_CVE_2025_55130_TenantContainer reproduces the analyst's
// reference reasoning. Missing local evidence must lower confidence without
// artificially lowering the score or producing a safety claim.
//
// See knowledgebase/patterns/nodejs.permissions-symlink-escape.yaml for
// the canonical preconditions used here.
func TestOPES_CVE_2025_55130_TenantContainer(t *testing.T) {
	in := cve202555130Input()
	score := Compute(in, DefaultConfig())

	if score.Category != schema.PriorityMedium {
		t.Errorf("category: got %s, want %s", score.Category, schema.PriorityMedium)
	}
	if score.Value < 3.5 || score.Value > 5.5 {
		t.Errorf("score: got %.2f, want 3.5..5.5 (Low territory)", score.Value)
	}
	if score.Confidence != schema.ConfidenceLow {
		t.Errorf("confidence: got %s, want low (unknown blockers)", score.Confidence)
	}
	if score.Override != "" {
		t.Errorf("override: got %q, want empty (no override should fire)", score.Override)
	}
	if score.Components.R == 0 {
		t.Errorf("R should be > 0 (asset is reachable, exploit is local)")
	}
	if score.Components.X >= 9.0 {
		t.Errorf("X should be < 9.0 (not in KEV)")
	}
	if score.EvaluatorVersion != Version {
		t.Errorf("evaluator version: got %q, want %q", score.EvaluatorVersion, Version)
	}

	t.Logf("OPES = %.2f / %s (%s)", score.Value, score.Category, score.Label)
	t.Logf("Components: %+v", score.Components)
	for _, c := range score.TopContributors {
		t.Logf("  - %s", c)
	}
	if score.Dampener != "" {
		t.Logf("Dampener: %s", score.Dampener)
	}

	// Pretty-print so devs can eyeball the structure.
	if testing.Verbose() {
		out, _ := json.MarshalIndent(score, "", "  ")
		t.Logf("\n%s", out)
	}
}

// TestOPES_CVE_2025_55130_PermissionsNotInUse demonstrates the
// path-scoped behavior. A failed documented condition reduces P, but cannot
// make a universal claim that every exploit path is impossible.
func TestOPES_CVE_2025_55130_PermissionsNotInUse(t *testing.T) {
	in := cve202555130Input()
	for i, e := range in.Preconditions {
		if e.Precondition.ID == "node-permissions-active" {
			in.Preconditions[i].Status = schema.PreconditionUnsatisfied
			in.Preconditions[i].Reason = "Container startup args do not include --experimental-permissions"
		}
	}

	score := Compute(in, DefaultConfig())

	if score.Value == 0.0 {
		t.Errorf("score: got %.2f, missing path must not force zero", score.Value)
	}
	if score.Override != "" {
		t.Errorf("override: got %q, want empty", score.Override)
	}
	if strings.Contains(strings.ToLower(score.Label), "not exploitable") {
		t.Errorf("label must not make universal safety claim: %q", score.Label)
	}
}

// TestOPES_CVE_2025_55130_KEVListed proves the KEV floor. If CISA
// catalogs the CVE as actively exploited, OPES floors at Critical regardless
// of unknown preconditions — verification becomes urgent rather than
// optional.
func TestOPES_CVE_2025_55130_KEVListed(t *testing.T) {
	in := cve202555130Input()
	in.Exploitation.InKEVSources = []string{"cisa_kev"}
	in.Exploitation.RecentPOCDays = 5

	score := Compute(in, DefaultConfig())

	if score.Category != schema.PriorityCritical {
		t.Errorf("category: got %s, want critical (KEV floor)", score.Category)
	}
	if score.Value < 8.5 {
		t.Errorf("score: got %.2f, want >= 8.5 (KEV floor)", score.Value)
	}
	if score.Override != "kev_floor" {
		t.Errorf("override: got %q, want kev_floor", score.Override)
	}
	if score.Label != "Actively Exploited" {
		t.Errorf("label: got %q, want Actively Exploited", score.Label)
	}
}

// TestOPES_AllPreconditionsSatisfied verifies that resolving all
// blocker preconditions in the satisfied direction (worst case) raises
// the score above the unknown-blocker cap.
func TestOPES_AllPreconditionsSatisfied(t *testing.T) {
	in := cve202555130Input()
	for i := range in.Preconditions {
		in.Preconditions[i].Status = schema.PreconditionSatisfied
		in.Preconditions[i].Reason = "Verified by container inspection"
	}

	score := Compute(in, DefaultConfig())

	if score.Value <= 5.5 {
		t.Errorf("score: got %.2f, want > 5.5 (cap removed)", score.Value)
	}
	if score.Dampener != "" {
		t.Errorf("dampener: got %q, want empty (no unknown blockers)", score.Dampener)
	}
}

// TestOPES_IsolatedAsset verifies isolation affects reachability without
// becoming a permanent "not reachable" override.
func TestOPES_IsolatedAsset(t *testing.T) {
	in := cve202555130Input()
	in.Asset.Exposure = schema.ExposureIsolated

	score := Compute(in, DefaultConfig())

	if score.Value == 0.0 {
		t.Errorf("score: got %.2f, isolation must not force zero", score.Value)
	}
	if score.Category != schema.PriorityLow {
		t.Errorf("category: got %s, want low (limited reachability evidence)", score.Category)
	}
	if score.Override != "" {
		t.Errorf("override: got %q, want empty", score.Override)
	}
}

// cve202555130Input builds the canonical input bundle representing the
// FTDS tenant-container scenario from the project's reference analysis.
//
// Don't change these values without updating the test expectations and
// the docs in README.md / the OPES walkthrough — this is the calibration
// fixture for the whole scoring system.
func cve202555130Input() Input {
	publishedAt := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	now := publishedAt.AddDate(0, 0, 18)
	authReq := true
	internet := true

	cve := &schema.CVE{
		ID:          "CVE-2025-55130",
		PublishedAt: publishedAt,
		ModifiedAt:  publishedAt.AddDate(0, 0, 5),
		Description: "Node.js permission model symlink escape — when --experimental-permissions is enabled with --allow-fs-* flags, an attacker with in-process JavaScript execution can craft symlink chains to read/write outside the allowed roots.",
		CWEs:        []string{"CWE-22", "CWE-59"},
		CVSSVectors: []schema.CVSSVector{
			{Source: "NVD", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 9.1},
			{Source: "HackerOne", Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 7.1},
			{Source: "vendor", Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 7.0},
		},
		POCCount:      1,
		PrimarySource: "cve.org",
	}

	intrinsic := &schema.IntrinsicAnalysis{
		CVEID:                "CVE-2025-55130",
		RemoteTriggerability: schema.TriggerNo,
		ExploitComplexity:    schema.ComplexityMedium,
		AttackerCapability:   schema.AttackerCodeExecution,
		Preconditions: []schema.Precondition{
			{
				ID:                 "node-permissions-active",
				Description:        "Node.js process started with --experimental-permissions (or --permissions) and --allow-fs-read/--allow-fs-write flags.",
				VerificationSignal: "runtime_flags.node",
				MatchKind:          "regex",
				MatchValue:         `(--experimental-permissions|--permissions).*--allow-fs-(read|write)`,
				VerificationMethod: "Inspect container startup args: docker inspect <container> | jq '.[0].Args' (or systemd unit ExecStart).",
				Severity:           schema.PreconditionBlocker,
			},
			{
				ID:                 "in-process-js-execution",
				Description:        "Attacker can execute arbitrary JavaScript inside the target Node.js process.",
				VerificationSignal: "tenant.runs_user_code",
				MatchKind:          "equals",
				MatchValue:         "true",
				VerificationMethod: "Determine if the workload exposes a JS sandbox, accepts uploaded user scripts, or has a known RCE foothold.",
				Severity:           schema.PreconditionBlocker,
			},
		},
		CVSSReconciliation: schema.CVSSReconciliation{
			CorrectVector:  "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CorrectScore:   7.1,
			CorrectVersion: "3.1",
			Rationale:      "Exploit requires code execution within the Node.js process to construct symlink chains. AV:N is incorrect because no network-reachable code path triggers the symlink walk; the attacker must already execute JavaScript in-process. Vendor and HackerOne agree on AV:L.",
			Disagreements: []schema.CVSSSourceDisagreement{
				{
					Source:       "NVD",
					TheirVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Disagreement: "AV:N implies network reach, but the documented attack requires in-process JS execution.",
				},
			},
		},
		AttackChainSummary: "Attacker with in-process JS execution constructs a symlink chain inside an allowed-fs path that resolves outside it; subsequent fs.readFileSync / writeFileSync calls bypass the permission model and access arbitrary files.",
		Confidence:         schema.ConfidenceHigh,
	}

	asset := &schema.Asset{
		ID:       "ftds-tenant-prod-7421",
		TenantID: "tenant-7421",
		Hostname: "tenant-7421.ftds.example.com",
		Signals: schema.AssetSignals{
			Network: &schema.NetworkSignals{InternetFacing: &internet},
			Auth:    &schema.AuthSignals{Required: &authReq, Method: "oauth2"},
			TechStack: []schema.TechComponent{
				{Name: "Node.js", Version: "24.10.0", Confidence: 1.0},
				{Name: "express", Version: "4.21.1", Confidence: 0.85},
			},
		},
		Criticality: schema.CriticalityHigh,
		Exposure:    schema.ExposureInternet,
		Source:      "asm-core-v2",
		UpdatedAt:   schema.NewFlexTime(now),
	}

	// Phase B output: both blockers Unknown — we can't read container
	// startup args or determine tenant code-execution policy from
	// external signals.
	preconditions := schema.PreconditionEvalSet{
		{
			Precondition: intrinsic.Preconditions[0],
			Status:       schema.PreconditionUnknown,
			Reason:       "asset signal `runtime_flags.node` not populated",
		},
		{
			Precondition: intrinsic.Preconditions[1],
			Status:       schema.PreconditionUnknown,
			Reason:       "asset signal `tenant.runs_user_code` not populated",
		},
	}

	return Input{
		CVE:           cve,
		Intrinsic:     intrinsic,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation: schema.ExploitationEvidence{
			RecentPOCDays: 18,
		},
		Now: now,
	}
}

// TestParseAVAC sanity-checks the CVSS vector parser used by the
// reachability and difficulty components.
func TestParseAVAC(t *testing.T) {
	cases := []struct {
		vector string
		av, ac string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N", "N", "L"},
		{"CVSS:3.1/AV:L/AC:H/PR:N", "L", "H"},
		{"AV:A/AC:L", "A", "L"},
		{"", "", ""},
	}
	for _, c := range cases {
		av, ac := parseAVAC(c.vector)
		if av != c.av || ac != c.ac {
			t.Errorf("parseAVAC(%q) = (%q,%q); want (%q,%q)",
				c.vector, av, ac, c.av, c.ac)
		}
	}
	// Make sure the canonical CVE-2025-55130 reconciled vector parses
	// correctly — this is what feeds the reachability score.
	v := "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
	av, _ := parseAVAC(v)
	if !strings.EqualFold(av, "L") {
		t.Errorf("CVE-2025-55130 reconciled vector should parse AV:L, got %q", av)
	}
}

func TestExploitationVulnCheckSignals(t *testing.T) {
	weaponizedInitialAccess := schema.ExploitationEvidence{
		VulnCheckWeaponized:   true,
		VulnCheckExploitTypes: []string{"initial-access"},
	}
	if got := exploitation(weaponizedInitialAccess); got < 8.5 {
		t.Fatalf("weaponized initial-access exploit score = %.1f; want >= 8.5", got)
	}

	ransomware := schema.ExploitationEvidence{
		VulnCheckRansomwareCount: 1,
	}
	if got := exploitation(ransomware); got < 9.0 {
		t.Fatalf("ransomware-associated VulnCheck score = %.1f; want >= 9.0", got)
	}
}
