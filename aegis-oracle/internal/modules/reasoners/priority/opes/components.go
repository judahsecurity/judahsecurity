package opes

import (
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// cweExploitCeiling returns the maximum difficulty (E) score allowed for a
// given CWE identifier. E contributes inversely to OPES, so a ceiling on E
// means we can never score a well-understood weakness class as "hard to
// exploit" regardless of other CVSS/attacker-capability signals.
//
// Values are calibrated against observed attack tool availability and
// analyst consensus on each weakness class:
//   - 1.0–2.0: trivial / push-button (hardcoded creds, missing auth)
//   - 2.5–3.5: easy, widely tooled (SQLi, path traversal, command injection)
//   - 4.0–5.0: moderate (SSRF, deserialization, race conditions)
//   - 10.0: no ceiling (unknown CWE — fall through to other signals)
func cweExploitCeiling(cweID string) float64 {
	switch strings.ToUpper(strings.TrimSpace(cweID)) {
	// Trivial — credential exposure or no auth required
	case "CWE-798": // Use of Hard-coded Credentials
		return 1.5
	case "CWE-259": // Use of Hard-coded Password
		return 1.5
	case "CWE-306": // Missing Authentication for Critical Function
		return 1.5
	case "CWE-288": // Auth Bypass Using Alternate Path
		return 2.0
	case "CWE-287": // Improper Authentication
		return 2.5
	case "CWE-284": // Improper Access Control (includes subdomain takeover)
		return 2.5

	// Easy — exposed sensitive data
	case "CWE-540": // Inclusion of Sensitive Information in Source Code
		return 2.0
	case "CWE-200": // Exposure of Sensitive Information to Unauthorized Actor
		return 2.5
	case "CWE-312": // Cleartext Storage of Sensitive Information
		return 2.5
	case "CWE-319": // Cleartext Transmission of Sensitive Information
		return 3.0

	// Easy — classic injection, widely tooled
	case "CWE-89": // SQL Injection
		return 3.0
	case "CWE-78": // OS Command Injection
		return 3.0
	case "CWE-77": // Command Injection (generic)
		return 3.0
	case "CWE-94": // Code Injection
		return 3.0
	case "CWE-79": // Cross-site Scripting (XSS)
		return 3.5
	case "CWE-22": // Path Traversal
		return 3.0
	case "CWE-23": // Relative Path Traversal
		return 3.0
	case "CWE-73": // External Control of File Name or Path
		return 3.5
	case "CWE-90": // LDAP Injection
		return 3.5
	case "CWE-91": // XML Injection
		return 3.5

	// Moderate — requires chaining or specific server-side conditions
	case "CWE-918": // Server-Side Request Forgery (SSRF)
		return 4.0
	case "CWE-611": // Improper Restriction of XML External Entity Reference (XXE)
		return 4.0
	case "CWE-502": // Deserialization of Untrusted Data
		return 4.5
	case "CWE-352": // Cross-Site Request Forgery (CSRF)
		return 4.0
	case "CWE-601": // Open Redirect
		return 4.0
	case "CWE-362": // Race Condition / Concurrent Execution
		return 4.5
	case "CWE-434": // Unrestricted Upload of Dangerous File Type
		return 3.5

	default:
		return 10.0 // no ceiling — rely entirely on other signals
	}
}

// difficulty (E) — how hard is the exploit in the abstract? Higher = harder.
//
// Inputs: reconciled CVSS AC + AT + UI, attacker capability, # of blocker
// preconditions, exploit complexity, presence of nuclei template, PoC
// availability, attack path class, and CWE weakness class ceiling.
//
// CVSS 4.0 introduces AT (Attack Requirements): AT:N means no special
// deployment conditions; AT:P means the attacker must prepare a specific
// condition (e.g., a specially-crafted file at a specific path). AT:P adds
// +1.0 difficulty — it does not block exploitation but raises the bar above
// a clean unauthenticated network attack.
//
// E contributes inversely (10-E) to the OPES sum, so harder exploits
// reduce the score.
func difficulty(in Input) float64 {
	if in.Intrinsic == nil {
		// When no intrinsic analysis is available, start from the CWE ceiling
		// (or 5.0 neutral) then apply detection confidence adjustment.
		// Non-CVE findings (Nuclei detections, port scan results) most commonly
		// land here, so detection confidence is especially impactful for them.
		base := 5.0
		if in.CWEID != "" {
			ceiling := cweExploitCeiling(in.CWEID)
			if ceiling < 10.0 {
				base = ceiling
			}
		}
		switch in.DetectionConfidence {
		case schema.ExploitConfirmed:
			base -= 2.0
		case schema.EndpointConfirmed:
			base -= 1.0
		case schema.VersionOnly:
			base += 1.5
		}
		return clamp(base, 0, 10)
	}
	base := 5.0

	_, ac := parseAVAC(in.Intrinsic.CVSSReconciliation.CorrectVector)
	switch ac {
	case "L":
		base = 4.0
	case "H":
		base = 7.0
	}

	// CVSS 4.0 AT (Attack Requirements) — applies on top of AC.
	// AT:P means the attacker must create or control a specific environmental
	// condition before exploitation (e.g., place a phar file at a loadable path,
	// enable a specific configuration, or pre-seed data). This is meaningfully
	// harder than AT:N (no requirements) and warrants a difficulty boost.
	if parseAT(in.Intrinsic.CVSSReconciliation.CorrectVector) == "P" {
		base += 1.0
	}

	// User interaction (UI) from CVSS — phishing-delivered exploits require
	// a human victim to trigger. This materially increases difficulty vs. an
	// automatable direct-service exploit.
	if parseUI(in.Intrinsic.CVSSReconciliation.CorrectVector) == "R" {
		base += 1.5
	}

	switch in.Intrinsic.AttackerCapability {
	case schema.AttackerUnauthenticatedNetwork:
		base -= 2.0
	case schema.AttackerAuthenticatedLowPriv:
		base -= 0.5
	case schema.AttackerAuthenticatedHighPriv:
		base += 1.0
	case schema.AttackerLocalUser:
		base += 1.5
	case schema.AttackerCodeExecution:
		base += 3.0
	case schema.AttackerPhysical:
		base += 4.0
	}

	// Attack path class adjustments. Phishing delivery gets partially captured
	// by UI:R above, but the path itself is also harder — email delivery,
	// victim selection, and AV/sandbox evasion all add operational complexity.
	// lateral_movement_required means the attacker needs an existing foothold
	// first, which is a meaningful prerequisite.
	switch in.Intrinsic.AttackPathClass {
	case schema.AttackPathPhishingDelivery:
		base += 1.0 // victim must open/click — not automatable at scanner scale
	case schema.AttackPathLateralMovementRequired:
		base += 1.5 // foothold required — attacker must have already breached the perimeter
	case schema.AttackPathValidCredentials:
		base += 2.0 // credential dependency is a high bar unless creds are widely compromised
	case schema.AttackPathExploitPublicFacing:
		base -= 0.5 // direct, automatable — easiest initial access class
	}

	blockers := 0
	for _, p := range in.Intrinsic.Preconditions {
		if p.Severity == schema.PreconditionBlocker {
			blockers++
		}
	}
	base += float64(blockers) * 0.5

	// Attacker discoverability — can an external, unauthenticated attacker
	// confirm this target is vulnerable using tools available on the internet?
	//
	// This supersedes the simple hasNucleiTemplate() fallback when the richer
	// discoverability analysis has run (i.e., AttackerDiscoverabilityTier is set).
	//
	// The critical design principle: Tenable credentialed or agent-based
	// detections are DEFENDER signals. They tell us we can find the vulnerability
	// with privileged access — but an external attacker cannot replicate a
	// credentialed Nessus scan. "Credentialed_only" actually means the attacker
	// faces higher recon uncertainty, so E increases slightly.
	discoverabilityApplied := false
	switch in.Exploitation.AttackerDiscoverabilityTier {
	case "mass_scanned":
		// OTX 20+ pulses confirms attacker community is actively deploying
		// tooling for this CVE at internet scale. Exploitation race is underway.
		base -= 2.5
		discoverabilityApplied = true
	case "remote_exploit":
		// Nuclei exploit/detect template or Tenable remote (no-auth) plugin.
		// An attacker running Nuclei or replicating a network Nessus check can
		// confirm the target is vulnerable without any credentials.
		base -= 1.5
		discoverabilityApplied = true
	case "version_detectable":
		// Only the vulnerable version is fingerprinted remotely (e.g., banner,
		// HTTP header, response content). Attacker knows the version is vulnerable
		// but must do additional work to confirm the feature is active.
		base -= 0.5
		discoverabilityApplied = true
	case "credentialed_only":
		// The only scanner detections require credentials or an agent.
		// A remote, unauthenticated attacker CANNOT replicate these checks.
		// Their recon burden is higher — they must guess or use other intel.
		base += 0.5
		discoverabilityApplied = true
	}

	// Fall back to the simple nuclei template check when discoverability
	// enrichment hasn't run yet (e.g., older records, offline analysis).
	if !discoverabilityApplied && hasNucleiTemplate(in) {
		base -= 1.5
	}

	if hasWeaponizedPOC(in) {
		base -= 1.0
	}

	switch in.Intrinsic.ExploitComplexity {
	case schema.ComplexityLow:
		base -= 0.5
	case schema.ComplexityHigh:
		base += 1.0
	}

	// Detection confidence — adjusts E based on how deeply the scanner
	// confirmed the vulnerable feature is actually reachable and triggerable.
	//
	// This models the attacker's remaining reconnaissance burden:
	//   ExploitConfirmed:  the vulnerable code path was definitively triggered;
	//                      the attacker's scout work is already done. E−2.0.
	//   EndpointConfirmed: the vulnerable feature/endpoint is live and accessible;
	//                      attacker skips feature-reachability recon. E−1.0.
	//   VersionOnly:       only the version string is known; attacker must still
	//                      confirm the feature is active and reachable. E+1.5.
	//   Unknown:           no adjustment.
	//
	// Applied before the CWE ceiling so that exploit-confirmed findings never
	// score higher than the CWE ceiling allows, even after the confidence boost.
	switch in.DetectionConfidence {
	case schema.ExploitConfirmed:
		base -= 2.0
	case schema.EndpointConfirmed:
		base -= 1.0
	case schema.VersionOnly:
		base += 1.5
	}

	// Apply CWE-class ceiling last: a well-understood weakness (e.g. SQLi,
	// hardcoded credentials) cannot be scored as genuinely hard to exploit
	// regardless of what CVSS or attacker-capability signals say.
	if in.CWEID != "" {
		ceiling := cweExploitCeiling(in.CWEID)
		if base > ceiling {
			base = ceiling
		}
	}

	return clamp(base, 0, 10)
}

// reachability (R) — can the relevant attacker class even reach this asset?
//
// Inputs: reconciled CVSS AV, asset exposure, attack path class, auth, WAF,
// network position signals.
//
// R == 0 short-circuits to "not exploitable" via the override in combine.go.
func reachability(in Input, _ Config) float64 {
	if in.Asset == nil {
		return 5.0
	}
	if in.Asset.Exposure == schema.ExposureIsolated {
		return 0.0
	}

	av, _ := parseAVAC(intrinsicVector(in))
	base := map[string]float64{
		"N": 10.0,
		"A": 7.0,
		"L": 3.0,
		"P": 1.0,
		"":  5.0,
	}[av]

	if in.Asset.Exposure == schema.ExposureInternal && av == "N" {
		base = 6.0
	}

	// Attack path class refines the base reachability:
	//
	// exploit_public_facing + internet-facing asset is the highest-risk
	// combination — attacker is one network hop away with no prerequisite.
	//
	// phishing_delivery reduces R because the attack is not directly
	// reachable from the internet — an attacker must go through a human
	// intermediary. However, once a phishing victim is on the network,
	// reachability to internal targets can be high.
	//
	// lateral_movement_required: the asset is only reachable after an
	// attacker has already compromised another host. R is NOT zero — an
	// attacker with a foothold can reach internal services — but we reduce
	// it to reflect the prerequisite foothold. Edge nodes and pivot points
	// partially restore R because they are frequently used as stepping stones.
	if in.Intrinsic != nil {
		switch in.Intrinsic.AttackPathClass {
		case schema.AttackPathExploitPublicFacing:
			if in.Asset.Exposure == schema.ExposureInternet {
				base = min(base+1.5, 10.0) // direct, automatable — highest-risk combination
			}
		case schema.AttackPathPhishingDelivery:
			base *= 0.75 // victim-mediated; not directly automatable at scanner scale
		case schema.AttackPathLateralMovementRequired:
			if in.Asset.Exposure == schema.ExposureInternet {
				// An internet-facing asset that requires lateral movement is
				// unusual; treat as internal for scoring purposes.
				base = 6.0
			}
			// Edge/pivot assets are natural lateral movement targets — partially
			// restore reachability for assets explicitly in that role.
			if in.Asset.Signals.NetworkPosition != nil {
				if in.Asset.Signals.NetworkPosition.IsPivotPoint != nil && *in.Asset.Signals.NetworkPosition.IsPivotPoint {
					base = min(base+1.5, 10.0)
				} else if in.Asset.Signals.NetworkPosition.IsEdgeNode != nil && *in.Asset.Signals.NetworkPosition.IsEdgeNode {
					base = min(base+1.0, 10.0)
				}
			}
		}
	}

	// Auth penalty applies only when the attacker is supposed to come in
	// over the network unauthenticated. For local/code-execution exploits,
	// the asset's HTTP auth doesn't gate anything.
	if in.Asset.Signals.Auth != nil &&
		in.Asset.Signals.Auth.Required != nil && *in.Asset.Signals.Auth.Required &&
		in.Intrinsic != nil &&
		in.Intrinsic.AttackerCapability == schema.AttackerUnauthenticatedNetwork {
		base *= 0.6
	}

	// WAF penalty for unauthenticated network attacks.
	if in.Asset.Signals.Network != nil && in.Asset.Signals.Network.WAF != "" {
		if in.Intrinsic != nil &&
			in.Intrinsic.AttackerCapability == schema.AttackerUnauthenticatedNetwork {
			base *= 0.7
		}
	}

	return clamp(base, 0, 10)
}

// preconditionScore (P) — fraction of preconditions actually satisfied.
//
// Per-evaluation values: Satisfied=10, Unknown=5 (neutral, signals no
// information), Unsatisfied=2 (contradicts one documented condition).
// Average across all preconditions, weighted equally.
//
// The Unknown=5 value is intentional: we don't penalize for not yet
// knowing. Missing evidence lowers confidence, not the score.
func preconditionScore(set schema.PreconditionEvalSet) float64 {
	if len(set) == 0 {
		return 5.0
	}
	total := 0.0
	for _, e := range set {
		var v float64
		switch e.Status {
		case schema.PreconditionSatisfied:
			v = 10.0
		case schema.PreconditionUnknown:
			v = 5.0
		case schema.PreconditionUnsatisfied:
			v = 2.0
		}
		total += v
	}
	return clamp(total/float64(len(set)), 0, 10)
}

// exploitation (X) — is this CVE being exploited in the wild right now?
//
// Scoring hierarchy (highest wins, applied independently then max taken):
//
//	FIRE confirmed (insurance loss data)    → 9.5  (financially motivated, real loss)
//	CISA KEV or ransomware-associated       → 9.5  (KEV-floor Critical trigger)
//	VulnCheck KEV or ENISA EUVD KEV         → 9.0
//	VCDB / Mandiant M-Trends breach         → 9.0  (breach-investigation confirmed)
//	CrowdStrike GTR active adversary        → 9.0  (tracked adversary exploitation)
//	VulnCheck reported exploited            → 8.5
//	VulnCheck weaponized exploit            → 8.0
//	Observation feeds (inthewild.io, etc.)  → 8.0
//	Google Project Zero pre-patch 0day      → 8.5
//	AttackerKB attacker_value = 5           → 7.5
//	AttackerKB attacker_value = 4           → 7.0
//	AttackerKB attacker_value = 3           → 5.5
//	Recent PoC (≤30 days)                  → 3.0
//
// X ≥ KEVFloorThreshold (default 9.0) triggers the KEV floor override:
// the finding lands at Critical regardless of other components.
func exploitation(e schema.ExploitationEvidence) float64 {
	score := 0.0

	// Misconfig breach intelligence — non-CVE findings (exposed services,
	// misconfigurations, Nuclei template detections). Set by the generic
	// finding classifier using historical breach data (VCDB, M-Trends, etc.).
	// Applied first because for non-CVE findings this may be the only X signal.
	if e.MisconfigBreachRisk > 0 {
		score = max(score, e.MisconfigBreachRisk)
	}

	// FIRE — CVE linked to a confirmed financial loss via insurance carrier data.
	// Ties with CISA KEV at the top tier: these are the vulnerabilities that
	// have actually been weaponized by financially-motivated actors and caused
	// documented real-world losses. Per cvedata.com analysis, FIRE CVEs are
	// often missed by KEV lists and have unpredictable EPSS scores — they are
	// a distinct, complementary signal.
	if e.FireLinked {
		score = max(score, 9.5)
	}

	// KEV source signals.
	for _, src := range e.InKEVSources {
		switch src {
		case "cisa_kev":
			score = max(score, 9.5)
		case "vulncheck_kev":
			score = max(score, 9.0)
		case "enisa_euvd_kev":
			score = max(score, 9.0)
		}
	}

	// Ransomware association — treat equivalent to CISA KEV.
	if e.RansomwareAssociated {
		score = max(score, 9.5)
	}

	// VCDB breach confirmation — CVE caused a real, documented breach.
	if e.BreachConfirmed {
		score = max(score, 9.0)
	}

	// Mandiant M-Trends — CVE seen in breach investigations by Mandiant
	// incident responders. This is breach-confirmed evidence at the same
	// quality tier as VCDB.
	if e.MandiantMTrends {
		score = max(score, 9.0)
	}

	// CrowdStrike GTR — CVE tracked by CrowdStrike Falcon Intelligence as
	// actively exploited by named adversary groups during the GTR report year.
	if e.CrowdStrikeGTR {
		score = max(score, 9.0)
	}

	// ENISA EUVD direct exploitation flag (also sets InKEVSources above,
	// but guard here in case Apply wasn't called).
	if e.ENISAExploited {
		score = max(score, 9.0)
	}

	// In-the-wild observation feeds.
	if len(e.ObservationSources) > 0 {
		score = max(score, 8.0)
	}

	// VulnCheck exploit intelligence: observed exploitation and validated
	// weaponization evidence should carry more weight than probability-only
	// signals such as EPSS.
	if e.VulnCheckReportedExploited {
		score = max(score, 8.5)
	}
	if e.VulnCheckWeaponized {
		boost := 8.0
		for _, typ := range e.VulnCheckExploitTypes {
			if typ == "initial-access" || typ == "initial access" {
				boost = 8.5
				break
			}
		}
		score = max(score, boost)
	}
	if e.VulnCheckThreatActorCount > 0 {
		score = max(score, 8.0)
	}
	if e.VulnCheckRansomwareCount > 0 || e.VulnCheckBotnetCount > 0 {
		score = max(score, 9.0)
	}
	if e.VulnCheckPublicExploit && e.VulnCheckExploitCount > 0 {
		score = max(score, 4.0)
	}

	// Google Project Zero — exploited before a patch existed.
	if e.ZeroDayConfirmed {
		score = max(score, 8.5)
	}

	// AttackerKB community practitioner value (0–5 scale).
	switch {
	case e.AttackerKBValue >= 5:
		score = max(score, 7.5)
	case e.AttackerKBValue >= 4:
		score = max(score, 7.0)
	case e.AttackerKBValue >= 3:
		score = max(score, 5.5)
	}

	// Metasploit exploit module — reliable, GUI-accessible weaponized exploit.
	// This is a stronger signal than a raw PoC; Metasploit lowers the skill
	// bar for attackers to near-zero. Score above AttackerKB.
	if e.MetasploitAvailable {
		modBoost := 8.0
		if e.MetasploitModCount >= 2 {
			modBoost = 8.5 // multiple modules = several attack surfaces weaponized
		}
		score = max(score, modBoost)
	}

	// CISA SSVC "Immediate" means CISA independently assessed the issue as
	// requiring emergency patching — treat equivalently to KEV-adjacent.
	switch e.CISASSVCDecision {
	case "Immediate":
		score = max(score, 9.0)
	case "Out-of-Cycle":
		score = max(score, 7.0)
	case "Scheduled":
		score = max(score, 3.5)
	}

	// Public PoC repos (e.g. nomi-sec/PoC-in-GitHub) — weaker than weaponized
	// modules or KEV, but confirms exploit/PoC code is circulating.
	if e.PublicPOCFound {
		score = max(score, 2.0)
	}
	// Recent public PoC — still weak, but fresher PoCs raise urgency slightly.
	if e.RecentPOCDays > 0 && e.RecentPOCDays <= 30 {
		score = max(score, 3.0)
	}

	return clamp(score, 0, 10)
}

// criticality (C) — blast radius if compromised.
//
// Base score sourced from the asset's Criticality classification, then
// boosted by:
//   - LateralMovementPotential from the intrinsic analysis (what does
//     exploiting this CVE enable an attacker to do next?)
//   - NetworkPosition signals (is this a credential store / pivot point
//     that amplifies the blast radius beyond its own classification?)
func criticality(a *schema.Asset, intrinsic *schema.IntrinsicAnalysis) float64 {
	if a == nil {
		return 5.0
	}
	base := map[schema.Criticality]float64{
		schema.CriticalityCritical: 9.5,
		schema.CriticalityHigh:     7.5,
		schema.CriticalityMedium:   5.0,
		schema.CriticalityLow:      2.5,
	}
	score, ok := base[a.Criticality]
	if !ok {
		score = 5.0
	}

	// Lateral movement potential from the CVE's intrinsic analysis.
	// High potential means exploiting this vulnerability hands the attacker
	// keys to move through the network — credential theft, domain controller
	// access, secrets manager — materially increasing the actual blast radius.
	if intrinsic != nil {
		switch intrinsic.LateralMovementPotential {
		case schema.LateralMovementHigh:
			score = min(score+2.0, 10.0)
		case schema.LateralMovementMedium:
			score = min(score+0.75, 10.0)
		}
	}

	// Network position signals from the asset. A credential store or pivot
	// point is worth more to an attacker than its Criticality label alone
	// implies — compromising it unlocks access to other assets.
	if np := a.Signals.NetworkPosition; np != nil {
		if np.IsCredentialStore != nil && *np.IsCredentialStore {
			score = min(score+2.5, 10.0) // keys to the kingdom
		}
		if np.IsPivotPoint != nil && *np.IsPivotPoint {
			score = min(score+1.5, 10.0) // gateway to otherwise-isolated segments
		}
		if np.IsEdgeNode != nil && *np.IsEdgeNode {
			score = min(score+0.75, 10.0) // perimeter position amplifies initial access value
		}
	}

	return clamp(score, 0, 10)
}

// timePressure (T) — how urgent is action, given disclosure age and severity?
//
// Age is the primary driver: newer CVEs have a window before widespread
// exploitation tooling matures. CVSS score modulates the initial urgency
// peak — a Critical (≥9.0) recently published vulnerability is more urgent
// than a Low-severity one published on the same day, because attackers race
// to weaponize critical issues first.
//
// EPSS is intentionally excluded from T. It is a probabilistic estimate;
// T should reflect structural urgency (how long has the attack surface
// been exposed?), not a probability guess.
func timePressure(in Input, now time.Time) float64 {
	if in.CVE == nil || in.CVE.PublishedAt.IsZero() {
		return 5.0
	}
	days := int(now.Sub(in.CVE.PublishedAt).Hours() / 24)

	// Base urgency by age.
	var base float64
	switch {
	case days < 7:
		base = 7.0
	case days < 30:
		base = 5.0
	case days < 90:
		base = 4.0
	default:
		base = 3.0
	}

	// CVSS severity modifier for freshly disclosed CVEs (< 30 days).
	// Critical severity races to weaponization faster than lower-severity
	// issues — attackers and red teams prioritise high-impact new disclosures.
	cvss := maxCVSSScore(in.CVE)
	if days < 30 && cvss >= 9.0 {
		base = min(base+1.0, 10.0)
	} else if days < 30 && cvss >= 7.0 {
		base = min(base+0.5, 10.0)
	}

	return clamp(base, 0, 10)
}

func parseAVAC(vector string) (av, ac string) {
	for _, p := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		switch k {
		case "AV":
			av = v
		case "AC":
			ac = v
		}
	}
	return
}

// parseUI returns the UI (User Interaction) field from a CVSS vector string.
// Returns "N" (none) or "R" (required). Empty string if not present.
func parseUI(vector string) string {
	for _, p := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		if k == "UI" {
			return v
		}
	}
	return ""
}

// parseAT returns the AT (Attack Requirements) field from a CVSS 4.0 vector.
// Returns "N" (none — no special deployment conditions required) or
// "P" (present — attacker must prepare a specific environmental condition).
// Returns empty string for CVSS 3.x vectors (field not present).
//
// AT is a CVSS 4.0-only field that is more granular than 3.x Attack Complexity:
//   - AC:L in CVSS 4.0 means no special attacker skill/tooling required
//   - AT:P means the target environment must have a specific condition present
//     (e.g., user-controlled file path available, specific module loaded)
//
// These two axes are independent: a CVE can be AC:L + AT:P (low skill, but
// the environment must be prepared — like a phar wrapper file read bypass).
func parseAT(vector string) string {
	for _, p := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		if k == "AT" {
			return v
		}
	}
	return ""
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func intrinsicVector(in Input) string {
	if in.Intrinsic == nil {
		return ""
	}
	return in.Intrinsic.CVSSReconciliation.CorrectVector
}

// maxCVSSScore returns the highest CVSS base score across all vectors for a CVE.
// Prefers CVSS 4.0 vectors over 3.x when both are present (4.0 is more precise),
// but falls back to the global max if no 4.0 vector is available.
func maxCVSSScore(cve *schema.CVE) float64 {
	if cve == nil || len(cve.CVSSVectors) == 0 {
		return 0
	}
	var best4, bestAny float64
	for _, v := range cve.CVSSVectors {
		if v.Score > bestAny {
			bestAny = v.Score
		}
		if v.Version == "4.0" && v.Score > best4 {
			best4 = v.Score
		}
	}
	if best4 > 0 {
		return best4
	}
	return bestAny
}

func hasNucleiTemplate(in Input) bool {
	return in.CVE != nil && in.CVE.NucleiTemplate != ""
}

func hasWeaponizedPOC(in Input) bool {
	return in.CVE != nil && in.CVE.POCCount > 0
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
