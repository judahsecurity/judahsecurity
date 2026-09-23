package opes

import (
	"fmt"
	"math"
	"strings"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// RiskModelVersion identifies the factor mapping below. Bump on any change
// to how signals map to factor scores.
const RiskModelVersion = "risk/v6"

// riskModel maps the OPES inputs onto the seven-factor Likelihood × Impact
// model. Every factor is scored 0–4 (0 = none, 4 = highest), Impact and
// Likelihood are normalised to 0–1, and Risk = Impact × Likelihood is
// reported as 0–100, so no likelihood means no risk. Every factor carries a one-line reason so an analyst can see why a
// finding scored the way it did. It never changes the OPES value.
func riskModel(in Input, cfg RiskModelConfig) *schema.RiskModelScore {
	realism := exploitRealism(in)
	f := schema.RiskFactors{
		BusinessImpact:        businessImpactFactor(in.Asset),
		NetworkLocation:       networkLocationFactor(in.Asset),
		VulnerabilitySeverity: severityFactor(in),
		SkillLevel:            skillLevelFactor(in, realism),
		EaseOfDiscovery:       discoveryFactor(in),
		EaseOfExploit:         easeOfExploitFactor(in, realism),
		Awareness:             awarenessFactor(in),
	}
	rm := scoreRiskFactors(f, realism, cfg)
	rm.NeedsAnalyst = markSources(&rm.Factors)
	return rm
}

// markSources labels every factor not already marked assumed as measured
// from evidence, and returns the keys an analyst should fill in at triage
// because the data to score them automatically was missing.
func markSources(f *schema.RiskFactors) []string {
	var needs []string
	for _, e := range []struct {
		key string
		f   *schema.RiskFactor
	}{
		{"business_impact", &f.BusinessImpact},
		{"network_location", &f.NetworkLocation},
		{"vulnerability_severity", &f.VulnerabilitySeverity},
		{"skill_level", &f.SkillLevel},
		{"ease_of_discovery", &f.EaseOfDiscovery},
		{"ease_of_exploit", &f.EaseOfExploit},
		{"awareness", &f.Awareness},
	} {
		if e.f.Source == schema.FactorAssumed {
			needs = append(needs, e.key)
			continue
		}
		e.f.Source = schema.FactorAuto
	}
	return needs
}

// scoreRiskFactors is the pure arithmetic of the model, split out so the
// documented worked examples can be tested without building full inputs.
// realism may be nil (no likelihood cap).
func scoreRiskFactors(f schema.RiskFactors, realism *schema.ExploitRealism, cfg RiskModelConfig) *schema.RiskModelScore {
	impact := float64(f.BusinessImpact.Score)*cfg.BusinessImpactWeight +
		float64(f.NetworkLocation.Score)*cfg.NetworkLocationWeight +
		float64(f.VulnerabilitySeverity.Score)*cfg.VulnerabilitySeverityWeight
	uncapped := float64(f.SkillLevel.Score+f.EaseOfDiscovery.Score+f.EaseOfExploit.Score+f.Awareness.Score) / 4
	likelihood := uncapped
	if realism != nil {
		switch realism.Tier {
		case schema.RealismBlocked:
			likelihood = math.Min(likelihood, cfg.BlockedLikelihoodCap)
		case schema.RealismConditional:
			likelihood = math.Min(likelihood, cfg.ConditionalLikelihoodCap)
		}
	}
	// Both sides normalised to 0–1 (factors max out at 4), so Risk is the
	// fraction of worst case: 0 likelihood or 0 impact → 0 risk.
	risk := (impact / 4) * (likelihood / 4) * 100
	practicality := float64(f.SkillLevel.Score+f.EaseOfExploit.Score+f.Awareness.Score) / 3

	// Bands are squares: Critical ≥ 64 means Impact and Likelihood both
	// around 0.8, High ≥ 36 ≈ 0.6, Medium ≥ 16 ≈ 0.4, Low ≥ 4 ≈ 0.2.
	level := schema.PriorityInformational
	switch {
	case risk >= cfg.Critical:
		level = schema.PriorityCritical
	case risk >= cfg.High:
		level = schema.PriorityHigh
	case risk >= cfg.Medium:
		level = schema.PriorityMedium
	case risk >= cfg.Low:
		level = schema.PriorityLow
	}

	return &schema.RiskModelScore{
		Score:               round2(risk),
		Level:               level,
		Impact:              round2(impact),
		Likelihood:          round2(likelihood),
		Severity:            f.VulnerabilitySeverity.Score,
		Discoverability:     f.EaseOfDiscovery.Score,
		ExploitPracticality: round2(practicality),
		Realism:             realism,
		LikelihoodUncapped:  round2(uncapped),
		Factors:             f,
		Version:             RiskModelVersion,
	}
}

// ── Impact factors ───────────────────────────────────────────────────────────

func businessImpactFactor(a *schema.Asset) schema.RiskFactor {
	if a == nil {
		return schema.RiskFactor{Score: 2, Rating: "Medium", Source: schema.FactorAssumed, Reason: "No asset context; assumed standard business operations"}
	}
	switch a.Criticality {
	case schema.CriticalityCritical:
		return schema.RiskFactor{Score: 4, Rating: "Critical", Reason: "Asset classified critical (revenue or critical operations)"}
	case schema.CriticalityHigh:
		return schema.RiskFactor{Score: 3, Rating: "High", Reason: "Asset classified high (important business function)"}
	case schema.CriticalityLow:
		return schema.RiskFactor{Score: 1, Rating: "Low", Reason: "Asset classified low (minimal business disruption)"}
	case schema.CriticalityMedium:
		return schema.RiskFactor{Score: 2, Rating: "Medium", Reason: "Asset classified medium (standard business operations)"}
	}
	return schema.RiskFactor{Score: 2, Rating: "Medium", Source: schema.FactorAssumed, Reason: "Asset criticality not set; assumed medium"}
}

// networkLocationFactor distinguishes company-hosted from third-party-hosted
// internet exposure using the ASM's hosting_type (owned, cloud, cdn,
// third_party, unknown), which arrives in signals.extra.
func networkLocationFactor(a *schema.Asset) schema.RiskFactor {
	if a == nil {
		return schema.RiskFactor{Score: 2, Rating: "Unknown", Source: schema.FactorAssumed, Reason: "No asset context; exposure unknown"}
	}
	exposure := a.Exposure
	if exposure == "" || exposure == schema.ExposureUnknown {
		if n := a.Signals.Network; n != nil && n.InternetFacing != nil {
			if *n.InternetFacing {
				exposure = schema.ExposureInternet
			} else {
				exposure = schema.ExposureInternal
			}
		}
	}
	switch exposure {
	case schema.ExposureIsolated:
		return schema.RiskFactor{Score: 0, Rating: "Segmented Network", Reason: "Asset is isolated / air-gapped"}
	case schema.ExposureInternal:
		return schema.RiskFactor{Score: 1, Rating: "Internal Only", Reason: "Asset is not internet-facing"}
	case schema.ExposureInternet:
		hosting := strings.ToLower(strings.TrimSpace(a.Signals.Extra["hosting_type"]))
		switch hosting {
		case "cloud", "cdn", "third_party":
			provider := a.Signals.Extra["hosting_provider"]
			if provider == "" {
				provider = hosting
			}
			return schema.RiskFactor{Score: 2, Rating: "Third Party Hosted",
				Reason: fmt.Sprintf("Internet-facing on third-party infrastructure (%s)", provider)}
		case "owned":
			return schema.RiskFactor{Score: 4, Rating: "Company Hosted",
				Reason: "Internet-facing on company-owned infrastructure"}
		}
		return schema.RiskFactor{Score: 4, Rating: "Company Hosted",
			Source: schema.FactorAssumed, Reason: "Internet-facing; hosting not classified, assumed company-hosted"}
	}
	return schema.RiskFactor{Score: 2, Rating: "Unknown", Source: schema.FactorAssumed, Reason: "Exposure unknown"}
}

func severityFactor(in Input) schema.RiskFactor {
	cvss := maxCVSSScore(in.CVE)
	switch {
	case cvss >= 9.0:
		return schema.RiskFactor{Score: 4, Rating: "Critical", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss >= 7.0:
		return schema.RiskFactor{Score: 3, Rating: "High", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss >= 4.0:
		return schema.RiskFactor{Score: 2, Rating: "Medium", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss > 0:
		return schema.RiskFactor{Score: 1, Rating: "Low", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	}
	// No CVSS: non-CVE findings (misconfigurations, exposed services) are
	// rated by their breach-intelligence class instead.
	if r := in.Exploitation.MisconfigBreachRisk; r > 0 {
		class := in.Exploitation.MisconfigBreachClass
		if class == "" {
			class = "misconfiguration"
		}
		switch {
		case r >= 8.5:
			return schema.RiskFactor{Score: 4, Rating: "Critical", Reason: fmt.Sprintf("No CVSS; %s leads to full compromise in breach data", class)}
		case r >= 7.5:
			return schema.RiskFactor{Score: 3, Rating: "High", Reason: fmt.Sprintf("No CVSS; %s exposes significant data or access", class)}
		}
		return schema.RiskFactor{Score: 2, Rating: "Medium", Reason: fmt.Sprintf("No CVSS; %s has limited impact", class)}
	}
	return schema.RiskFactor{Score: 2, Rating: "Medium", Source: schema.FactorAssumed, Reason: "No CVSS score available; assumed medium"}
}

// ── Likelihood factors ───────────────────────────────────────────────────────

// skillLevelFactor rates the skill an attacker needs, modelled on the OWASP
// Risk Rating "Skill level" threat-agent factor: 4 = no technical skills,
// 3 = some technical skills, 2 = advanced computer user, 1 = security
// penetration skills. It is driven by how intrinsically hard the
// flaw is to exploit (CVSS AC/AT/PR/UI, required attacker position, exploit
// complexity, attack path, blocking preconditions). Exploit tooling then
// lowers the skill bar: a Metasploit module or weaponized exploit automates
// the hard part, so it raises the score to what the tool leaves the attacker
// to do. Tooling cannot remove a positional requirement (existing code
// execution or physical access), so those stay capped at Advanced User.
func skillLevelFactor(in Input, realism *schema.ExploitRealism) schema.RiskFactor {
	vector := intrinsicVector(in)
	if vector == "" {
		vector = bestCVSSVector(in.CVE)
	}
	if vector == "" && in.Intrinsic == nil {
		switch r := in.Exploitation.MisconfigBreachRisk; {
		case r >= 7.5:
			return schema.RiskFactor{Score: 4, Rating: "No Technical Skills", Reason: "Exposure is usable with standard clients, no exploitation technique needed"}
		case r > 0:
			return schema.RiskFactor{Score: 3, Rating: "Some Technical Skills", Reason: "Misconfiguration abusable with basic security knowledge"}
		}
		return schema.RiskFactor{Score: 2, Rating: "Advanced Computer User", Source: schema.FactorAssumed, Reason: "No CVSS vector or exploit analysis; assumed advanced user"}
	}

	// Difficulty points: higher = more skill needed. A clean
	// unauthenticated, low-complexity network attack lands at 0 (score 4).
	points := 1.0
	var why []string
	add := func(v float64, reason string) {
		points += v
		why = append(why, reason)
	}

	_, ac := parseAVAC(vector)
	if ac == "H" {
		add(1.5, "high attack complexity (AC:H)")
	}
	if parseAT(vector) == "P" {
		add(1.0, "attack requirements present (AT:P)")
	}
	if parseUI(vector) == "R" {
		add(0.5, "needs user interaction (UI:R)")
	}

	capability := schema.AttackerCapability("")
	if in.Intrinsic != nil {
		capability = in.Intrinsic.AttackerCapability
	}
	switch capability {
	case schema.AttackerUnauthenticatedNetwork:
		add(-1.0, "unauthenticated network attack")
	case schema.AttackerAuthenticatedLowPriv:
		why = append(why, "needs a low-privilege account")
	case schema.AttackerAuthenticatedHighPriv:
		add(1.0, "needs a high-privilege account")
	case schema.AttackerLocalUser:
		add(1.0, "needs local access")
	case schema.AttackerCodeExecution:
		add(2.0, "needs existing code execution")
	case schema.AttackerPhysical:
		add(2.0, "needs physical access")
	default:
		switch parsePR(vector) {
		case "N":
			add(-1.0, "no privileges required (PR:N)")
		case "L":
			why = append(why, "low privileges required (PR:L)")
		case "H":
			add(1.0, "high privileges required (PR:H)")
		}
	}

	if in.Intrinsic != nil {
		switch in.Intrinsic.ExploitComplexity {
		case schema.ComplexityLow:
			add(-0.5, "low exploit complexity")
		case schema.ComplexityHigh:
			add(1.5, "high exploit complexity")
		}
		switch in.Intrinsic.AttackPathClass {
		case schema.AttackPathLateralMovementRequired:
			add(1.0, "requires lateral movement from a foothold")
		case schema.AttackPathValidCredentials:
			add(0.5, "requires valid credentials")
		case schema.AttackPathPhishingDelivery:
			add(0.5, "requires phishing delivery")
		}
		blockers := 0
		for _, p := range in.Intrinsic.Preconditions {
			if p.Severity == schema.PreconditionBlocker {
				blockers++
			}
		}
		if blockers > 0 {
			add(math.Min(float64(blockers)*0.5, 1.5), fmt.Sprintf("%d blocking precondition(s)", blockers))
		}
	}

	score := int(math.Round(4 - points))
	if score < 1 {
		score = 1
	}
	if score > 4 {
		score = 4
	}

	// Well-documented weakness classes (SQLi, command injection, hard-coded
	// credentials, missing auth) are taught widely; exploiting them never
	// needs specialist skills.
	if in.CWEID != "" && cweExploitCeiling(in.CWEID) <= 3.0 && score < 2 {
		score = 2
		why = append(why, in.CWEID+" is a well-documented technique")
	}

	if len(why) == 0 {
		why = append(why, "standard exploitation, no special conditions")
	}

	if floor, tool := toolingSkillFloor(in); floor > score {
		if capability == schema.AttackerCodeExecution || capability == schema.AttackerPhysical {
			floor = minInt(floor, 2)
		}
		// A tool only lowers the bar if it can realistically be used here.
		if realism != nil && floor > realism.Score {
			floor = realism.Score
		}
		if floor > score {
			why = append(why, fmt.Sprintf("%s automates exploitation (difficulty alone: %d)", tool, score))
			score = floor
		}
	}
	return schema.RiskFactor{Score: score, Rating: skillRatings[score], Reason: strings.Join(why, "; ")}
}

var skillRatings = map[int]string{
	4: "No Technical Skills",
	3: "Some Technical Skills",
	2: "Advanced Computer User",
	1: "Security Penetration Skills",
	0: "Not Feasible",
}

// toolingSkillFloor returns the skill score public exploit tooling brings a
// finding up to, and the tool responsible.
func toolingSkillFloor(in Input) (int, string) {
	e := in.Exploitation
	switch {
	case e.MetasploitAvailable:
		return 4, "Metasploit module"
	case e.VulnCheckWeaponized:
		return 4, "Weaponized exploit (VulnCheck)"
	case in.DetectionConfidence == schema.ExploitConfirmed:
		return 4, "Automated scanner exploit check"
	case e.ExploitDBFound || e.VulnCheckPublicExploit || e.AttackerKBExploitability >= 4:
		return 3, "Public exploit (Exploit-DB / VulnCheck)"
	case e.PublicPOCFound || e.TrickestFound || hasWeaponizedPOC(in):
		return 2, "Public PoC"
	}
	return 0, ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// bestCVSSVector returns the vector string behind maxCVSSScore.
func bestCVSSVector(cve *schema.CVE) string {
	if cve == nil {
		return ""
	}
	best := maxCVSSScore(cve)
	for _, v := range cve.CVSSVectors {
		if v.Score == best && v.Vector != "" {
			return v.Vector
		}
	}
	return ""
}

// parsePR returns the PR (Privileges Required) field from a CVSS vector.
func parsePR(vector string) string {
	for _, p := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(p, ":"); ok && k == "PR" {
			return v
		}
	}
	return ""
}

func discoveryFactor(in Input) schema.RiskFactor {
	e := in.Exploitation
	switch e.AttackerDiscoverabilityTier {
	case "mass_scanned":
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: fmt.Sprintf("Mass-scanned in the wild (%d OTX pulses)", e.OTXPulseCount)}
	case "remote_exploit":
		if in.CVE != nil {
			return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Public CVE with remote scanner signatures (Nuclei / Tenable remote)"}
		}
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Remote scanner signatures detect it"}
	case "version_detectable":
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Vulnerable version visible remotely to scanners"}
	case "credentialed_only":
		return schema.RiskFactor{Score: 2, Rating: "Difficult", Reason: "Only detectable with credentials or an agent; external attacker is blind"}
	}
	if hasNucleiTemplate(in) {
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Public CVE with a Nuclei template"}
	}
	switch in.DetectionConfidence {
	case schema.ExploitConfirmed, schema.EndpointConfirmed:
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Our external scanner found it, so attacker tooling can too"}
	case schema.VersionOnly:
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Detected by version fingerprint"}
	}
	if e.MisconfigBreachRisk > 0 {
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Exposure class is routinely found by internet scanners"}
	}
	if in.CVE != nil {
		return schema.RiskFactor{Score: 3, Rating: "Easy", Source: schema.FactorAssumed, Reason: "Public CVE; no scanner coverage data"}
	}
	return schema.RiskFactor{Score: 3, Rating: "Easy", Source: schema.FactorAssumed, Reason: "No discoverability data; assumed detectable with effort"}
}

func easeOfExploitFactor(in Input, realism *schema.ExploitRealism) schema.RiskFactor {
	e := in.Exploitation
	var f schema.RiskFactor
	switch {
	case in.DetectionConfidence == schema.ExploitConfirmed:
		f = schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Exploit confirmed against this asset by an automated check"}
	case e.MisconfigBreachRisk >= 7.5:
		f = schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Exposure is directly usable (no exploit needed)"}
	case e.MetasploitAvailable || e.VulnCheckWeaponized:
		f = schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Metasploit module or weaponized exploit available"}
	case e.ExploitDBFound || e.VulnCheckPublicExploit || e.PublicPOCFound || e.TrickestFound || hasWeaponizedPOC(in) || e.MisconfigBreachRisk > 0:
		f = schema.RiskFactor{Score: 3, Rating: "Easy", Reason: "Public PoC / Exploit-DB entry; may need modification"}
	case in.Intrinsic != nil && in.Intrinsic.ExploitComplexity != schema.ComplexityHigh:
		f = schema.RiskFactor{Score: 2, Rating: "Difficult", Reason: "No public exploit; working exploit must be built"}
	default:
		f = schema.RiskFactor{Score: 1, Rating: "Practically Impossible", Reason: "No known working exploit"}
	}

	// Having an exploit is not the same as it working here: cap by what
	// the asset evidence says is realistic.
	if realism != nil && f.Score > realism.Score {
		f = schema.RiskFactor{Score: realism.Score, Rating: easeRatings[realism.Score],
			Reason: fmt.Sprintf("%s, but on this asset: %s", f.Reason, strings.Join(realism.Reasons, "; "))}
	}
	return f
}

var easeRatings = map[int]string{
	4: "Automated Tools Available",
	3: "Easy",
	2: "Difficult",
	1: "Practically Impossible",
	0: "Not Exploitable Here",
}

// awarenessFactor follows the OWASP awareness scale: 4 = public knowledge,
// 3 = obvious, 2 = hidden, 1 = unknown. The reason names the strongest
// public signal (KEV, ransomware, breach data) so active exploitation
// stays visible even though it shares the top score.
func awarenessFactor(in Input) schema.RiskFactor {
	e := in.Exploitation
	public := func(reason string) schema.RiskFactor {
		return schema.RiskFactor{Score: 4, Rating: "Public Knowledge", Reason: reason}
	}
	for _, src := range e.InKEVSources {
		if src == "cisa_kev" {
			return public("Listed in CISA KEV (actively exploited)")
		}
	}
	switch {
	case len(e.InKEVSources) > 0:
		return public("Listed in " + strings.Join(e.InKEVSources, ", ") + " (actively exploited)")
	case e.RansomwareAssociated || e.VulnCheckRansomwareCount > 0:
		return public("Used by ransomware operators")
	case e.BreachConfirmed || e.FireLinked || e.MandiantMTrends || e.CrowdStrikeGTR:
		return public("Linked to confirmed breaches")
	case e.ENISAExploited || e.VulnCheckReportedExploited || e.ZeroDayConfirmed || len(e.ObservationSources) > 0 ||
		e.VulnCheckThreatActorCount > 0 || e.VulnCheckBotnetCount > 0:
		return public("Exploitation observed in the wild")
	case e.OTXActiveCampaign || e.AttackerKBValue >= 4 || e.CISASSVCDecision == "Immediate" || e.CISASSVCDecision == "Out-of-Cycle" || e.MetasploitAvailable:
		return public("Widespread security-community attention")
	case in.CVE != nil:
		return public("Publicly disclosed CVE")
	case e.MisconfigBreachRisk >= 7.5:
		return public("Exposure class is well known to attackers")
	case e.MisconfigBreachRisk > 0:
		return schema.RiskFactor{Score: 3, Rating: "Obvious", Reason: "Exposure is visible to anyone who looks"}
	}
	return schema.RiskFactor{Score: 1, Rating: "Unknown", Source: schema.FactorAssumed, Reason: "No public disclosure (internal discovery)"}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// exploitRealism checks whether the known exploit can realistically work
// against this asset, using only asset-specific evidence: prerequisite
// evaluations, what our scanner confirmed, how the attacker must reach it,
// and controls in front of it. The most restrictive finding wins.
//
//	confirmed   4  exploit or vulnerable code path proven on this asset
//	likely      4  feature confirmed live / prerequisites met, nothing in the way
//	unverified  3  only the version matched; exploit may not apply (backport,
//	               feature disabled, config) — needs verification
//	conditional 2  needs something first: foothold, credentials, a victim,
//	               adjacent/local access, or getting past auth or a WAF
//	blocked     0  a required prerequisite is not met on this asset, so the
//	               documented exploit paths do not work here today
func exploitRealism(in Input) *schema.ExploitRealism {
	var blocked, conditional, verified []string

	for _, e := range in.Preconditions {
		if e.Precondition.Severity != schema.PreconditionBlocker {
			continue
		}
		desc := e.Precondition.Description
		if desc == "" {
			desc = e.Precondition.ID
		}
		switch e.Status {
		case schema.PreconditionUnsatisfied:
			blocked = append(blocked, "required condition not met: "+desc)
		case schema.PreconditionSatisfied:
			verified = append(verified, "required condition met: "+desc)
		}
	}
	if in.Asset != nil && in.Asset.Exposure == schema.ExposureIsolated {
		blocked = append(blocked, "asset is isolated / air-gapped")
	}

	vector := intrinsicVector(in)
	if vector == "" {
		vector = bestCVSSVector(in.CVE)
	}
	internetFacing := in.Asset != nil && in.Asset.Exposure == schema.ExposureInternet
	switch av, _ := parseAVAC(vector); av {
	case "A":
		if internetFacing {
			conditional = append(conditional, "needs adjacent-network access (AV:A), not reachable from the internet")
		}
	case "L", "P":
		conditional = append(conditional, fmt.Sprintf("needs local or physical access (AV:%s)", av))
	}

	unauthNetwork := false
	if in.Intrinsic != nil {
		switch in.Intrinsic.RemoteTriggerability {
		case schema.TriggerNo:
			conditional = append(conditional, "cannot be triggered remotely")
		case schema.TriggerConditional:
			conditional = append(conditional, "only remotely triggerable under specific conditions")
		}
		switch in.Intrinsic.AttackPathClass {
		case schema.AttackPathLateralMovementRequired:
			conditional = append(conditional, "attacker needs a foothold on the network first")
		case schema.AttackPathValidCredentials:
			conditional = append(conditional, "attacker needs valid credentials first")
		case schema.AttackPathPhishingDelivery:
			conditional = append(conditional, "attacker needs a victim to open or click something")
		}
		switch in.Intrinsic.AttackerCapability {
		case schema.AttackerCodeExecution:
			conditional = append(conditional, "attacker needs existing code execution")
		case schema.AttackerPhysical:
			conditional = append(conditional, "attacker needs physical access")
		case schema.AttackerUnauthenticatedNetwork:
			unauthNetwork = true
		}
	}
	if unauthNetwork && in.Asset != nil {
		if a := in.Asset.Signals.Auth; a != nil && a.Required != nil && *a.Required {
			conditional = append(conditional, "unauthenticated exploit, but the asset requires authentication in front")
		}
		if n := in.Asset.Signals.Network; n != nil && n.WAF != "" {
			conditional = append(conditional, "unauthenticated exploit, but a WAF ("+n.WAF+") sits in front")
		}
	}

	switch {
	case in.DetectionConfidence == schema.ExploitConfirmed:
		// Proven beats inferred: the exploit fired against this asset.
		return &schema.ExploitRealism{Score: 4, Tier: schema.RealismConfirmed,
			Reasons: []string{"exploit or vulnerable code path confirmed on this asset by our scanner"}}
	case len(blocked) > 0:
		return &schema.ExploitRealism{Score: 0, Tier: schema.RealismBlocked,
			Reasons: append(blocked, "documented exploit paths do not work here today; not a guarantee against other paths")}
	case len(conditional) > 0:
		return &schema.ExploitRealism{Score: 2, Tier: schema.RealismConditional, Reasons: conditional}
	case in.DetectionConfidence == schema.EndpointConfirmed || len(verified) > 0:
		reasons := verified
		if in.DetectionConfidence == schema.EndpointConfirmed {
			reasons = append([]string{"vulnerable feature confirmed live on this asset"}, reasons...)
		}
		return &schema.ExploitRealism{Score: 4, Tier: schema.RealismLikely, Reasons: reasons}
	case in.Exploitation.MisconfigBreachRisk > 0 && in.CVE == nil:
		// Exposure findings: the exposure itself is the observation.
		return &schema.ExploitRealism{Score: 4, Tier: schema.RealismLikely,
			Reasons: []string{"exposure observed directly on this asset"}}
	}
	reason := "no asset evidence that the exploit applies (version match only); verify before treating as exploitable"
	if in.DetectionConfidence != schema.VersionOnly {
		reason = "no asset evidence either way; verify before treating as exploitable"
	}
	return &schema.ExploitRealism{Score: 3, Tier: schema.RealismUnverified, Reasons: []string{reason}}
}
