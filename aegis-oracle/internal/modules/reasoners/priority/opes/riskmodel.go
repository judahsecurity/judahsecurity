package opes

import (
	"fmt"
	"math"
	"strings"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// RiskModelVersion identifies the factor mapping below. Bump on any change
// to how signals map to factor scores.
const RiskModelVersion = "risk/v2"

// riskModel maps the OPES inputs onto the seven-factor Likelihood × Impact
// model. Every factor carries a one-line reason so an analyst can see why a
// finding scored the way it did. It never changes the OPES value.
func riskModel(in Input, cfg RiskModelConfig) *schema.RiskModelScore {
	f := schema.RiskFactors{
		BusinessImpact:        businessImpactFactor(in.Asset),
		NetworkLocation:       networkLocationFactor(in.Asset),
		VulnerabilitySeverity: severityFactor(in),
		SkillLevel:            skillLevelFactor(in),
		EaseOfDiscovery:       discoveryFactor(in),
		EaseOfExploit:         easeOfExploitFactor(in),
		Awareness:             awarenessFactor(in),
	}
	return scoreRiskFactors(f, cfg)
}

// scoreRiskFactors is the pure arithmetic of the model, split out so the
// documented worked examples can be tested without building full inputs.
func scoreRiskFactors(f schema.RiskFactors, cfg RiskModelConfig) *schema.RiskModelScore {
	impact := float64(f.BusinessImpact.Score)*cfg.BusinessImpactWeight +
		float64(f.NetworkLocation.Score)*cfg.NetworkLocationWeight +
		float64(f.VulnerabilitySeverity.Score)*cfg.VulnerabilitySeverityWeight
	likelihood := float64(f.SkillLevel.Score+f.EaseOfDiscovery.Score+f.EaseOfExploit.Score+f.Awareness.Score) / 4
	risk := impact * likelihood
	practicality := float64(f.SkillLevel.Score+f.EaseOfExploit.Score+f.Awareness.Score) / 3

	// Mirrors the workbook: IF(>=16,CRITICAL,IF(>=11,HIGH,IF(>=6,MEDIUM,
	// IF(>=1,LOW,"N/A")))). Below 1 is only reachable on a segmented network
	// with every other factor at 1, and maps to informational.
	level := schema.PriorityInformational
	switch {
	case risk >= cfg.Critical:
		level = schema.PriorityCritical
	case risk >= cfg.High:
		level = schema.PriorityHigh
	case risk >= cfg.Medium:
		level = schema.PriorityMedium
	case risk >= 1:
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
		Factors:             f,
		Version:             RiskModelVersion,
	}
}

// ── Impact factors ───────────────────────────────────────────────────────────

func businessImpactFactor(a *schema.Asset) schema.RiskFactor {
	if a == nil {
		return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: "No asset context; assumed standard business operations"}
	}
	switch a.Criticality {
	case schema.CriticalityCritical:
		return schema.RiskFactor{Score: 5, Rating: "Critical", Reason: "Asset classified critical (revenue or critical operations)"}
	case schema.CriticalityHigh:
		return schema.RiskFactor{Score: 4, Rating: "High", Reason: "Asset classified high (important business function)"}
	case schema.CriticalityLow:
		return schema.RiskFactor{Score: 2, Rating: "Low", Reason: "Asset classified low (minimal business disruption)"}
	case schema.CriticalityMedium:
		return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: "Asset classified medium (standard business operations)"}
	}
	return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: "Asset criticality not set; assumed medium"}
}

// networkLocationFactor distinguishes company-hosted from third-party-hosted
// internet exposure using the ASM's hosting_type (owned, cloud, cdn,
// third_party, unknown), which arrives in signals.extra.
func networkLocationFactor(a *schema.Asset) schema.RiskFactor {
	if a == nil {
		return schema.RiskFactor{Score: 3, Rating: "Unknown", Reason: "No asset context; exposure unknown"}
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
			return schema.RiskFactor{Score: 3, Rating: "Third Party Hosted (Internet-Facing)",
				Reason: fmt.Sprintf("Internet-facing on third-party infrastructure (%s)", provider)}
		case "owned":
			return schema.RiskFactor{Score: 5, Rating: "Company Hosted (Internet-Facing)",
				Reason: "Internet-facing on company-owned infrastructure"}
		}
		return schema.RiskFactor{Score: 5, Rating: "Company Hosted (Internet-Facing)",
			Reason: "Internet-facing; hosting not classified, assumed company-hosted"}
	}
	return schema.RiskFactor{Score: 3, Rating: "Unknown", Reason: "Exposure unknown"}
}

func severityFactor(in Input) schema.RiskFactor {
	cvss := maxCVSSScore(in.CVE)
	switch {
	case cvss >= 9.0:
		return schema.RiskFactor{Score: 5, Rating: "Critical", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss >= 7.0:
		return schema.RiskFactor{Score: 4, Rating: "High", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss >= 4.0:
		return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
	case cvss > 0:
		return schema.RiskFactor{Score: 2, Rating: "Low", Reason: fmt.Sprintf("CVSS %.1f", cvss)}
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
			return schema.RiskFactor{Score: 5, Rating: "Critical", Reason: fmt.Sprintf("No CVSS; %s leads to full compromise in breach data", class)}
		case r >= 7.5:
			return schema.RiskFactor{Score: 4, Rating: "High", Reason: fmt.Sprintf("No CVSS; %s exposes significant data or access", class)}
		}
		return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: fmt.Sprintf("No CVSS; %s has limited impact", class)}
	}
	return schema.RiskFactor{Score: 3, Rating: "Medium", Reason: "No CVSS score available; assumed medium"}
}

// ── Likelihood factors ───────────────────────────────────────────────────────

// skillLevelFactor rates the skill an attacker needs, modelled on the OWASP
// Risk Rating "Skill level" threat-agent factor: 5 = no technical skills,
// 1 = security penetration skills. It is driven by how intrinsically hard the
// flaw is to exploit (CVSS AC/AT/PR/UI, required attacker position, exploit
// complexity, attack path, blocking preconditions), not by whether exploit
// tooling exists; tooling is scored under Ease of Exploit.
func skillLevelFactor(in Input) schema.RiskFactor {
	vector := intrinsicVector(in)
	if vector == "" {
		vector = bestCVSSVector(in.CVE)
	}
	if vector == "" && in.Intrinsic == nil {
		switch r := in.Exploitation.MisconfigBreachRisk; {
		case r >= 7.5:
			return schema.RiskFactor{Score: 5, Rating: "No Technical Skills", Reason: "Exposure is usable with standard clients, no exploitation technique needed"}
		case r > 0:
			return schema.RiskFactor{Score: 4, Rating: "Some Technical Skills", Reason: "Misconfiguration abusable with basic security knowledge"}
		}
		return schema.RiskFactor{Score: 3, Rating: "Moderate Technical Skills", Reason: "No CVSS vector or exploit analysis; assumed moderate"}
	}

	// Difficulty points: higher = more skill needed. A clean
	// unauthenticated, low-complexity network attack lands at 0 (score 5).
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

	score := int(math.Round(5 - points))
	if score < 1 {
		score = 1
	}
	if score > 5 {
		score = 5
	}

	// Well-documented weakness classes (SQLi, command injection, hard-coded
	// credentials, missing auth) are taught widely; exploiting them never
	// needs specialist skills.
	if in.CWEID != "" && cweExploitCeiling(in.CWEID) <= 3.0 && score < 3 {
		score = 3
		why = append(why, in.CWEID+" is a well-documented technique")
	}

	if len(why) == 0 {
		why = append(why, "standard exploitation, no special conditions")
	}
	ratings := map[int]string{
		5: "No Technical Skills",
		4: "Some Technical Skills",
		3: "Moderate Technical Skills",
		2: "Advanced Technical Skills",
		1: "Security Penetration Skills",
	}
	return schema.RiskFactor{Score: score, Rating: ratings[score], Reason: strings.Join(why, "; ")}
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
		return schema.RiskFactor{Score: 5, Rating: "Visible/Published", Reason: fmt.Sprintf("Mass-scanned in the wild (%d OTX pulses)", e.OTXPulseCount)}
	case "remote_exploit":
		if in.CVE != nil {
			return schema.RiskFactor{Score: 5, Rating: "Visible/Published", Reason: "Public CVE with remote scanner signatures (Nuclei / Tenable remote)"}
		}
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Remote scanner signatures detect it"}
	case "version_detectable":
		return schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Vulnerable version visible remotely to scanners"}
	case "credentialed_only":
		return schema.RiskFactor{Score: 2, Rating: "Difficult", Reason: "Only detectable with credentials or an agent; external attacker is blind"}
	}
	if hasNucleiTemplate(in) {
		return schema.RiskFactor{Score: 5, Rating: "Visible/Published", Reason: "Public CVE with a Nuclei template"}
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
		return schema.RiskFactor{Score: 3, Rating: "Easy", Reason: "Public CVE; no scanner coverage data"}
	}
	return schema.RiskFactor{Score: 3, Rating: "Easy", Reason: "No discoverability data; assumed detectable with effort"}
}

func easeOfExploitFactor(in Input) schema.RiskFactor {
	e := in.Exploitation
	var f schema.RiskFactor
	switch {
	case in.DetectionConfidence == schema.ExploitConfirmed:
		f = schema.RiskFactor{Score: 5, Rating: "Simple/Scripted", Reason: "Exploit confirmed against this asset by an automated check"}
	case e.MisconfigBreachRisk >= 7.5:
		f = schema.RiskFactor{Score: 5, Rating: "Simple/Scripted", Reason: "Exposure is directly usable (no exploit needed)"}
	case e.MetasploitAvailable || e.VulnCheckWeaponized:
		f = schema.RiskFactor{Score: 4, Rating: "Automated Tools Available", Reason: "Metasploit module or weaponized exploit available"}
	case e.ExploitDBFound || e.VulnCheckPublicExploit || e.PublicPOCFound || e.TrickestFound || hasWeaponizedPOC(in) || e.MisconfigBreachRisk > 0:
		f = schema.RiskFactor{Score: 3, Rating: "Easy", Reason: "Public PoC / Exploit-DB entry; may need modification"}
	case in.Intrinsic != nil && in.Intrinsic.ExploitComplexity != schema.ComplexityHigh:
		f = schema.RiskFactor{Score: 2, Rating: "Difficult", Reason: "No public exploit; working exploit must be built"}
	default:
		f = schema.RiskFactor{Score: 1, Rating: "Theoretical", Reason: "No known working exploit"}
	}

	// Real-world practicality: a multi-stage path (foothold, phishing,
	// credentials) or unmet preconditions caps how easy it is in practice.
	if in.Intrinsic != nil && f.Score > 2 {
		switch in.Intrinsic.AttackPathClass {
		case schema.AttackPathLateralMovementRequired, schema.AttackPathPhishingDelivery, schema.AttackPathValidCredentials:
			f = schema.RiskFactor{Score: 2, Rating: "Difficult",
				Reason: fmt.Sprintf("%s, but exploitation needs a multi-stage path (%s)", f.Reason, in.Intrinsic.AttackPathClass)}
		}
	}
	if f.Score > 2 && in.Preconditions.CountBlockers(schema.PreconditionUnsatisfied) > 0 {
		f = schema.RiskFactor{Score: 2, Rating: "Difficult",
			Reason: fmt.Sprintf("%s, but a required condition is not met on this asset", f.Reason)}
	}
	return f
}

func awarenessFactor(in Input) schema.RiskFactor {
	e := in.Exploitation
	for _, src := range e.InKEVSources {
		if src == "cisa_kev" {
			return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Listed in CISA KEV"}
		}
	}
	switch {
	case len(e.InKEVSources) > 0:
		return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Listed in " + strings.Join(e.InKEVSources, ", ")}
	case e.RansomwareAssociated || e.VulnCheckRansomwareCount > 0:
		return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Used by ransomware operators"}
	case e.BreachConfirmed || e.FireLinked || e.MandiantMTrends || e.CrowdStrikeGTR:
		return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Linked to confirmed breaches"}
	case e.ENISAExploited || e.VulnCheckReportedExploited || e.ZeroDayConfirmed || len(e.ObservationSources) > 0 ||
		e.VulnCheckThreatActorCount > 0 || e.VulnCheckBotnetCount > 0:
		return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Exploitation observed in the wild"}
	case e.MisconfigBreachRisk >= 9.0:
		return schema.RiskFactor{Score: 5, Rating: "Active Exploitation", Reason: "Exposure class is mass-exploited in breach data"}
	case e.OTXActiveCampaign || e.AttackerKBValue >= 4 || e.CISASSVCDecision == "Immediate" || e.CISASSVCDecision == "Out-of-Cycle" || e.MetasploitAvailable:
		return schema.RiskFactor{Score: 4, Rating: "High", Reason: "Widespread security-community attention"}
	case e.MisconfigBreachRisk >= 7.5:
		return schema.RiskFactor{Score: 4, Rating: "High", Reason: "Exposure class is well known to attackers"}
	case in.CVE != nil || e.MisconfigBreachRisk > 0:
		return schema.RiskFactor{Score: 3, Rating: "Moderate", Reason: "Publicly disclosed, no widespread attention"}
	}
	return schema.RiskFactor{Score: 1, Rating: "Unknown", Reason: "No public disclosure (internal discovery)"}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
