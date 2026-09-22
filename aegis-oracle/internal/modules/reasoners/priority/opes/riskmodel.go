package opes

import (
	"fmt"
	"math"
	"strings"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// RiskModelVersion identifies the factor mapping below. Bump on any change
// to how signals map to factor scores.
const RiskModelVersion = "risk/v1"

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

// skillLevelFactor: 5 = no technical skill needed, 1 = specialist expertise.
func skillLevelFactor(in Input) schema.RiskFactor {
	e := in.Exploitation
	switch {
	case e.MetasploitAvailable:
		return schema.RiskFactor{Score: 5, Rating: "No Technical Skills", Reason: "Metasploit module available"}
	case e.VulnCheckWeaponized:
		return schema.RiskFactor{Score: 5, Rating: "No Technical Skills", Reason: "Weaponized exploit available (VulnCheck)"}
	case in.DetectionConfidence == schema.ExploitConfirmed:
		return schema.RiskFactor{Score: 5, Rating: "No Technical Skills", Reason: "Our scanner triggered it with an automated check"}
	case e.MisconfigBreachRisk >= 7.5:
		return schema.RiskFactor{Score: 5, Rating: "No Technical Skills", Reason: "Exposed service or misconfiguration usable with standard clients"}
	case e.ExploitDBFound || e.VulnCheckPublicExploit || e.AttackerKBExploitability >= 4:
		return schema.RiskFactor{Score: 4, Rating: "Some Technical Skills", Reason: "Public exploit write-up available"}
	case e.PublicPOCFound || e.TrickestFound || hasWeaponizedPOC(in) || e.MisconfigBreachRisk > 0:
		return schema.RiskFactor{Score: 3, Rating: "Moderate Technical Skills", Reason: "Public PoC exists but needs adapting"}
	}
	if in.Intrinsic != nil {
		switch in.Intrinsic.AttackerCapability {
		case schema.AttackerCodeExecution, schema.AttackerPhysical:
			return schema.RiskFactor{Score: 1, Rating: "Security Penetration Skills", Reason: "Requires prior code execution or physical access and no public exploit"}
		}
		if in.Intrinsic.ExploitComplexity == schema.ComplexityHigh {
			return schema.RiskFactor{Score: 1, Rating: "Security Penetration Skills", Reason: "High exploit complexity and no public exploit"}
		}
	}
	return schema.RiskFactor{Score: 2, Rating: "Advanced Technical Skills", Reason: "No public exploit code; attacker must write one"}
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
