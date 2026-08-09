// Package enrichers provides lightweight, network-fetching enrichers that
// attach real-world exploitation and breach evidence to CVE records before
// OPES scoring.
//
// Each enricher is a free-standing function returning a typed result.
// Errors are swallowed — every function returns a zero-value result on failure
// so the pipeline remains intact. All fetches time out in ≤ 20 s.
//
// Sources
//
//   - VCDB          Verizon DBIR incident database (github.com/vz-risk/VCDB).
//                   Confirms whether the CVE appears in a real breach record.
//   - ENISA EUVD    EU Vulnerability Database (euvdservices.enisa.europa.eu).
//                   exploitedSince non-null → EU-confirmed exploitation.
//   - Google P0     "0day In The Wild" spreadsheet (Project Zero).
//                   CVE was exploited before a vendor patch existed.
//   - AttackerKB    Community exploitation scoring (api.attackerkb.com).
//   - CISA Vulnrichment  CVSS 4.0 + SSVC triage decisions (GitHub).
//   - Metasploit    Weaponized exploit module detection (GitHub search).
//   - Nuclei        Automated scan template detection (GitHub search).
//   - PoC-in-GitHub Public PoC repos via nomi-sec/PoC-in-GitHub raw index.
//   - trickest/cve  Broader GitHub PoC aggregator (Markdown per CVE).
//   - Exploit-DB    Public exploit archive via offensive-security/exploitdb mirror.
//   - CXSecurity    Public advisory/exploit index via cveshow pages (best-effort).
//   - JVN iPedia    Japanese national vulnerability database (MyJVN API).
//   - BDU FSTEC     Russian national vulnerability database (GitHub mirror).
//   - ATT&CK        CVE → MITRE technique mappings (CTID Mappings Explorer).
//   - OWASP         CWE → OWASP Top 10 2021 category (static mapping).
package enrichers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// ─────────────────────────── Result types ────────────────────────────────────

// VCDBResult holds breach attribution from the Verizon VERIS Community DB.
type VCDBResult struct {
	Found         bool     `json:"found"`
	IncidentCount int      `json:"incident_count,omitempty"`
	IncidentURLs  []string `json:"incident_urls,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// ENISAResult holds exploitation confirmation from ENISA EUVD.
type ENISAResult struct {
	Found            bool    `json:"found"`
	EUVDID           string  `json:"euvd_id,omitempty"`
	ExploitConfirmed bool    `json:"exploit_confirmed"`
	ExploitedSince   string  `json:"exploited_since,omitempty"`
	BaseScore        float64 `json:"base_score,omitempty"`
	BaseScoreVector  string  `json:"base_score_vector,omitempty"`
	Note             string  `json:"note,omitempty"`
}

// GP0Result holds Google Project Zero pre-patch zero-day confirmation.
type GP0Result struct {
	Found            bool   `json:"found"`
	ZeroDayConfirmed bool   `json:"zero_day_confirmed"`
	Product          string `json:"product,omitempty"`
	Notes            string `json:"notes,omitempty"`
	// Note carries fetch/parse error messages for diagnostic purposes.
	Note string `json:"note,omitempty"`
}

// AttackerKBResult holds community exploitation scoring from AttackerKB.
// Scores are on a 0–5 scale; 5 is maximum.
type AttackerKBResult struct {
	Found          bool    `json:"found"`
	AttackerValue  int     `json:"attacker_value,omitempty"`
	Exploitability int     `json:"exploitability,omitempty"`
	CommonScore    float64 `json:"common_score,omitempty"`
	Note           string  `json:"note,omitempty"`
}

// VulnCheckExploitResult holds exploit intelligence from VulnCheck's
// /v3/index/exploits API, including XDB-backed exploit records and reported
// exploitation. These are observed/validated evidence signals, not probability
// estimates like EPSS.
type VulnCheckExploitResult struct {
	Found                       bool     `json:"found"`
	PublicExploitFound          bool     `json:"public_exploit_found,omitempty"`
	CommercialExploitFound      bool     `json:"commercial_exploit_found,omitempty"`
	WeaponizedExploitFound      bool     `json:"weaponized_exploit_found,omitempty"`
	MaxExploitMaturity          string   `json:"max_exploit_maturity,omitempty"`
	ReportedExploited          bool     `json:"reported_exploited,omitempty"`
	ReportedExploitedByActors  bool     `json:"reported_exploited_by_threat_actors,omitempty"`
	ReportedExploitedByRansom  bool     `json:"reported_exploited_by_ransomware,omitempty"`
	ReportedExploitedByBotnets bool     `json:"reported_exploited_by_botnets,omitempty"`
	InCISAKEV                   bool     `json:"in_cisa_kev,omitempty"`
	InVulnCheckKEV              bool     `json:"in_vulncheck_kev,omitempty"`
	ExploitCount                int      `json:"exploit_count,omitempty"`
	ThreatActorCount            int      `json:"threat_actor_count,omitempty"`
	RansomwareFamilyCount       int      `json:"ransomware_family_count,omitempty"`
	BotnetCount                 int      `json:"botnet_count,omitempty"`
	ExploitTypes                []string `json:"exploit_types,omitempty"`
	ExploitURLs                 []string `json:"exploit_urls,omitempty"`
	ReportedExploitationSources []string `json:"reported_exploitation_sources,omitempty"`
	Note                        string   `json:"note,omitempty"`
}

// ExternalEnrichment bundles all enricher results for one CVE.
// Fetch it with FetchAll, then call Apply to merge signals into ExploitationEvidence.
type ExternalEnrichment struct {
	// Breach and exploitation evidence
	VCDB       VCDBResult       `json:"vcdb"`
	ENISA      ENISAResult      `json:"enisa"`
	GP0        GP0Result        `json:"gp0"`
	AttackerKB AttackerKBResult `json:"attackerkb"`

	// Weaponization / public exploit artifacts
	Metasploit  MetasploitResult       `json:"metasploit"`
	Nuclei      NucleiResult           `json:"nuclei"`
	PoCGitHub   PoCGitHubResult        `json:"poc_github"`
	Trickest    TrickestResult         `json:"trickest"`
	ExploitDB   ExploitDBResult        `json:"exploitdb"`
	CXSecurity  CXSecurityResult       `json:"cxsecurity"`
	VulnCheck   VulnCheckExploitResult `json:"vulncheck"`

	// Government / national database coverage
	Vulnrichment VulnrichmentResult `json:"vulnrichment"`
	JVN          JVNResult          `json:"jvn"`
	BDU          BDUResult          `json:"bdu"`

	// Threat intelligence
	ATTACK ATTACKResult `json:"attack"`
	OWASP  OWASPResult  `json:"owasp"` // populated by Apply using CWE data; no network call

	// FIRE / ICE static lookups — no network; results from embedded CVE lists.
	// See fire_ice.go for data sources and update instructions.
	FIRE          FIREResult          `json:"fire"`
	MandiantMTrends MandiantMTrendsResult `json:"mandiant_mtrends"`
	CrowdStrikeGTR  CrowdStrikeGTRResult  `json:"crowdstrike_gtr"`

	// Discoverability — attacker-perspective detectability from the outside.
	// Synthesises AlienVault OTX (threat-intel pulse count, no API key needed),
	// Nuclei template classification (exploit vs detect vs version), and Tenable
	// plugin family (remote/no-auth vs credentialed/agent). Only
	// remote/unauthenticated signals are attacker-relevant; credentialed checks
	// are defender signals and actually raise attacker difficulty.
	Discoverability AttackerDiscoverabilityResult `json:"discoverability"`
}

// ─────────────────────────── FetchAll ────────────────────────────────────────

// FetchAll runs all network-based enrichers concurrently and returns the
// combined ExternalEnrichment. Individual failures are silently swallowed.
// Treat absent/zero-value fields as "unknown" — never as "safe".
//
// Pass the caller's context; each enricher applies its own sub-timeout.
// OWASP mapping is populated later by ApplyWithCWEs, not here, because the
// CWE list comes from the intrinsic analysis rather than a network call.
func FetchAll(ctx context.Context, cveID string) ExternalEnrichment {
	return FetchAllWithVulnCheck(ctx, cveID, "")
}

// FetchAllWithVulnCheck is FetchAll plus optional VulnCheck Exploit
// Intelligence/XDB enrichment when a bearer token is configured.
func FetchAllWithVulnCheck(ctx context.Context, cveID, vulnCheckToken string) ExternalEnrichment {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		result ExternalEnrichment
	)

	type job struct{ name string; fn func() }
	jobs := []job{
		{"vcdb", func() {
			r := FetchVCDB(ctx, cveID)
			mu.Lock(); result.VCDB = r; mu.Unlock()
		}},
		{"enisa", func() {
			r := FetchENISAEUVD(ctx, cveID)
			mu.Lock(); result.ENISA = r; mu.Unlock()
		}},
		{"gp0", func() {
			r := FetchGoogleP0(ctx, cveID)
			mu.Lock(); result.GP0 = r; mu.Unlock()
		}},
		{"attackerkb", func() {
			r := FetchAttackerKB(ctx, cveID)
			mu.Lock(); result.AttackerKB = r; mu.Unlock()
		}},
		{"metasploit", func() {
			r := FetchMetasploit(ctx, cveID)
			mu.Lock(); result.Metasploit = r; mu.Unlock()
		}},
		{"nuclei", func() {
			r := FetchNucleiTemplate(ctx, cveID)
			mu.Lock(); result.Nuclei = r; mu.Unlock()
		}},
		{"poc_github", func() {
			r := FetchPoCGitHub(ctx, cveID)
			mu.Lock(); result.PoCGitHub = r; mu.Unlock()
		}},
		{"trickest", func() {
			r := FetchTrickest(ctx, cveID)
			mu.Lock(); result.Trickest = r; mu.Unlock()
		}},
		{"exploitdb", func() {
			r := FetchExploitDB(ctx, cveID)
			mu.Lock(); result.ExploitDB = r; mu.Unlock()
		}},
		{"cxsecurity", func() {
			r := FetchCXSecurity(ctx, cveID)
			mu.Lock(); result.CXSecurity = r; mu.Unlock()
		}},
		{"vulnrichment", func() {
			r := FetchVulnrichment(ctx, cveID)
			mu.Lock(); result.Vulnrichment = r; mu.Unlock()
		}},
		{"jvn", func() {
			r := FetchJVNiPedia(ctx, cveID)
			mu.Lock(); result.JVN = r; mu.Unlock()
		}},
		{"bdu", func() {
			r := FetchBDUFSTEC(ctx, cveID)
			mu.Lock(); result.BDU = r; mu.Unlock()
		}},
		{"attack", func() {
			r := FetchATTACKMappings(ctx, cveID)
			mu.Lock(); result.ATTACK = r; mu.Unlock()
		}},
	}
	if strings.TrimSpace(vulnCheckToken) != "" {
		jobs = append(jobs, job{"vulncheck", func() {
			r := FetchVulnCheckExploits(ctx, cveID, vulnCheckToken)
			mu.Lock(); result.VulnCheck = r; mu.Unlock()
		}})
	}

	wg.Add(len(jobs))
	for _, j := range jobs {
		j := j
		go func() { defer wg.Done(); j.fn() }()
	}
	wg.Wait()

	// FIRE/ICE static lookups — no network; run synchronously after goroutines
	// complete since they're instant map lookups.
	result.FIRE = LookupFIRE(cveID)
	result.MandiantMTrends = LookupMandiantMTrends(cveID)
	result.CrowdStrikeGTR = LookupCrowdStrikeGTR(cveID)

	// Attacker discoverability — concurrent OTX + Nuclei classify + Tenable.
	// Runs after the main batch; all three sub-fetches run concurrently inside
	// FetchAttackerDiscoverability so total added latency is ~15 s max.
	result.Discoverability = FetchAttackerDiscoverability(ctx, cveID)

	return result
}

// FetchAllWithCWEs is like FetchAll but also populates the OWASP field using
// the given CWE identifiers (which come from intrinsic analysis, not a
// network source). Call this variant when CWE data is available upfront.
func FetchAllWithCWEs(ctx context.Context, cveID string, cweIDs []string) ExternalEnrichment {
	result := FetchAll(ctx, cveID)
	if len(cweIDs) > 0 {
		result.OWASP = MapOWASP(cweIDs)
	}
	return result
}

// ─────────────────────────── Apply ───────────────────────────────────────────

// Apply merges an ExternalEnrichment into a schema.ExploitationEvidence so
// OPES scoring picks up all signals. Call after FetchAll / FetchAllWithCWEs.
func Apply(ext ExternalEnrichment, ev *schema.ExploitationEvidence) {
	if ev == nil {
		return
	}
	// Breach / exploitation sources
	if ext.VCDB.Found {
		ev.BreachConfirmed = true
		ev.BreachIncidentCount = ext.VCDB.IncidentCount
		ev.BreachSources = appendUnique(ev.BreachSources, "vcdb")
	}
	if ext.ENISA.ExploitConfirmed {
		ev.ENISAExploited = true
		ev.ENISAExploitedSince = ext.ENISA.ExploitedSince
		ev.EUVDID = ext.ENISA.EUVDID
		ev.InKEVSources = appendUnique(ev.InKEVSources, "enisa_euvd_kev")
	}
	if ext.GP0.ZeroDayConfirmed {
		ev.ZeroDayConfirmed = true
	}
	if ext.AttackerKB.Found {
		ev.AttackerKBValue = ext.AttackerKB.AttackerValue
		ev.AttackerKBExploitability = ext.AttackerKB.Exploitability
	}

	// Weaponization signals
	if ext.Metasploit.Found {
		ev.MetasploitAvailable = true
		ev.MetasploitModCount = ext.Metasploit.ModuleCount
	}
	if ext.PoCGitHub.Found {
		ev.PublicPOCFound = true
		ev.PublicPOCCount = ext.PoCGitHub.POCCount
		urls := make([]string, 0, len(ext.PoCGitHub.POCs))
		for _, p := range ext.PoCGitHub.POCs {
			if p.URL != "" {
				urls = append(urls, p.URL)
			}
		}
		ev.PublicPOCURLs = appendUniqueAll(ev.PublicPOCURLs, urls)
		// Prefer the freshest PoC age when multiple sources contribute later.
		if ext.PoCGitHub.RecentPOCDays > 0 {
			if ev.RecentPOCDays <= 0 || ext.PoCGitHub.RecentPOCDays < ev.RecentPOCDays {
				ev.RecentPOCDays = ext.PoCGitHub.RecentPOCDays
			}
		}
	}
	if ext.Trickest.Found {
		ev.PublicPOCFound = true
		ev.TrickestFound = true
		ev.TrickestCount = ext.Trickest.POCCount
		urls := make([]string, 0, len(ext.Trickest.POCs))
		for _, p := range ext.Trickest.POCs {
			if p.URL != "" {
				urls = append(urls, p.URL)
			}
		}
		ev.TrickestURLs = appendUniqueAll(ev.TrickestURLs, urls)
		ev.PublicPOCURLs = appendUniqueAll(ev.PublicPOCURLs, urls)
		// Prefer unique merged URL count when trickest adds coverage beyond nomi-sec.
		if len(ev.PublicPOCURLs) > ev.PublicPOCCount {
			ev.PublicPOCCount = len(ev.PublicPOCURLs)
		} else if ev.PublicPOCCount < ext.Trickest.POCCount {
			ev.PublicPOCCount = ext.Trickest.POCCount
		}
	}
	if ext.ExploitDB.Found {
		ev.PublicPOCFound = true
		ev.ExploitDBFound = true
		ev.ExploitDBCount = ext.ExploitDB.ExploitCount
		urls := make([]string, 0, len(ext.ExploitDB.Exploits))
		for _, e := range ext.ExploitDB.Exploits {
			if e.URL != "" {
				urls = append(urls, e.URL)
			}
		}
		ev.ExploitDBURLs = appendUniqueAll(ev.ExploitDBURLs, urls)
		ev.PublicPOCURLs = appendUniqueAll(ev.PublicPOCURLs, urls)
		if ev.PublicPOCCount < ext.ExploitDB.ExploitCount {
			ev.PublicPOCCount = ext.ExploitDB.ExploitCount
		}
	}
	if ext.CXSecurity.Found {
		ev.PublicPOCFound = true
		ev.CXSecurityFound = true
		ev.CXSecurityCount = ext.CXSecurity.Count
		urls := make([]string, 0, len(ext.CXSecurity.Entries)+1)
		if ext.CXSecurity.PageURL != "" {
			urls = append(urls, ext.CXSecurity.PageURL)
		}
		for _, e := range ext.CXSecurity.Entries {
			if e.URL != "" {
				urls = append(urls, e.URL)
			}
		}
		ev.CXSecurityURLs = appendUniqueAll(ev.CXSecurityURLs, urls)
		ev.PublicPOCURLs = appendUniqueAll(ev.PublicPOCURLs, urls)
		if ev.PublicPOCCount < ext.CXSecurity.Count {
			ev.PublicPOCCount = ext.CXSecurity.Count
		}
	}
	if ext.VulnCheck.Found {
		applyVulnCheck(ext.VulnCheck, ev)
	}

	// CISA SSVC triage decision
	if ext.Vulnrichment.Found && ext.Vulnrichment.SSVCDecision != "" {
		ev.CISASSVCDecision = ext.Vulnrichment.SSVCDecision
	}

	// FIRE — financial loss confirmed via insurance carrier data
	if ext.FIRE.Found {
		ev.FireLinked = true
		ev.FireSources = appendUniqueAll(ev.FireSources, ext.FIRE.Sources)
	}

	// ICE additional sources — annual breach-investigation and threat reports
	if ext.MandiantMTrends.Found {
		ev.MandiantMTrends = true
		ev.BreachConfirmed = true
		ev.BreachSources = appendUnique(ev.BreachSources, "mandiant_mtrends")
	}
	if ext.CrowdStrikeGTR.Found {
		ev.CrowdStrikeGTR = true
		ev.BreachSources = appendUnique(ev.BreachSources, "crowdstrike_gtr")
	}

	// Attacker discoverability — only propagate when a meaningful tier was
	// determined (not "unknown"). Credentialed-only is explicitly propagated
	// because it increases OPES difficulty (defender signal, not attacker signal).
	d := ext.Discoverability
	if d.Tier != "" && d.Tier != "unknown" {
		ev.AttackerDiscoverabilityTier = d.Tier
		ev.AttackerDiscoverabilityScore = d.Score
	}
	// OTX active campaign: 20+ pulses = widely deployed attacker tooling
	if d.OTX.Found && d.OTX.PulseCount >= 20 {
		ev.OTXActiveCampaign = true
		ev.OTXPulseCount = d.OTX.PulseCount
	} else if d.OTX.Found && d.OTX.PulseCount > 0 {
		ev.OTXPulseCount = d.OTX.PulseCount
	}
}

func applyVulnCheck(vc VulnCheckExploitResult, ev *schema.ExploitationEvidence) {
	ev.VulnCheckReportedExploited = vc.ReportedExploited
	ev.VulnCheckWeaponized = vc.WeaponizedExploitFound
	ev.VulnCheckPublicExploit = vc.PublicExploitFound
	ev.VulnCheckCommercialExploit = vc.CommercialExploitFound
	ev.VulnCheckMaxMaturity = vc.MaxExploitMaturity
	ev.VulnCheckExploitTypes = appendUniqueAll(ev.VulnCheckExploitTypes, vc.ExploitTypes)
	ev.VulnCheckExploitCount = vc.ExploitCount
	ev.VulnCheckThreatActorCount = vc.ThreatActorCount
	ev.VulnCheckRansomwareCount = vc.RansomwareFamilyCount
	ev.VulnCheckBotnetCount = vc.BotnetCount
	ev.VulnCheckExploitURLs = appendUniqueAll(ev.VulnCheckExploitURLs, vc.ExploitURLs)

	if vc.InCISAKEV {
		ev.InKEVSources = appendUnique(ev.InKEVSources, "cisa_kev")
	}
	if vc.InVulnCheckKEV {
		ev.InKEVSources = appendUnique(ev.InKEVSources, "vulncheck_kev")
	}
	if vc.ReportedExploited {
		ev.ObservationSources = appendUnique(ev.ObservationSources, "vulncheck_reported_exploitation")
	}
	if vc.ReportedExploitedByRansom || vc.RansomwareFamilyCount > 0 {
		ev.RansomwareAssociated = true
	}
}

// ─────────────────────────── VulnCheck Exploits/XDB ──────────────────────────

// FetchVulnCheckExploits queries VulnCheck Exploit Intelligence. The response
// includes XDB exploit records when available, plus exploitation timelines and
// observed threat actor/ransomware/botnet evidence.
func FetchVulnCheckExploits(ctx context.Context, cveID, token string) VulnCheckExploitResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	token = strings.TrimSpace(token)
	if cveID == "" {
		return VulnCheckExploitResult{Note: "cve_id is required"}
	}
	if token == "" {
		return VulnCheckExploitResult{Note: "VULNCHECK_API_TOKEN not configured"}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf(
		"https://api.vulncheck.com/v3/index/exploits?cve=%s",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return VulnCheckExploitResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return VulnCheckExploitResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return VulnCheckExploitResult{Note: "VulnCheck unauthorized; check VULNCHECK_API_TOKEN"}
	case http.StatusPaymentRequired, http.StatusForbidden:
		return VulnCheckExploitResult{Note: fmt.Sprintf("VulnCheck access denied HTTP %d", resp.StatusCode)}
	case http.StatusTooManyRequests:
		return VulnCheckExploitResult{Note: "VulnCheck rate limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return VulnCheckExploitResult{Note: fmt.Sprintf("VulnCheck HTTP %d", resp.StatusCode)}
	}

	var payload struct {
		Data []struct {
			PublicExploitFound          bool   `json:"public_exploit_found"`
			CommercialExploitFound      bool   `json:"commercial_exploit_found"`
			WeaponizedExploitFound      bool   `json:"weaponized_exploit_found"`
			MaxExploitMaturity          string `json:"max_exploit_maturity"`
			ReportedExploited          bool   `json:"reported_exploited"`
			ReportedExploitedByActors  bool   `json:"reported_exploited_by_threat_actors"`
			ReportedExploitedByRansom  bool   `json:"reported_exploited_by_ransomware"`
			ReportedExploitedByBotnets bool   `json:"reported_exploited_by_botnets"`
			InCISAKEV                   bool   `json:"inKEV"`
			InVulnCheckKEV              bool   `json:"inVCKEV"`
			Counts                      struct {
				Exploits             int `json:"exploits"`
				ThreatActors         int `json:"threat_actors"`
				Botnets              int `json:"botnets"`
				RansomwareFamilies   int `json:"ransomware_families"`
				RansomwareCampaigns  int `json:"ransomware"`
			} `json:"counts"`
			Exploits []struct {
				URL             string `json:"url"`
				ExploitType     string `json:"exploit_type"`
				ExploitMaturity string `json:"exploit_maturity"`
			} `json:"exploits"`
			ReportedExploitation []struct {
				Refsource string `json:"refsource"`
			} `json:"reported_exploitation"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&payload); err != nil {
		return VulnCheckExploitResult{Note: "JSON decode failed"}
	}
	if len(payload.Data) == 0 {
		return VulnCheckExploitResult{Found: false}
	}

	d := payload.Data[0]
	out := VulnCheckExploitResult{
		Found:                       true,
		PublicExploitFound:          d.PublicExploitFound,
		CommercialExploitFound:      d.CommercialExploitFound,
		WeaponizedExploitFound:      d.WeaponizedExploitFound,
		MaxExploitMaturity:          strings.ToLower(d.MaxExploitMaturity),
		ReportedExploited:          d.ReportedExploited,
		ReportedExploitedByActors:  d.ReportedExploitedByActors,
		ReportedExploitedByRansom:  d.ReportedExploitedByRansom,
		ReportedExploitedByBotnets: d.ReportedExploitedByBotnets,
		InCISAKEV:                   d.InCISAKEV,
		InVulnCheckKEV:              d.InVulnCheckKEV,
		ExploitCount:                d.Counts.Exploits,
		ThreatActorCount:            d.Counts.ThreatActors,
		RansomwareFamilyCount:       maxInt(d.Counts.RansomwareFamilies, d.Counts.RansomwareCampaigns),
		BotnetCount:                 d.Counts.Botnets,
	}
	for _, exploit := range d.Exploits {
		if exploit.URL != "" && len(out.ExploitURLs) < 10 {
			out.ExploitURLs = appendUnique(out.ExploitURLs, exploit.URL)
		}
		if exploit.ExploitType != "" {
			out.ExploitTypes = appendUnique(out.ExploitTypes, strings.ToLower(exploit.ExploitType))
		}
	}
	for _, reported := range d.ReportedExploitation {
		if reported.Refsource != "" {
			out.ReportedExploitationSources = appendUnique(out.ReportedExploitationSources, reported.Refsource)
		}
	}
	out.Note = fmt.Sprintf(
		"VulnCheck: maturity=%s public=%t weaponized=%t reported_exploited=%t exploits=%d actors=%d ransomware=%d",
		out.MaxExploitMaturity, out.PublicExploitFound, out.WeaponizedExploitFound,
		out.ReportedExploited, out.ExploitCount, out.ThreatActorCount, out.RansomwareFamilyCount,
	)
	return out
}

// ─────────────────────────── VCDB ────────────────────────────────────────────

// FetchVCDB searches the Verizon VERIS Community Database (GitHub) for
// incident JSON files that reference the given CVE ID.
func FetchVCDB(ctx context.Context, cveID string) VCDBResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:vz-risk/VCDB+extension:json",
		cveID,
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return VCDBResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return VCDBResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return VCDBResult{Note: "GitHub rate-limited; set GITHUB_TOKEN for higher limits"}
	}
	if resp.StatusCode != http.StatusOK {
		return VCDBResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&payload); err != nil {
		return VCDBResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return VCDBResult{Found: false}
	}

	urls := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		urls = append(urls, item.HTMLURL)
	}
	return VCDBResult{
		Found:         true,
		IncidentCount: payload.TotalCount,
		IncidentURLs:  urls,
		Note: fmt.Sprintf(
			"%d VCDB breach record(s) reference %s — confirmed in Verizon DBIR incident data",
			payload.TotalCount, cveID,
		),
	}
}

// ─────────────────────────── ENISA EUVD ──────────────────────────────────────

// FetchENISAEUVD queries the ENISA European Union Vulnerability Database.
// A non-empty exploitedSince field confirms EU-verified exploitation in the wild.
func FetchENISAEUVD(ctx context.Context, cveID string) ENISAResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://euvdservices.enisa.europa.eu/api/enisaid?id=%s", cveID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return ENISAResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ENISAResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ENISAResult{Found: false}
	}
	if resp.StatusCode != http.StatusOK {
		return ENISAResult{Note: fmt.Sprintf("HTTP %d from ENISA", resp.StatusCode)}
	}

	var d struct {
		ID             string  `json:"id"`
		ExploitedSince string  `json:"exploitedSince"`
		BaseScore      float64 `json:"baseScore"`
		BaseScoreVector string `json:"baseScoreVector"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&d); err != nil {
		return ENISAResult{Note: "JSON decode failed"}
	}
	if d.ID == "" {
		return ENISAResult{Found: false}
	}

	exploited := strings.TrimSpace(d.ExploitedSince) != ""
	note := fmt.Sprintf("ENISA EUVD: id=%s exploited=%v", d.ID, exploited)
	if exploited {
		note = fmt.Sprintf("ENISA EUVD confirms exploitation since %s (id=%s)", d.ExploitedSince, d.ID)
	}
	return ENISAResult{
		Found:            true,
		EUVDID:           d.ID,
		ExploitConfirmed: exploited,
		ExploitedSince:   d.ExploitedSince,
		BaseScore:        d.BaseScore,
		BaseScoreVector:  d.BaseScoreVector,
		Note:             note,
	}
}

// ─────────────────────────── Google Project Zero ─────────────────────────────

const googleP0CSV = "https://docs.google.com/spreadsheets/d/" +
	"1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=2"

// FetchGoogleP0 checks whether the CVE appears in Google Project Zero's
// "0day In The Wild" spreadsheet — confirming exploitation before a patch existed.
func FetchGoogleP0(ctx context.Context, cveID string) GP0Result {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, googleP0CSV, nil)
	if err != nil {
		return GP0Result{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return GP0Result{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GP0Result{Note: fmt.Sprintf("HTTP %d from Google Sheets", resp.StatusCode)}
	}

	r := csv.NewReader(io.LimitReader(resp.Body, 2*1024*1024))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	headers, err := r.Read()
	if err != nil {
		return GP0Result{Note: "CSV header read failed"}
	}

	// Find column indices.
	cveCol, productCol, notesCol := 0, -1, -1
	for i, h := range headers {
		lo := strings.ToLower(strings.TrimSpace(h))
		switch {
		case strings.Contains(lo, "cve"):
			cveCol = i
		case strings.Contains(lo, "product") || strings.Contains(lo, "software"):
			productCol = i
		case strings.Contains(lo, "note") || strings.Contains(lo, "desc"):
			notesCol = i
		}
	}

	upper := strings.ToUpper(cveID)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rowText := strings.ToUpper(strings.Join(row, " "))
		if !strings.Contains(rowText, upper) {
			continue
		}
		if cveCol < len(row) && !strings.Contains(strings.ToUpper(row[cveCol]), upper) {
			continue
		}

		product, notes := "", ""
		if productCol >= 0 && productCol < len(row) {
			product = strings.TrimSpace(row[productCol])
		}
		if notesCol >= 0 && notesCol < len(row) {
			notes = strings.TrimSpace(row[notesCol])
		}
		return GP0Result{Found: true, ZeroDayConfirmed: true, Product: product, Notes: notes}
	}
	return GP0Result{Found: false}
}

// ─────────────────────────── AttackerKB ──────────────────────────────────────

// FetchAttackerKB queries the AttackerKB community scoring API.
// Scores are 0–5: AttackerValue (how useful to an attacker?) and
// Exploitability (how reliably can it be exploited?).
func FetchAttackerKB(ctx context.Context, cveID string) AttackerKBResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.attackerkb.com/v1/topics?q=%s&size=1", cveID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return AttackerKBResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AttackerKBResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return AttackerKBResult{Note: "AttackerKB rate-limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return AttackerKBResult{Note: fmt.Sprintf("HTTP %d from AttackerKB", resp.StatusCode)}
	}

	var payload struct {
		Data []struct {
			Name  string `json:"name"`
			Score struct {
				AttackerValue       int     `json:"attackerValue"`
				ExploitabilityScore int     `json:"exploitabilityScore"`
				CommonScore         float64 `json:"commonScore"`
			} `json:"score"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return AttackerKBResult{Note: "JSON decode failed"}
	}
	if len(payload.Data) == 0 {
		return AttackerKBResult{Found: false}
	}

	t := payload.Data[0]
	if !strings.EqualFold(t.Name, cveID) {
		return AttackerKBResult{Found: false}
	}
	return AttackerKBResult{
		Found:          true,
		AttackerValue:  t.Score.AttackerValue,
		Exploitability: t.Score.ExploitabilityScore,
		CommonScore:    t.Score.CommonScore,
		Note: fmt.Sprintf(
			"AttackerKB: attacker_value=%d exploitability=%d common_score=%.1f",
			t.Score.AttackerValue, t.Score.ExploitabilityScore, t.Score.CommonScore,
		),
	}
}

// ─────────────────────────── helpers ─────────────────────────────────────────

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func appendUniqueAll(dst []string, src []string) []string {
	for _, v := range src {
		dst = appendUnique(dst, v)
	}
	return dst
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
