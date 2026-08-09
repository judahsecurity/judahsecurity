// Package tools provides the Oracle-specific tools available to the ReAct loop.
//
// Each tool implements react.Tool and is registered into a react.Registry
// by BuildRegistry. Tools are deliberately thin — they do the minimum work
// to surface structured data to the LLM and return it as JSON text.
//
// Tool contract for the LLM:
//   - lookup_cve              — fetch CVE metadata + description from the store
//   - get_asset               — fetch an asset record and its signals from inventory
//   - check_epss_kev          — fetch EPSS score and CISA/VulnCheck KEV status
//   - search_exploit_evidence — search for public PoCs, GHSA advisory text
//   - lookup_kb_pattern       — query the KB for matching CWE / dev patterns
//   - get_open_findings       — list Oracle findings, optionally filtered
//   - run_analysis            — execute the full Phase A → Phase B → OPES pipeline
//   - check_breach_context    — VCDB breach records + ENISA EUVD + Google P0
//   - check_attackerkb        — AttackerKB community practitioner scoring
//   - check_weaponization     — Metasploit exploit modules + Nuclei templates
//   - check_vulncheck_exploits — VulnCheck Exploit Intelligence/XDB evidence
//   - check_cisa_vulnrichment — CISA Vulnrichment CVSS 4.0 + SSVC triage decision
//   - check_regional_nvds     — JVN iPedia (JP) + BDU FSTEC (RU) national DB coverage
//   - check_attack_mappings   — MITRE ATT&CK + Mappings Explorer CVE→TTP techniques
//   - map_owasp               — static CWE→OWASP Top 10 2021 category mapping
//   - check_osv               — OSV.dev: 20+ ecosystem CVE advisories by CVE ID or package name
//   - check_openssf_malicious_packages — OpenSSF Malicious Packages: backdoor/supply chain flags
//   - check_exploitdb         — Exploit-DB mirror: working exploit code lookup via GitHub index
//   - check_poc_github        — nomi-sec/PoC-in-GitHub: public PoC repo URLs + first-seen dates
//   - check_trickest          — trickest/cve: broader GitHub PoC aggregator links
//   - check_cnw_kev           — CNW (EU CSIRTs network) KEV: exploitation type + reporting CSIRT
//   - check_cisa_ics_advisory — CISA ICS-CERT CSAF advisories: affected ICS/OT products and vendors
//   - check_ics_vendor_csaf   — NVD CPE + vendor PSIRT data: exact ICS product models, firmware versions, vendor advisory URLs
//   - check_ransomfeed        — RansomFeed.it: gang victim profile (sector, country, data volume) for financial impact scoring
package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/modules/enrichers"
	"github.com/your-org/aegis-oracle/internal/pipeline"
	"github.com/your-org/aegis-oracle/internal/react"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// ─────────────────────────── Deps ────────────────────────────────────────────

// Deps are the shared dependencies injected into every tool at build time.
type Deps struct {
	Store          ToolStore
	Runner         *pipeline.Runner
	KB             *knowledgebase.KB
	PDCPKey        string // ProjectDiscovery Cloud Platform API key (optional; higher rate limits)
	VulnCheckToken string // VulnCheck API bearer token (optional; enables XDB/exploit intelligence)
}

// ToolStore is the minimal persistence surface tools need.
type ToolStore interface {
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
	GetAsset(ctx context.Context, assetID string) (*schema.Asset, error)
	GetOpenFindings(ctx context.Context, cveID, assetID string) ([]*schema.Finding, error)
	GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error)
}

// ─────────────────────────── BuildRegistry ────────────────────────────────

// BuildRegistry constructs and returns a react.Registry populated with all
// Oracle tools wired to the provided dependencies.
func BuildRegistry(d Deps) *react.Registry {
	reg := react.NewRegistry()
	reg.Register(&lookupCVETool{store: d.Store})
	reg.Register(&getAssetTool{store: d.Store})
	reg.Register(&searchVulnxTool{pdcpKey: d.PDCPKey}) // single CVE deep-dive (ID lookup)
	reg.Register(&vulnxSearchTool{pdcpKey: d.PDCPKey}) // CVE discovery by technology/query
	reg.Register(&checkEPSSKEVTool{})                  // EPSS + KEV (no API key needed)
	reg.Register(&searchExploitEvidenceTool{})         // cvelistV5 + GHSA advisory text
	reg.Register(&lookupKBPatternTool{kb: d.KB})
	reg.Register(&getOpenFindingsTool{store: d.Store})
	reg.Register(&runAnalysisTool{runner: d.Runner, vulnCheckToken: d.VulnCheckToken})
	reg.Register(&checkBreachContextTool{})                            // VCDB + ENISA EUVD + Google P0
	reg.Register(&checkAttackerKBTool{})                               // community practitioner scoring
	reg.Register(&checkWeaponizationTool{})                            // Metasploit modules + Nuclei templates
	reg.Register(&checkVulnCheckExploitsTool{token: d.VulnCheckToken}) // VulnCheck XDB/exploit intelligence
	reg.Register(&checkCISAVulnrichmentTool{})                         // CVSS 4.0 + SSVC from CISA
	reg.Register(&checkRegionalNVDsTool{})                             // JVN iPedia (JP) + BDU FSTEC (RU)
	reg.Register(&checkATTACKMappingsTool{})                           // MITRE ATT&CK CVE→TTP mappings
	reg.Register(&mapOWASPTool{})                                      // CWE → OWASP Top 10 (static)
	reg.Register(&checkOSVTool{})                                      // OSV.dev: 20+ ecosystem CVE / package advisories
	reg.Register(&checkOpenSSFMaliciousTool{})                         // OpenSSF malicious packages (supply chain)
	reg.Register(&checkExploitDBTool{})                                // Exploit-DB working exploit code
	reg.Register(&checkPoCGitHubTool{})                                // nomi-sec/PoC-in-GitHub public PoC repos
	reg.Register(&checkTrickestTool{})                                 // trickest/cve broader GitHub PoC aggregator
	reg.Register(&checkCNWKEVTool{})                                   // EU CSIRTs network KEV (ransomware type + reporting CSIRT)
	reg.Register(&checkCISAICSAdvisoryTool{})                          // CISA ICS-CERT CSAF advisories (ICS/OT product context)
	reg.Register(&checkICSVendorCSAFTool{})                            // NVD CPE + vendor PSIRT: exact ICS product models + advisory links
	reg.Register(&checkRansomfeedTool{})                               // RansomFeed.it: gang activity profile + recent victim intelligence
	return reg
}

// ─────────────────────────── lookup_cve ─────────────────────────────────────

type lookupCVETool struct{ store ToolStore }

func (t *lookupCVETool) Name() string { return "lookup_cve" }
func (t *lookupCVETool) Description() string {
	return "Fetch CVE metadata (description, CVSS, CWEs, affected packages) from the Oracle store. " +
		"If the CVE is not yet ingested it returns a not-found message — use the CVE ID from the user question."
}
func (t *lookupCVETool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2025-55130",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *lookupCVETool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cve, err := t.store.GetCVE(ctx, strings.ToUpper(cveID))
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	if cve == nil {
		return fmt.Sprintf(`{"found":false,"cve_id":%q,"note":"CVE not yet ingested. Proceed with what you know from training data and label confidence as low."}`, cveID), nil
	}
	b, _ := json.MarshalIndent(cve, "", "  ")
	return string(b), nil
}

// ─────────────────────────── search_vulnx ───────────────────────────────────

// searchVulnxTool calls the ProjectDiscovery vulnx API
// (https://api.projectdiscovery.io/v2/vulnerability/{id}) and returns a
// structured snapshot combining CVSS, EPSS, CISA KEV, VulnCheck KEV, PoC
// tracking, HackerOne stats, Nuclei template coverage, Shodan/Fofa exposure,
// affected products, requirements (preconditions), and remediation guidance.
//
// This is the richest single-call CVE data source available and should be
// preferred over the separate check_epss_kev + search_exploit_evidence calls
// when a PDCP key is available. Works unauthenticated with stricter rate limits.
type searchVulnxTool struct{ pdcpKey string }

func (t *searchVulnxTool) Name() string { return "search_vulnx" }
func (t *searchVulnxTool) Description() string {
	return "Query the ProjectDiscovery vulnx API for rich CVE intelligence in one call: " +
		"CVSS, EPSS, CISA KEV, VulnCheck KEV, PoC URLs, HackerOne report count, " +
		"Nuclei template name, internet exposure (Shodan/Fofa), affected products, " +
		"requirements/preconditions, and remediation guidance. " +
		"Prefer this over check_epss_kev and search_exploit_evidence when available."
}
func (t *searchVulnxTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *searchVulnxTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	url := fmt.Sprintf("https://api.projectdiscovery.io/v2/vulnerability/%s", cveID)
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	if t.pdcpKey != "" {
		req.Header.Set("X-PDCP-Key", t.pdcpKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vulnx API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Sprintf(`{"found":false,"cve_id":%q,"note":"CVE not in ProjectDiscovery database."}`, cveID), nil
	case http.StatusTooManyRequests:
		return fmt.Sprintf(`{"rate_limited":true,"cve_id":%q,"note":"vulnx rate limit hit. Set PDCP_API_KEY for higher limits."}`, cveID), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vulnx HTTP %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	// Parse top-level envelope {"data": {...}}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Data == nil {
		// Return raw JSON if parsing fails — LLM can still read it
		return string(body), nil
	}
	d := envelope.Data

	// Re-serialise as pretty-printed JSON so the LLM can read it clearly.
	// Filter to the fields most useful for exploitability reasoning.
	useful := map[string]any{
		"cve_id":             cveID,
		"severity":           d["severity"],
		"cvss_score":         d["cvss_score"],
		"cvss_metrics":       d["cvss_metrics"],
		"epss_score":         d["epss_score"],
		"epss_percentile":    d["epss_percentile"],
		"is_kev":             d["is_kev"],
		"is_vkev":            d["is_vkev"],
		"kev":                d["kev"],
		"is_poc":             d["is_poc"],
		"poc_count":          d["poc_count"],
		"pocs":               d["pocs"],
		"h1":                 d["h1"],
		"is_template":        d["is_template"],
		"filename":           d["filename"],
		"tags":               d["tags"],
		"requirements":       d["requirements"],
		"requirement_type":   d["requirement_type"],
		"exposure":           d["exposure"],
		"affected_products":  limitSlice(d["affected_products"], 5),
		"description":        truncStr(d["description"], 600),
		"remediation":        truncStr(d["remediation"], 400),
		"cwe":                d["cwe"],
		"is_remote":          d["is_remote"],
		"is_auth":            d["is_auth"],
		"is_patch_available": d["is_patch_available"],
		"vuln_status":        d["vuln_status"],
	}
	out, _ := json.MarshalIndent(useful, "", "  ")
	return string(out), nil
}

// ─────────────────────────── vulnx_search ───────────────────────────────────

// vulnxSearchTool uses the ProjectDiscovery PDCP search API to find CVEs
// matching a rich query string — technology, severity, exploit status, date
// ranges — and returns a summary list. This is distinct from search_vulnx
// (which fetches a single CVE by ID): vulnx_search is for DISCOVERY (e.g.
// "what high-severity remotely-exploitable CVEs affect Node.js 24?") while
// search_vulnx is for ENRICHMENT (deep intel on a known CVE ID).
//
// If vulnx binary is installed, it is exec'd with --json --silent for the
// richest output. Falls back to the PDCP HTTP search API otherwise.
type vulnxSearchTool struct{ pdcpKey string }

func (t *vulnxSearchTool) Name() string { return "vulnx_search" }
func (t *vulnxSearchTool) Description() string {
	return "Search the ProjectDiscovery vulnerability database using a rich query string. " +
		"Use this to DISCOVER CVEs relevant to a technology stack or asset profile — e.g. " +
		"'nodejs && severity:high && is_remote:true', " +
		"'apache && is_kev:true', " +
		"'severity:critical && is_poc:true && age_in_days:<30'. " +
		"Supports boolean logic (&&, ||, NOT), field filters (severity:, cvss_score:>, epss_score:>, is_kev:, is_poc:, " +
		"is_template:, is_remote:, affected_products.vendor:, affected_products.product:, age_in_days:), " +
		"and date ranges (cve_created_at:>=2024). Returns a ranked list of matching CVEs. " +
		"Distinct from search_vulnx (single CVE deep-dive) — use this when you don't have a specific CVE yet."
}
func (t *vulnxSearchTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "vulnx query string, e.g. 'nodejs && severity:high && is_remote:true'",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": "Max results to return (default 10, max 25)",
			},
			"sort": map[string]any{
				"type":        "string",
				"description": "Field to sort descending by: cvss_score, epss_score, cve_created_at (default: cvss_score)",
			},
		},
		"required": []string{"query"},
	}
}

func (t *vulnxSearchTool) Run(ctx context.Context, args map[string]any) (string, error) {
	query, _ := args["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	limit := 10
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}
	if limit > 25 {
		limit = 25
	}
	sortField := "cvss_score"
	if s, ok := args["sort"].(string); ok && s != "" {
		sortField = s
	}

	// Prefer binary exec if available.
	if result, err := t.runViaBinary(ctx, query, limit, sortField); err == nil {
		return result, nil
	}

	// Fall back to HTTP API.
	return t.runViaAPI(ctx, query, limit, sortField)
}

func (t *vulnxSearchTool) runViaBinary(ctx context.Context, query string, limit int, sort string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmdArgs := []string{
		"search", query,
		"--json", "--silent", "--disable-update-check",
		"--limit", fmt.Sprintf("%d", limit),
		"--sort-desc", sort,
	}
	out, err := runCommand(execCtx, "vulnx", cmdArgs, map[string]string{
		"PDCP_API_KEY": t.pdcpKey,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *vulnxSearchTool) runViaAPI(ctx context.Context, query string, limit int, sort string) (string, error) {
	// PDCP search API: GET /v2/vulnerability?q=QUERY&limit=N&sort-desc=FIELD
	apiURL := fmt.Sprintf(
		"https://api.projectdiscovery.io/v2/vulnerability?q=%s&limit=%d&sort-desc=%s",
		urlEncodeQuery(query), limit, sort,
	)

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	if t.pdcpKey != "" {
		req.Header.Set("X-PDCP-Key", t.pdcpKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vulnx search API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return fmt.Sprintf(`{"rate_limited":true,"note":"vulnx rate limit. Set PDCP_API_KEY for higher limits.","query":%q}`, query), nil
	case http.StatusUnauthorized:
		return fmt.Sprintf(`{"error":"unauthorized","note":"PDCP_API_KEY invalid or missing.","query":%q}`, query), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vulnx search HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	// The response is {"data": {"vulnerabilities": [...], "count": N}} or similar.
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return string(body), nil
	}

	// Normalise to a clean summary list for the LLM.
	data, _ := envelope["data"].(map[string]any)
	if data == nil {
		// Try flat array response.
		return summariseVulnList(body, query), nil
	}
	vulnsAny := data["vulnerabilities"]
	if vulnsAny == nil {
		vulnsAny = data["data"]
	}
	if vulnsAny == nil {
		return string(body), nil
	}
	vulnBytes, _ := json.Marshal(vulnsAny)
	return summariseVulnList(vulnBytes, query), nil
}

// summariseVulnList renders a list of vulnerability objects as a compact
// summary the LLM can scan quickly without hitting token limits.
func summariseVulnList(raw []byte, query string) string {
	var vulns []map[string]any
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return string(raw)
	}
	if len(vulns) == 0 {
		return fmt.Sprintf(`{"query":%q,"count":0,"note":"No CVEs matched the query."}`, query)
	}
	type row struct {
		CVEID    string  `json:"cve_id"`
		Severity string  `json:"severity"`
		CVSS     float64 `json:"cvss_score"`
		EPSS     float64 `json:"epss_score"`
		IsKEV    bool    `json:"is_kev"`
		IsPOC    bool    `json:"is_poc"`
		IsRemote bool    `json:"is_remote"`
		Template bool    `json:"is_template"`
		Age      any     `json:"age_in_days"`
		Desc     string  `json:"description"`
	}
	var rows []row
	for _, v := range vulns {
		r := row{}
		r.CVEID, _ = v["cve_id"].(string)
		r.Severity, _ = v["severity"].(string)
		r.CVSS, _ = v["cvss_score"].(float64)
		r.EPSS, _ = v["epss_score"].(float64)
		r.IsKEV, _ = v["is_kev"].(bool)
		r.IsPOC, _ = v["is_poc"].(bool)
		r.IsRemote, _ = v["is_remote"].(bool)
		r.Template, _ = v["is_template"].(bool)
		r.Age = v["age_in_days"]
		desc, _ := v["description"].(string)
		if len(desc) > 150 {
			desc = desc[:150] + "…"
		}
		r.Desc = desc
		rows = append(rows, r)
	}
	out := map[string]any{
		"query":           query,
		"count":           len(rows),
		"vulnerabilities": rows,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

func urlEncodeQuery(q string) string {
	// Manual percent-encoding of the query string without importing net/url
	// (which is already imported via the http package).
	var sb strings.Builder
	for _, c := range q {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			sb.WriteRune(c)
		case c == '-', c == '_', c == '.', c == '~':
			sb.WriteRune(c)
		default:
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return sb.String()
}

// runCommand execs a binary with args and env overrides.
// Returns stdout bytes on success.
func runCommand(ctx context.Context, name string, args []string, env map[string]string) ([]byte, error) {
	import_exec := execLookup(name)
	if import_exec == "" {
		return nil, fmt.Errorf("%q not found in PATH", name)
	}
	return execRun(ctx, import_exec, args, env)
}

func limitSlice(v any, n int) any {
	if v == nil {
		return nil
	}
	s, ok := v.([]any)
	if !ok || len(s) <= n {
		return v
	}
	return s[:n]
}

func truncStr(v any, max int) any {
	s, ok := v.(string)
	if !ok || len(s) <= max {
		return v
	}
	return s[:max] + "…"
}

// ─────────────────────────── get_asset ──────────────────────────────────────

type getAssetTool struct{ store ToolStore }

func (t *getAssetTool) Name() string { return "get_asset" }
func (t *getAssetTool) Description() string {
	return "Fetch an asset record from the ASM inventory including its technology fingerprints, " +
		"network exposure class, and runtime signals. Returns not-found if the asset ID is unknown."
}
func (t *getAssetTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Asset identifier as stored in the Oracle inventory, e.g. ftds-tenant-prod-7421",
			},
		},
		"required": []string{"asset_id"},
	}
}
func (t *getAssetTool) Run(ctx context.Context, args map[string]any) (string, error) {
	assetID, _ := args["asset_id"].(string)
	if assetID == "" {
		return "", fmt.Errorf("asset_id is required")
	}
	asset, err := t.store.GetAsset(ctx, assetID)
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	if asset == nil {
		return fmt.Sprintf(`{"found":false,"asset_id":%q,"note":"Asset not found in inventory. Proceed with unknown asset signals — preconditions will be marked unknown."}`, assetID), nil
	}
	b, _ := json.MarshalIndent(asset, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_epss_kev ─────────────────────────────────

type checkEPSSKEVTool struct{}

func (t *checkEPSSKEVTool) Name() string { return "check_epss_kev" }
func (t *checkEPSSKEVTool) Description() string {
	return "Fetch the FIRST EPSS score (probability of exploitation in the next 30 days) " +
		"and CISA KEV membership for a CVE from live public APIs. " +
		"EPSS > 0.5 and KEV membership are strong signals of active exploitation."
}
func (t *checkEPSSKEVTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkEPSSKEVTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(cveID)

	type result struct {
		CVEID    string  `json:"cve_id"`
		EPSS     float64 `json:"epss_score"`
		EPSSPerc float64 `json:"epss_percentile"`
		InKEV    bool    `json:"in_cisa_kev"`
		KEVAdded string  `json:"kev_date_added,omitempty"`
		Source   string  `json:"source"`
	}
	r := result{CVEID: cveID, Source: "first.org/EPSS + CISA KEV"}

	// EPSS — first.org public API
	epssURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)
	epssResp, err := httpGetWithTimeout(ctx, epssURL, 8*time.Second)
	if err == nil {
		var out struct {
			Data []struct {
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if jsonErr := json.Unmarshal(epssResp, &out); jsonErr == nil && len(out.Data) > 0 {
			fmt.Sscanf(out.Data[0].EPSS, "%f", &r.EPSS)
			fmt.Sscanf(out.Data[0].Percentile, "%f", &r.EPSSPerc)
		}
	}

	// CISA KEV — public JSON catalogue
	kevURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevResp, err := httpGetWithTimeout(ctx, kevURL, 10*time.Second)
	if err == nil {
		var kev struct {
			Vulnerabilities []struct {
				CVEID     string `json:"cveID"`
				DateAdded string `json:"dateAdded"`
			} `json:"vulnerabilities"`
		}
		if jsonErr := json.Unmarshal(kevResp, &kev); jsonErr == nil {
			for _, v := range kev.Vulnerabilities {
				if strings.EqualFold(v.CVEID, cveID) {
					r.InKEV = true
					r.KEVAdded = v.DateAdded
					break
				}
			}
		}
	}

	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b), nil
}

// ─────────────────────────── search_exploit_evidence ────────────────────────

type searchExploitEvidenceTool struct{}

func (t *searchExploitEvidenceTool) Name() string { return "search_exploit_evidence" }
func (t *searchExploitEvidenceTool) Description() string {
	return "Search GitHub Security Advisories (GHSA) and CVElistV5 for PoC references, " +
		"exploit code links, and vendor-published CVSS vectors for a given CVE. " +
		"Returns public advisory text that may contain precondition details not in NVD."
}
func (t *searchExploitEvidenceTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *searchExploitEvidenceTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(cveID)

	type advisory struct {
		Source  string `json:"source"`
		CVEID   string `json:"cve_id"`
		Summary string `json:"summary,omitempty"`
		URL     string `json:"url"`
	}
	var results []advisory

	// CVE.org cvelistV5 raw advisory
	parts := strings.SplitN(strings.TrimPrefix(cveID, "CVE-"), "-", 2)
	if len(parts) == 2 {
		year := parts[0]
		num := parts[1]
		// Bucket: last 3 digits of the sequence number → directory prefix
		prefix := "0xxx"
		if len(num) >= 3 {
			prefix = num[:len(num)-3] + "xxx"
		}
		cveListURL := fmt.Sprintf(
			"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%s/CVE-%s-%s.json",
			year, prefix, year, num,
		)
		body, err := httpGetWithTimeout(ctx, cveListURL, 8*time.Second)
		if err == nil {
			var raw map[string]any
			if jsonErr := json.Unmarshal(body, &raw); jsonErr == nil {
				summary := extractCVEDescription(raw)
				results = append(results, advisory{
					Source:  "cvelistV5",
					CVEID:   cveID,
					Summary: summary,
					URL:     cveListURL,
				})
			}
		}
	}

	// GitHub Security Advisory API (public, no auth for read).
	// We capture both summary (one-line) and description (full technical body)
	// so the LLM can surface mechanism details and patch context to developers.
	ghsaURL := fmt.Sprintf("https://api.github.com/advisories?cve_id=%s&per_page=3", cveID)
	ghsaBody, err := httpGetWithTimeout(ctx, ghsaURL, 8*time.Second)
	if err == nil {
		var ghsa []struct {
			GHSAID      string `json:"ghsa_id"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			URL         string `json:"html_url"`
		}
		if jsonErr := json.Unmarshal(ghsaBody, &ghsa); jsonErr == nil {
			for _, g := range ghsa {
				desc := g.Description
				if len(desc) > 2000 {
					desc = desc[:2000] + "…[truncated]"
				}
				results = append(results, advisory{
					Source:  "GHSA",
					CVEID:   cveID,
					Summary: g.Summary,
					URL:     g.URL,
				})
				// Append the full technical description as a separate advisory entry
				// so the LLM sees the root-cause detail without confusing it with metadata.
				if desc != "" && desc != g.Summary {
					results = append(results, advisory{
						Source:  "GHSA-detail",
						CVEID:   cveID,
						Summary: desc,
						URL:     g.URL,
					})
				}
			}
		}
	}

	if len(results) == 0 {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"No public advisory data found from cvelistV5 or GHSA."}`, cveID), nil
	}
	b, _ := json.MarshalIndent(map[string]any{"cve_id": cveID, "advisories": results}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── lookup_kb_pattern ──────────────────────────────

type lookupKBPatternTool struct{ kb *knowledgebase.KB }

func (t *lookupKBPatternTool) Name() string { return "lookup_kb_pattern" }
func (t *lookupKBPatternTool) Description() string {
	return "Search the Oracle knowledge base for CWE profiles and dev patterns matching " +
		"a CWE ID or keyword (e.g. 'path traversal', 'symlink', 'Node.js permissions'). " +
		"Returns curated exploit archetypes, preconditions, and ecosystem-specific notes."
}
func (t *lookupKBPatternTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cwe_id": map[string]any{
				"type":        "string",
				"description": "CWE identifier, e.g. CWE-22 (optional if keyword provided)",
			},
			"keyword": map[string]any{
				"type":        "string",
				"description": "Keyword to search across pattern names and descriptions (optional)",
			},
		},
	}
}
func (t *lookupKBPatternTool) Run(_ context.Context, args map[string]any) (string, error) {
	if t.kb == nil {
		return `{"note":"Knowledge base not loaded."}`, nil
	}
	cweID, _ := args["cwe_id"].(string)
	keyword, _ := args["keyword"].(string)

	type kbMatch struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
		Data any    `json:"data"`
	}
	var matches []kbMatch

	// CWE profile lookup
	if cweID != "" {
		cweID = strings.ToUpper(strings.TrimSpace(cweID))
		if profile, ok := t.kb.CWEProfile(cweID); ok {
			matches = append(matches, kbMatch{Kind: "cwe_profile", ID: cweID, Data: profile})
		}
	}

	// Dev pattern search
	for _, pattern := range t.kb.AllPatterns() {
		name := strings.ToLower(pattern.PatternName + " " + pattern.Summary)
		kw := strings.ToLower(keyword)
		if (keyword != "" && strings.Contains(name, kw)) ||
			(cweID != "" && containsString(pattern.CWEIDs, cweID)) {
			matches = append(matches, kbMatch{Kind: "dev_pattern", ID: pattern.PatternID, Data: pattern})
		}
	}

	if len(matches) == 0 {
		return fmt.Sprintf(`{"found":false,"cwe_id":%q,"keyword":%q,"note":"No KB matches. Proceed without curated preconditions."}`, cweID, keyword), nil
	}
	b, _ := json.MarshalIndent(map[string]any{"matches": matches}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── get_open_findings ──────────────────────────────

type getOpenFindingsTool struct{ store ToolStore }

func (t *getOpenFindingsTool) Name() string { return "get_open_findings" }
func (t *getOpenFindingsTool) Description() string {
	return "List open Oracle findings from the database, optionally filtered by CVE ID " +
		"or asset ID. Returns OPES scores, categories, and precondition statuses."
}
func (t *getOpenFindingsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "Filter to a specific CVE (optional)",
			},
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Filter to a specific asset (optional)",
			},
		},
	}
}
func (t *getOpenFindingsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	assetID, _ := args["asset_id"].(string)

	findings, err := t.store.GetOpenFindings(ctx, cveID, assetID)
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"findings": findings,
		"count":    len(findings),
	}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_vulncheck_exploits ───────────────────────

type checkVulnCheckExploitsTool struct{ token string }

func (t *checkVulnCheckExploitsTool) Name() string { return "check_vulncheck_exploits" }
func (t *checkVulnCheckExploitsTool) Description() string {
	return "Fetch VulnCheck Exploit Intelligence/XDB evidence for a CVE: public/commercial/" +
		"weaponized exploit flags, exploit maturity/type, reported exploitation, CISA/VulnCheck KEV, " +
		"ransomware/botnet/threat actor counts, timelines, and exploit URLs. This is observed evidence, " +
		"not EPSS probability."
}
func (t *checkVulnCheckExploitsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkVulnCheckExploitsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	result := enrichers.FetchVulnCheckExploits(ctx, strings.ToUpper(cveID), t.token)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── run_analysis ───────────────────────────────────

type runAnalysisTool struct {
	runner         *pipeline.Runner
	vulnCheckToken string
}

func (t *runAnalysisTool) Name() string { return "run_analysis" }
func (t *runAnalysisTool) Description() string {
	return "Execute the full Oracle analysis pipeline (Phase A LLM intrinsic analysis → " +
		"Phase B contextual precondition evaluation → OPES scoring) for a (cve_id, asset_id) pair. " +
		"This is the terminal tool — call it when you have enough context. " +
		"The output contains the complete OracleFinding with OPES score and recommendation."
}
func (t *runAnalysisTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Asset identifier from the ASM inventory",
			},
		},
		"required": []string{"cve_id", "asset_id"},
	}
}
func (t *runAnalysisTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	assetID, _ := args["asset_id"].(string)
	if cveID == "" || assetID == "" {
		return "", fmt.Errorf("both cve_id and asset_id are required")
	}

	exploitation := schema.ExploitationEvidence{}
	ext := enrichers.FetchAllWithVulnCheck(ctx, cveID, t.vulnCheckToken)
	enrichers.Apply(ext, &exploitation)

	result, err := t.runner.Run(
		ctx,
		strings.ToUpper(cveID),
		assetID,
		nil,
		exploitation,
	)
	if err != nil {
		return "", fmt.Errorf("pipeline: %w", err)
	}

	b, _ := json.MarshalIndent(map[string]any{
		"finding":    result.Finding,
		"llm_model":  result.LLMModel,
		"elapsed_ms": result.ElapsedMS,
	}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── shared helpers ─────────────────────────────────

func httpGetWithTimeout(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
}

func extractCVEDescription(raw map[string]any) string {
	cnaAny, ok := raw["containers"]
	if !ok {
		return ""
	}
	cna, ok := cnaAny.(map[string]any)["cna"].(map[string]any)
	if !ok {
		return ""
	}
	descs, ok := cna["descriptions"].([]any)
	if !ok || len(descs) == 0 {
		return ""
	}
	first, ok := descs[0].(map[string]any)
	if !ok {
		return ""
	}
	val, _ := first["value"].(string)
	return val
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ─────────────────────────── check_breach_context ───────────────────────────

// checkBreachContextTool aggregates three free breach/exploitation sources:
//   - VCDB  (Verizon DBIR incident database)
//   - ENISA EUVD (EU-confirmed exploitation)
//   - Google Project Zero (pre-patch zero-day)
//
// Use this when you want evidence that a CVE caused actual harm — beyond
// theoretical exploitability or KEV listing.
type checkBreachContextTool struct{}

func (t *checkBreachContextTool) Name() string { return "check_breach_context" }
func (t *checkBreachContextTool) Description() string {
	return "Fetch real-world breach and exploitation confirmation for a CVE from three sources: " +
		"(1) VCDB — Verizon DBIR incident database: appears here means the CVE caused a confirmed breach; " +
		"(2) ENISA EUVD — EU Vulnerability Database, exploitedSince field confirms EU-verified exploitation; " +
		"(3) Google Project Zero — '0day In The Wild' tracker, confirms exploitation before a patch existed. " +
		"Use this alongside check_epss_kev to distinguish 'theoretically exploitable' from 'caused real losses'."
}
func (t *checkBreachContextTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkBreachContextTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}

	// Run all three concurrently with a shared 20 s deadline.
	fetchCtx, cancel := context.WithTimeout(ctx, 22*time.Second)
	defer cancel()

	vcdb := enrichers.FetchVCDB(fetchCtx, cveID)
	enisa := enrichers.FetchENISAEUVD(fetchCtx, cveID)
	gp0 := enrichers.FetchGoogleP0(fetchCtx, cveID)

	// Derive a plain-English summary.
	signals := []string{}
	if vcdb.Found {
		signals = append(signals, fmt.Sprintf("VCDB: %d breach record(s) confirmed", vcdb.IncidentCount))
	}
	if enisa.ExploitConfirmed {
		signals = append(signals, fmt.Sprintf("ENISA EUVD: exploitation confirmed since %s", enisa.ExploitedSince))
	} else if enisa.Found {
		signals = append(signals, fmt.Sprintf("ENISA EUVD: catalogued as %s (no exploitation date)", enisa.EUVDID))
	}
	if gp0.ZeroDayConfirmed {
		signals = append(signals, "Google P0: confirmed exploited before patch (0day ITW)")
	}

	summary := "No breach or pre-patch exploitation evidence found in VCDB, ENISA EUVD, or Google P0."
	if len(signals) > 0 {
		summary = "Breach/exploitation evidence: " + strings.Join(signals, "; ")
	}

	result := map[string]any{
		"cve_id":  strings.ToUpper(cveID),
		"summary": summary,
		"vcdb":    vcdb,
		"enisa":   enisa,
		"gp0":     gp0,
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_attackerkb ───────────────────────────────

// checkAttackerKBTool queries the AttackerKB community scoring API.
// AttackerKB aggregates practitioner assessments of how useful and exploitable
// a CVE is. Scores are on a 0–5 scale; ≥4 is strong attacker interest.
type checkAttackerKBTool struct{}

func (t *checkAttackerKBTool) Name() string { return "check_attackerkb" }
func (t *checkAttackerKBTool) Description() string {
	return "Query AttackerKB for community practitioner scoring of a CVE. Returns: " +
		"attacker_value (0–5: how useful to an attacker?), " +
		"exploitability (0–5: how reliably can it be exploited?), " +
		"common_score (weighted average). " +
		"Scores ≥ 4 represent strong practitioner consensus. " +
		"Useful as a complement to CVSS/EPSS — these are real practitioner votes, not algorithmic estimates."
}
func (t *checkAttackerKBTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkAttackerKBTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result := enrichers.FetchAttackerKB(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_weaponization ────────────────────────────

type checkWeaponizationTool struct{}

func (t *checkWeaponizationTool) Name() string { return "check_weaponization" }
func (t *checkWeaponizationTool) Description() string {
	return "Check whether a weaponized exploit module exists for a CVE in Metasploit " +
		"(rapid7/metasploit-framework) and whether a Nuclei template exists for automated " +
		"scanning/detection (projectdiscovery/nuclei-templates). " +
		"A Metasploit module is one of the strongest OPES weaponization signals — it means " +
		"a reliable, GUI-accessible exploit exists. A Nuclei template means automated detection " +
		"is trivially achievable. Both signals significantly raise practical exploitability."
}
func (t *checkWeaponizationTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkWeaponizationTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type result struct {
		Metasploit enrichers.MetasploitResult `json:"metasploit"`
		Nuclei     enrichers.NucleiResult     `json:"nuclei"`
		Summary    string                     `json:"summary"`
	}
	msf := enrichers.FetchMetasploit(fetchCtx, cveID)
	nuc := enrichers.FetchNucleiTemplate(fetchCtx, cveID)

	summaryParts := []string{}
	if msf.Found {
		summaryParts = append(summaryParts, fmt.Sprintf("%d Metasploit module(s)", msf.ModuleCount))
	} else {
		summaryParts = append(summaryParts, "no Metasploit module")
	}
	if nuc.Found {
		summaryParts = append(summaryParts, fmt.Sprintf("%d Nuclei template(s)", nuc.TemplateCount))
	} else {
		summaryParts = append(summaryParts, "no Nuclei template")
	}

	r := result{
		Metasploit: msf,
		Nuclei:     nuc,
		Summary:    strings.Join(summaryParts, "; "),
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_cisa_vulnrichment ─────────────────────────

type checkCISAVulnrichmentTool struct{}

func (t *checkCISAVulnrichmentTool) Name() string { return "check_cisa_vulnrichment" }
func (t *checkCISAVulnrichmentTool) Description() string {
	return "Fetch CISA Vulnrichment data for a CVE from the cisagov/vulnrichment GitHub repository. " +
		"CISA enriches CVEs with CVSS 4.0 scores, SSVC (Stakeholder-Specific Vulnerability " +
		"Categorization) triage decisions, and CPE product annotations — often before NVD does. " +
		"SSVC decisions: 'Immediate' = patch ASAP (equivalent to KEV risk), 'Out-of-Cycle' = next " +
		"patch window, 'Scheduled' = routine cycle, 'Defer' = deprioritize. " +
		"Use this when NVD CVSS data is missing or when you need an official triage signal."
}
func (t *checkCISAVulnrichmentTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2024-3094",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkCISAVulnrichmentTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := enrichers.FetchVulnrichment(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_regional_nvds ─────────────────────────────

type checkRegionalNVDsTool struct{}

func (t *checkRegionalNVDsTool) Name() string { return "check_regional_nvds" }
func (t *checkRegionalNVDsTool) Description() string {
	return "Check national/regional vulnerability databases for a CVE: " +
		"JVN iPedia (Japan's IPA/JPCERT national DB — covers Japanese-vendor software often " +
		"before NVD), and BDU FSTEC (Russia's national DB — bdu.fstec.ru is geo-blocked but " +
		"accessed via public GitHub mirror). Useful for confirming whether a CVE in Japan- or " +
		"Russia-origin software has been independently catalogued by those authorities. " +
		"A hit in JVN often means the Japanese vendor has published their own advisory."
}
func (t *checkRegionalNVDsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2023-12345",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkRegionalNVDsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type combined struct {
		JVN enrichers.JVNResult `json:"jvn_ipedia"`
		BDU enrichers.BDUResult `json:"bdu_fstec"`
	}

	var (
		jvn enrichers.JVNResult
		bdu enrichers.BDUResult
	)
	done := make(chan struct{}, 2)
	go func() { jvn = enrichers.FetchJVNiPedia(fetchCtx, cveID); done <- struct{}{} }()
	go func() { bdu = enrichers.FetchBDUFSTEC(fetchCtx, cveID); done <- struct{}{} }()
	<-done
	<-done

	b, _ := json.MarshalIndent(combined{JVN: jvn, BDU: bdu}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_attack_mappings ───────────────────────────

type checkATTACKMappingsTool struct{}

func (t *checkATTACKMappingsTool) Name() string { return "check_attack_mappings" }
func (t *checkATTACKMappingsTool) Description() string {
	return "Look up MITRE ATT&CK technique mappings for a CVE using the Center for " +
		"Threat-Informed Defense (CTID) Mappings Explorer dataset and the mitre-attack/attack-stix-data " +
		"repository. Returns the ATT&CK technique IDs (T#### format) and their associated tactics " +
		"(e.g. Initial Access, Execution, Privilege Escalation). Use this to understand the adversary " +
		"kill-chain step where the vulnerability is used and to inform detection engineering."
}
func (t *checkATTACKMappingsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkATTACKMappingsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := enrichers.FetchATTACKMappings(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── map_owasp ───────────────────────────────────────

type mapOWASPTool struct{}

func (t *mapOWASPTool) Name() string { return "map_owasp" }
func (t *mapOWASPTool) Description() string {
	return "Map CWE identifiers to OWASP Top 10 2021 categories. This is a deterministic " +
		"static mapping (no network call). Provide a list of CWE IDs (e.g. [\"CWE-79\", \"CWE-89\"]) " +
		"and receive the corresponding OWASP Top 10 categories (e.g. A03:2021 Injection). " +
		"Use this for classification, reporting, and understanding which OWASP Top 10 risk " +
		"category the vulnerability falls under."
}
func (t *mapOWASPTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cwe_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "List of CWE identifiers, e.g. [\"CWE-79\", \"89\", \"CWE-22\"]",
			},
		},
		"required": []string{"cwe_ids"},
	}
}
func (t *mapOWASPTool) Run(_ context.Context, args map[string]any) (string, error) {
	rawList, ok := args["cwe_ids"].([]interface{})
	if !ok || len(rawList) == 0 {
		return "", fmt.Errorf("cwe_ids must be a non-empty array")
	}
	cweIDs := make([]string, 0, len(rawList))
	for _, v := range rawList {
		if s, ok := v.(string); ok && s != "" {
			cweIDs = append(cweIDs, s)
		}
	}
	result := enrichers.MapOWASP(cweIDs)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_osv ──────────────────────────────────────

// checkOSVTool queries the OSV (Open Source Vulnerabilities) database.
// OSV aggregates advisories from 20+ ecosystems under a unified API:
// npm, PyPI, Go, crates.io, RubyGems, Maven, Debian, Alpine, Ubuntu, AlmaLinux,
// Rocky Linux, Bitnami, Drupal, Haskell, OCaml, OSS-Fuzz, RustSec, and more.
//
// Two query modes:
//   - CVE ID:              GET /v1/vulns/{CVE-ID} — returns the OSV advisory cross-linked to that CVE
//   - package + ecosystem: POST /v1/query          — returns all advisories for that package version
//
// This is the primary source for supply chain CVEs where NVD data is sparse
// but the ecosystem advisory (e.g. RustSec, PySec) has detailed affected ranges
// and patch versions. Also used by check_openssf_malicious_packages.
type checkOSVTool struct{}

func (t *checkOSVTool) Name() string { return "check_osv" }
func (t *checkOSVTool) Description() string {
	return "Query OSV.dev (Open Source Vulnerabilities) for advisories covering 20+ package " +
		"ecosystems: npm, PyPI, Go, crates.io, RubyGems, Maven, Debian, Alpine, Ubuntu, " +
		"AlmaLinux, Bitnami, RustSec, OSS-Fuzz, and more. " +
		"Accepts a CVE ID to retrieve the cross-linked OSV advisory, or a package name + " +
		"ecosystem for direct package-level vulnerability lookup with affected version ranges. " +
		"Particularly valuable for supply chain CVEs where NVD data is sparse but the " +
		"ecosystem-specific advisory has detailed patch and affected-range information."
}
func (t *checkOSVTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228 (optional if package provided)",
			},
			"package_name": map[string]any{
				"type":        "string",
				"description": "Exact package name, e.g. 'lodash', 'requests' (optional if cve_id provided)",
			},
			"ecosystem": map[string]any{
				"type":        "string",
				"description": "Package ecosystem: npm, PyPI, Go, crates.io, RubyGems, Maven, Debian, Alpine, etc.",
			},
		},
	}
}
func (t *checkOSVTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	pkgName, _ := args["package_name"].(string)
	ecosystem, _ := args["ecosystem"].(string)

	if cveID == "" && pkgName == "" {
		return "", fmt.Errorf("provide cve_id or package_name + ecosystem")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if cveID != "" {
		cveID = strings.ToUpper(strings.TrimSpace(cveID))
		body, err := httpGetWithTimeout(fetchCtx, "https://api.osv.dev/v1/vulns/"+cveID, 12*time.Second)
		if err != nil {
			return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"OSV: %s"}`, cveID, err.Error()), nil
		}
		return summariseOSVAdvisory(body, cveID), nil
	}

	// Package query.
	queryBody, _ := json.Marshal(map[string]any{
		"package": map[string]any{
			"name":      pkgName,
			"ecosystem": ecosystem,
		},
	})
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(queryBody))
	if err != nil {
		return "", fmt.Errorf("build OSV query: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"package":%q,"ecosystem":%q,"found":false,"note":"OSV API unavailable"}`, pkgName, ecosystem), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read OSV response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"package":%q,"ecosystem":%q,"found":false,"note":"OSV HTTP %d"}`, pkgName, ecosystem, resp.StatusCode), nil
	}
	return summariseOSVQueryResult(respBody, pkgName, ecosystem), nil
}

// summariseOSVAdvisory renders a single OSV advisory record into a compact
// JSON string the LLM can read clearly.
func summariseOSVAdvisory(body []byte, id string) string {
	var adv map[string]any
	if err := json.Unmarshal(body, &adv); err != nil {
		return string(body)
	}
	aliases, _ := adv["aliases"].([]any)
	aliasStrs := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if s, ok := a.(string); ok {
			aliasStrs = append(aliasStrs, s)
		}
	}
	type affRow struct {
		Package string `json:"package"`
	}
	var affected []affRow
	if raw, ok := adv["affected"].([]any); ok {
		for _, a := range raw {
			if m, ok := a.(map[string]any); ok {
				pkg := ""
				if p, ok := m["package"].(map[string]any); ok {
					name, _ := p["name"].(string)
					eco, _ := p["ecosystem"].(string)
					if eco != "" {
						pkg = name + " (" + eco + ")"
					} else {
						pkg = name
					}
				}
				affected = append(affected, affRow{Package: pkg})
			}
		}
	}
	out := map[string]any{
		"id":       adv["id"],
		"aliases":  aliasStrs,
		"summary":  truncStr(adv["summary"], 300),
		"details":  truncStr(adv["details"], 1500),
		"affected": limitSlice(affected, 5),
		"modified": adv["modified"],
		"source":   "osv.dev",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

// summariseOSVQueryResult renders a package advisory list into a compact
// summary the LLM can scan without hitting token limits.
func summariseOSVQueryResult(body []byte, pkgName, ecosystem string) string {
	var result struct {
		Vulns []map[string]any `json:"vulns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return string(body)
	}
	if len(result.Vulns) == 0 {
		return fmt.Sprintf(`{"package":%q,"ecosystem":%q,"found":false,"vuln_count":0,"note":"No OSV advisories found for this package."}`, pkgName, ecosystem)
	}
	type row struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases,omitempty"`
		Summary string   `json:"summary,omitempty"`
	}
	var rows []row
	for _, v := range result.Vulns {
		r := row{}
		r.ID, _ = v["id"].(string)
		if als, ok := v["aliases"].([]any); ok {
			for _, a := range als {
				if s, ok := a.(string); ok {
					r.Aliases = append(r.Aliases, s)
				}
			}
		}
		sum, _ := v["summary"].(string)
		if len(sum) > 150 {
			sum = sum[:150] + "…"
		}
		r.Summary = sum
		rows = append(rows, r)
	}
	out := map[string]any{
		"package":    pkgName,
		"ecosystem":  ecosystem,
		"found":      true,
		"vuln_count": len(rows),
		"vulns":      rows,
		"source":     "osv.dev",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

// ─────────────────────────── check_openssf_malicious_packages ────────────────

// checkOpenSSFMaliciousTool checks whether a package has been reported as
// malicious by the OpenSSF Malicious Packages project
// (github.com/ossf/malicious-packages). Malicious packages are confirmed
// backdoors, typosquatters, dependency confusion payloads, and supply chain
// injection attacks — distinct from ordinary CVEs (bugs). Advisories carry
// IDs like MAL-2024-NNNN and are indexed by the OSV database.
//
// This is especially relevant for JS/npm recon where jsluice and similar
// tools surface third-party package dependencies that may have been reported
// as malicious after the fact.
type checkOpenSSFMaliciousTool struct{}

func (t *checkOpenSSFMaliciousTool) Name() string { return "check_openssf_malicious_packages" }
func (t *checkOpenSSFMaliciousTool) Description() string {
	return "Check whether a package has been flagged as malicious in the OpenSSF Malicious " +
		"Packages dataset (github.com/ossf/malicious-packages). Covers confirmed backdoors, " +
		"typosquatting, dependency confusion, and supply chain injection — distinct from CVEs. " +
		"Returns advisory records with IDs like MAL-YYYY-NNNN. Especially valuable for npm, " +
		"PyPI, crates.io, and Go packages encountered during JS recon or supply chain analysis. " +
		"Provide the exact published package name and its ecosystem."
}
func (t *checkOpenSSFMaliciousTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"package_name": map[string]any{
				"type":        "string",
				"description": "Exact published package name, e.g. 'node-ipc', 'ctx', 'colors'",
			},
			"ecosystem": map[string]any{
				"type":        "string",
				"description": "Package ecosystem: npm, PyPI, crates.io, Go, RubyGems, Maven",
			},
		},
		"required": []string{"package_name", "ecosystem"},
	}
}
func (t *checkOpenSSFMaliciousTool) Run(ctx context.Context, args map[string]any) (string, error) {
	pkgName, _ := args["package_name"].(string)
	ecosystem, _ := args["ecosystem"].(string)
	if pkgName == "" || ecosystem == "" {
		return "", fmt.Errorf("package_name and ecosystem are required")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// OSV includes the openssf/malicious-packages database. Malicious entries
	// carry IDs starting with "MAL-". We query all advisories for the package
	// and filter to those IDs.
	queryBody, _ := json.Marshal(map[string]any{
		"package": map[string]any{
			"name":      pkgName,
			"ecosystem": ecosystem,
		},
	})
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(queryBody))
	if err != nil {
		return "", fmt.Errorf("build OSV query: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"package":%q,"ecosystem":%q,"malicious":false,"note":"OSV API unavailable"}`, pkgName, ecosystem), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read OSV response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"package":%q,"ecosystem":%q,"malicious":false,"note":"OSV HTTP %d"}`, pkgName, ecosystem, resp.StatusCode), nil
	}

	var result struct {
		Vulns []map[string]any `json:"vulns"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return string(respBody), nil
	}

	type malEntry struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases,omitempty"`
		Summary  string   `json:"summary,omitempty"`
		Modified string   `json:"modified,omitempty"`
	}
	var malicious []malEntry
	for _, v := range result.Vulns {
		id, _ := v["id"].(string)
		if !strings.HasPrefix(id, "MAL-") {
			continue
		}
		e := malEntry{ID: id}
		e.Modified, _ = v["modified"].(string)
		if als, ok := v["aliases"].([]any); ok {
			for _, a := range als {
				if s, ok := a.(string); ok {
					e.Aliases = append(e.Aliases, s)
				}
			}
		}
		sum, _ := v["summary"].(string)
		if len(sum) > 200 {
			sum = sum[:200] + "…"
		}
		e.Summary = sum
		malicious = append(malicious, e)
	}

	out := map[string]any{
		"package":         pkgName,
		"ecosystem":       ecosystem,
		"malicious":       len(malicious) > 0,
		"malicious_count": len(malicious),
		"advisories":      malicious,
		"source":          "openssf/malicious-packages via osv.dev",
	}
	if len(malicious) == 0 {
		out["note"] = "No malicious package reports found. Package has not been flagged by OpenSSF."
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_exploitdb ────────────────────────────────

// checkExploitDBTool searches Exploit-DB (exploit-db.com) for working exploit
// code against a CVE using the offensive-security/exploitdb GitHub mirror index.
//
// An Exploit-DB entry is a stronger weaponization signal than a raw PoC gist:
// it represents a categorized, reviewable exploit in the most widely used
// public exploit archive. The tool uses GitHub Code Search to find the CVE in
// the exploitdb repository and classifies matches by exploit type
// (remote / local / webapps / shellcode).
type checkExploitDBTool struct{}

func (t *checkExploitDBTool) Name() string { return "check_exploitdb" }
func (t *checkExploitDBTool) Description() string {
	return "Search Exploit-DB (exploit-db.com / offensive-security/exploitdb) for working exploit " +
		"code against a CVE. An Exploit-DB entry is stronger than a raw PoC — it is a categorized, " +
		"peer-reviewed exploit in the most widely used public exploit archive. " +
		"Returns exploit file paths, URLs, and type (remote/local/webapps/shellcode). " +
		"Uses the Exploit-DB GitHub mirror via Code Search — no API key required, " +
		"though anonymous GitHub search is rate-limited to 10 req/min."
}
func (t *checkExploitDBTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkExploitDBTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// GitHub Code Search within the exploitdb repository.
	// The files_exploits.csv index includes a 'codes' column with CVE IDs;
	// individual exploit source files also reference the CVE in header comments.
	searchURL := "https://api.github.com/search/code?q=" + cveID + "+repo:offensive-security/exploitdb&per_page=10"
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search unavailable"}`, cveID), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub rate limit hit. Set GITHUB_TOKEN env var for higher limits."}`, cveID), nil
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search rejected query (422). CVE ID may be malformed."}`, cveID), nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search HTTP %d"}`, cveID, resp.StatusCode), nil
	}

	var ghResult struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name    string `json:"name"`
			Path    string `json:"path"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &ghResult); err != nil {
		return string(body), nil
	}
	if ghResult.TotalCount == 0 {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"exploit_count":0,"note":"No Exploit-DB entries found for this CVE."}`, cveID), nil
	}

	type exploit struct {
		File    string `json:"file"`
		URL     string `json:"url"`
		Type    string `json:"type,omitempty"`
		Preview string `json:"technique_preview,omitempty"`
	}
	var exploits []exploit
	for _, item := range ghResult.Items {
		// Skip the CSV index and documentation — we want actual exploit source files.
		if strings.HasSuffix(item.Name, ".csv") || strings.HasSuffix(item.Name, ".md") {
			continue
		}
		expType := ""
		switch {
		case strings.Contains(item.Path, "/remote/"):
			expType = "remote"
		case strings.Contains(item.Path, "/local/"):
			expType = "local"
		case strings.Contains(item.Path, "/webapps/"):
			expType = "webapps"
		case strings.HasPrefix(item.Path, "shellcodes/"):
			expType = "shellcode"
		case strings.HasPrefix(item.Path, "exploits/"):
			expType = "exploit"
		}
		e := exploit{File: item.Path, URL: item.HTMLURL, Type: expType}

		// Fetch the first 100 lines of the exploit source so the LLM can describe
		// the technique to a developer. The raw URL for the exploitdb GitHub mirror
		// is constructed from the path under the repo root.
		rawURL := "https://raw.githubusercontent.com/offensive-security/exploitdb/main/" + item.Path
		if src, fetchErr := httpGetWithTimeout(fetchCtx, rawURL, 6*time.Second); fetchErr == nil {
			lines := strings.SplitN(string(src), "\n", 101)
			if len(lines) > 100 {
				lines = lines[:100]
			}
			preview := strings.Join(lines, "\n")
			if len(preview) > 3000 {
				preview = preview[:3000] + "\n…[truncated at 3000 chars]"
			}
			e.Preview = preview
		}

		exploits = append(exploits, e)
	}

	out := map[string]any{
		"cve_id":        cveID,
		"found":         len(exploits) > 0,
		"exploit_count": ghResult.TotalCount,
		"exploits":      exploits,
		"source":        "exploit-db.com (offensive-security/exploitdb)",
		"note":          "technique_preview contains the first 100 lines of exploit source — use it to explain the attack technique to developers",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_poc_github ───────────────────────────────

// checkPoCGitHubTool looks up public PoC repositories in nomi-sec/PoC-in-GitHub.
// This is the same GitHub PoC index used by aggregators such as Zero Day Clock
// Explorer. A hit confirms circulating proof-of-concept code — weaker than
// Metasploit/VulnCheck weaponization or KEV, but useful for DEV NOTE attack
// mechanism detail and RecentPOCDays / OPES X flooring.
type checkPoCGitHubTool struct{}

func (t *checkPoCGitHubTool) Name() string { return "check_poc_github" }
func (t *checkPoCGitHubTool) Description() string {
	return "Look up public proof-of-concept repositories for a CVE via nomi-sec/PoC-in-GitHub " +
		"(the GitHub PoC index also used by Zero Day Clock Explorer). " +
		"Returns PoC repo URLs, star counts, created dates, newest/earliest PoC timestamps, " +
		"and recent_poc_days. A PoC is weaker than Metasploit/VulnCheck weaponization or KEV " +
		"(confirmed in-the-wild) — use it to show exploit code is circulating and to ground " +
		"DEV NOTE attack steps. No API key required."
}
func (t *checkPoCGitHubTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkPoCGitHubTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result := enrichers.FetchPoCGitHub(fetchCtx, cveID)
	out := map[string]any{
		"cve_id":          strings.ToUpper(strings.TrimSpace(cveID)),
		"found":           result.Found,
		"poc_count":       result.POCCount,
		"recent_poc_days": result.RecentPOCDays,
		"newest_poc_at":   result.NewestPOCAt,
		"earliest_poc_at": result.EarliestPOCAt,
		"pocs":            result.POCs,
		"source":          "nomi-sec/PoC-in-GitHub",
		"note":            result.Note,
		"signal_strength": "poc_only — not confirmed ITW; prefer check_vulncheck_exploits / check_weaponization / check_epss_kev for stronger exploitation signals",
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ─────────────────────────── check_trickest ─────────────────────────────────

// checkTrickestTool looks up public PoC/GitHub links in trickest/cve.
// This complements nomi-sec/PoC-in-GitHub with a broader Markdown-indexed
// aggregator (same source used by exploit-availability-check).
type checkTrickestTool struct{}

func (t *checkTrickestTool) Name() string { return "check_trickest" }
func (t *checkTrickestTool) Description() string {
	return "Look up public GitHub PoC/exploit links for a CVE via trickest/cve " +
		"(broader GitHub PoC aggregator that complements nomi-sec/PoC-in-GitHub). " +
		"Returns unique github.com/owner/repo URLs extracted from the CVE Markdown page. " +
		"A hit means public PoC-related repos are indexed — weaker than Metasploit/VulnCheck " +
		"weaponization or KEV. No API key required."
}
func (t *checkTrickestTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkTrickestTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result := enrichers.FetchTrickest(fetchCtx, cveID)
	out := map[string]any{
		"cve_id":          strings.ToUpper(strings.TrimSpace(cveID)),
		"found":           result.Found,
		"poc_count":       result.POCCount,
		"pocs":            result.POCs,
		"source":          "trickest/cve",
		"note":            result.Note,
		"signal_strength": "poc_only — not confirmed ITW; prefer check_vulncheck_exploits / check_weaponization / check_epss_kev for stronger exploitation signals",
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ─────────────────────────── check_cnw_kev ───────────────────────────────────

// checkCNWKEVTool checks whether a CVE appears in the CNW (EU CSIRTs Network)
// KEV catalog, maintained by the European network of national CERTs/CSIRTs
// and exposed via the CIRCL vulnerability-lookup public API.
//
// This is distinct from CISA KEV and ENISA EUVD:
//   - CISA KEV is US-centric and driven by CISA's own observations
//   - ENISA EUVD confirms EU exploitation but lacks exploitation type metadata
//   - CNW KEV is reported bottom-up by individual EU CSIRTs (CERT-PL, CERT Italia,
//     CERT-FR, etc.) and includes exploitation type (ransomware, APT, mass-scanning)
//     and the specific CSIRT that flagged it — useful signal for EU-exposed assets
//
// The catalog is small (~20–100 entries) but high-signal: every entry reflects
// a CSIRT that has directly observed active exploitation in European infrastructure.
// The full list is fetched and searched for the CVE ID.
type checkCNWKEVTool struct{}

func (t *checkCNWKEVTool) Name() string { return "check_cnw_kev" }
func (t *checkCNWKEVTool) Description() string {
	return "Check the CNW (EU CSIRTs Network) Known Exploited Vulnerabilities catalog via the " +
		"CIRCL vulnerability-lookup public API. Distinct from CISA KEV and ENISA EUVD: entries are " +
		"reported bottom-up by individual EU national CSIRTs (CERT-PL, CERT Italia, CERT-FR, etc.) " +
		"and include exploitation type (ransomware, APT), the specific reporting CSIRT, and EUVD ID. " +
		"Membership here means a European CSIRT has directly observed active exploitation — " +
		"strong signal for assets with EU exposure. Small catalog, all entries are high-confidence."
}
func (t *checkCNWKEVTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2024-55591",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkCNWKEVTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// The CNW KEV endpoint returns the full catalog as a paged list.
	// The catalog is small enough to fetch in one call.
	body, err := httpGetWithTimeout(fetchCtx, "https://vulnerability.circl.lu/api/cnw_kev/", 12*time.Second)
	if err != nil {
		return fmt.Sprintf(`{"cve_id":%q,"in_cnw_kev":false,"note":"CNW KEV API unavailable: %s"}`, cveID, err.Error()), nil
	}

	var response struct {
		Metadata struct {
			Count int `json:"count"`
		} `json:"metadata"`
		Data []struct {
			CVE                   string `json:"CVE"`
			EUVD                  string `json:"EUVD,omitempty"`
			VendorProject         string `json:"vendorProject,omitempty"`
			Product               string `json:"product,omitempty"`
			DateReported          string `json:"dateReported,omitempty"`
			OriginSource          string `json:"originSource,omitempty"`
			ShortDescription      string `json:"shortDescription,omitempty"`
			ExploitationType      string `json:"exploitationType,omitempty"`
			ThreatActorsExploiting string `json:"threatActorsExploiting,omitempty"`
			Notes                 string `json:"notes,omitempty"`
			CWEs                  string `json:"cwes,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Sprintf(`{"cve_id":%q,"in_cnw_kev":false,"note":"CNW KEV parse error"}`, cveID), nil
	}

	for _, entry := range response.Data {
		if strings.EqualFold(entry.CVE, cveID) {
			// Omit dash-only placeholder values.
			clean := func(s string) string {
				if strings.TrimSpace(s) == "-" {
					return ""
				}
				return s
			}
			result := map[string]any{
				"cve_id":                 cveID,
				"in_cnw_kev":             true,
				"euvd_id":                clean(entry.EUVD),
				"vendor_project":         clean(entry.VendorProject),
				"product":                clean(entry.Product),
				"date_reported":          clean(entry.DateReported),
				"reporting_csirt":        clean(entry.OriginSource),
				"exploitation_type":      clean(entry.ExploitationType),
				"threat_actors":          clean(entry.ThreatActorsExploiting),
				"short_description":      clean(entry.ShortDescription),
				"csirt_advisory_url":     clean(entry.Notes),
				"cwes":                   clean(entry.CWEs),
				"source":                 "CNW (EU CSIRTs Network) KEV via vulnerability.circl.lu",
				"catalog_size":           response.Metadata.Count,
			}
			b, _ := json.MarshalIndent(result, "", "  ")
			return string(b), nil
		}
	}

	return fmt.Sprintf(
		`{"cve_id":%q,"in_cnw_kev":false,"catalog_size":%d,"note":"Not in EU CSIRTs Network KEV. Catalog has %d entries — absence does not rule out exploitation, only EU CSIRT-reported cases are listed.","source":"CNW KEV via vulnerability.circl.lu"}`,
		cveID, response.Metadata.Count, response.Metadata.Count,
	), nil
}

// ─────────────────────────── check_cisa_ics_advisory ─────────────────────────

// checkCISAICSAdvisoryTool checks whether a CVE appears in CISA ICS-CERT CSAF
// advisories (advisories.cisa.gov / github.com/cisagov/CSAF).
//
// These are distinct from CISA Vulnrichment (which enriches CVE records at the
// metadata level). ICS-CERT advisories are published for CVEs that affect
// specific industrial control system products: PLCs, HMIs, RTUs, SCADA
// software, industrial networking equipment, and safety systems.
//
// An ICS advisory identifies EXACTLY which OT vendor products are vulnerable
// (e.g. "Siemens SIMATIC S7-1500 PLC, firmware < 3.1.0") — context NVD does
// not provide. Advisory IDs follow the pattern ICSA-YY-DDD-NN for ICS-CERT and
// ICSMA-YY-DDD-NN for medical device advisories.
//
// Uses GitHub Code Search on the cisagov/CSAF repository — no API key needed.
type checkCISAICSAdvisoryTool struct{}

func (t *checkCISAICSAdvisoryTool) Name() string { return "check_cisa_ics_advisory" }
func (t *checkCISAICSAdvisoryTool) Description() string {
	return "Check CISA ICS-CERT CSAF advisories for a CVE. ICS advisories are distinct from " +
		"CISA Vulnrichment: they identify specific industrial control system products affected — " +
		"PLCs, HMIs, RTUs, SCADA software, industrial networking gear, and safety systems. " +
		"An ICS advisory (ICSA-YY-DDD-NN) tells you WHICH OT vendor products are vulnerable " +
		"(e.g. 'Siemens SIMATIC S7-1500 firmware < 3.1.0') — context NVD does not carry. " +
		"Presence here is a strong ICS/OT relevance signal: CISA only publishes ICS advisories " +
		"for vulnerabilities with confirmed industrial system impact. " +
		"Uses the cisagov/CSAF GitHub repo via Code Search — no API key required."
}
func (t *checkCISAICSAdvisoryTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2023-46604",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkCISAICSAdvisoryTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Search the cisagov/CSAF repository for CSAF advisory files referencing
	// this CVE. ICS-CERT advisories use the filename pattern icsa-* or icsma-*.
	searchURL := "https://api.github.com/search/code?q=" + cveID + "+repo:cisagov/CSAF&per_page=10"
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search unavailable"}`, cveID), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub rate limit hit. Set GITHUB_TOKEN env var for higher limits."}`, cveID), nil
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search rejected query (422)."}`, cveID), nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"GitHub search HTTP %d"}`, cveID, resp.StatusCode), nil
	}

	var ghResult struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name    string `json:"name"`
			Path    string `json:"path"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &ghResult); err != nil {
		return string(body), nil
	}
	if ghResult.TotalCount == 0 {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"ics_advisory_count":0,"note":"No CISA ICS-CERT advisory found for this CVE. This does not rule out ICS impact — not all ICS CVEs receive a dedicated advisory."}`, cveID), nil
	}

	type advisory struct {
		AdvisoryID string `json:"advisory_id"`
		Type       string `json:"type"`
		File       string `json:"file"`
		URL        string `json:"url"`
	}
	var advisories []advisory
	for _, item := range ghResult.Items {
		// Only count actual CSAF advisory JSON files, not README or index files.
		if !strings.HasSuffix(item.Name, ".json") {
			continue
		}
		name := strings.ToLower(item.Name)
		advType := "cisa"
		switch {
		case strings.HasPrefix(name, "icsa-"):
			advType = "ICS-CERT"
		case strings.HasPrefix(name, "icsma-"):
			advType = "ICS-CERT Medical"
		case strings.HasPrefix(name, "aa"):
			advType = "CISA Alert"
		}
		// Derive a clean advisory ID from the filename (strip .json suffix).
		advID := strings.TrimSuffix(item.Name, ".json")
		advisories = append(advisories, advisory{
			AdvisoryID: advID,
			Type:       advType,
			File:       item.Path,
			URL:        item.HTMLURL,
		})
	}

	icsFound := len(advisories) > 0
	out := map[string]any{
		"cve_id":           cveID,
		"found":            icsFound,
		"advisory_count":   ghResult.TotalCount,
		"advisories":       advisories,
		"source":           "CISA ICS-CERT (cisagov/CSAF)",
		"ics_ot_relevant":  icsFound,
	}
	if icsFound {
		out["note"] = "CISA published an ICS-CERT advisory for this CVE — it affects industrial control systems. Fetch the advisory URL for affected product details (vendor, model, firmware version)."
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_ics_vendor_csaf ───────────────────────────

// icsVendorEntry maps a CPE vendor string prefix to display metadata for a
// known ICS/OT vendor.
type icsVendorEntry struct {
	Name        string // Human-readable vendor name
	AdvisoryURL string // Security advisory portal (may contain {CVE} placeholder)
	CSAFIndex   string // CSAF index or provider-metadata URL, if published
	PSIRTEmail  string // CNA source identifier email from NVD (if known)
}

// icsVendorMap is keyed by the lowercase CPE vendor string that NVD uses.
// Entries with a PSIRTEmail will also match via the CVE's sourceIdentifier field,
// catching cases where the CPE configurations section is sparse or missing.
var icsVendorMap = map[string]icsVendorEntry{
	"siemens": {
		Name:        "Siemens ProductCERT",
		AdvisoryURL: "https://cert-portal.siemens.com/productcert/html/search.html",
		CSAFIndex:   "https://cert-portal.siemens.com/productcert/csaf/",
		PSIRTEmail:  "productcert@siemens.com",
	},
	"rockwell_automation": {
		Name:        "Rockwell Automation",
		AdvisoryURL: "https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html",
		PSIRTEmail:  "secure@ra.rockwell.com",
	},
	"schneider-electric": {
		Name:        "Schneider Electric",
		AdvisoryURL: "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp",
		PSIRTEmail:  "cybersecurity@se.com",
	},
	"honeywell": {
		Name:        "Honeywell Product Security",
		AdvisoryURL: "https://www.honeywell.com/us/en/product-security",
		PSIRTEmail:  "product.security@honeywell.com",
	},
	"abb": {
		Name:        "ABB PSIRT",
		AdvisoryURL: "https://new.abb.com/about/technology/cyber-security/alerts-and-notifications",
		PSIRTEmail:  "cybersecurity@abb.com",
	},
	"beckhoff": {
		Name:        "Beckhoff Automation",
		AdvisoryURL: "https://cert.beckhoff.com/",
		CSAFIndex:   "https://cert.beckhoff.com/.well-known/csaf/provider-metadata.json",
		PSIRTEmail:  "security@beckhoff.com",
	},
	"phoenix_contact": {
		Name:        "Phoenix Contact PSIRT",
		AdvisoryURL: "https://cert.phoenix-contact.com/",
		CSAFIndex:   "https://cert.phoenix-contact.com/.well-known/csaf/provider-metadata.json",
		PSIRTEmail:  "product-security@phoenixcontact.com",
	},
	"moxa": {
		Name:        "Moxa PSIRT",
		AdvisoryURL: "https://www.moxa.com/en/support/product-support/security-advisory",
		PSIRTEmail:  "security@moxa.com",
	},
	"advantech": {
		Name:        "Advantech PSIRT",
		AdvisoryURL: "https://www.advantech.com/en/support/details/cybersecurity-advisory",
		PSIRTEmail:  "security@advantech.com.tw",
	},
	"ge_digital": {
		Name:        "GE / GE Vernova Digital",
		AdvisoryURL: "https://www.ge.com/digital/cybersecurity",
	},
	"emerson": {
		Name:        "Emerson Electric PSIRT",
		AdvisoryURL: "https://www.emerson.com/en-us/support/certificates-and-notifications",
		PSIRTEmail:  "IPCS@Emerson.com",
	},
	"yokogawa": {
		Name:        "Yokogawa PSIRT",
		AdvisoryURL: "https://www.yokogawa.com/library/resources/white-papers/yokogawa-security-advisories/",
		PSIRTEmail:  "security@yokogawa.com",
	},
	"mitsubishielectric": {
		Name:        "Mitsubishi Electric PSIRT",
		AdvisoryURL: "https://www.mitsubishielectric.com/en/psirt/vulnerability/index.html",
		PSIRTEmail:  "Mitsubishi.CyberSecurity@mt.MitsubishiElectric.co.jp",
	},
	"codesys": {
		Name:        "CODESYS PSIRT",
		AdvisoryURL: "https://www.codesys.com/security/security-reports.html",
		PSIRTEmail:  "security@codesys.com",
	},
	"wago": {
		Name:        "WAGO CERT",
		AdvisoryURL: "https://cert.wago.com/",
	},
	"pilz": {
		Name:        "Pilz CERT",
		AdvisoryURL: "https://cert.pilz.com/",
	},
	"sick_ag": {
		Name:        "SICK AG Product Security",
		AdvisoryURL: "https://www.sick.com/security",
	},
	"omron": {
		Name:        "Omron PSIRT",
		AdvisoryURL: "https://www.ia.omron.com/product/vulnerability/",
	},
	"fanuc": {
		Name:        "FANUC Product Security",
		AdvisoryURL: "https://www.fanuc.co.jp/en/product/cybersecurity/index.html",
	},
	"bosch": {
		Name:        "Bosch PSIRT",
		AdvisoryURL: "https://psirt.bosch.com/security-advisories/",
		PSIRTEmail:  "cybersecurity@bosch.com",
	},
	"b-r_industrial_automation": {
		Name:        "B&R Industrial Automation",
		AdvisoryURL: "https://www.br-automation.com/en/downloads/software/safety-and-security/security-advisories/",
	},
	"pepperl-fuchs": {
		Name:        "Pepperl+Fuchs",
		AdvisoryURL: "https://www.pepperl-fuchs.com/global/en/security_advisories.htm",
		CSAFIndex:   "https://cert.pepperl-fuchs.com/.well-known/csaf/provider-metadata.json",
	},
	"endress_hauser": {
		Name:        "Endress+Hauser",
		AdvisoryURL: "https://www.endress.com/en/support/cybersecurity",
	},
	"festo": {
		Name:        "Festo SE",
		AdvisoryURL: "https://www.festo.com/net/SupportPortal/Downloads/cybersecurity",
	},
	"nozomi_networks": {
		Name:        "Nozomi Networks",
		AdvisoryURL: "https://www.nozominetworks.com/security",
	},
}

// checkICSVendorCSAFTool resolves ICS/OT vendor context for a CVE using the
// NVD CVE 2.0 API. It extracts:
//
//  1. The CVE's sourceIdentifier (CNA email) to identify which ICS vendor
//     PSIRT reported the vulnerability directly — the strongest ICS signal
//     (e.g. productcert@siemens.com means Siemens assigned and owns this CVE).
//
//  2. CPE configuration vendor strings from the NVD configurations array,
//     cross-referenced against 25+ known ICS/OT vendor prefixes.
//
//  3. Affected product details from the vendor CNA's "affected" block —
//     exact product model names and firmware version ranges as the vendor
//     reported them (e.g. "SIMATIC S7-1200 firmware < 4.0, Function State < 11").
//
//  4. Vendor advisory reference URLs from the NVD references array,
//     filtered to vendor advisory and CSAF portal links.
//
// This surfaces the same product-level ICS context that platforms like
// BreachSpider aggregate, without requiring paid API access.
// Set NVD_API_KEY env var for higher rate limits (50 req/30s vs 5 req/30s).
type checkICSVendorCSAFTool struct{}

func (t *checkICSVendorCSAFTool) Name() string { return "check_ics_vendor_csaf" }
func (t *checkICSVendorCSAFTool) Description() string {
	return "Resolve ICS/OT vendor context for a CVE via the NVD API. Returns: " +
		"(1) which ICS vendor PSIRT owns the CVE as CNA (e.g. Siemens ProductCERT, Rockwell, Schneider); " +
		"(2) CPE-matched ICS vendors with links to their security advisory portals and CSAF indexes; " +
		"(3) exact affected product models and firmware version ranges as reported by the vendor CNA; " +
		"(4) direct vendor advisory reference URLs. " +
		"An ICS PSIRT as CNA is the strongest OT relevance signal — it means the vendor " +
		"discovered and assigned the CVE to their own industrial product. " +
		"Covers 25+ vendors: Siemens, Rockwell, Schneider, Honeywell, ABB, Beckhoff, " +
		"Phoenix Contact, Moxa, Advantech, Emerson, Yokogawa, Mitsubishi, CODESYS, and more. " +
		"Set NVD_API_KEY env var for higher rate limits."
}
func (t *checkICSVendorCSAFTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2019-13945",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkICSVendorCSAFTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	nvdURL := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, nvdURL, nil)
	if err != nil {
		return "", fmt.Errorf("build NVD request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	// Use NVD_API_KEY if configured for higher rate limits.
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		req.Header.Set("apiKey", key)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"cve_id":%q,"ics_relevant":false,"note":"NVD API unavailable: %s"}`, cveID, err.Error()), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap
	if err != nil {
		return "", fmt.Errorf("read NVD response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return fmt.Sprintf(`{"cve_id":%q,"ics_relevant":false,"note":"NVD rate limit hit. Set NVD_API_KEY for 50 req/30s."}`, cveID), nil
	case http.StatusNotFound:
		return fmt.Sprintf(`{"cve_id":%q,"ics_relevant":false,"note":"CVE not found in NVD."}`, cveID), nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"cve_id":%q,"ics_relevant":false,"note":"NVD HTTP %d"}`, cveID, resp.StatusCode), nil
	}

	// Parse the NVD response envelope.
	var nvdResp struct {
		TotalResults int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID               string `json:"id"`
				SourceIdentifier string `json:"sourceIdentifier"`
				Affected         []struct {
					Source      string `json:"source"`
					AffectedData []struct {
						Vendor   string `json:"vendor"`
						Product  string `json:"product"`
						Versions []struct {
							Version string `json:"version"`
							Status  string `json:"status"`
						} `json:"versions"`
					} `json:"affectedData"`
				} `json:"affected"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Vulnerable bool   `json:"vulnerable"`
							Criteria   string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL  string   `json:"url"`
					Tags []string `json:"tags"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvdResp); err != nil || nvdResp.TotalResults == 0 {
		return fmt.Sprintf(`{"cve_id":%q,"ics_relevant":false,"note":"CVE not in NVD or parse error."}`, cveID), nil
	}
	cve := nvdResp.Vulnerabilities[0].CVE

	// ── Step 1: CNA / sourceIdentifier check ───────────────────────────────
	// If the CVE source email matches a known ICS PSIRT, this is a direct ICS CVE.
	type matchedVendor struct {
		Name        string `json:"name"`
		MatchedVia  string `json:"matched_via"`
		AdvisoryURL string `json:"advisory_url,omitempty"`
		CSAFIndex   string `json:"csaf_index,omitempty"`
	}
	matchedVendors := make(map[string]matchedVendor) // keyed by vendor name to deduplicate

	srcLower := strings.ToLower(cve.SourceIdentifier)
	for cpeKey, info := range icsVendorMap {
		if info.PSIRTEmail != "" && strings.EqualFold(cve.SourceIdentifier, info.PSIRTEmail) {
			matchedVendors[cpeKey] = matchedVendor{
				Name:        info.Name,
				MatchedVia:  "CNA (sourceIdentifier: " + cve.SourceIdentifier + ")",
				AdvisoryURL: info.AdvisoryURL,
				CSAFIndex:   info.CSAFIndex,
			}
		}
		_ = srcLower // used via strings.EqualFold above
	}

	// ── Step 2: CPE configuration vendor strings ────────────────────────────
	cpeVendors := make(map[string]bool)
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpe := range node.CPEMatch {
				// CPE format: cpe:2.3:{part}:{vendor}:{product}:...
				parts := strings.Split(cpe.Criteria, ":")
				if len(parts) >= 5 {
					vendor := strings.ToLower(parts[3])
					cpeVendors[vendor] = true
				}
			}
		}
	}
	for cpeKey, info := range icsVendorMap {
		if _, hit := cpeVendors[cpeKey]; hit {
			if _, exists := matchedVendors[cpeKey]; !exists {
				matchedVendors[cpeKey] = matchedVendor{
					Name:        info.Name,
					MatchedVia:  "CPE vendor string: " + cpeKey,
					AdvisoryURL: info.AdvisoryURL,
					CSAFIndex:   info.CSAFIndex,
				}
			}
		}
	}

	// ── Step 3: Vendor CNA affected product details ─────────────────────────
	type affectedProduct struct {
		Vendor   string `json:"vendor"`
		Product  string `json:"product"`
		Versions string `json:"versions,omitempty"`
	}
	var products []affectedProduct
	for _, aff := range cve.Affected {
		for _, ad := range aff.AffectedData {
			versionStr := ""
			for _, v := range ad.Versions {
				if versionStr != "" {
					versionStr += "; "
				}
				versionStr += v.Version
				if v.Status != "" && v.Status != "affected" {
					versionStr += " (" + v.Status + ")"
				}
			}
			products = append(products, affectedProduct{
				Vendor:   ad.Vendor,
				Product:  ad.Product,
				Versions: versionStr,
			})
		}
	}
	// Cap at 10 products to avoid token explosion on wide CVEs.
	if len(products) > 10 {
		products = products[:10]
	}

	// ── Step 4: Vendor advisory reference URLs ─────────────────────────────
	type advisoryRef struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags,omitempty"`
	}
	var vendorRefs []advisoryRef
	for _, ref := range cve.References {
		for _, tag := range ref.Tags {
			if strings.Contains(strings.ToLower(tag), "vendor") ||
				strings.Contains(strings.ToLower(tag), "advisory") ||
				strings.Contains(strings.ToLower(tag), "csaf") {
				vendorRefs = append(vendorRefs, advisoryRef{URL: ref.URL, Tags: ref.Tags})
				break
			}
		}
	}

	// ── Compose result ──────────────────────────────────────────────────────
	icsRelevant := len(matchedVendors) > 0
	vendorList := make([]matchedVendor, 0, len(matchedVendors))
	for _, v := range matchedVendors {
		vendorList = append(vendorList, v)
	}

	out := map[string]any{
		"cve_id":              cveID,
		"ics_relevant":        icsRelevant,
		"source_identifier":   cve.SourceIdentifier,
		"matched_ics_vendors": vendorList,
		"affected_products":   products,
		"vendor_advisories":   vendorRefs,
		"source":              "NVD CVE 2.0 API (services.nvd.nist.gov)",
	}
	if !icsRelevant {
		out["note"] = "No ICS/OT vendor CPE strings or PSIRT CNA email matched. This CVE does not appear to directly affect industrial control system products from the 25 monitored vendors. It may still affect IT components deployed in OT networks."
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_ransomfeed ────────────────────────────────
//
// checkRansomfeedTool queries the RansomFeed.it live feed to surface recent
// ransomware victim activity for a specific gang or domain.
//
// Use case in CVE analysis: when another tool (check_epss_kev, check_cnw_kev,
// check_vulncheck_exploits) identifies a ransomware group actively exploiting
// a CVE, this tool answers "how active and financially impactful is that group
// right now?" — victim count, sectors targeted, countries hit, and data volumes
// published — all strong predictors of breach cost per the FIRE report.
//
// API: https://api.ransomfeed.it/ returns ~100 most-recent victim events as a
// flat JSON array. Filtering by gang is performed client-side.

type checkRansomfeedTool struct{}

func (t *checkRansomfeedTool) Name() string { return "check_ransomfeed" }

func (t *checkRansomfeedTool) Description() string {
	return `Query the RansomFeed.it live feed for ransomware gang activity and victim intelligence.

Provide EITHER:
  gang_name — look up recent victims attributed to a specific ransomware group (e.g. "lockbit3", "qilin", "akira")
  domain     — check whether a specific company domain appears as a recent victim

Returns: victim count, top targeted sectors, top countries, average data volume published,
and up to 5 recent notable victims. Use this AFTER check_epss_kev or check_cnw_kev
identifies a gang known to exploit the CVE under analysis — the profile tells you how
prolific and financially impactful that group is, which directly informs OPES prioritisation.`
}

func (t *checkRansomfeedTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"gang_name": map[string]any{
				"type":        "string",
				"description": "Ransomware group name (case-insensitive partial match, e.g. 'lockbit', 'akira', 'qilin').",
			},
			"domain": map[string]any{
				"type":        "string",
				"description": "Company domain to look up as a potential victim (e.g. 'example.com').",
			},
		},
	}
}

func (t *checkRansomfeedTool) Run(ctx context.Context, args map[string]any) (string, error) {
	gangName, _ := args["gang_name"].(string)
	domain, _ := args["domain"].(string)

	if gangName == "" && domain == "" {
		return `{"error":"Provide either gang_name or domain."}`, nil
	}

	// Fetch the RansomFeed live event feed.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ransomfeed.it/", nil)
	if err != nil {
		return "", fmt.Errorf("ransomfeed: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"error":"RansomFeed API unreachable: %s"}`, err), nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf(`{"error":"RansomFeed API HTTP %d"}`, resp.StatusCode), nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("ransomfeed: read: %w", err)
	}

	type rfEvent struct {
		ID          int    `json:"id"`
		Date        string `json:"date"`
		Victim      string `json:"victim"`
		Gang        string `json:"gang"`
		Country     string `json:"country"`
		Website     string `json:"website"`
		Description string `json:"description"`
		WorkSector  string `json:"work_sector"`
		DatasetPub  string `json:"dataset_pub"` // GB of data published, if any
	}
	var events []rfEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return fmt.Sprintf(`{"error":"RansomFeed parse failed: %s"}`, err), nil
	}

	gangLower := strings.ToLower(gangName)
	domainLower := strings.ToLower(domain)

	// Filter events.
	var matched []rfEvent
	for _, e := range events {
		if gangLower != "" && strings.Contains(strings.ToLower(e.Gang), gangLower) {
			matched = append(matched, e)
		} else if domainLower != "" &&
			(strings.Contains(strings.ToLower(e.Website), domainLower) ||
				strings.Contains(strings.ToLower(e.Victim), domainLower)) {
			matched = append(matched, e)
		}
	}

	if len(matched) == 0 {
		query := gangName
		if domain != "" {
			query = domain
		}
		return fmt.Sprintf(`{"query":%q,"found":false,"note":"No recent RansomFeed events matched. The gang may be inactive in the current feed window, or the domain has not been listed as a public victim."}`, query), nil
	}

	// Aggregate statistics.
	sectorCount := map[string]int{}
	countryCount := map[string]int{}
	var dataPoints []string

	type recentVictim struct {
		Date    string `json:"date"`
		Victim  string `json:"victim"`
		Gang    string `json:"gang"`
		Country string `json:"country"`
		Sector  string `json:"sector,omitempty"`
	}
	var recent []recentVictim

	for _, e := range matched {
		if e.WorkSector != "" {
			sectorCount[e.WorkSector]++
		}
		if e.Country != "" {
			countryCount[e.Country]++
		}
		if e.DatasetPub != "" && e.DatasetPub != "0" {
			dataPoints = append(dataPoints, e.DatasetPub+" GB ("+e.Victim+")")
		}
		if len(recent) < 5 {
			recent = append(recent, recentVictim{
				Date:    e.Date,
				Victim:  e.Victim,
				Gang:    e.Gang,
				Country: e.Country,
				Sector:  e.WorkSector,
			})
		}
	}

	topSectors := topN(sectorCount, 5)
	topCountries := topN(countryCount, 5)

	out := map[string]any{
		"query":         gangName + domain,
		"match_type":    func() string {
			if gangLower != "" {
				return "gang"
			}
			return "domain"
		}(),
		"event_count":   len(matched),
		"top_sectors":   topSectors,
		"top_countries": topCountries,
		"recent_victims": recent,
		"source":        "RansomFeed.it live feed (api.ransomfeed.it)",
		"note": fmt.Sprintf(
			"Feed reflects the ~100 most recent publicly posted ransomware events. "+
				"%d events matched '%s'. Use for sector/impact profiling of ransomware groups "+
				"known to exploit the CVE under analysis.",
			len(matched), gangName+domain,
		),
	}
	if len(dataPoints) > 0 {
		out["published_data_samples"] = dataPoints
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}

// topN returns up to n keys from a frequency map, sorted by count descending.
func topN(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range m {
		if k != "" {
			pairs = append(pairs, kv{k, v})
		}
	}
	// Simple insertion sort — small maps (<100 keys).
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j].v > pairs[j-1].v; j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
	if n > len(pairs) {
		n = len(pairs)
	}
	out := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		out[i] = map[string]any{"name": pairs[i].k, "count": pairs[i].v}
	}
	return out
}

// ─────────────────────────── exec helpers ───────────────────────────────────

// execLookup returns the full path to a binary or "" if not found.
func execLookup(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// execRun runs a binary with the given args and additional env vars.
// Returns combined stdout/stderr on success, error on non-zero exit.
func execRun(ctx context.Context, path string, args []string, extraEnv map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	// Inherit current env and add overrides.
	cmd.Env = os.Environ()
	for k, v := range extraEnv {
		if v != "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec %s: %w (stderr: %s)", path, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
