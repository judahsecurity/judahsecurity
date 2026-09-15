package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// vulnxBaseURL is the public ProjectDiscovery vulnerability lookup endpoint.
// Unauthenticated requests are heavily rate-limited; PDCP_API_KEY raises the
// quota.
const vulnxBaseURL = "https://api.projectdiscovery.io/v2/vulnerability/"

// VulnxClient fetches CVE records from the ProjectDiscovery vulnx API and
// returns them in schema.CVE shape. Used by the daemon on-demand whenever a
// CVE id isn't already in oracle.cves.
//
// We pick vulnx as the primary on-demand source because:
//
//   - One HTTP call returns a merged record (CVSS from multiple sources +
//     EPSS + CISA/VulnCheck KEV + references + CPEs + PoC count + Nuclei
//     template name). Equivalent NVD/EPSS calls would be 3-4 round trips.
//   - The same source is already used by the ReAct loop's search_vulnx tool,
//     so the LLM and the store stay consistent.
//
// The client is intentionally minimal — no retries, no caching. Callers
// (the daemon) handle caching by upserting into oracle.cves; this struct is
// stateless and safe for concurrent use.
type VulnxClient struct {
	httpClient *http.Client
	pdcpKey    string
}

// NewVulnxClient constructs a VulnxClient. The pdcpKey is optional; when
// supplied it is sent as X-PDCP-Key for higher rate limits.
func NewVulnxClient(pdcpKey string) *VulnxClient {
	return &VulnxClient{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		pdcpKey:    pdcpKey,
	}
}

// FetchCVE returns a canonical CVE record for the given id, or (nil, nil)
// if vulnx does not have that CVE. A genuine error (network, parsing) is
// returned as a non-nil error.
//
// The CVE id is case-normalised to upper-case before issuing the request.
func (c *VulnxClient) FetchCVE(ctx context.Context, cveID string) (*schema.CVE, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("vulnx: empty cve id")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnxBaseURL+cveID, nil)
	if err != nil {
		return nil, fmt.Errorf("vulnx: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")
	if c.pdcpKey != "" {
		req.Header.Set("X-PDCP-Key", c.pdcpKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vulnx: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("vulnx: rate limited (set PDCP_API_KEY for higher quota)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vulnx: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB
	if err != nil {
		return nil, fmt.Errorf("vulnx: read body: %w", err)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("vulnx: parse envelope: %w", err)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, nil
	}
	return parseVulnx(cveID, envelope.Data)
}

// vulnxRaw is the subset of fields we consume from the vulnx response.
// Extra fields are silently ignored so vulnx schema additions don't break
// the daemon.
type vulnxRaw struct {
	CVEID          string          `json:"cve_id"`
	Severity       string          `json:"severity"`
	Description    string          `json:"description"`
	CVSSScore      float64         `json:"cvss_score"`
	CVSSMetrics    json.RawMessage `json:"cvss_metrics"`
	EPSSScore      float64         `json:"epss_score"`
	EPSSPercentile float64         `json:"epss_percentile"`
	IsKEV          bool            `json:"is_kev"`
	IsVKEV         bool            `json:"is_vkev"`
	KEV            *struct {
		DateAdded string `json:"dateAdded"`
	} `json:"kev"`
	POCCount         int              `json:"poc_count"`
	POCs             []map[string]any `json:"pocs"`
	Templates        []map[string]any `json:"templates"`
	Filename         string           `json:"filename"`
	CWE              []string         `json:"cwe"`
	References       []string         `json:"references"`
	AffectedProducts []map[string]any `json:"affected_products"`
	CPEs             []string         `json:"cpe"`
	PublishedAt      string           `json:"published_at"`
	UpdatedAt        string           `json:"updated_at"`
	DateAdded        string           `json:"date_added"`
}

// parseVulnx converts a raw vulnx response into a schema.CVE.
//
// vulnx packages all CVSS variants (NVD, CNA, ADP, vendor) under
// "cvss_metrics". We flatten them into []CVSSVector so the Phase A reasoner
// can reconcile disagreements as it does for natively-ingested CVEs.
func parseVulnx(cveID string, data json.RawMessage) (*schema.CVE, error) {
	var raw vulnxRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("vulnx: parse data: %w", err)
	}

	pub := parseTime(raw.PublishedAt, time.Now().UTC())
	mod := parseTime(raw.UpdatedAt, pub)

	cve := &schema.CVE{
		ID:            cveID,
		PublishedAt:   pub,
		ModifiedAt:    mod,
		Description:   raw.Description,
		CWEs:          dedupeStrings(raw.CWE),
		POCCount:      raw.POCCount,
		PrimarySource: "vulnx",
		InKEV:         raw.IsKEV || raw.IsVKEV,
	}

	if raw.KEV != nil && raw.KEV.DateAdded != "" {
		if t, err := time.Parse("2006-01-02", raw.KEV.DateAdded); err == nil {
			cve.KEVAddedOn = &t
		}
	} else if raw.DateAdded != "" {
		if t, err := time.Parse("2006-01-02", raw.DateAdded); err == nil {
			cve.KEVAddedOn = &t
		}
	}

	if raw.EPSSScore > 0 || raw.EPSSPercentile > 0 {
		cve.EPSS = &schema.EPSSScore{
			Score:      raw.EPSSScore,
			Percentile: raw.EPSSPercentile,
			ScoredOn:   time.Now().UTC(),
		}
	}

	// CVSS vectors — vulnx returns them under cvss_metrics with keys like
	// "cvss_v31", "cvss_v40", with "source" + "vector" + "score" fields.
	cve.CVSSVectors = parseCVSSMetrics(raw.CVSSMetrics, raw.CVSSScore, raw.Severity)

	// Nuclei template name is exposed as `filename` on a hit row, e.g.
	// "cves/2024/CVE-2024-12345.yaml". Templates array may also be present.
	if raw.Filename != "" {
		cve.NucleiTemplate = raw.Filename
	} else if len(raw.Templates) > 0 {
		if fn, ok := raw.Templates[0]["filename"].(string); ok {
			cve.NucleiTemplate = fn
		}
	}

	for _, url := range raw.References {
		if url == "" {
			continue
		}
		cve.References = append(cve.References, schema.Reference{
			URL:        url,
			SourceKind: classifyReferenceKind(url),
		})
	}

	for _, cpe := range raw.CPEs {
		if cpe == "" {
			continue
		}
		cve.CPEs = append(cve.CPEs, schema.CPEMatch{URI: cpe, Vulnerable: true})
	}

	return cve, nil
}

// parseCVSSMetrics walks the cvss_metrics object. vulnx returns shape:
//
//	{
//	  "cvss_v31": [
//	    {"type":"Primary","source":"nvd","score":9.8,"vector":"CVSS:3.1/...","severity":"CRITICAL"},
//	    {"type":"Secondary","source":"cisa-adp","score":7.5,...}
//	  ],
//	  "cvss_v40": [...]
//	}
//
// Each version slice may have multiple entries from different sources.
// We flatten into []CVSSVector and tag the version from the key.
func parseCVSSMetrics(raw json.RawMessage, topScore float64, severity string) []schema.CVSSVector {
	var byVersion map[string][]struct {
		Type     string  `json:"type"`
		Source   string  `json:"source"`
		Score    float64 `json:"score"`
		Vector   string  `json:"vector"`
		Severity string  `json:"severity"`
	}
	if err := json.Unmarshal(raw, &byVersion); err != nil {
		// Fall back to a single vector built from the top-level score.
		if topScore > 0 {
			return []schema.CVSSVector{{
				Source: "vulnx", Version: "3.1", Score: topScore, Severity: strings.ToLower(severity),
			}}
		}
		return nil
	}

	var out []schema.CVSSVector
	for key, items := range byVersion {
		version := "3.1"
		switch {
		case strings.Contains(key, "v40"), strings.Contains(key, "v4"):
			version = "4.0"
		case strings.Contains(key, "v30"):
			version = "3.0"
		case strings.Contains(key, "v20"), strings.Contains(key, "v2"):
			version = "2.0"
		}
		for _, it := range items {
			out = append(out, schema.CVSSVector{
				Source:   strings.ToUpper(it.Source),
				Version:  version,
				Vector:   it.Vector,
				Score:    it.Score,
				Severity: strings.ToLower(it.Severity),
			})
		}
	}
	return out
}

// classifyReferenceKind guesses the source kind from a reference URL host.
// Only the most common buckets — the LLM reads SourceKind to weigh vendor
// advisories more heavily than blog posts.
func classifyReferenceKind(url string) string {
	u := strings.ToLower(url)
	switch {
	case strings.Contains(u, "github.com"):
		return "github"
	case strings.Contains(u, "hackerone.com"):
		return "hackerone"
	case strings.Contains(u, "msrc.microsoft.com"),
		strings.Contains(u, "support.apple.com"),
		strings.Contains(u, "redhat.com"),
		strings.Contains(u, "oracle.com/security-alerts"),
		strings.Contains(u, "adobe.com/security"),
		strings.Contains(u, "cisco.com/security"),
		strings.Contains(u, "vmware.com/security"),
		strings.Contains(u, "fortinet.com/psirt"),
		strings.Contains(u, "paloaltonetworks.com"):
		return "vendor"
	case strings.Contains(u, "mitre.org"), strings.Contains(u, "nvd.nist.gov"):
		return "mitre"
	case strings.Contains(u, "oss-security"), strings.Contains(u, "openwall.com"):
		return "oss-security"
	}
	return "other"
}

// parseTime parses an ISO-8601 timestamp, falling back to a default when
// vulnx returns blank or unparseable data.
func parseTime(s string, fallback time.Time) time.Time {
	if s == "" {
		return fallback
	}
	layouts := []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return fallback
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
