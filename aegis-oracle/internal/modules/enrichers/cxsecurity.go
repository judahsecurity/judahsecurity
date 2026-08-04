package enrichers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CXSecurityResult holds public advisory/exploit pages from CXSecurity.
type CXSecurityResult struct {
	Found    bool             `json:"found"`
	Count    int              `json:"count,omitempty"`
	Entries  []CXSecurityHit  `json:"entries,omitempty"`
	PageURL  string           `json:"page_url,omitempty"`
	Note     string           `json:"note,omitempty"`
}

// CXSecurityHit is a single WLB / issue link on CXSecurity.
type CXSecurityHit struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

var (
	cxWLBHrefRe  = regexp.MustCompile(`(?i)href=["']((?:https?://(?:www\.)?cxsecurity\.com)?/issue/WLB-[^"']+)["']`)
	cxTitleRe    = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	cxNotFoundRe = regexp.MustCompile(`(?i)(not\s+found|no\s+results|404)`)
)

// FetchCXSecurity looks up https://cxsecurity.com/cveshow/{CVE}/ for related
// advisories. Best-effort HTML parse — site layout changes may reduce hits.
func FetchCXSecurity(ctx context.Context, cveID string) CXSecurityResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return CXSecurityResult{Note: "cve_id is required"}
	}

	pageURL := "https://cxsecurity.com/cveshow/" + cveID + "/"
	fetchCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, pageURL, nil)
	if err != nil {
		return CXSecurityResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0 (+vuln-intel; authorized research)")
	req.Header.Set("Accept", "text/html")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return CXSecurityResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	html := string(body)

	if resp.StatusCode == http.StatusNotFound {
		return CXSecurityResult{Found: false, PageURL: pageURL, Note: "No CXSecurity cveshow page"}
	}
	if resp.StatusCode != http.StatusOK {
		return CXSecurityResult{Note: fmt.Sprintf("CXSecurity HTTP %d", resp.StatusCode), PageURL: pageURL}
	}
	if cxNotFoundRe.MatchString(html) && !strings.Contains(strings.ToUpper(html), cveID) {
		return CXSecurityResult{Found: false, PageURL: pageURL, Note: "CVE not listed on CXSecurity"}
	}

	seen := map[string]struct{}{}
	var hits []CXSecurityHit
	for _, m := range cxWLBHrefRe.FindAllStringSubmatch(html, 20) {
		href := m[1]
		if strings.HasPrefix(href, "/") {
			href = "https://cxsecurity.com" + href
		}
		if _, ok := seen[href]; ok {
			continue
		}
		seen[href] = struct{}{}
		hits = append(hits, CXSecurityHit{Title: "CXSecurity advisory", URL: href})
		if len(hits) >= 10 {
			break
		}
	}

	if len(hits) == 0 {
		// Page exists and mentions the CVE — treat as a soft hit with the index URL.
		if strings.Contains(strings.ToUpper(html), cveID) {
			title := cveID
			if tm := cxTitleRe.FindStringSubmatch(html); len(tm) > 1 {
				title = strings.TrimSpace(tm[1])
			}
			return CXSecurityResult{
				Found:   true,
				Count:   1,
				PageURL: pageURL,
				Entries: []CXSecurityHit{{Title: title, URL: pageURL}},
				Note:    "cveshow page present; no WLB issue links parsed",
			}
		}
		return CXSecurityResult{Found: false, PageURL: pageURL, Note: "No CXSecurity advisories parsed"}
	}

	return CXSecurityResult{
		Found:   true,
		Count:   len(hits),
		Entries: hits,
		PageURL: pageURL,
		Note:    "cxsecurity.com cveshow (best-effort HTML)",
	}
}
