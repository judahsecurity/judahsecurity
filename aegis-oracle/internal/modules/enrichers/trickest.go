package enrichers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TrickestResult holds public PoC repository links extracted from
// github.com/trickest/cve — a broader GitHub PoC aggregator that complements
// nomi-sec/PoC-in-GitHub (used by exploit-availability-check and similar tools).
//
// Each CVE is published as Markdown:
//
//	https://raw.githubusercontent.com/trickest/cve/main/{YYYY}/{CVE-ID}.md
//
// A hit means public PoC/exploit-related GitHub links are indexed; it is
// weaker than Metasploit / VulnCheck weaponization or KEV.
type TrickestResult struct {
	Found    bool           `json:"found"`
	POCCount int            `json:"poc_count,omitempty"`
	POCs     []TrickestRepo `json:"pocs,omitempty"`
	Note     string         `json:"note,omitempty"`
}

// TrickestRepo is a GitHub repository URL extracted from a trickest CVE page.
type TrickestRepo struct {
	URL      string `json:"url"`
	FullName string `json:"full_name,omitempty"` // owner/repo
}

// githubRepoRE matches https://github.com/owner/repo (optionally with a path).
var githubRepoRE = regexp.MustCompile(`https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)

// FetchTrickest looks up trickest/cve for GitHub PoC links tagged to the given CVE.
// No API key is required. A 404 means no indexed entry (not an error).
func FetchTrickest(ctx context.Context, cveID string) TrickestResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return TrickestResult{Note: "cve_id is required"}
	}
	year, ok := cveYear(cveID)
	if !ok {
		return TrickestResult{Note: "CVE ID does not contain a parseable year"}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/trickest/cve/main/%s/%s.md",
		year, cveID,
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return TrickestResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "text/plain, text/markdown, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TrickestResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return TrickestResult{
			Found: false,
			Note:  "No entry indexed in trickest/cve for this CVE",
		}
	case http.StatusOK:
		// continue
	default:
		return TrickestResult{Note: fmt.Sprintf("HTTP %d from trickest/cve raw index", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return TrickestResult{Note: "read failed: " + err.Error()}
	}
	md := string(body)
	if strings.TrimSpace(md) == "" {
		return TrickestResult{Found: false, Note: "Empty trickest/cve entry"}
	}

	// Prefer the #### Github section when present (cleaner PoC list); fall back
	// to scanning the whole document — same idea as exploit-availability-check.
	scan := md
	if idx := strings.Index(md, "#### Github"); idx >= 0 {
		scan = md[idx:]
	}

	repos := extractGitHubRepos(scan)
	if len(repos) == 0 {
		// Fall back to full-document scan if the Github section had no links.
		if scan != md {
			repos = extractGitHubRepos(md)
		}
	}
	if len(repos) == 0 {
		return TrickestResult{
			Found: false,
			Note:  "trickest/cve entry found but no GitHub repo links extracted",
		}
	}

	const maxPOCs = 25
	trimmed := repos
	if len(trimmed) > maxPOCs {
		trimmed = trimmed[:maxPOCs]
	}

	return TrickestResult{
		Found:    true,
		POCCount: len(repos),
		POCs:     trimmed,
		Note: fmt.Sprintf(
			"%d GitHub PoC link(s) in trickest/cve — broader public PoC index (complements nomi-sec/PoC-in-GitHub; not confirmed ITW)",
			len(repos),
		),
	}
}

// extractGitHubRepos returns unique, sorted https://github.com/owner/repo URLs.
func extractGitHubRepos(md string) []TrickestRepo {
	matches := githubRepoRE.FindAllStringSubmatch(md, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]TrickestRepo, 0, len(matches))
	for _, m := range matches {
		owner := strings.TrimSuffix(m[1], ".git")
		repo := strings.TrimSuffix(m[2], ".git")
		if owner == "" || repo == "" {
			continue
		}
		// Skip non-repo path segments that sometimes appear as "repo" names.
		switch strings.ToLower(repo) {
		case "blob", "tree", "raw", "commit", "issues", "pull", "wiki", "releases", "actions", "projects", "settings":
			continue
		}
		fullName := owner + "/" + repo
		if _, ok := seen[fullName]; ok {
			continue
		}
		seen[fullName] = struct{}{}
		out = append(out, TrickestRepo{
			URL:      "https://github.com/" + fullName,
			FullName: fullName,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out
}
