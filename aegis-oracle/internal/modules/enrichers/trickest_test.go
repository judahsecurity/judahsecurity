package enrichers

import (
	"testing"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestExtractGitHubRepos(t *testing.T) {
	md := `
#### Github
- https://github.com/alice/log4j-poc
- https://github.com/alice/log4j-poc/tree/main/src
- https://github.com/bob/scanner.git
- http://packetstormsecurity.com/files/123
- https://github.com/carol/blob
`
	got := extractGitHubRepos(md)
	if len(got) != 2 {
		t.Fatalf("len=%d; want 2 (%v)", len(got), got)
	}
	if got[0].FullName != "alice/log4j-poc" || got[0].URL != "https://github.com/alice/log4j-poc" {
		t.Fatalf("unexpected first repo: %+v", got[0])
	}
	if got[1].FullName != "bob/scanner" {
		t.Fatalf("unexpected second repo: %+v", got[1])
	}
}

func TestApplyTrickestSetsEvidence(t *testing.T) {
	ext := ExternalEnrichment{
		PoCGitHub: PoCGitHubResult{
			Found:    true,
			POCCount: 1,
			POCs:     []PoCGitHubRepo{{URL: "https://github.com/example/poc-a"}},
		},
		Trickest: TrickestResult{
			Found:    true,
			POCCount: 3,
			POCs: []TrickestRepo{
				{URL: "https://github.com/example/poc-a", FullName: "example/poc-a"},
				{URL: "https://github.com/example/poc-b", FullName: "example/poc-b"},
				{URL: "https://github.com/example/poc-c", FullName: "example/poc-c"},
			},
		},
	}
	var ev schema.ExploitationEvidence
	Apply(ext, &ev)

	if !ev.PublicPOCFound {
		t.Fatal("expected PublicPOCFound")
	}
	if !ev.TrickestFound || ev.TrickestCount != 3 {
		t.Fatalf("TrickestFound=%v count=%d", ev.TrickestFound, ev.TrickestCount)
	}
	if len(ev.TrickestURLs) != 3 {
		t.Fatalf("TrickestURLs len=%d; want 3", len(ev.TrickestURLs))
	}
	// Merged unique URLs: poc-a/b/c
	if len(ev.PublicPOCURLs) != 3 {
		t.Fatalf("PublicPOCURLs len=%d; want 3", len(ev.PublicPOCURLs))
	}
	if ev.PublicPOCCount != 3 {
		t.Fatalf("PublicPOCCount=%d; want 3", ev.PublicPOCCount)
	}
}
