// aegis-oracle-cli is the operator/analyst entry point for Aegis Oracle.
//
// Phase 1 subcommands:
//
//	analyze    score a single (CVE, asset) pair from local JSON files
//	kb         inspect/validate the knowledge base
//	version    print build version info
//
// The analyze command is intentionally LLM-free in this build: it
// consumes a pre-computed intrinsic analysis JSON (the Phase A output
// you'd otherwise get from the LLM reasoner), runs Phase B contextual
// evaluation, and produces an OPES score + recommendation. This lets
// the math be exercised end-to-end before the reasoner ingest path is
// wired up.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/contextual"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

const (
	cliName    = "aegis-oracle-cli"
	cliVersion = "0.1.0-phase1"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "analyze":
		os.Exit(runAnalyze(args))
	case "kb":
		os.Exit(runKB(args))
	case "version", "-v", "--version":
		fmt.Printf("%s %s\n", cliName, cliVersion)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s — Aegis Oracle command-line interface

Usage:
  %s <command> [flags]

Commands:
  analyze   Score a (CVE, asset) pair from local JSON files
  kb        Inspect and validate the knowledge base
  version   Print version info
  help      Show this help

Run "%s <command> -h" for command-specific flags.
`, cliName, cliName, cliName)
}

// ─────────────────────────── analyze ───────────────────────────────────

func runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	intrinsicPath := fs.String("intrinsic", "", "Path to Phase A intrinsic analysis JSON (required)")
	assetPath := fs.String("asset", "", "Path to asset JSON (required)")
	cvePath := fs.String("cve", "", "Path to canonical CVE JSON (optional, drives time-pressure component)")
	exploitPath := fs.String("exploitation", "", "Path to ExploitationEvidence JSON (optional, drives KEV/EPSS components)")
	pretty := fs.Bool("pretty", true, "Indent JSON output")
	humanFlag := fs.Bool("human", false, "Render a human-readable summary alongside the JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s analyze --intrinsic FILE --asset FILE [--cve FILE] [--exploitation FILE]\n\nFlags:\n", cliName)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *intrinsicPath == "" || *assetPath == "" {
		fmt.Fprintln(os.Stderr, "error: --intrinsic and --asset are required")
		fs.Usage()
		return 2
	}

	var intrinsic schema.IntrinsicAnalysis
	if err := readJSON(*intrinsicPath, &intrinsic); err != nil {
		fmt.Fprintf(os.Stderr, "read intrinsic: %v\n", err)
		return 1
	}
	var asset schema.Asset
	if err := readJSON(*assetPath, &asset); err != nil {
		fmt.Fprintf(os.Stderr, "read asset: %v\n", err)
		return 1
	}

	var cvePtr *schema.CVE
	if *cvePath != "" {
		var cve schema.CVE
		if err := readJSON(*cvePath, &cve); err != nil {
			fmt.Fprintf(os.Stderr, "read cve: %v\n", err)
			return 1
		}
		cvePtr = &cve
	}

	var exploitation schema.ExploitationEvidence
	if *exploitPath != "" {
		if err := readJSON(*exploitPath, &exploitation); err != nil {
			fmt.Fprintf(os.Stderr, "read exploitation: %v\n", err)
			return 1
		}
	}

	assessment := contextual.Assess(&intrinsic, &asset, time.Now().UTC())
	preconditions := assessment.Preconditions
	score := opes.Compute(opes.Input{
		CVE:           cvePtr,
		Intrinsic:     &intrinsic,
		Asset:         &asset,
		Preconditions: preconditions,
		Contextual:    &assessment,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, opes.DefaultConfig())

	output := analyzeOutput{
		CVEID:                  intrinsic.CVEID,
		AssetID:                asset.ID,
		EvaluatorVersion:       opes.Version,
		EvaluatedAt:            time.Now().UTC(),
		OPES:                   score,
		PreconditionsEvaluated: preconditions,
		ContextualAssessment:   assessment,
		CVSSReconciliation:     intrinsic.CVSSReconciliation,
		Recommendation:         recommendation(intrinsic, score, preconditions),
		VerificationTasks:      buildVerificationTasks(asset.ID, preconditions),
	}

	encoder := json.NewEncoder(os.Stdout)
	if *pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		return 1
	}

	if *humanFlag {
		printHumanSummary(os.Stderr, output)
	}
	return 0
}

type analyzeOutput struct {
	CVEID                  string                      `json:"cve_id"`
	AssetID                string                      `json:"asset_id"`
	EvaluatorVersion       string                      `json:"evaluator_version"`
	EvaluatedAt            time.Time                   `json:"evaluated_at"`
	OPES                   schema.OPESScore            `json:"opes"`
	PreconditionsEvaluated schema.PreconditionEvalSet  `json:"preconditions_evaluated"`
	ContextualAssessment   schema.ContextualAssessment `json:"contextual_assessment"`
	CVSSReconciliation     schema.CVSSReconciliation   `json:"cvss_reconciliation"`
	Recommendation         string                      `json:"recommendation"`
	VerificationTasks      []schema.VerificationTask   `json:"verification_tasks,omitempty"`
}

func recommendation(intrinsic schema.IntrinsicAnalysis, score schema.OPESScore, set schema.PreconditionEvalSet) string {
	var sb strings.Builder
	highestNVD := 0.0
	for _, v := range []schema.CVSSVector{} {
		if strings.EqualFold(v.Source, "NVD") && v.Score > highestNVD {
			highestNVD = v.Score
		}
	}
	fmt.Fprintf(&sb, "OPES %.1f / %s — %s.\n", score.Value, score.Category, score.Label)
	if score.Override != "" {
		fmt.Fprintf(&sb, "Override: %s.\n", score.Override)
	}
	if score.Dampener != "" {
		fmt.Fprintf(&sb, "%s.\n", score.Dampener)
	}
	if intrinsic.CVSSReconciliation.CorrectScore > 0 {
		fmt.Fprintf(&sb, "Reconciled CVSS: %.1f (%s). %s\n",
			intrinsic.CVSSReconciliation.CorrectScore,
			intrinsic.CVSSReconciliation.CorrectVector,
			intrinsic.CVSSReconciliation.Rationale,
		)
	}
	unknown := set.CountBlockers(schema.PreconditionUnknown)
	unsat := set.CountBlockers(schema.PreconditionUnsatisfied)
	switch {
	case unsat > 0:
		sb.WriteString("At least one blocker precondition is unsatisfied — exploit is impossible on this asset; finding can be auto-suppressed.\n")
	case unknown > 0:
		fmt.Fprintf(&sb, "%d blocker precondition(s) currently unknown; verify before assuming risk level. Verification tasks below are ready to file.\n", unknown)
	default:
		sb.WriteString("All blocker preconditions verified satisfied — finding represents real exploitable risk on this asset.\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func buildVerificationTasks(assetID string, set schema.PreconditionEvalSet) []schema.VerificationTask {
	tasks := make([]schema.VerificationTask, 0)
	for _, e := range set {
		if e.Status != schema.PreconditionUnknown {
			continue
		}
		kind := "manual"
		if strings.HasPrefix(e.Precondition.VerificationSignal, "container.") || strings.HasPrefix(e.Precondition.VerificationSignal, "runtime_flags.") {
			kind = "container_inspect"
		}
		tasks = append(tasks, schema.VerificationTask{
			ID:                    "ver-" + assetID + "-" + e.Precondition.ID,
			PreconditionID:        e.Precondition.ID,
			Summary:               "Verify " + e.Precondition.Description,
			TaskKind:              kind,
			Command:               e.Precondition.VerificationMethod,
			ExpectedSignalPath:    e.Precondition.VerificationSignal,
			ExpectedMatch:         e.Precondition.MatchValue,
			ResolvesPreconditions: []string{e.Precondition.ID},
			Status:                "open",
			CreatedAt:             time.Now().UTC(),
		})
	}
	return tasks
}

func printHumanSummary(w io.Writer, out analyzeOutput) {
	fmt.Fprintln(w, strings.Repeat("─", 72))
	fmt.Fprintf(w, "CVE: %s    Asset: %s\n", out.CVEID, out.AssetID)
	fmt.Fprintf(w, "OPES %.1f / %s — %s   (confidence: %s)\n",
		out.OPES.Value, out.OPES.Category, out.OPES.Label, out.OPES.Confidence)
	fmt.Fprintln(w, strings.Repeat("─", 72))
	fmt.Fprintf(w, "Components: E=%.1f R=%.1f P=%.1f X=%.1f C=%.1f T=%.1f\n",
		out.OPES.Components.E, out.OPES.Components.R, out.OPES.Components.P,
		out.OPES.Components.X, out.OPES.Components.C, out.OPES.Components.T)
	if out.OPES.Override != "" {
		fmt.Fprintf(w, "Override: %s\n", out.OPES.Override)
	}
	if out.OPES.Dampener != "" {
		fmt.Fprintf(w, "Dampener: %s\n", out.OPES.Dampener)
	}
	for _, c := range out.OPES.TopContributors {
		fmt.Fprintf(w, "  • %s\n", c)
	}
	fmt.Fprintln(w, strings.Repeat("─", 72))
	fmt.Fprintln(w, "Preconditions:")
	for _, e := range out.PreconditionsEvaluated {
		marker := "?"
		switch e.Status {
		case schema.PreconditionSatisfied:
			marker = "+"
		case schema.PreconditionUnsatisfied:
			marker = "-"
		}
		fmt.Fprintf(w, "  [%s] %s (%s)\n      %s\n      %s\n",
			marker, e.Precondition.ID, e.Precondition.Severity, e.Precondition.Description, e.Reason)
	}
	if len(out.VerificationTasks) > 0 {
		fmt.Fprintln(w, strings.Repeat("─", 72))
		fmt.Fprintln(w, "Open verification tasks:")
		for _, t := range out.VerificationTasks {
			fmt.Fprintf(w, "  • %s — %s\n", t.PreconditionID, t.Summary)
			if t.Command != "" {
				fmt.Fprintf(w, "    %s\n", t.Command)
			}
		}
	}
	fmt.Fprintln(w, strings.Repeat("─", 72))
	fmt.Fprintln(w, out.Recommendation)
}

// ─────────────────────────── kb ────────────────────────────────────────

func runKB(args []string) int {
	fs := flag.NewFlagSet("kb", flag.ContinueOnError)
	root := fs.String("root", defaultKBRoot(), "Knowledge base root directory")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s kb <subcommand> [flags]\n\n  validate              Load + validate the KB\n  stats                 Print summary counts\n  show <CWE-ID>         Pretty-print a CWE profile\n  pattern <pattern_id>  Pretty-print a dev pattern\n\nFlags:\n", cliName)
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		return 2
	}
	sub := args[0]
	rest := args[1:]
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	kb, err := knowledgebase.Load(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load kb: %v\n", err)
		return 1
	}

	switch sub {
	case "validate":
		if err := kb.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "validation errors:\n%v\n", err)
			return 1
		}
		fmt.Println("knowledge base OK")
		return 0
	case "stats":
		s := kb.Stats()
		out, _ := json.MarshalIndent(s, "", "  ")
		fmt.Println(string(out))
		return 0
	case "show":
		if len(fs.Args()) == 0 {
			fmt.Fprintln(os.Stderr, "show: CWE-ID required")
			return 2
		}
		id := fs.Arg(0)
		p, ok := kb.CWEProfiles[id]
		if !ok {
			fmt.Fprintf(os.Stderr, "no CWE profile %q in %s\n", id, *root)
			return 1
		}
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
		return 0
	case "pattern":
		if len(fs.Args()) == 0 {
			fmt.Fprintln(os.Stderr, "pattern: pattern_id required")
			return 2
		}
		id := fs.Arg(0)
		p, ok := kb.DevPatterns[id]
		if !ok {
			fmt.Fprintf(os.Stderr, "no dev pattern %q in %s\n", id, *root)
			return 1
		}
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
		return 0
	default:
		fs.Usage()
		return 2
	}
}

// ─────────────────────────── helpers ───────────────────────────────────

func readJSON(path string, dest any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(dest)
}

func defaultKBRoot() string {
	// When running from the repo, ./knowledgebase is convenient. Walk up
	// from cwd looking for it, fall back to ./knowledgebase.
	cwd, err := os.Getwd()
	if err != nil {
		return "knowledgebase"
	}
	dir := cwd
	for i := 0; i < 5; i++ {
		try := filepath.Join(dir, "knowledgebase")
		if _, err := os.Stat(try); err == nil {
			return try
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return filepath.Join(cwd, "knowledgebase")
}
