// aegis-oracle is the Aegis Oracle daemon.
//
// Usage:
//
//	aegis-oracle -config config.yaml
//
// On startup it:
//  1. Loads and validates the knowledge base
//  2. Opens the Postgres connection (shared ASM database)
//  3. Applies pending migrations (oracle schema only)
//  4. Initialises the LLM provider
//  5. Starts the analysis HTTP API on :8742 (configurable)
//
// The HTTP API exposes:
//
//	POST /analyze          — run the full pipeline for a (cve_id, asset_id) pair
//	GET  /cve/:id          — Phase-A intrinsic analysis for a CVE (no asset required;
//	                         ad-hoc lookups, "what is this CVE?" questions, ASM batch
//	                         enrichment when an asset isn't yet known)
//	GET  /findings         — list open findings (queryable by cve_id, asset_id, category)
//	GET  /findings/:id     — single finding detail
//	POST /findings/:id/suppress  — suppress a finding
//	GET  /health           — liveness probe
//	GET  /kb/stats         — knowledge base summary
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/llm"
	"github.com/your-org/aegis-oracle/internal/modules/enrichers"
	"github.com/your-org/aegis-oracle/internal/modules/ingest"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/contextual"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/internal/pipeline"
	"github.com/your-org/aegis-oracle/internal/react"
	reacttools "github.com/your-org/aegis-oracle/internal/react/tools"
	"github.com/your-org/aegis-oracle/internal/store/pg"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

type Config struct {
	DB            pg.Config  `yaml:"db"`
	LLM           llm.Config `yaml:"llm"`
	Knowledgebase struct {
		Root string `yaml:"root"`
	} `yaml:"knowledgebase"`
	OPES           opes.Config `yaml:"opes"`
	PDCPKey        string      `yaml:"pdcp_api_key"`        // ProjectDiscovery Cloud Platform key (optional)
	VulnCheckToken string      `yaml:"vulncheck_api_token"` // optional; enables VulnCheck Exploit Intelligence/XDB
	NVDKey         string      `yaml:"nvd_api_key"`         // optional; raises NVD rate limit for on-demand ingest
	Log            struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
	Addr string `yaml:"addr"`

	// Scheduler controls the background CVE freshness sync jobs.
	// Omit or set to zero to use DefaultIntervals (1h NVD delta, 6h KEV, 12h EPSS, 15m analyze).
	Scheduler struct {
		Disabled            bool          `yaml:"disabled"`              // set true to run on-demand only
		NVDDeltaEvery       time.Duration `yaml:"nvd_delta_every"`       // default: 1h
		CISAKEVEvery        time.Duration `yaml:"cisa_kev_every"`        // default: 6h
		EPSSEvery           time.Duration `yaml:"epss_every"`            // default: 12h
		AnalyzePendingEvery time.Duration `yaml:"analyze_pending_every"` // default: 15m
	} `yaml:"scheduler"`
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to config YAML")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Knowledge base.
	kbRoot := cfg.Knowledgebase.Root
	if kbRoot == "" {
		kbRoot = "knowledgebase"
	}
	kb, err := knowledgebase.Load(kbRoot)
	if err != nil {
		slog.Error("failed to load knowledge base", "error", err)
		os.Exit(1)
	}
	if err := kb.Validate(); err != nil {
		slog.Error("knowledge base validation failed", "error", err)
		os.Exit(1)
	}
	stats := kb.Stats()
	slog.Info("knowledge base loaded",
		"cwe_profiles", stats.CWEProfiles,
		"dev_patterns", stats.DevPatterns)

	// Postgres.
	store, err := pg.New(ctx, cfg.DB)
	if err != nil {
		slog.Error("postgres connection failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	slog.Info("postgres connected", "dsn_prefix", safeDSN(cfg.DB.DSN))

	// LLM provider — optional at process start: without API keys the daemon
	// still binds :8742 and /health returns 200 with llm_ready=false so
	// docker-compose curl checks stop failing with "connection reset"
	// (formerly we os.Exit(1) before ListenAndServe).
	llmReady := true
	provider, err := llm.New(cfg.LLM)
	if err != nil {
		slog.Warn("oracle starting without a working LLM — set ANTHROPIC_API_KEY or OPENAI_API_KEY in the environment; /cve and /chat need a key", "error", err)
		provider = llm.Disabled(err)
		llmReady = false
	} else {
		slog.Info("llm provider ready", "provider", cfg.LLM.Provider)
	}

	// Phase A reasoner.
	reasoner, err := intrinsic.New(provider, store, kb)
	if err != nil {
		slog.Error("intrinsic reasoner init failed", "error", err)
		os.Exit(1)
	}

	// Pipeline runner.
	runner := pipeline.New(store, reasoner, cfg.OPES)

	// On-demand CVE ingester. Backs both the /cve/{id} lookup and the
	// /analyze endpoint so a brand-new CVE id (one never seen by the
	// nightly merge pipeline) is fetched from vulnx/NVD on first use,
	// persisted to oracle.cves, and analysed without manual seeding.
	ingester := ingest.New(store, cfg.PDCPKey, cfg.NVDKey)

	// Phase 2 background ingestion scheduler.
	// Continuously keeps oracle.cves fresh: NVD delta (hourly), CISA KEV
	// bulk-mark (every 6h), and EPSS score refresh (every 12h). Can be
	// disabled in config for environments that prefer purely on-demand ingest.
	if !cfg.Scheduler.Disabled {
		intervals := ingest.SchedulerIntervals{
			NVDDelta:       cfg.Scheduler.NVDDeltaEvery,
			CISAKEV:        cfg.Scheduler.CISAKEVEvery,
			EPSS:           cfg.Scheduler.EPSSEvery,
			AnalyzePending: cfg.Scheduler.AnalyzePendingEvery,
		}
		// Wire the intrinsic reasoner for auto-analysis only when the LLM is
		// ready — skip if no API key was configured to avoid noisy failures.
		var autoAnalyzer func(ctx context.Context, cve *schema.CVE) error
		if llmReady {
			autoAnalyzer = func(ctx context.Context, cve *schema.CVE) error {
				_, err := reasoner.Analyze(ctx, cve, nil)
				return err
			}
		}
		scheduler := ingest.NewScheduler(store, cfg.NVDKey, intervals, autoAnalyzer)
		go scheduler.Start(ctx)
	}

	// ReAct loop — wires Oracle tools to the LLM for iterative reasoning.
	toolRegistry := reacttools.BuildRegistry(reacttools.Deps{
		Store:          store,
		Runner:         runner,
		KB:             kb,
		PDCPKey:        cfg.PDCPKey, // optional; higher vulnx rate limits
		VulnCheckToken: cfg.VulnCheckToken,
	})
	reactLoop := react.New(react.Config{
		LLM:           provider,
		Tools:         toolRegistry,
		MaxIterations: 10,
		MaxTokens:     3072, // structured final-answer format needs more room than a 1-3 sentence summary
	})

	// HTTP API.
	addr := cfg.Addr
	if addr == "" {
		addr = ":8742"
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      buildMux(runner, reasoner, store, kb, reactLoop, ingester, cfg.VulnCheckToken, cfg.OPES, llmReady),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 180 * time.Second,
	}

	go func() {
		slog.Info("aegis-oracle listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}

// ─────────────────────────── HTTP handlers ──────────────────────────────

func buildMux(
	runner *pipeline.Runner,
	reasoner *intrinsic.Reasoner,
	store *pg.Store,
	kb *knowledgebase.KB,
	loop *react.Loop,
	ingester *ingest.Ingester,
	vulnCheckToken string,
	opesCfg opes.Config,
	llmReady bool,
) http.Handler {
	mux := http.NewServeMux()

	// POST /chat  body: {"question":"..."}
	//
	// Runs the ReAct loop: the LLM iteratively selects tools (lookup_cve,
	// get_asset, check_epss_kev, search_exploit_evidence, lookup_kb_pattern,
	// get_open_findings, run_analysis) until it produces a final answer.
	// This is the natural-language entry point — use /analyze for direct calls.
	mux.HandleFunc("POST /chat", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Question string `json:"question"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		if req.Question == "" {
			writeError(w, http.StatusBadRequest, "question is required")
			return
		}

		result, err := loop.Run(r.Context(), req.Question)
		if err != nil {
			slog.Error("react loop failed", "error", err)
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"answer":     result.Answer,
			"finding":    result.Finding,
			"iterations": result.Iterations,
			"elapsed_ms": result.ElapsedMS,
			"trace":      result.Trace,
		})
	})

	// POST /analyze
	//
	// Body shapes (the endpoint accepts either):
	//
	//   1. {"cve_id":"CVE-...","asset_id":"asset-..."}
	//      The asset is loaded from Oracle's own assets table. Use when
	//      the asset is already known to Oracle (asset sync done elsewhere).
	//
	//   2. {"cve_id":"CVE-...","asset":{...full schema.Asset...}}
	//      The asset is supplied inline. Use this from external systems
	//      (the ASM platform) that own asset state and don't want to mirror
	//      it into Oracle's DB. The asset is passed straight to the pipeline
	//      via RunWithObjects — no Oracle-side write.
	//
	// If the CVE is not in oracle.cves, it is fetched on demand from vulnx
	// (preferred) or NVD (fallback), persisted, and analysed. Subsequent
	// calls hit the cached row.
	mux.HandleFunc("POST /analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CVEID   string        `json:"cve_id"`
			AssetID string        `json:"asset_id"`
			Asset   *schema.Asset `json:"asset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		req.CVEID = strings.ToUpper(strings.TrimSpace(req.CVEID))
		if req.CVEID == "" {
			writeError(w, http.StatusBadRequest, "cve_id is required")
			return
		}
		if req.AssetID == "" && req.Asset == nil {
			writeError(w, http.StatusBadRequest, "either asset_id or asset is required")
			return
		}

		// Ensure the CVE record exists in our store before running analysis.
		// This auto-ingests if missing.
		cve, _, err := ingester.EnsureCVE(r.Context(), req.CVEID)
		if err != nil {
			slog.Error("ensure cve", "cve", req.CVEID, "error", err)
			writeError(w, http.StatusBadGateway, "cve ingest failed: "+err.Error())
			return
		}
		if cve == nil {
			writeError(w, http.StatusNotFound, "cve not found upstream (vulnx/nvd)")
			return
		}

		exploitation := buildExploitationEvidence(r.Context(), req.CVEID, vulnCheckToken)

		var result *pipeline.RunResult
		if req.Asset != nil {
			// Inline asset path: feed the analysis directly without writing
			// the asset to Oracle's DB. The caller (ASM) is the source of
			// truth for asset state.
			if req.Asset.ID == "" {
				writeError(w, http.StatusBadRequest, "asset.asset_id is required when sending inline asset")
				return
			}
			result, err = runner.RunWithObjects(r.Context(), cve, req.Asset, nil, exploitation)
		} else {
			result, err = runner.Run(r.Context(), req.CVEID, req.AssetID, nil, exploitation)
		}
		if err != nil {
			slog.Error("pipeline run failed",
				"cve", req.CVEID, "asset_id", req.AssetID,
				"asset_inline", req.Asset != nil, "error", err)
			// Surface "asset not found" as 404 so the caller can decide
			// whether to retry with an inline payload.
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			// Degrade gracefully on LLM/pipeline failures: return 200 with
			// analysis_status="failed" so the ASM platform can persist the
			// error state and show actionable information to the analyst —
			// rather than an opaque 500 that surfaces as "An internal server
			// error occurred." in the UI.
			writeJSON(w, http.StatusOK, map[string]any{
				"finding":         nil,
				"analysis_status": "failed",
				"analysis_error":  "Analysis pipeline could not be completed: " + err.Error(),
				"exploitation":    exploitation,
				"llm_model":       "",
				"elapsed_ms":      int64(0),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"finding":         result.Finding,
			"analysis_status": "complete",
			"exploitation":    exploitation,
			"llm_model":       result.LLMModel,
			"elapsed_ms":      result.ElapsedMS,
		})
	})

	// POST /analyze-finding
	//
	// ASM-native vulnerability analysis for findings that may not have a CVE:
	// exposed datastores, leaked secrets, cloud misconfigurations, debug
	// endpoints, and other scanner/manual findings. The current implementation
	// uses deterministic classifiers to produce an intrinsic analysis, then
	// runs the same contextual evaluator and OPES scorer used by CVE findings.
	mux.HandleFunc("POST /analyze-finding", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Vulnerability schema.GenericVulnerability `json:"vulnerability"`
			Asset         *schema.Asset               `json:"asset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		req.Vulnerability.Title = strings.TrimSpace(req.Vulnerability.Title)
		if req.Vulnerability.Title == "" {
			writeError(w, http.StatusBadRequest, "vulnerability.title is required")
			return
		}
		if req.Asset == nil || req.Asset.ID == "" {
			writeError(w, http.StatusBadRequest, "asset.asset_id is required")
			return
		}

		result := analyzeGenericFinding(req.Vulnerability, req.Asset, opesCfg)
		writeJSON(w, http.StatusOK, map[string]any{
			"finding":         result,
			"analysis_status": "complete",
		})
	})

	// GET /cve/{id}
	//
	// Phase-A-only CVE analysis. Returns the IntrinsicAnalysis (analyst brief,
	// attack path class, preconditions, CVSS reconciliation) plus the canonical
	// CVE record and observed exploitation evidence. No asset required.
	//
	// Intended for:
	//   • ad-hoc analyst questions ("what is CVE-X?") — fast, deterministic,
	//     and cached on the (cve_id, prompt_version) pair
	//   • ASM batch enrichment when the asset graph isn't yet linked
	//   • a CVE-only "Quick Lookup" UI
	//
	// Uses the same Phase A reasoner as /analyze — cached output is reused
	// across endpoints so the first /analyze call after a /cve lookup is
	// effectively free.
	mux.HandleFunc("GET /cve/{id}", func(w http.ResponseWriter, r *http.Request) {
		cveID := strings.ToUpper(r.PathValue("id"))
		if cveID == "" {
			writeError(w, http.StatusBadRequest, "cve id is required")
			return
		}

		// Auto-ingest if the CVE isn't in the store yet. First call for a
		// fresh id pays a ~1-3s upstream fetch; subsequent calls are cached.
		cve, ingested, err := ingester.EnsureCVE(r.Context(), cveID)
		if err != nil {
			slog.Error("ensure cve", "cve", cveID, "error", err)
			writeError(w, http.StatusBadGateway, "cve ingest failed: "+err.Error())
			return
		}
		if cve == nil {
			writeError(w, http.StatusNotFound, "cve not found in oracle store or upstream (vulnx/nvd)")
			return
		}
		if ingested {
			slog.Info("cve served via on-demand ingest", "cve", cveID,
				"primary_source", cve.PrimarySource)
		}

		// Exploitation evidence: same enrichment path as /analyze. This is
		// observed evidence (KEV, VulnCheck XDB, Metasploit, etc.), not asset
		// reachability. Build it before Phase A so an LLM/provider failure can
		// still return useful deterministic intelligence.
		exploitation := buildExploitationEvidence(r.Context(), cveID, vulnCheckToken)

		// Phase A — intrinsic analysis. Cached when available.
		analysis, err := reasoner.Analyze(r.Context(), cve, nil)
		if err != nil {
			slog.Error("intrinsic analyze", "cve", cveID, "error", err)
			writeJSON(w, http.StatusOK, map[string]any{
				"cve":             cve,
				"analysis":        nil,
				"analysis_status": "failed",
				"analysis_error":  "CVE intelligence was found, but LLM analysis could not be completed: " + err.Error(),
				"exploitation":    exploitation,
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"cve":             cve,
			"analysis":        analysis,
			"analysis_status": "complete",
			"exploitation":    exploitation,
		})
	})

	// GET /findings?cve_id=...&asset_id=...&category=P0
	mux.HandleFunc("GET /findings", func(w http.ResponseWriter, r *http.Request) {
		cveID := r.URL.Query().Get("cve_id")
		assetID := r.URL.Query().Get("asset_id")
		findings, err := store.GetOpenFindings(r.Context(), cveID, assetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "count": len(findings)})
	})

	// GET /health
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if llmReady {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "llm_ready": true})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "degraded",
			"llm_ready": false,
			"detail":    "Set ANTHROPIC_API_KEY or OPENAI_API_KEY (and rebuild/restart) for Phase A analysis and /chat",
		})
	})

	// GET /kb/stats
	mux.HandleFunc("GET /kb/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, kb.Stats())
	})

	return mux
}

// ─────────────────────────── helpers ────────────────────────────────────

func loadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, err
	}
	// Allow env var overrides for secrets.
	if v := os.Getenv("ORACLE_DB_DSN"); v != "" {
		cfg.DB.DSN = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		cfg.LLM.Anthropic.APIKey = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.LLM.OpenAI.APIKey = v
	}
	if v := os.Getenv("PDCP_API_KEY"); v != "" {
		cfg.PDCPKey = v
	}
	if v := os.Getenv("VULNCHECK_API_TOKEN"); v != "" {
		cfg.VulnCheckToken = v
	}
	if v := os.Getenv("NVD_API_KEY"); v != "" {
		cfg.NVDKey = v
	}
	return cfg, nil
}

func buildExploitationEvidence(ctx context.Context, cveID, vulnCheckToken string) schema.ExploitationEvidence {
	ev := schema.ExploitationEvidence{}
	ext := enrichers.FetchAllWithVulnCheck(ctx, cveID, vulnCheckToken)
	enrichers.Apply(ext, &ev)
	return ev
}

func analyzeGenericFinding(v schema.GenericVulnerability, asset *schema.Asset, cfg opes.Config) schema.GenericFindingAnalysis {
	class, analysis, exploitation, detectionSignals := classifyGenericFinding(v)
	assessedAt := time.Now().UTC()
	contextualAssessment := contextual.Assess(analysis, asset, assessedAt)
	preconditions := contextualAssessment.Preconditions

	// Infer detection confidence from scanner signals. This tells OPES difficulty
	// whether the vulnerable feature was confirmed active (endpoint_confirmed,
	// exploit_confirmed) or only the version/presence is known (version_only).
	dc := inferDetectionConfidence(v)
	if dc != schema.DetectionUnknown {
		detectionSignals = append(detectionSignals, "detection_confidence="+string(dc))
	}

	score := opes.Compute(opes.Input{
		Intrinsic:           analysis,
		Asset:               asset,
		Preconditions:       preconditions,
		Exploitation:        exploitation,
		Now:                 assessedAt,
		CWEID:               v.CWEID,
		DetectionConfidence: dc,
	}, cfg)
	return schema.GenericFindingAnalysis{
		ID:                       genericFindingID(v, asset),
		VulnerabilityID:          v.ID,
		AssetID:                  asset.ID,
		FindingClass:             class,
		OPES:                     score,
		AnalystBrief:             analysis.AnalystBrief,
		AttackPathClass:          analysis.AttackPathClass,
		LateralMovementPotential: analysis.LateralMovementPotential,
		PreconditionsEvaluated:   preconditions,
		ContextualAssessment:     contextualAssessment,
		RecommendationText:       buildGenericRecommendation(v, asset, analysis, score, preconditions),
		DetectionSignals:         detectionSignals,
	}
}

// cweIntrinsic returns a pre-populated IntrinsicAnalysis for a known CWE,
// giving the OPES engine accurate weakness-class priors when no CVE-backed
// LLM analysis is available. Returns nil for unrecognized CWEs so the
// caller can fall through to the text-heuristic classifier.
func cweIntrinsic(cweID, title string) *schema.IntrinsicAnalysis {
	switch strings.ToUpper(strings.TrimSpace(cweID)) {

	case "CWE-89": // SQL Injection
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementMedium,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", CorrectScore: 9.8, CorrectVersion: "3.1", Rationale: "SQL injection is network-triggerable with no auth, low complexity."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "SQL Injection (CWE-89): Attacker-Controlled Database Query",
				WhatIsIt:            "An attacker can inject SQL syntax into a user-supplied input field, altering the intended query logic.",
				AttackScenario:      "Attacker injects a payload such as ' OR 1=1-- to bypass authentication, dump rows, or modify data. Automated tools like sqlmap can enumerate the full schema with minimal effort.",
				AttackVectorSummary: "Network-reachable input field with insufficient parameterization.",
				RealWorldLikelihood: "High — SQL injection remains one of the most reliably exploited weaknesses; scanner detection strongly predicts exploitability.",
				AffectedIf:          "Affected when user-supplied input reaches a database query without parameterized statements or ORM escaping.",
				NotAffectedIf:       "Not affected if all queries use parameterized statements, prepared queries, or a vetted ORM with no raw-query escape hatches.",
				ExploitabilityScore: 4.5,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-79": // Cross-site Scripting
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementLow,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", CorrectScore: 6.1, CorrectVersion: "3.1", Rationale: "Reflected/stored XSS requires user interaction (UI:R) and crosses scope boundary (S:C)."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Cross-Site Scripting (CWE-79): Injected Script Executes in Victim's Browser",
				WhatIsIt:            "Unsanitized user input is reflected or stored and executed as JavaScript in another user's browser session.",
				AttackScenario:      "Attacker crafts a URL or post containing <script> content; a victim's browser executes it, allowing session cookie theft, keylogging, or DOM manipulation.",
				AttackVectorSummary: "Attacker-controlled input rendered without encoding in victim's browser context.",
				RealWorldLikelihood: "High for reflected XSS where a link can be delivered via phishing; high for stored XSS with authenticated victim users.",
				AffectedIf:          "Affected when user-supplied content is embedded in HTML/JS responses without output encoding.",
				NotAffectedIf:       "Not affected when all user-supplied content is HTML-encoded at output and a strict Content Security Policy blocks inline scripts.",
				ExploitabilityScore: 3.5,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-22", "CWE-23": // Path Traversal
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementMedium,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", CorrectScore: 7.5, CorrectVersion: "3.1", Rationale: "Path traversal is network-triggerable with no auth; impact limited to confidentiality unless write access is available."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Path Traversal (" + cweID + "): Attacker Reads Arbitrary Files",
				WhatIsIt:            "A filename or path parameter is not normalized, allowing an attacker to escape the intended directory and read arbitrary files.",
				AttackScenario:      "Attacker sends ../../../../etc/passwd or similar in a file-path parameter and receives the file contents in the response.",
				AttackVectorSummary: "Network-reachable file-serving endpoint with insufficient path normalization.",
				RealWorldLikelihood: "High when a scanner confirms the traversal sequence in a response; frequently leads to credential disclosure from config files.",
				AffectedIf:          "Affected when user-supplied path input is not canonicalized and compared against an allowed root before filesystem access.",
				NotAffectedIf:       "Not affected when all file paths are resolved to a canonical form and validated against an allowlist before any I/O.",
				ExploitabilityScore: 4.0,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-78": // OS Command Injection
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementHigh,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CorrectScore: 9.8, CorrectVersion: "3.1", Rationale: "Command injection directly yields code execution; full CIA impact."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "OS Command Injection (CWE-78): Remote Code Execution via Shell",
				WhatIsIt:            "User-supplied input is passed directly to a shell command without sanitization, allowing arbitrary OS commands to run.",
				AttackScenario:      "Attacker appends ; id or $(whoami) to an input parameter; the server executes the injected command and returns or stores the output. Trivially escalates to a reverse shell.",
				AttackVectorSummary: "Network-reachable input passed to OS shell functions without sanitization.",
				RealWorldLikelihood: "Critical — command injection is reliably RCE; automated scanners routinely confirm this class of vulnerability.",
				AffectedIf:          "Affected when any user-controlled value reaches exec(), system(), popen(), or equivalent without shell escaping.",
				NotAffectedIf:       "Not affected when OS commands are avoided entirely or all inputs are strictly validated against an allowlist before shell invocation.",
				ExploitabilityScore: 5.0,
				ExploitabilityTier:  "push_button",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-798", "CWE-259": // Hardcoded / Hard-coded Credentials
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathValidCredentials,
			LateralMovementPotential: schema.LateralMovementHigh,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", CorrectScore: 9.1, CorrectVersion: "3.1", Rationale: "Hardcoded credential grants direct authenticated access; no complexity barrier once secret is found."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Hardcoded Credentials (" + cweID + "): Live Secret Grants Direct Access",
				WhatIsIt:            "A credential, API key, or secret is embedded in source code or configuration and is accessible to anyone who can read the artifact.",
				AttackScenario:      "Attacker discovers the secret via repository search, leaked artifact, or secret scanner; uses it to authenticate to the target service with full granted permissions.",
				AttackVectorSummary: "Secret present in accessible artifact; authentication is trivial once the credential is retrieved.",
				RealWorldLikelihood: "High when the secret is verified live; automated credential hunters scan public repos and leaked build artifacts continuously.",
				AffectedIf:          "Affected when the secret is still valid and the service it authenticates to is reachable.",
				NotAffectedIf:       "Not affected once the secret is rotated, all dependent sessions are invalidated, and the commit history is purged.",
				ExploitabilityScore: 5.0,
				ExploitabilityTier:  "push_button",
			},
			Preconditions: []schema.Precondition{secretLivePrecondition()},
		}

	case "CWE-540": // Sensitive Information in Source Code (unverified secret)
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathValidCredentials,
			LateralMovementPotential: schema.LateralMovementMedium,
			Confidence:               schema.ConfidenceMedium,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", CorrectScore: 7.5, CorrectVersion: "3.1", Rationale: "Unverified secret still represents information disclosure; exploitability depends on whether the credential is live."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Sensitive Information in Source Code (CWE-540): Potential Credential Exposure",
				WhatIsIt:            "A secret-shaped value is present in source code or configuration but has not been confirmed live by the scanner.",
				AttackScenario:      "Attacker tests the secret against the target service; if still valid, exploits it the same way as a confirmed credential exposure.",
				AttackVectorSummary: "Potential credential present in accessible artifact; liveness requires verification.",
				RealWorldLikelihood: "Medium — unverified secrets are frequently live; rotation is often incomplete.",
				AffectedIf:          "Affected if the secret is still accepted by the target service.",
				NotAffectedIf:       "Not affected if the secret has been rotated and the commit history has been purged.",
				ExploitabilityScore: 3.5,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{secretLivePrecondition()},
		}

	case "CWE-284": // Improper Access Control (subdomain takeover)
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementMedium,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", CorrectScore: 6.1, CorrectVersion: "3.1", Rationale: "Subdomain takeover enables serving arbitrary content under the victim domain; UI:R because impact requires a user to visit the hijacked subdomain."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Subdomain Takeover (CWE-284): Attacker Claims Dangling DNS Target",
				WhatIsIt:            "A DNS CNAME or A record points to a resource (cloud bucket, CDN endpoint, SaaS service) that has been deprovisioned and can be reclaimed by an attacker.",
				AttackScenario:      "Attacker registers the dangling resource on the target provider and begins serving content under the victim's subdomain. Can host phishing pages, steal cookies scoped to the parent domain, or intercept OAuth redirect URIs.",
				AttackVectorSummary: "Attacker registers unclaimed cloud/CDN resource referenced by a dangling DNS record.",
				RealWorldLikelihood: "High when the takeover is confirmed; registration on most providers is trivial and automated.",
				AffectedIf:          "Affected until the dangling DNS record is removed or the underlying resource is reclaimed.",
				NotAffectedIf:       "Not affected when the DNS record is removed or the resource is held by the owning organization.",
				ExploitabilityScore: 4.0,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-306": // Missing Authentication for Critical Function
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityLow,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementHigh,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CorrectScore: 9.8, CorrectVersion: "3.1", Rationale: "Unauthenticated access to a critical function; no barrier to exploitation."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Missing Authentication (CWE-306): Critical Function Accessible Without Credentials",
				WhatIsIt:            "A function that should require authentication (admin panel, data API, control endpoint) accepts requests with no credential check.",
				AttackScenario:      "Attacker accesses the endpoint directly without any credentials and performs actions intended for privileged users.",
				AttackVectorSummary: "Network-reachable endpoint with no authentication enforcement.",
				RealWorldLikelihood: "Critical — if a scanner confirms no auth is required, exploitation is immediate.",
				AffectedIf:          "Affected when the endpoint is reachable and no authentication or authorization is enforced.",
				NotAffectedIf:       "Not affected when authentication is enforced at every entry point for the critical function.",
				ExploitabilityScore: 5.0,
				ExploitabilityTier:  "push_button",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	case "CWE-918": // Server-Side Request Forgery
		return &schema.IntrinsicAnalysis{
			RemoteTriggerability:     schema.TriggerYes,
			ExploitComplexity:        schema.ComplexityMedium,
			AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
			AttackPathClass:          schema.AttackPathExploitPublicFacing,
			LateralMovementPotential: schema.LateralMovementHigh,
			Confidence:               schema.ConfidenceHigh,
			PromptVersion:            "cwe/deterministic/v1",
			LLMModel:                 "deterministic",
			CVSSReconciliation:       schema.CVSSReconciliation{CorrectVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", CorrectScore: 8.6, CorrectVersion: "3.1", Rationale: "SSRF crosses scope boundary (S:C) and can reach internal metadata services; confidentiality impact is high."},
			AnalystBrief: schema.AnalystBrief{
				Title:               "Server-Side Request Forgery (CWE-918): Attacker Pivots Through Server",
				WhatIsIt:            "The server fetches a user-supplied URL without restriction, allowing an attacker to make the server issue requests to internal services.",
				AttackScenario:      "Attacker supplies http://169.254.169.254/latest/meta-data/ (cloud metadata) or an internal service URL; the server fetches it and returns the content, leaking credentials or enabling internal pivoting.",
				AttackVectorSummary: "Server fetches attacker-controlled URL with access to internal network.",
				RealWorldLikelihood: "High in cloud environments where metadata services expose instance credentials; commonly pivots to full account compromise.",
				AffectedIf:          "Affected when user-supplied URLs are fetched server-side without an allowlist restricting target hosts.",
				NotAffectedIf:       "Not affected when all outbound requests are validated against an allowlist that excludes internal IP ranges and cloud metadata endpoints.",
				ExploitabilityScore: 4.0,
				ExploitabilityTier:  "opportunistic",
			},
			Preconditions: []schema.Precondition{internetFacingPrecondition()},
		}

	default:
		return nil
	}
}

func classifyGenericFinding(v schema.GenericVulnerability) (string, *schema.IntrinsicAnalysis, schema.ExploitationEvidence, []string) {
	text := strings.ToLower(strings.Join([]string{
		v.Title, v.Description, v.Evidence, v.ProofOfConcept, v.DetectedBy,
		v.TemplateID, strings.Join(v.Tags, " "),
	}, " "))
	for k, val := range v.Metadata {
		text += " " + strings.ToLower(k) + " " + strings.ToLower(fmt.Sprint(val))
	}

	// CWE-first routing: if a known CWE is present, use its curated intrinsic
	// analysis instead of relying purely on keyword heuristics. This gives
	// non-CVE findings with a populated cwe_id accurate OPES E-component priors
	// and a proper analyst brief even without LLM analysis.
	if v.CWEID != "" {
		if cweAnalysis := cweIntrinsic(v.CWEID, v.Title); cweAnalysis != nil {
			ev := schema.ExploitationEvidence{}
			signals := []string{"cwe_id=" + v.CWEID}
			if v.Evidence != "" {
				signals = append(signals, "finding evidence present")
			}
			if v.DetectedBy != "" {
				signals = append(signals, "detected_by="+v.DetectedBy)
			}
			// Apply misconfig breach intelligence even on the CWE path — a port
			// finding can have both a CWE and be an exposed_remote_access class.
			applyMisconfigBreachIntel(v, &ev, &signals)
			cweAnalysis.CVEID = v.CVEID
			cweAnalysis.Rationale = "Classified from CWE " + v.CWEID + " profile. " + cweAnalysis.AnalystBrief.Title + "."
			return genericClassFromCWE(v.CWEID), cweAnalysis, ev, signals
		}
	}

	base := &schema.IntrinsicAnalysis{
		CVEID:                    v.CVEID,
		RemoteTriggerability:     schema.TriggerYes,
		ExploitComplexity:        schema.ComplexityLow,
		AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
		AttackPathClass:          schema.AttackPathExploitPublicFacing,
		LateralMovementPotential: schema.LateralMovementLow,
		Confidence:               schema.ConfidenceMedium,
		PromptVersion:            "generic/deterministic/v1",
		LLMModel:                 "deterministic",
		CVSSReconciliation: schema.CVSSReconciliation{
			CorrectVector:  genericVector(v),
			CorrectScore:   genericScore(v),
			CorrectVersion: "3.1",
			Rationale:      "Derived from ASM finding evidence and asset exposure rather than a CVE-specific advisory.",
		},
	}
	ev := schema.ExploitationEvidence{}
	signals := []string{}

	switch {
	case containsAny(text, "mongodb", "redis", "elasticsearch", "postgres", "mysql", "mssql", "couchdb", "cassandra", "database", "datastore"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Internet-Exposed Datastore: Unauthenticated or Risky Data-Service Exposure",
			WhatIsIt:            "The finding indicates a datastore or database service is reachable where direct internet exposure is dangerous and often exploitable without application-layer controls.",
			AttackScenario:      "An attacker scans for the exposed port, connects with a native client, enumerates metadata, and, when authentication is absent or weak, reads or modifies data directly.",
			AttackVectorSummary: "Remote network attacker reaches the datastore service directly.",
			RealWorldLikelihood: "High when the port is internet-facing; exposed datastores are heavily scanned and frequently abused for theft or extortion.",
			AffectedIf:          "Affected when the database port is reachable from untrusted networks or anonymous/default authentication is accepted.",
			NotAffectedIf:       "Not affected if firewall rules restrict access to trusted application hosts and authentication is enforced.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementMedium
		base.Preconditions = []schema.Precondition{internetFacingPrecondition(), portPresentPrecondition()}
		if containsAny(text, "read_me_to_recover", "ransom", "bitcoin", "onionmail", "recover your data") {
			ev.RansomwareAssociated = true
			ev.ObservationSources = append(ev.ObservationSources, "asm_ransom_marker")
			signals = append(signals, "ransomware/extortion marker in datastore evidence")
		}
	case containsAny(text, "secret", "token", "credential", "api key", "accountkey", "client_secret", "azurewebjobsstorage", "cosmos", "storage key"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Leaked Credential: Downstream Service Access from Exposed Secret",
			WhatIsIt:            "The finding contains credential material or secret-shaped evidence that may authenticate to a downstream cloud, identity, source-code, or data service.",
			AttackScenario:      "An attacker retrieves the exposed secret, validates it with a read-only or metadata request, then uses the granted permissions to enumerate data or pivot into related services.",
			AttackVectorSummary: "Remote attacker obtains a secret from exposed application, repository, or artifact content.",
			RealWorldLikelihood: "High when the secret is verified or appears in public content; automated secret hunters continuously scan these sources.",
			AffectedIf:          "Affected when the secret is live and grants access beyond a single low-value test resource.",
			NotAffectedIf:       "Not affected if the secret is revoked, scoped to harmless test data, and all dependent sessions/keys have been rotated.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.AttackPathClass = schema.AttackPathValidCredentials
		base.AttackerCapability = schema.AttackerUnauthenticatedNetwork
		base.LateralMovementPotential = schema.LateralMovementHigh
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
		if !containsAny(text, "verified true", "live true", "secret_verified true", "confirmed live") {
			base.Preconditions = append(base.Preconditions, secretLivePrecondition())
		}
	case containsAny(text, "blob", "bucket", "public storage", "publicaccess", "s3", "gcs", "azure storage"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Public Storage Exposure: Anonymous Access to Cloud Object Data",
			WhatIsIt:            "The finding indicates cloud object storage can be accessed anonymously or with overly broad credentials.",
			AttackScenario:      "An attacker discovers the storage endpoint, lists or retrieves exposed objects, and extracts sensitive documents, packages, or embedded credentials.",
			AttackVectorSummary: "Remote unauthenticated attacker reaches a public storage endpoint.",
			RealWorldLikelihood: "High for public containers and buckets because they are easy to enumerate and commonly indexed by scanners.",
			AffectedIf:          "Affected when public read/list is enabled or a leaked key grants broad storage permissions.",
			NotAffectedIf:       "Not affected when anonymous access is disabled and access is limited by identity, network, and least privilege.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementMedium
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	case containsAny(text, "debug", "tester", "environment", "env", "config", "settings", "function app", "azurewebsites"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Public Debug Endpoint: Runtime Configuration Disclosure",
			WhatIsIt:            "The finding indicates an endpoint discloses runtime configuration, environment variables, or parsed application settings.",
			AttackScenario:      "An attacker requests the endpoint anonymously, extracts credentials and service endpoints, then validates downstream access or chains through cloud identity.",
			AttackVectorSummary: "Remote unauthenticated attacker accesses a public diagnostic or test endpoint.",
			RealWorldLikelihood: "High when the endpoint is internet-facing and returns secrets or cloud configuration.",
			AffectedIf:          "Affected when debug/test routes are deployed in production or unauthenticated function routes expose environment data.",
			NotAffectedIf:       "Not affected when diagnostic routes are removed or protected and all previously disclosed secrets are rotated.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementHigh
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	default:
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "ASM Finding: Practical Exploitability Requires Context Review",
			WhatIsIt:            "This is an ASM-native security finding without a CVE identifier. Oracle can still evaluate it using detector evidence and asset exposure.",
			AttackScenario:      "An attacker follows the detected exposure path and attempts to turn the observed condition into access, data exposure, or service disruption.",
			AttackVectorSummary: "Attacker path depends on the detected finding class and reachable asset surface.",
			RealWorldLikelihood: "Medium until the finding is classified with stronger evidence or validated by a scanner/operator.",
			AffectedIf:          "Affected when the detector evidence accurately reflects a reachable, exploitable condition on this asset.",
			NotAffectedIf:       "Not affected only when current, asset-scoped evidence independently verifies that every documented exploitation path is blocked or the vulnerable condition is absent. Stale or missing evidence remains unknown.",
			ExploitabilityScore: 3.0,
			ExploitabilityTier:  "moderate",
		}
		base.RemoteTriggerability = schema.TriggerConditional
		base.ExploitComplexity = schema.ComplexityMedium
		base.AttackPathClass = schema.AttackPathUnknown
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	}
	base.Rationale = "Classified from ASM finding evidence (text heuristics)."
	if v.Evidence != "" {
		signals = append(signals, "finding evidence present")
	}
	if v.DetectedBy != "" {
		signals = append(signals, "detected_by="+v.DetectedBy)
	}
	// Apply misconfig breach intelligence: maps Nuclei template IDs, tags,
	// and port/service patterns to VCDB/M-Trends/CISA breach data, setting
	// MisconfigBreachRisk on ExploitationEvidence for the X component.
	applyMisconfigBreachIntel(v, &ev, &signals)
	return genericClass(text), base, ev, signals
}

// applyMisconfigBreachIntel looks up the finding against historical breach
// data and writes the result onto ev. Safe to call on any GenericVulnerability
// — returns immediately when no pattern matches.
func applyMisconfigBreachIntel(v schema.GenericVulnerability, ev *schema.ExploitationEvidence, signals *[]string) {
	bci := enrichers.LookupMisconfigBreachRisk(v.Tags, v.TemplateID, v.Title, v.Description)
	if !bci.Found {
		return
	}
	ev.MisconfigBreachRisk = bci.Score
	ev.MisconfigBreachClass = bci.Class
	ev.MisconfigBreachSources = bci.Sources
	*signals = append(*signals, "breach_class="+bci.Class)
}

// inferDetectionConfidence infers how deeply the scanner confirmed the
// vulnerable feature is active from template_id, detected_by, tags, and
// evidence text. Used when the caller has not already set DetectionConfidence
// on the GenericVulnerability.
//
// Classification logic:
//
//	exploit_confirmed  — the scanner sent a payload and received confirming
//	                     evidence (DNS callback, data extraction, redirect,
//	                     auth bypass with response proof, verified secret).
//	endpoint_confirmed — the vulnerable endpoint/feature responded and is
//	                     demonstrably live, but no exploit payload was fired.
//	version_only       — only version information was gathered (banner, header,
//	                     port fingerprint, passive SBOM version match).
//	unknown            — cannot be inferred from available signals.
func inferDetectionConfidence(v schema.GenericVulnerability) schema.DetectionConfidence {
	// Explicit value from the calling scanner service — trust it.
	if v.DetectionConfidence != "" && v.DetectionConfidence != schema.DetectionUnknown {
		return v.DetectionConfidence
	}

	tid := strings.ToLower(v.TemplateID)
	det := strings.ToLower(v.DetectedBy)
	evid := strings.ToLower(v.Evidence + " " + v.ProofOfConcept)
	tags := strings.ToLower(strings.Join(v.Tags, " "))

	// ── Exploit-confirmed signals ──────────────────────────────────────────
	// TruffleHog verified=true means the secret was validated against a live API.
	if det == "trufflehog" && (strings.Contains(evid, "verified=true") || strings.Contains(evid, "verified: true") || strings.Contains(evid, "\"verified\":true")) {
		return schema.ExploitConfirmed
	}
	// Evidence keywords indicating a working payload was confirmed.
	if containsAny(evid, "dns callback", "dnslog", "oast", "out-of-band", "canary token",
		"data extracted", "dumped", "blind injection", "rce confirmed", "command output",
		"reverse shell", "code execution confirmed") {
		return schema.ExploitConfirmed
	}
	// Nuclei templates classified as exploits in the template hierarchy.
	// Templates under cves/, exploits/, or rce/ that got a match are exploit-confirmed.
	if isExploitTemplate(tid) && (v.Evidence != "" || v.ProofOfConcept != "") {
		return schema.ExploitConfirmed
	}

	// ── Endpoint-confirmed signals ─────────────────────────────────────────
	// Nuclei detect/exposure/misconfiguration templates confirm the feature is live.
	if containsAny(tags, "exposure", "misconfiguration", "default-login", "auth-bypass") {
		return schema.EndpointConfirmed
	}
	if containsAny(tid, "detect", "exposure", "misconfiguration", "default-login", "login-panel",
		"config-detect", "status-check", "open-redirect", "directory-listing",
		"backup-files", "spring-actuator", "debug", "phpinfo", "info-disclosure") {
		return schema.EndpointConfirmed
	}
	// Subdomain takeover — the scanner confirmed the DNS points to an unclaimed service.
	if det == "takeover_scanner" {
		return schema.EndpointConfirmed
	}
	// Port scanner confirming an exposed service (not just a port open, but service responded).
	if det == "port_scanner" && v.Evidence != "" {
		return schema.EndpointConfirmed
	}
	// Nuclei matched a template with evidence — we got a response body match,
	// not just a TCP handshake.
	if det == "nuclei" && v.Evidence != "" && !isVersionTemplate(tid) {
		return schema.EndpointConfirmed
	}

	// ── Version-only signals ───────────────────────────────────────────────
	if containsAny(tid, "version", "tech-detect", "fingerprint", "headers", "banner", "detect") {
		return schema.VersionOnly
	}
	if containsAny(det, "port_scanner", "sbom", "passive") {
		return schema.VersionOnly
	}
	if containsAny(tags, "tech", "version-detection") {
		return schema.VersionOnly
	}

	// Default: unknown — no adjustment to difficulty.
	return schema.DetectionUnknown
}

// isExploitTemplate returns true when a Nuclei template ID pattern indicates
// the template sends an actual exploit payload (not just a detection probe).
func isExploitTemplate(templateID string) bool {
	return containsAny(templateID,
		"/cves/",     // CVE-specific exploits
		"/exploits/", // explicit exploit category
		"/rce/",      // remote code execution
		"/sqli/",     // SQL injection
		"/ssrf/",     // server-side request forgery
		"/lfi/",      // local file inclusion
		"/rfi/",      // remote file inclusion
		"-rce",       // e.g. spring4shell-rce, log4j-rce
		"-sqli",
		"-ssrf",
		"-blind", // blind injection variants
		"-oast",  // out-of-band application security testing
	)
}

// isVersionTemplate returns true when a Nuclei template ID indicates version
// detection only (not a functional exploit or endpoint probe).
func isVersionTemplate(templateID string) bool {
	return containsAny(templateID, "version", "tech-detect", "fingerprint", "-detect")
}

func genericClass(text string) string {
	switch {
	case containsAny(text, "mongodb", "redis", "elasticsearch", "postgres", "mysql", "mssql", "database", "datastore"):
		return "exposed_datastore"
	case containsAny(text, "secret", "token", "credential", "api key", "client_secret", "accountkey"):
		return "leaked_secret"
	case containsAny(text, "blob", "bucket", "public storage", "s3", "gcs", "azure storage"):
		return "public_storage"
	case containsAny(text, "debug", "tester", "environment", "config", "settings", "function app"):
		return "public_debug_endpoint"
	default:
		return "generic_asm_finding"
	}
}

// genericClassFromCWE maps a CWE ID to a finding_class string, used when CWE
// routing produces the intrinsic analysis rather than keyword heuristics.
func genericClassFromCWE(cweID string) string {
	switch strings.ToUpper(strings.TrimSpace(cweID)) {
	case "CWE-798", "CWE-259", "CWE-540":
		return "leaked_secret"
	case "CWE-89", "CWE-78", "CWE-77", "CWE-94":
		return "injection_vulnerability"
	case "CWE-79":
		return "cross_site_scripting"
	case "CWE-22", "CWE-23", "CWE-73":
		return "path_traversal"
	case "CWE-918":
		return "ssrf"
	case "CWE-284", "CWE-306", "CWE-287", "CWE-288":
		return "access_control_weakness"
	case "CWE-200", "CWE-312", "CWE-319":
		return "information_disclosure"
	case "CWE-611":
		return "xxe"
	case "CWE-502":
		return "deserialization"
	default:
		return "generic_asm_finding"
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func internetFacingPrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "internet-facing",
		Description:        "The affected service or endpoint is reachable from an untrusted network.",
		VerificationSignal: "network.internet_facing",
		MatchKind:          "equals",
		MatchValue:         "true",
		VerificationMethod: "Confirm asset exposure and firewall/load-balancer path.",
		Severity:           schema.PreconditionBlocker,
	}
}

func portPresentPrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "service-port-open",
		Description:        "The relevant datastore or management service port is open.",
		VerificationSignal: "network.open_ports",
		MatchKind:          "present",
		VerificationMethod: "Confirm port scan or service inventory shows the service as open.",
		Severity:           schema.PreconditionContributing,
	}
}

func secretLivePrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "secret-live",
		Description:        "The recovered credential is still accepted by the downstream service.",
		VerificationSignal: "extra.secret_verified",
		MatchKind:          "equals",
		MatchValue:         "true",
		VerificationMethod: "Perform only a read-only or metadata validation request against the downstream service.",
		Severity:           schema.PreconditionBlocker,
	}
}

func genericVector(v schema.GenericVulnerability) string {
	if strings.HasPrefix(v.CVSSVector, "CVSS:") {
		return v.CVSSVector
	}
	return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
}

func genericScore(v schema.GenericVulnerability) float64 {
	if v.CVSSScore > 0 {
		return v.CVSSScore
	}
	switch strings.ToLower(v.Severity) {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 3.0
	default:
		return 6.5
	}
}

func genericFindingID(v schema.GenericVulnerability, asset *schema.Asset) string {
	h := sha256.Sum256([]byte(v.ID + "|" + v.Title + "|" + v.Evidence + "|" + asset.ID))
	return "asm-" + hex.EncodeToString(h[:])[:20]
}

func buildGenericRecommendation(v schema.GenericVulnerability, asset *schema.Asset, analysis *schema.IntrinsicAnalysis, score schema.OPESScore, preconditions schema.PreconditionEvalSet) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s] %s — OPES %.1f (confidence: %s)\n", score.Category, score.Label, score.Value, score.Confidence)
	if asset != nil {
		fmt.Fprintf(&sb, "Asset: %s (%s)\n", asset.Hostname, asset.ID)
	}
	if analysis != nil {
		sb.WriteString("\nATTACK PATH\n")
		sb.WriteString(analysis.AnalystBrief.AttackScenario + "\n")
		sb.WriteString("\nAFFECTED IF\n")
		sb.WriteString(analysis.AnalystBrief.AffectedIf + "\n")
		if analysis.AnalystBrief.NotAffectedIf != "" {
			sb.WriteString("\nNOT AFFECTED IF\n")
			sb.WriteString(analysis.AnalystBrief.NotAffectedIf + "\n")
		}
	}
	if len(preconditions) > 0 {
		sb.WriteString("\nVERIFICATION\n")
		for _, p := range preconditions {
			fmt.Fprintf(&sb, "- %s: %s (%s)\n", p.Precondition.ID, p.Status, p.Reason)
		}
	}
	if v.Remediation != "" {
		sb.WriteString("\nREMEDIATION\n")
		sb.WriteString(v.Remediation + "\n")
	}
	return sb.String()
}

func buildLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func safeDSN(dsn string) string {
	if i := len(dsn); i > 30 {
		return dsn[:30] + "..."
	}
	return dsn
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
