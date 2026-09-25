package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// SchedulerStore is the minimal persistence surface the Scheduler needs.
// *pg.Store satisfies this interface; it is a superset of Ingester.Store.
type SchedulerStore interface {
	// Inherited from on-demand ingest — used for NVD delta upserts.
	UpsertCVE(ctx context.Context, c *schema.CVE) error

	// KEV bulk mark: sets in_kev=true and kev_added_on for matching rows.
	// Rows not present in oracle.cves are silently skipped.
	BulkMarkKEV(ctx context.Context, cveIDs []string, addedOns []time.Time) error

	// EPSS point update: updates epss_score + epss_percentile for one CVE.
	// No-ops if the CVE is not in oracle.cves.
	UpdateEPSS(ctx context.Context, cveID string, score, percentile float64) error

	// ListCVEIDsSince returns all CVE IDs whose updated_at > since.
	// Used by the EPSS refresh job to bound the refresh window.
	ListCVEIDsSince(ctx context.Context, since time.Time) ([]string, error)

	// ListCVEsWithoutAnalysis returns up to limit CVE IDs that have no
	// intrinsic analysis row yet. Used by the auto-analyze job.
	ListCVEsWithoutAnalysis(ctx context.Context, limit int) ([]string, error)

	// GetCVE returns the full CVE record for analysis. Returns nil, nil if
	// the CVE is not in the store.
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
}

// SchedulerIntervals controls how often each background sync job runs.
type SchedulerIntervals struct {
	NVDDelta       time.Duration // default: 1h   — recently-modified CVE delta from NVD
	CISAKEV        time.Duration // default: 6h   — full CISA KEV catalogue refresh
	EPSS           time.Duration // default: 12h  — EPSS score refresh for recent CVEs
	AnalyzePending time.Duration // default: 15m  — auto Phase-A analysis of unanalyzed CVEs
}

// DefaultIntervals returns conservative production-ready intervals.
func DefaultIntervals() SchedulerIntervals {
	return SchedulerIntervals{
		NVDDelta:       time.Hour,
		CISAKEV:        6 * time.Hour,
		EPSS:           12 * time.Hour,
		AnalyzePending: 15 * time.Minute,
	}
}

// Scheduler runs background CVE freshness sync jobs.
//
// Four jobs run concurrently on independent tickers:
//
//   - nvd_delta       (every 1h):  Queries the NVD CVE 2.0 API for any CVE whose
//     lastModified falls in the previous window. New CVEs are inserted; existing
//     rows have their CVSS vectors, CWEs, and references refreshed. Handles NVD
//     pagination (2000 results/page) with mandatory inter-page sleep.
//
//   - cisa_kev        (every 6h):  Downloads the full CISA Known Exploited
//     Vulnerabilities catalogue (~1400 CVEs as of 2026) and bulk-marks any
//     matching rows in oracle.cves with in_kev=true / kev_added_on. Rows not
//     yet in oracle.cves are not auto-ingested — KEV status is applied lazily
//     the next time that CVE is requested.
//
//   - epss            (every 12h): Fetches fresh EPSS scores from FIRST.org for
//     every CVE updated in oracle.cves within the last 30 days. Uses the EPSS
//     batch API (up to 500 CVE IDs per request) and updates scores in-place
//     without touching other columns.
//
//   - analyze_pending (every 15m): Runs Phase-A intrinsic analysis on CVEs that
//     have no entry in cve_intrinsic_analyses yet. Processes up to 20 CVEs per
//     run, newest-first, so KEV additions are prioritised. Skipped when no LLM
//     analyzer is wired (analyzer == nil).
//
// All jobs fire once immediately at startup so the store is never more than
// one interval stale from a cold start.
type Scheduler struct {
	store      SchedulerStore
	analyzer   func(ctx context.Context, cve *schema.CVE) error // nil = disabled
	nvdAPIKey  string
	intervals  SchedulerIntervals
	httpClient *http.Client
}

// NewScheduler constructs a Scheduler ready to be started.
// nvdKey is optional; passing one raises NVD's rate limit from 5 to 50 req/30s.
// analyzer is optional; pass nil to disable the auto-analyze job.
func NewScheduler(store SchedulerStore, nvdKey string, intervals SchedulerIntervals, analyzer func(ctx context.Context, cve *schema.CVE) error) *Scheduler {
	if intervals.NVDDelta == 0 {
		intervals = DefaultIntervals()
	}
	if intervals.AnalyzePending == 0 {
		intervals.AnalyzePending = 15 * time.Minute
	}
	return &Scheduler{
		store:      store,
		analyzer:   analyzer,
		nvdAPIKey:  nvdKey,
		intervals:  intervals,
		httpClient: &http.Client{Timeout: 45 * time.Second},
	}
}

// Start launches all sync goroutines. They run until ctx is cancelled.
// Safe to call in a go-routine: "go scheduler.Start(ctx)".
func (s *Scheduler) Start(ctx context.Context) {
	slog.Info("background ingestion scheduler starting",
		"nvd_delta_interval", s.intervals.NVDDelta,
		"cisa_kev_interval", s.intervals.CISAKEV,
		"epss_interval", s.intervals.EPSS,
		"analyze_pending_interval", s.intervals.AnalyzePending,
	)
	go s.loop(ctx, "nvd_delta", s.intervals.NVDDelta, s.syncNVDDelta)
	go s.loop(ctx, "cisa_kev", s.intervals.CISAKEV, s.syncCISAKEV)
	go s.loop(ctx, "epss", s.intervals.EPSS, s.syncEPSS)
	if s.analyzer != nil {
		go s.loop(ctx, "analyze_pending", s.intervals.AnalyzePending, s.syncAnalyzePending)
	}
}

// loop fires job immediately, then on every tick until ctx is done.
func (s *Scheduler) loop(ctx context.Context, name string, interval time.Duration, job func(context.Context) error) {
	run := func() {
		if err := job(ctx); err != nil {
			slog.Warn("scheduler sync error", "job", name, "error", err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler job stopped", "job", name)
			return
		case <-ticker.C:
			run()
		}
	}
}

// ─────────────────────────── NVD delta sync ─────────────────────────────────

const nvdCVEsURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// syncNVDDelta fetches CVEs modified in the last NVDDelta window and upserts
// them. Handles multi-page responses with mandatory inter-page sleep.
func (s *Scheduler) syncNVDDelta(ctx context.Context) error {
	end := time.Now().UTC()
	// Pull a slightly wider window than the ticker interval to handle clock
	// skew and NVD's eventual-consistency lag (NVD recommends 2h overlap).
	start := end.Add(-(s.intervals.NVDDelta + 2*time.Hour))

	const pageSize = 2000
	startIdx := 0
	var ingested int

	for {
		requestURL := nvdDeltaURL(start, end, pageSize, startIdx)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return fmt.Errorf("nvd delta: build request: %w", err)
		}
		req.Header.Set("User-Agent", "aegis-oracle/1.0")
		req.Header.Set("Accept", "application/json")
		if s.nvdAPIKey != "" {
			req.Header.Set("apiKey", s.nvdAPIKey)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("nvd delta: fetch: %w", err)
		}
		if resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return fmt.Errorf("nvd delta: HTTP 403 (rate limit — set NVD_API_KEY)")
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("nvd delta: HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("nvd delta: read body: %w", err)
		}

		var page nvdDeltaPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("nvd delta: parse: %w", err)
		}

		for _, item := range page.Vulnerabilities {
			cve := nvdDeltaItemToSchema(item.CVE)
			if err := s.store.UpsertCVE(ctx, cve); err != nil {
				slog.Warn("nvd delta: upsert failed", "cve", cve.ID, "error", err)
			} else {
				ingested++
			}
		}

		fetched := startIdx + len(page.Vulnerabilities)
		if fetched >= page.TotalResults || len(page.Vulnerabilities) < pageSize {
			break
		}
		startIdx += pageSize

		// NVD requires callers to sleep between paginated requests.
		// Key: 50 req/30s → 600 ms min; no key: 5 req/30s → 6 s min.
		if s.nvdAPIKey != "" {
			time.Sleep(700 * time.Millisecond)
		} else {
			time.Sleep(7 * time.Second)
		}
	}

	if ingested > 0 {
		slog.Info("nvd delta sync complete",
			"ingested", ingested,
			"window", fmt.Sprintf("%s → %s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
		)
	}
	return nil
}

func nvdDeltaURL(start, end time.Time, pageSize, startIdx int) string {
	params := url.Values{}
	params.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000+00:00"))
	params.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000+00:00"))
	params.Set("resultsPerPage", fmt.Sprint(pageSize))
	params.Set("startIndex", fmt.Sprint(startIdx))
	return nvdCVEsURL + "?" + params.Encode()
}

// ─────────────────────────── CISA KEV sync ──────────────────────────────────

const cisaKEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

func (s *Scheduler) syncCISAKEV(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKEVFeedURL, nil)
	if err != nil {
		return fmt.Errorf("cisa kev: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cisa kev: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cisa kev: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return fmt.Errorf("cisa kev: read: %w", err)
	}

	var kev struct {
		Vulnerabilities []struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"` // "2021-11-03"
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &kev); err != nil {
		return fmt.Errorf("cisa kev: parse: %w", err)
	}

	ids := make([]string, 0, len(kev.Vulnerabilities))
	addedOns := make([]time.Time, 0, len(kev.Vulnerabilities))
	for _, v := range kev.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		t, _ := time.Parse("2006-01-02", v.DateAdded)
		ids = append(ids, strings.ToUpper(v.CVEID))
		addedOns = append(addedOns, t)
	}

	if err := s.store.BulkMarkKEV(ctx, ids, addedOns); err != nil {
		return fmt.Errorf("cisa kev: bulk mark: %w", err)
	}
	slog.Info("cisa kev sync complete", "kev_entries", len(ids))
	return nil
}

// ─────────────────────────── EPSS sync ──────────────────────────────────────

const epssAPIURL = "https://api.first.org/data/v1/epss"

func (s *Scheduler) syncEPSS(ctx context.Context) error {
	since := time.Now().UTC().AddDate(0, 0, -30)
	ids, err := s.store.ListCVEIDsSince(ctx, since)
	if err != nil {
		return fmt.Errorf("epss: list cve ids: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}

	// FIRST EPSS API: up to 500 CVE IDs per request (stay well under limit).
	const batchSize = 500
	var updated int

	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[i:end]

		url := fmt.Sprintf("%s?cve=%s&envelope=true&pretty=false",
			epssAPIURL, strings.Join(batch, ","))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("epss: build request: %w", err)
		}
		req.Header.Set("User-Agent", "aegis-oracle/1.0")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			slog.Warn("epss: batch fetch failed", "batch_start", i, "error", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			slog.Warn("epss: batch HTTP error", "batch_start", i, "status", resp.StatusCode)
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if err != nil {
			slog.Warn("epss: read failed", "batch_start", i, "error", err)
			continue
		}

		var result struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			slog.Warn("epss: parse failed", "batch_start", i, "error", err)
			continue
		}

		for _, d := range result.Data {
			if d.CVE == "" {
				continue
			}
			var score, perc float64
			fmt.Sscanf(d.EPSS, "%f", &score)
			fmt.Sscanf(d.Percentile, "%f", &perc)
			if score == 0 && perc == 0 {
				continue
			}
			if err := s.store.UpdateEPSS(ctx, strings.ToUpper(d.CVE), score, perc); err != nil {
				slog.Warn("epss: update failed", "cve", d.CVE, "error", err)
				continue
			}
			updated++
		}
	}

	slog.Info("epss sync complete", "refreshed", updated, "window_days", 30, "total_ids", len(ids))
	return nil
}

// ─────────────────────────── Auto-analyze pending ───────────────────────────

// syncAnalyzePending runs Phase-A intrinsic analysis on CVEs that have no
// analysis row yet. Processes up to 20 CVEs per run, newest-first, with a
// 5-second pause between calls to stay gentle on LLM rate limits.
func (s *Scheduler) syncAnalyzePending(ctx context.Context) error {
	const batchSize = 20

	ids, err := s.store.ListCVEsWithoutAnalysis(ctx, batchSize)
	if err != nil {
		return fmt.Errorf("analyze_pending: list: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}

	slog.Info("analyze_pending: starting batch", "count", len(ids))
	var analyzed, skipped int

	for _, cveID := range ids {
		if ctx.Err() != nil {
			break
		}

		cve, err := s.store.GetCVE(ctx, cveID)
		if err != nil {
			slog.Warn("analyze_pending: get cve failed", "cve", cveID, "error", err)
			skipped++
			continue
		}
		if cve == nil {
			skipped++
			continue
		}

		analyzeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		err = s.analyzer(analyzeCtx, cve)
		cancel()
		if err != nil {
			slog.Warn("analyze_pending: analysis failed", "cve", cveID, "error", err)
			skipped++
		} else {
			slog.Info("analyze_pending: analyzed", "cve", cveID)
			analyzed++
		}

		// Pause between LLM calls to avoid rate limit spikes.
		select {
		case <-ctx.Done():
			break
		case <-time.After(5 * time.Second):
		}
	}

	slog.Info("analyze_pending: batch complete", "analyzed", analyzed, "skipped", skipped)
	return nil
}

// ─────────────────────────── NVD delta structs ──────────────────────────────
//
// These mirror the shape of nvd.go's internal struct but are defined here to
// avoid duplication while keeping the delta-only fields independent.

type nvdDeltaPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdDeltaItem `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdDeltaItem struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics struct {
		CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
		CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
		CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Criteria   string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

func nvdDeltaItemToSchema(v nvdDeltaItem) *schema.CVE {
	cve := &schema.CVE{
		ID:            v.ID,
		PublishedAt:   parseTime(v.Published, time.Now().UTC()),
		ModifiedAt:    parseTime(v.LastModified, time.Now().UTC()),
		PrimarySource: "nvd_delta",
	}
	for _, d := range v.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			cve.Description = d.Value
			break
		}
	}
	if cve.Description == "" && len(v.Descriptions) > 0 {
		cve.Description = v.Descriptions[0].Value
	}
	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cve.CWEs = append(cve.CWEs, d.Value)
			}
		}
	}
	cve.CWEs = dedupeStrings(cve.CWEs)
	cve.CVSSVectors = append(cve.CVSSVectors, nvdMetricsToVectors(v.Metrics.CVSSMetricV40, "4.0")...)
	cve.CVSSVectors = append(cve.CVSSVectors, nvdMetricsToVectors(v.Metrics.CVSSMetricV31, "3.1")...)
	cve.CVSSVectors = append(cve.CVSSVectors, nvdMetricsToVectors(v.Metrics.CVSSMetricV30, "3.0")...)
	cve.CVSSVectors = append(cve.CVSSVectors, nvdMetricsToVectors(v.Metrics.CVSSMetricV2, "2.0")...)
	for _, r := range v.References {
		if r.URL == "" {
			continue
		}
		cve.References = append(cve.References, schema.Reference{
			URL:        r.URL,
			SourceKind: classifyReferenceKind(r.URL),
			Tags:       r.Tags,
		})
	}
	for _, conf := range v.Configurations {
		for _, n := range conf.Nodes {
			for _, m := range n.CPEMatch {
				if m.Criteria == "" {
					continue
				}
				cve.CPEs = append(cve.CPEs, schema.CPEMatch{URI: m.Criteria, Vulnerable: m.Vulnerable})
			}
		}
	}
	return cve
}
