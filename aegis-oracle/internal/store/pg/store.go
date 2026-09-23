// Package pg implements the Aegis Oracle Postgres store: asset inventory
// reads and finding writes against the shared ASM database.
//
// Connection assumptions:
//   - Single Postgres DSN from config (same DB your ASM uses)
//   - Aegis Oracle schema objects live in the "oracle" schema to avoid
//     collisions with existing ASM tables. Set search_path if needed.
//   - Asset rows come from the ASM's existing asset table. The adapter
//     maps ASM columns → schema.Asset via a view or the asset_view query.
//
// No ORM. Plain pgx v5 with prepared statements. sqlc can be added later
// once the query surface stabilises.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Store holds a pool and implements both the asset inventory read-side
// and the finding write-side against Postgres.
type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

// Config is the Postgres connection and mapping configuration.
type Config struct {
	DSN string `yaml:"dsn"` // e.g. "postgres://user:pass@host:5432/dbname"

	// AssetTable is the fully-qualified table/view that exposes ASM assets
	// in the column mapping expected by scanAsset. Default: "assets".
	AssetTable string `yaml:"asset_table"`

	// Schema prefix for oracle-owned tables ("oracle" by default).
	// All findings/verification tables are prefixed with this.
	OracleSchema string `yaml:"oracle_schema"`
}

func (c Config) withDefaults() Config {
	if c.AssetTable == "" {
		c.AssetTable = "assets"
	}
	if c.OracleSchema == "" {
		c.OracleSchema = "oracle"
	}
	return c
}

// New opens a pgxpool connection. Call Close when done.
func New(ctx context.Context, cfg Config) (*Store, error) {
	cfg = cfg.withDefaults()
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool, cfg: cfg}, nil
}

func (s *Store) Close() { s.pool.Close() }

// ─────────────────────────── Asset reads ───────────────────────────────

// GetAsset returns a single asset by ID.
func (s *Store) GetAsset(ctx context.Context, assetID string) (*schema.Asset, error) {
	q := fmt.Sprintf(`SELECT asset_id, tenant_id, hostname, ip::text,
		open_ports, signals, criticality, exposure, source, updated_at
		FROM %s WHERE asset_id = $1`, s.cfg.AssetTable)
	row := s.pool.QueryRow(ctx, q, assetID)
	return scanAsset(row)
}

// ListAssets walks all assets matching the filter. Returns an error-yielding
// iterator; callers must check both the asset and the error on each iteration.
//
// Example:
//
//	for asset, err := range store.ListAssets(ctx, pg.ListFilter{}) {
//	    if err != nil { return err }
//	    // use asset
//	}
func (s *Store) ListAssets(ctx context.Context, f ListFilter) ([](*schema.Asset), error) {
	q := fmt.Sprintf(`SELECT asset_id, tenant_id, hostname, ip::text,
		open_ports, signals, criticality, exposure, source, updated_at
		FROM %s WHERE 1=1`, s.cfg.AssetTable)
	args := []any{}
	n := 1
	if f.TenantID != "" {
		q += fmt.Sprintf(" AND tenant_id = $%d", n)
		args = append(args, f.TenantID)
		n++
	}
	if len(f.Exposure) > 0 {
		q += fmt.Sprintf(" AND exposure = ANY($%d)", n)
		args = append(args, f.Exposure)
		n++
	}
	if f.UpdatedSince != nil {
		q += fmt.Sprintf(" AND updated_at >= $%d", n)
		args = append(args, *f.UpdatedSince)
		n++
	}
	_ = n
	q += " ORDER BY updated_at DESC"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	var out []*schema.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListFilter constrains ListAssets.
type ListFilter struct {
	TenantID     string
	Exposure     []string
	UpdatedSince *time.Time
}

func scanAsset(row pgx.Row) (*schema.Asset, error) {
	var (
		a          schema.Asset
		ipStr      *string
		openPorts  []int32
		signalsRaw []byte
		tenantID   *string
		hostname   *string
	)
	err := row.Scan(
		&a.ID, &tenantID, &hostname, &ipStr,
		&openPorts, &signalsRaw, &a.Criticality, &a.Exposure, &a.Source, &a.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan asset: %w", err)
	}
	if tenantID != nil {
		a.TenantID = *tenantID
	}
	if hostname != nil {
		a.Hostname = *hostname
	}
	if ipStr != nil {
		a.IP = *ipStr
	}
	for _, p := range openPorts {
		a.OpenPorts = append(a.OpenPorts, int(p))
	}
	if len(signalsRaw) > 0 {
		if err := json.Unmarshal(signalsRaw, &a.Signals); err != nil {
			return nil, fmt.Errorf("unmarshal signals: %w", err)
		}
	}
	return &a, nil
}

// ─────────────────────────── CVE reads ─────────────────────────────────

// GetCVE returns a canonical CVE record by ID.
func (s *Store) GetCVE(ctx context.Context, cveID string) (*schema.CVE, error) {
	q := fmt.Sprintf(`SELECT cve_id, published_at, modified_at, description,
		cwes, cpes, cvss_vectors, in_kev, kev_added_on,
		nuclei_template, poc_count, primary_source,
		COALESCE(epss_score, 0), COALESCE(epss_percentile, 0)
		FROM %s.cves WHERE cve_id = $1`, s.cfg.OracleSchema)
	row := s.pool.QueryRow(ctx, q, cveID)
	return scanCVE(row)
}

func scanCVE(row pgx.Row) (*schema.CVE, error) {
	var (
		c          schema.CVE
		cpesRaw    []byte
		vectorsRaw []byte
		kevAdded   *time.Time
		nuclei     *string
		epss       float64
		epssPerc   float64
	)
	err := row.Scan(
		&c.ID, &c.PublishedAt, &c.ModifiedAt, &c.Description,
		&c.CWEs, &cpesRaw, &vectorsRaw, &c.InKEV, &kevAdded,
		&nuclei, &c.POCCount, &c.PrimarySource,
		&epss, &epssPerc,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan cve: %w", err)
	}
	if kevAdded != nil {
		c.KEVAddedOn = kevAdded
	}
	if nuclei != nil {
		c.NucleiTemplate = *nuclei
	}
	if epss > 0 {
		c.EPSS = &schema.EPSSScore{Score: epss, Percentile: epssPerc}
	}
	if len(cpesRaw) > 0 {
		_ = json.Unmarshal(cpesRaw, &c.CPEs)
	}
	if len(vectorsRaw) > 0 {
		_ = json.Unmarshal(vectorsRaw, &c.CVSSVectors)
	}
	return &c, nil
}

// UpsertCVE writes a canonical CVE record into the oracle.cves table. Used by
// the on-demand ingest path: when an analyst pastes a CVE id we haven't seen
// before, the daemon fetches it from upstream (vulnx, NVD, etc.), normalises
// to schema.CVE, and persists with this function. Subsequent calls hit the
// row by GetCVE without re-fetching upstream.
//
// We never lose ingested data: an existing row is updated in-place with the
// fields we have. NULLs on epss/kev_added_on are preserved by treating the
// zero value of EPSS as "no score" and the zero KEVAddedOn as NULL.
//
// References (URL list) live alongside the canonical row in
// oracle.cves.reference_urls; the rendered text caches are written to
// oracle.reference_content by the reference-fetcher when the LLM needs them.
func (s *Store) UpsertCVE(ctx context.Context, c *schema.CVE) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("upsert cve: missing id")
	}

	cpesJSON, err := json.Marshal(c.CPEs)
	if err != nil {
		return fmt.Errorf("marshal cpes: %w", err)
	}
	vectorsJSON, err := json.Marshal(c.CVSSVectors)
	if err != nil {
		return fmt.Errorf("marshal cvss_vectors: %w", err)
	}

	refURLs := make([]string, 0, len(c.References))
	for _, ref := range c.References {
		if ref.URL != "" {
			refURLs = append(refURLs, ref.URL)
		}
	}
	cwes := c.CWEs
	if cwes == nil {
		cwes = []string{}
	}

	var (
		epssScore *float64
		epssPerc  *float64
	)
	if c.EPSS != nil {
		// Treat zeroed EPSS as "no signal" so we don't blow away an earlier
		// non-zero value with a placeholder.
		if c.EPSS.Score > 0 || c.EPSS.Percentile > 0 {
			s := c.EPSS.Score
			p := c.EPSS.Percentile
			epssScore = &s
			epssPerc = &p
		}
	}

	var kevAdded *time.Time
	if c.KEVAddedOn != nil && !c.KEVAddedOn.IsZero() {
		kevAdded = c.KEVAddedOn
	}

	primarySource := c.PrimarySource
	if primarySource == "" {
		primarySource = "vulnx"
	}

	q := fmt.Sprintf(`INSERT INTO %s.cves
		(cve_id, published_at, modified_at, description,
		 cwes, cpes, cvss_vectors, reference_urls,
		 epss_score, epss_percentile, in_kev, kev_added_on,
		 nuclei_template, poc_count, primary_source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())
		ON CONFLICT (cve_id) DO UPDATE SET
		  published_at    = EXCLUDED.published_at,
		  modified_at     = EXCLUDED.modified_at,
		  description     = EXCLUDED.description,
		  cwes            = EXCLUDED.cwes,
		  cpes            = EXCLUDED.cpes,
		  cvss_vectors    = EXCLUDED.cvss_vectors,
		  reference_urls  = EXCLUDED.reference_urls,
		  epss_score      = COALESCE(EXCLUDED.epss_score, %s.cves.epss_score),
		  epss_percentile = COALESCE(EXCLUDED.epss_percentile, %s.cves.epss_percentile),
		  in_kev          = EXCLUDED.in_kev OR %s.cves.in_kev,
		  kev_added_on    = COALESCE(EXCLUDED.kev_added_on, %s.cves.kev_added_on),
		  nuclei_template = COALESCE(NULLIF(EXCLUDED.nuclei_template, ''), %s.cves.nuclei_template),
		  poc_count       = GREATEST(EXCLUDED.poc_count, %s.cves.poc_count),
		  primary_source  = EXCLUDED.primary_source,
		  updated_at      = now()`,
		s.cfg.OracleSchema,
		s.cfg.OracleSchema, s.cfg.OracleSchema, s.cfg.OracleSchema,
		s.cfg.OracleSchema, s.cfg.OracleSchema, s.cfg.OracleSchema,
	)

	_, err = s.pool.Exec(ctx, q,
		c.ID, c.PublishedAt, c.ModifiedAt, c.Description,
		cwes, cpesJSON, vectorsJSON, refURLs,
		epssScore, epssPerc, c.InKEV, kevAdded,
		nullableText(c.NucleiTemplate), c.POCCount, primarySource,
	)
	if err != nil {
		return fmt.Errorf("upsert cve %s: %w", c.ID, err)
	}
	return nil
}

// nullableText returns nil for an empty string so pgx writes SQL NULL instead
// of an empty string — needed for optional text columns where downstream
// readers distinguish "absent" from "empty".
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ─────────────────────────── Intrinsic analysis ─────────────────────────

// GetIntrinsicAnalysis returns the latest cached intrinsic analysis for a
// CVE, or nil if one doesn't exist yet.
func (s *Store) GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error) {
	q := fmt.Sprintf(`SELECT
		remote_triggerability, exploit_complexity, attacker_capability,
		preconditions, cvss_reconciliation, attack_chain_summary,
		detection_signals, rationale, confidence,
		prompt_version, llm_model,
		COALESCE(attack_path_class, ''),
		COALESCE(lateral_movement_potential, ''),
		COALESCE(analyst_brief, '{}'::jsonb),
		COALESCE(intrinsic_context, '{}'::jsonb)
		FROM %s.cve_intrinsic_analyses
		WHERE cve_id = $1
		ORDER BY created_at DESC LIMIT 1`, s.cfg.OracleSchema)
	row := s.pool.QueryRow(ctx, q, cveID)

	var (
		a             schema.IntrinsicAnalysis
		precondsRaw   []byte
		reconcileRaw  []byte
		detectionRaw  []byte
		briefRaw      []byte
		contextRaw    []byte
		promptVersion *string
		llmModel      *string
		attackPath    string
		lateralMov    string
	)
	err := row.Scan(
		&a.RemoteTriggerability, &a.ExploitComplexity, &a.AttackerCapability,
		&precondsRaw, &reconcileRaw, &a.AttackChainSummary,
		&detectionRaw, &a.Rationale, &a.Confidence,
		&promptVersion, &llmModel,
		&attackPath, &lateralMov, &briefRaw, &contextRaw,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan intrinsic: %w", err)
	}
	if promptVersion != nil {
		a.PromptVersion = *promptVersion
	}
	if llmModel != nil {
		a.LLMModel = *llmModel
	}
	a.AttackPathClass = schema.AttackPathClass(attackPath)
	a.LateralMovementPotential = schema.LateralMovementPotential(lateralMov)
	_ = json.Unmarshal(precondsRaw, &a.Preconditions)
	_ = json.Unmarshal(reconcileRaw, &a.CVSSReconciliation)
	_ = json.Unmarshal(detectionRaw, &a.DetectionSignals)
	_ = json.Unmarshal(briefRaw, &a.AnalystBrief)
	var intrinsicContext schema.IntrinsicContext
	_ = json.Unmarshal(contextRaw, &intrinsicContext)
	a.ApplyContext(intrinsicContext)
	a.CVEID = cveID
	return &a, nil
}

// UpsertIntrinsicAnalysis writes a new intrinsic analysis row.
// Uses ON CONFLICT DO NOTHING — same (cve_id, input_hash, prompt_version)
// is idempotent.
func (s *Store) UpsertIntrinsicAnalysis(ctx context.Context, cveID, inputHash string, a *schema.IntrinsicAnalysis, costUSD float64) error {
	precondsJSON, _ := json.Marshal(a.Preconditions)
	reconcileJSON, _ := json.Marshal(a.CVSSReconciliation)
	detectionJSON, _ := json.Marshal(a.DetectionSignals)
	briefJSON, _ := json.Marshal(a.AnalystBrief)
	contextJSON, _ := json.Marshal(a.Context())

	q := fmt.Sprintf(`INSERT INTO %s.cve_intrinsic_analyses
		(cve_id, input_hash, prompt_version, llm_provider, llm_model,
		 remote_triggerability, exploit_complexity, attacker_capability,
		 preconditions, cvss_reconciliation, attack_chain_summary,
		 detection_signals, rationale, confidence, cost_usd,
		 attack_path_class, lateral_movement_potential, analyst_brief, intrinsic_context)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT DO NOTHING`, s.cfg.OracleSchema)

	provider := providerFromModel(a.LLMModel)
	attackPath := nullableText(string(a.AttackPathClass))
	lateralMov := nullableText(string(a.LateralMovementPotential))
	_, err := s.pool.Exec(ctx, q,
		cveID, inputHash, a.PromptVersion, provider, a.LLMModel,
		string(a.RemoteTriggerability), string(a.ExploitComplexity), string(a.AttackerCapability),
		precondsJSON, reconcileJSON, a.AttackChainSummary,
		detectionJSON, a.Rationale, string(a.Confidence), costUSD,
		attackPath, lateralMov, briefJSON, contextJSON,
	)
	return err
}

// ─────────────────────────── Finding writes ─────────────────────────────

// UpsertFinding writes a finding. If an identical (cve, asset, hashes,
// evaluator) row exists it is a no-op; otherwise inserts a new row and
// marks the previous open finding as superseded.
func (s *Store) UpsertFinding(ctx context.Context, f *schema.Finding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Supersede any open finding for this (cve, asset) pair that predates
	// this evaluation. This keeps only the latest finding active per pair.
	supersedQ := fmt.Sprintf(`UPDATE %s.findings
		SET status = 'superseded', superseded_by = $1, updated_at = now()
		WHERE cve_id = $2 AND asset_id = $3
		  AND status = 'open' AND finding_id != $1`, s.cfg.OracleSchema)
	_, err = tx.Exec(ctx, supersedQ, f.ID, f.CVEID, f.AssetID)
	if err != nil {
		return fmt.Errorf("supersede old findings: %w", err)
	}

	precsJSON, _ := json.Marshal(f.PreconditionsEvaluated)
	compsJSON, _ := json.Marshal(f.OPES.Components)
	contribsJSON, _ := json.Marshal(f.OPES.TopContributors)
	reconcileJSON, _ := json.Marshal(f.CVSSReconciliation)
	briefJSON, _ := json.Marshal(f.AnalystBrief)
	contextJSON, _ := json.Marshal(f.ContextualAssessment)
	attackPath := nullableText(string(f.AttackPathClass))
	lateralMov := nullableText(string(f.LateralMovementPotential))

	insertQ := fmt.Sprintf(`INSERT INTO %s.findings
		(finding_id, cve_id, asset_id,
		 intrinsic_input_hash, asset_signals_hash, evaluator_version,
		 preconditions_evaluated, contextual_assessment,
		 opes_score, opes_category, opes_label, opes_components,
		 opes_top_contributors, opes_dampener, opes_override,
		 confidence, priority_rationale, recommendation_text,
		 cvss_reconciliation, analyst_brief,
		 attack_path_class, lateral_movement_potential,
		 status, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,now(),now())
		ON CONFLICT (cve_id, asset_id, intrinsic_input_hash, asset_signals_hash, evaluator_version)
		DO NOTHING`, s.cfg.OracleSchema)

	_, err = tx.Exec(ctx, insertQ,
		f.ID, f.CVEID, f.AssetID,
		f.IntrinsicInputHash, f.AssetSignalsHash, f.EvaluatorVersion,
		precsJSON, contextJSON,
		f.OPES.Value, string(f.OPES.Category), f.OPES.Label, compsJSON,
		contribsJSON, f.OPES.Dampener, f.OPES.Override,
		string(f.OPES.Confidence), "", f.RecommendationText,
		reconcileJSON, briefJSON,
		attackPath, lateralMov,
		string(schema.StatusOpen),
	)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}

	// Write verification tasks for unknown-blocker preconditions.
	for _, t := range f.VerificationTasks {
		taskQ := fmt.Sprintf(`INSERT INTO %s.verification_tasks
			(finding_id, precondition_id, task_kind, command,
			 expected_signal_path, expected_match, status)
			VALUES ($1,$2,$3,$4,$5,$6,'open')
			ON CONFLICT DO NOTHING`, s.cfg.OracleSchema)
		_, err = tx.Exec(ctx, taskQ,
			f.ID, t.PreconditionID, t.TaskKind, t.Command,
			t.ExpectedSignalPath, t.ExpectedMatch,
		)
		if err != nil {
			return fmt.Errorf("insert verification task: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// GetOpenFindings returns all open findings optionally filtered by CVE or
// asset. Used by the ASM UI query layer.
func (s *Store) GetOpenFindings(ctx context.Context, cveID, assetID string) ([]*schema.Finding, error) {
	q := fmt.Sprintf(`SELECT
		finding_id, cve_id, asset_id,
		opes_score, opes_category, opes_label, opes_dampener, opes_override,
		confidence, recommendation_text, status, created_at, updated_at,
		COALESCE(cvss_reconciliation, '{}'::jsonb),
		COALESCE(analyst_brief, '{}'::jsonb),
		COALESCE(attack_path_class, ''),
		COALESCE(lateral_movement_potential, ''),
		COALESCE(preconditions_evaluated, '[]'::jsonb),
		COALESCE(contextual_assessment, '{}'::jsonb),
		opes_components, opes_top_contributors
		FROM %s.findings WHERE status = 'open'`, s.cfg.OracleSchema)
	args := []any{}
	n := 1
	if cveID != "" {
		q += fmt.Sprintf(" AND cve_id = $%d", n)
		args = append(args, cveID)
		n++
	}
	if assetID != "" {
		q += fmt.Sprintf(" AND asset_id = $%d", n)
		args = append(args, assetID)
		n++
	}
	_ = n
	q += " ORDER BY opes_score DESC, created_at DESC"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*schema.Finding
	for rows.Next() {
		var f schema.Finding
		var dampener, override *string
		var reconcileRaw, briefRaw, precsRaw, contextRaw []byte
		var compsRaw, contribsRaw []byte
		var attackPath, lateralMov string
		err := rows.Scan(
			&f.ID, &f.CVEID, &f.AssetID,
			&f.OPES.Value, &f.OPES.Category, &f.OPES.Label, &dampener, &override,
			&f.OPES.Confidence, &f.RecommendationText, &f.Status, &f.CreatedAt, &f.UpdatedAt,
			&reconcileRaw, &briefRaw, &attackPath, &lateralMov, &precsRaw, &contextRaw,
			&compsRaw, &contribsRaw,
		)
		if err != nil {
			return nil, err
		}
		if dampener != nil {
			f.OPES.Dampener = *dampener
		}
		if override != nil {
			f.OPES.Override = *override
		}
		f.AttackPathClass = schema.AttackPathClass(attackPath)
		f.LateralMovementPotential = schema.LateralMovementPotential(lateralMov)
		_ = json.Unmarshal(reconcileRaw, &f.CVSSReconciliation)
		_ = json.Unmarshal(briefRaw, &f.AnalystBrief)
		_ = json.Unmarshal(precsRaw, &f.PreconditionsEvaluated)
		_ = json.Unmarshal(contextRaw, &f.ContextualAssessment)
		_ = json.Unmarshal(compsRaw, &f.OPES.Components)
		_ = json.Unmarshal(contribsRaw, &f.OPES.TopContributors)
		out = append(out, &f)
	}
	return out, rows.Err()
}

// ─────────────────────────── Scheduler support ──────────────────────────────

// BulkMarkKEV sets in_kev=true and kev_added_on for every CVE ID that already
// exists in oracle.cves. IDs that are not yet in the store are silently
// skipped — they will be marked on first on-demand ingest. Callers pass
// parallel slices: cveIDs[i] corresponds to addedOns[i].
func (s *Store) BulkMarkKEV(ctx context.Context, cveIDs []string, addedOns []time.Time) error {
	if len(cveIDs) == 0 {
		return nil
	}
	q := fmt.Sprintf(`UPDATE %s.cves
		SET in_kev      = true,
		    kev_added_on = COALESCE(%s.cves.kev_added_on, u.added_on),
		    updated_at  = now()
		FROM unnest($1::text[], $2::timestamptz[]) AS u(cve_id, added_on)
		WHERE %s.cves.cve_id = u.cve_id`,
		s.cfg.OracleSchema, s.cfg.OracleSchema, s.cfg.OracleSchema)

	_, err := s.pool.Exec(ctx, q, cveIDs, addedOns)
	if err != nil {
		return fmt.Errorf("bulk mark kev: %w", err)
	}
	return nil
}

// UpdateEPSS sets epss_score and epss_percentile for a single CVE without
// touching any other column. No-ops if the CVE is not in oracle.cves.
func (s *Store) UpdateEPSS(ctx context.Context, cveID string, score, percentile float64) error {
	q := fmt.Sprintf(`UPDATE %s.cves
		SET epss_score      = $2,
		    epss_percentile = $3,
		    updated_at      = now()
		WHERE cve_id = $1`, s.cfg.OracleSchema)
	_, err := s.pool.Exec(ctx, q, cveID, score, percentile)
	if err != nil {
		return fmt.Errorf("update epss %s: %w", cveID, err)
	}
	return nil
}

// ListCVEsWithoutAnalysis returns up to limit CVE IDs that have no row in
// cve_intrinsic_analyses. Ordered by updated_at DESC so newly-ingested CVEs
// (e.g. fresh KEV additions) are prioritised. Used by the auto-analyze job.
func (s *Store) ListCVEsWithoutAnalysis(ctx context.Context, limit int) ([]string, error) {
	q := fmt.Sprintf(`SELECT c.cve_id
		FROM %s.cves c
		LEFT JOIN %s.cve_intrinsic_analyses a ON a.cve_id = c.cve_id
		WHERE a.cve_id IS NULL
		ORDER BY c.updated_at DESC
		LIMIT $1`, s.cfg.OracleSchema, s.cfg.OracleSchema)
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list cves without analysis: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan cve id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListCVEIDsSince returns all CVE IDs in oracle.cves whose updated_at is
// more recent than since. Used by the background EPSS refresh job to bound
// its refresh window to recently active rows.
func (s *Store) ListCVEIDsSince(ctx context.Context, since time.Time) ([]string, error) {
	q := fmt.Sprintf(`SELECT cve_id FROM %s.cves WHERE updated_at > $1 ORDER BY updated_at DESC`,
		s.cfg.OracleSchema)
	rows, err := s.pool.Query(ctx, q, since)
	if err != nil {
		return nil, fmt.Errorf("list cve ids since: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan cve id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ─────────────────────────── helpers ────────────────────────────────────

func providerFromModel(model string) string {
	switch {
	case len(model) > 9 && model[:9] == "anthropic":
		return "anthropic"
	case len(model) > 3 && model[:3] == "gpt":
		return "openai"
	default:
		return "unknown"
	}
}
