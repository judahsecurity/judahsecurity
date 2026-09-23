package opes

// Config holds the tunable parameters for OPES. Defaults match the
// numbers documented in the architecture plan; per-tenant overrides
// load from YAML at runtime via the priority reasoner module's Init.
type Config struct {
	Weights   Weights
	Dampeners Dampeners
	Bucketing Bucketing
}

// Weights distribute influence across the six components. Must sum to
// roughly 1.0 to keep the score in 0–10. Defaults bias toward active
// exploitation evidence (X) and precondition satisfaction (P) because
// those are the strongest predictors of real-world risk.
type Weights struct {
	X float64 // active exploitation
	P float64 // precondition satisfaction
	R float64 // reachability
	E float64 // exploit difficulty (applied as 10-E)
	C float64 // asset criticality
	T float64 // time pressure
}

// Dampeners shape the score around uncertainty.
//
//   - UnknownBlockerCap: when any blocker precondition is Unknown, cap the
//     final score at this value (default P3-territory). Prevents the bot
//     from overstating priority on facts it cannot verify.
//
//   - KEVFloorThreshold / KEVFloorScore: when X ≥ threshold (KEV-listed),
//     floor the score at FloorScore. CISA/VulnCheck KEV listing means
//     this CVE is being exploited right now — it gets P0 regardless of
//     what other components say.
type Dampeners struct {
	UnknownBlockerCap float64
	KEVFloorThreshold float64
	KEVFloorScore     float64
}

// Bucketing is the score → priority mapping. A score ≥ the threshold maps to
// that bucket; below Low falls to Informational. Tune per customer risk appetite.
type Bucketing struct {
	Critical     float64
	High         float64
	Medium       float64
	Low          float64
}

// DefaultConfig returns the baseline OPES configuration. These numbers
// are calibrated against the CVE-2025-55130 golden test in opes_test.go.
// Adjust there too when changing weights.
func DefaultConfig() Config {
	return Config{
		Weights: Weights{
			X: 0.25,
			P: 0.20,
			R: 0.15,
			E: 0.15,
			C: 0.15,
			T: 0.10,
		},
		Dampeners: Dampeners{
			UnknownBlockerCap: 5.5,
			KEVFloorThreshold: 9.0,
			KEVFloorScore:     8.5,
		},
		Bucketing: Bucketing{
			Critical:     8.5,
			High:         7.0,
			Medium:       5.0,
			Low:          3.0,
		},
	}
}

// WithDefaults fills any zero-valued sub-struct with defaults. Used when
// loading partial configs from YAML.
func (c Config) WithDefaults() Config {
	d := DefaultConfig()
	if c.Weights == (Weights{}) {
		c.Weights = d.Weights
	}
	if c.Dampeners == (Dampeners{}) {
		c.Dampeners = d.Dampeners
	}
	if c.Bucketing == (Bucketing{}) {
		c.Bucketing = d.Bucketing
	}
	return c
}
