// Package opes implements the Oracle Practical Exploitability Score —
// Aegis Oracle's deterministic, auditable risk score for a (CVE, Asset)
// pair.
//
// The LLM extracts structured facts in upstream phases. This package
// converts those facts into a 0–10 score and a P0..P4 priority bucket
// using pure arithmetic. Same inputs always produce the same score,
// which is what makes findings defensible at scale.
//
// See ../../../../knowledgebase/ for the curated CWE profiles and dev
// patterns that feed the upstream intrinsic reasoner.
package opes

import (
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Version is the OPES evaluator version. Bump on any logic change so
// findings can be re-evaluated and old scores marked superseded.
const Version = "opes/v2"

// Input bundles everything OPES needs to compute a score. All fields
// are owned by upstream pipeline stages — OPES does not fetch anything.
type Input struct {
	CVE           *schema.CVE
	Intrinsic     *schema.IntrinsicAnalysis
	Asset         *schema.Asset
	Preconditions schema.PreconditionEvalSet
	Exploitation  schema.ExploitationEvidence
	Now           time.Time

	// CWEID is the primary CWE for this finding (e.g. "CWE-89").
	// When empty and CVE is set, Compute auto-populates from CVE.CWEs[0].
	// Used by the difficulty (E) component to apply a weakness-class ceiling:
	// well-understood weakness classes like SQLi or hardcoded credentials
	// cannot be scored as "hard to exploit" regardless of other signals.
	CWEID string

	// DetectionConfidence describes whether the vulnerable feature / code path
	// was confirmed active by the scanner, or whether we only know the version.
	//
	//   ExploitConfirmed  → difficulty −2.0 (code path proven; attacker scout work done)
	//   EndpointConfirmed → difficulty −1.0 (feature is live; weaponization still needed)
	//   VersionOnly       → difficulty +1.5 (attacker must confirm reachability themselves)
	//   DetectionUnknown  → no adjustment
	//
	// This directly addresses the gap between "Server: Apache/2.4.50" (version_only)
	// and a Nuclei RCE template that got a DNS callback (exploit_confirmed).
	// Both would otherwise receive identical difficulty scores, mispricing the
	// attacker's remaining work.
	DetectionConfidence schema.DetectionConfidence
}

// Compute runs the OPES pipeline: components → overrides → weighted sum
// → dampeners → bucketize. Returns a fully-populated OPESScore ready to
// embed in a Finding.
//
// Compute never returns an error: bad inputs degrade gracefully (e.g. no
// intrinsic analysis → middle-of-range component values + low confidence)
// rather than panicking. This keeps the scoring path safe to call from
// anywhere in the pipeline.
func Compute(in Input, cfg Config) schema.OPESScore {
	cfg = cfg.WithDefaults()
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	// Auto-populate CWEID from CVE when not explicitly supplied by the caller.
	if in.CWEID == "" && in.CVE != nil && len(in.CVE.CWEs) > 0 {
		in.CWEID = in.CVE.CWEs[0]
	}

	components := schema.OPESComponents{
		E: difficulty(in),
		R: reachability(in, cfg),
		P: preconditionScore(in.Preconditions),
		X: exploitation(in.Exploitation),
		C: criticality(in.Asset, in.Intrinsic),
		T: timePressure(in, in.Now),
	}

	return combine(in, components, cfg)
}
