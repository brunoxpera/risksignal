package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file implements the read port of the priority factor rebuild (ARCH-004
// §5, WP-4.04b / DEV-077). Rebuild assembles one signal's fresh
// PriorityFactors from its persisted context: the linked match's method
// (confidence re-derived per ADR-015), the vulnerability's latest KEV/CVSS/
// EPSS evidence, and the owning asset's criticality/exposure. Both reads are
// plain, transaction-free lookups — the recompute reads before it decides
// whether anything changed, so an identical recompute touches no database.
//
// The factor evidence shapes are the canonical values the sources write (the
// I1b synthetic shapes and the I2 adapter shapes, a superset): cvss
// {cve_id, base_score, …}, kev {cve_id, known_exploited, …}, epss {cve_id,
// percentile}. KEV carries one nuance — a kev_removed evidence historises the
// removal of a CVE from the catalog (ARCH-002 §2.2) — so the latest kev and
// the latest kev_removed rows are compared by observed_at: a removal newer
// than the newest membership evidence wins (known_exploited = false).

// PriorityFactorRepo is the postgres implementation of
// application.PriorityFactorRepo.
type PriorityFactorRepo struct {
	q *gen.Queries
}

// NewPriorityFactorRepo binds the repository to one query set.
func NewPriorityFactorRepo(q *gen.Queries) *PriorityFactorRepo { return &PriorityFactorRepo{q: q} }

// Rebuild resolves the fresh factor set of one signal. A missing signal is a
// not-found Error; a match method the ADR-015 mapping does not know is an
// infrastructure error (a stored row the write paths could not have produced).
func (r *PriorityFactorRepo) Rebuild(ctx context.Context, signalID string) (application.PriorityFactorRebuild, error) {
	const op = "priority_factors.rebuild"

	uid, err := toUUID(signalID)
	if err != nil {
		return application.PriorityFactorRebuild{}, application.ValidationError(op, err)
	}
	src, err := r.q.GetSignalPriorityFactorSource(ctx, uid)
	if err != nil {
		return application.PriorityFactorRebuild{}, mapDBError(op, err)
	}
	rows, err := r.q.ListVulnerabilityFactorEvidence(ctx, src.VulnerabilityID)
	if err != nil {
		return application.PriorityFactorRebuild{}, mapDBError(op, err)
	}
	factors, err := factorsFromSource(op, src, rows)
	if err != nil {
		return application.PriorityFactorRebuild{}, err
	}
	if err := factors.Validate(); err != nil {
		return application.PriorityFactorRebuild{}, application.ValidationError(op, err)
	}
	return application.PriorityFactorRebuild{CVEID: src.CveID, Factors: factors}, nil
}

// factorsFromSource assembles the factor set from the signal's context and
// its vulnerability's latest factor evidence. Confidence is re-derived from
// the authoritative match method (ADR-015) rather than trusted from a stored
// copy.
func factorsFromSource(op string, src gen.GetSignalPriorityFactorSourceRow, rows []gen.ListVulnerabilityFactorEvidenceRow) (domain.PriorityFactors, error) {
	factors := domain.PriorityFactors{
		Method:      domain.MatchMethod(src.Method),
		Criticality: domain.Criticality(src.Criticality),
		Exposure:    domain.Exposure(src.Exposure),
	}
	conf, ok := factors.Method.Confidence()
	if !ok {
		return domain.PriorityFactors{}, application.InfraError(op, fmt.Errorf("match method %q has no ADR-015 confidence", src.Method))
	}
	factors.Confidence = conf

	var kevAt, kevRemovedAt time.Time
	for _, row := range rows {
		switch domain.EvidenceType(row.Type) {
		case domain.EvidenceTypeCVSS:
			var v struct {
				BaseScore float64 `json:"base_score"`
			}
			if err := json.Unmarshal(row.Value, &v); err != nil {
				return domain.PriorityFactors{}, application.InfraError(op, fmt.Errorf("decode cvss evidence: %w", err))
			}
			factors.CVSS = v.BaseScore
		case domain.EvidenceTypeEPSS:
			var v struct {
				Percentile float64 `json:"percentile"`
			}
			if err := json.Unmarshal(row.Value, &v); err != nil {
				return domain.PriorityFactors{}, application.InfraError(op, fmt.Errorf("decode epss evidence: %w", err))
			}
			factors.EPSS = v.Percentile
		case domain.EvidenceTypeKEV:
			var v struct {
				KnownExploited bool `json:"known_exploited"`
			}
			if err := json.Unmarshal(row.Value, &v); err != nil {
				return domain.PriorityFactors{}, application.InfraError(op, fmt.Errorf("decode kev evidence: %w", err))
			}
			factors.KEV = v.KnownExploited
			kevAt = row.ObservedAt.Time
		case domain.EvidenceTypeKEVRemoved:
			kevRemovedAt = row.ObservedAt.Time
		}
	}
	// A membership evidence older than the newest removal means the CVE is no
	// longer in the catalog (ARCH-002 §2.2): the removal wins.
	if !kevRemovedAt.IsZero() && (kevAt.IsZero() || kevRemovedAt.After(kevAt)) {
		factors.KEV = false
	}
	return factors, nil
}
