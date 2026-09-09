package application

// This file implements the matching.recompute run of WP-3.08 (ARCH-003
// §5, ADR-012, DEV-064): MatchingRunner.RecomputeMatching executes the
// pre-filtered CVE batch job — the incremental path for new evidence
// whose affected products have inventory relevance. Nothing in the I3
// code base enqueues the job yet (the NVD incremental runs of WP-3.09/
// DEV-052 do, after the candidate pre-filter); this file is the consumer
// side of the contract matching_jobs.go declares.
//
// Direction (ADR-012 point 3): the job carries a batch of vulnerability
// row ids (guide 500) that the enqueue side already pre-filtered for
// inventory relevance — there is no unfiltered CVE-driven fan-out, the
// job count stays proportional to the evidence change, never to the CVE
// population. The run resolves — per CVE of the batch, through the
// WP-3.07 candidate pre-filter (CandidateComponentIDs over the inventory
// product index) — the candidate components of the CVE's normalised
// affected-name pairs, assembles the (component, vulnerability)
// candidates and commits them through the RunMatching core in bounded
// transactions. A CVE without candidate components (its pairs meet no
// component) yields no candidates and therefore no work — the pre-filter
// gate of ADR-012.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// RecomputeMatching executes one matching.recompute job (ARCH-003 §5):
// resolve the candidate components of every vulnerability of the
// pre-filtered batch through the candidate pre-filter, assemble the
// candidates and commit them through the matching core. The batch is
// processed in ascending id order (the same order the dedupe key hashes),
// so a re-run of the same job always derives the same candidates. A
// failure mid-run aborts at that point — the earlier candidates of the
// run are already committed and the re-claimed job (expired lease,
// TR-012) resumes with no double effect (the idempotent match insert).
// Inputs that violate the job contract (no ids, more than
// matchingRecomputeMaxIDs ids, no rule version) are validation errors,
// i.e. permanent job failures.
func (r *MatchingRunner) RecomputeMatching(ctx context.Context, in RecomputeMatchingInput) (RecomputeMatchingResult, error) {
	const op = "matching_recompute"

	if in.RuleVersion == "" {
		return RecomputeMatchingResult{}, Validationf(op, "recompute job carries no rule_version")
	}
	if len(in.VulnerabilityIDs) == 0 {
		return RecomputeMatchingResult{}, Validationf(op, "recompute job carries no vulnerability ids")
	}
	if len(in.VulnerabilityIDs) > matchingRecomputeMaxIDs {
		return RecomputeMatchingResult{}, Validationf(op, "recompute job carries %d vulnerability ids, the batch guide is %d",
			len(in.VulnerabilityIDs), matchingRecomputeMaxIDs)
	}
	st, err := r.ruleState(ctx, op)
	if err != nil {
		return RecomputeMatchingResult{}, err
	}
	if st.ruleVersion != in.RuleVersion {
		// A ruleset change between the enqueue and this run (its own
		// recompute/rebuild was enqueued): run under the live rules, the
		// idempotent match insert makes the overlap harmless.
		r.logger.Warn("matching.recompute run under a ruleset newer than the job payload",
			slog.String("job_rule_version", in.RuleVersion),
			slog.String("live_rule_version", st.ruleVersion))
	}
	now := r.clk.Now()

	ids := sortedUniqueIDs(in.VulnerabilityIDs)
	rows, err := r.vulns.ListByIDs(ctx, ids)
	if err != nil {
		return RecomputeMatchingResult{}, err
	}
	if len(rows) == 0 {
		return RecomputeMatchingResult{}, nil // no rows, no work
	}

	candidates, err := r.recomputeCandidates(ctx, rows, st, now)
	if err != nil {
		return RecomputeMatchingResult{}, err
	}
	if len(candidates) == 0 {
		return RecomputeMatchingResult{Vulnerabilities: len(rows)}, nil
	}
	run, err := r.core.RunMatching(ctx, candidates)
	if err != nil {
		return RecomputeMatchingResult{}, err
	}
	return RecomputeMatchingResult{
		Vulnerabilities: len(rows),
		Candidates:      run.Candidates,
		Transactions:    run.Transactions,
	}, nil
}

// recomputeCandidates assembles the candidate batch of the recompute
// rows: per row (ascending id), the candidate components of the row's
// normalised affected-name pairs are resolved through the candidate
// pre-filter (CandidateComponentIDs — the alias closure and the
// product-index semi-join of ADR-012) and read back as full rows, and
// every (component, vulnerability) pair becomes a MatchCandidate. A row
// without name pairs (an identifier-only or digest-only statement set) or
// without candidate components yields no candidates — no work.
func (r *MatchingRunner) recomputeCandidates(ctx context.Context, rows []VulnerabilityMatch, st matchingRuleState, now time.Time) ([]MatchCandidate, error) {
	const op = "matching_recompute"

	candidates := make([]MatchCandidate, 0)
	for ri := range rows {
		row := &rows[ri]
		pairs := statementNamePairs(row.Statements)
		if len(pairs) == 0 {
			continue // no name-level candidates to resolve
		}
		compIDs, err := CandidateComponentIDs(ctx, pairs, st.aliasRules, r.components)
		if err != nil {
			return nil, InfraError(op, fmt.Errorf("resolve candidate components of %s (%s): %w", row.CVEID, row.ID, err))
		}
		if len(compIDs) == 0 {
			continue // the pre-filter gate: no candidate ⇒ no matching work (ADR-012)
		}
		comps, err := r.components.ListComponentsByIDs(ctx, compIDs)
		if err != nil {
			return nil, InfraError(op, fmt.Errorf("read candidate components of %s (%s): %w", row.CVEID, row.ID, err))
		}
		for ci := range comps {
			dc, err := componentForMatch(comps[ci])
			if err != nil {
				return nil, ValidationError(op, fmt.Errorf("component %s: %w", comps[ci].ID, err))
			}
			candidates = append(candidates, MatchCandidate{
				VulnerabilityID: row.ID,
				Evaluation:      candidateInput(*row, dc, st, now),
			})
		}
	}
	return candidates, nil
}

// sortedUniqueIDs sorts a copy of the given vulnerability ids ascending
// and removes duplicates — the canonical id set of one recompute batch.
// The dedupe key hashes the sorted list; processing the same sorted set
// keeps the run deterministic even when the enqueuer's batch carried an
// id twice.
func sortedUniqueIDs(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	uniq := out[:0]
	var last string
	for _, id := range out {
		if id == last {
			continue
		}
		uniq = append(uniq, id)
		last = id
	}
	return uniq
}
