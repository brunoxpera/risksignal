package application

// This file implements the shared matching-run core of WP-3.08 (ARCH-003
// §5, DEV-063): RunMatching computes and writes the method-led matches of
// one candidate batch — the (component, vulnerability) pairs the WP-3.07
// candidate pre-filter resolves (CandidateComponentIDs over the inventory
// product index) and the WP-3.08 rebuild/recompute handlers assemble into
// full engine inputs (DEV-064). The core owns the compute-and-write loop
// only: the evaluation is pure (application/matching.Evaluate over the
// candidate's statements, component, alias/decision rules and ruleset
// counters — the engine applies the decision_rules of the current ruleset
// version, ARCH-003 §3) and the write is the idempotent method-led match
// insert (UQ (vulnerability_id, component_id, rule_version), ADR-015).
//
// Transactioning — ARCH-003 §5: matches are computed and written in
// bounded batches of matchingBatchSize (guide 500) candidates per
// transaction, so a long run commits progress incrementally and a crash
// resumes at the next batch (the idempotent insert makes a re-run of an
// already-committed batch a no-op). A batch larger than one transaction's
// bound spans several transactions: a failure inside one transaction rolls
// that transaction back and aborts the run at that point, while the
// already-committed earlier transactions stay committed — the caller
// re-runs the whole batch and the idempotent key absorbs the overlap. An
// empty batch is a no-op: no transaction, zero result.
//
// What the core does not do (deliberately, ARCH-003 §5): it does not read
// components, rules or vulnerabilities — the candidates carry everything
// the evaluation reads (the engine has no hidden state), and it does not
// enqueue or run matching.rebuild/matching.recompute jobs (DEV-064).

import (
	"context"
	"fmt"

	"github.com/xpera/risksignal/internal/application/matching"
)

// matchingBatchSize bounds the candidates of one RunMatching transaction
// (ARCH-003 §5 "guide 500/transaction"): a run commits progress in
// batches of this size and a crash resumes at the next batch. The value is
// a batch-size guide, not a data limit — the caller may hand RunMatching a
// larger candidate list, which is then processed in several transactions.
const matchingBatchSize = 500

// MatchCandidate is one (component, vulnerability) pair of a matching run
// (ARCH-003 §3/§5): the persisted row identities of the pair — the
// VulnerabilityID the match row references (matches.vulnerability_id) and
// the component identity carried by the engine input
// (Evaluation.Component.ID, the persisted components row id) — plus the
// complete evaluation input of the pair. Everything the engine reads is in
// the input: the vulnerability-side affected-product statements, the
// component (as the full I3 row the lister returned), the effective alias
// and decision rules of the current ruleset version, the two ruleset
// version counters the outcome's rule_version is derived from
// (domain.RulesetVersion) and the clock instant for the decision-rule
// validity windows (Input.Now — the caller supplies the injected clock
// reading). The rebuild/recompute handler assembles candidates from its
// own reads (vulnerability statements, lister rows, rules); this use case
// never reads them again.
type MatchCandidate struct {
	// VulnerabilityID is the persisted vulnerabilities row id the match
	// row references; it must be non-empty.
	VulnerabilityID string
	// Evaluation is the full matching engine input of the pair.
	Evaluation matching.Input
}

// RunMatchingResult reports one RunMatching call: the number of evaluated
// candidates and the number of committed transactions the candidates were
// processed in (one per matchingBatchSize, so a batch of 500 commits in
// one transaction and a batch of 501 in two — ARCH-003 §5 incremental
// commit). An empty batch reports zero of both.
type RunMatchingResult struct {
	Candidates   int
	Transactions int
}

// RunMatching computes and writes the matches of one candidate batch
// (ARCH-003 §5, WP-3.08): every candidate is evaluated by the pure
// matching engine — which applies the decision rules of the candidate's
// ruleset (an exclude emits a visible no_match referencing the rule, an
// override forces its action while the raw computed triple moves into
// auto_*, ARCH-003 §3) — and the outcome is written as a method-led match
// through the MatchRepo port (idempotent on UQ (vulnerability_id,
// component_id, rule_version): a re-run of an already-written pair
// returns the existing row and never duplicates). The writes run in
// bounded transactions of matchingBatchSize candidates; created_at comes
// from the injected clock, read once per transaction. A malformed
// candidate (missing persistence id or an evaluation the engine rejects)
// aborts its whole transaction — no partial batch state — and is reported
// as a validation error; an insert failure propagates with its own error
// kind.
func (s *Service) RunMatching(ctx context.Context, batch []MatchCandidate) (RunMatchingResult, error) {
	const op = "matching_run"

	if len(batch) == 0 {
		return RunMatchingResult{}, nil // no candidates, no work, no transaction
	}
	res := RunMatchingResult{Candidates: len(batch)}

	for start := 0; start < len(batch); start += matchingBatchSize {
		end := start + matchingBatchSize
		if end > len(batch) {
			end = len(batch)
		}
		if err := s.runTx(ctx, func(tx Tx) error {
			now := s.clock.Now()
			for i := start; i < end; i++ {
				c := &batch[i]
				if c.VulnerabilityID == "" {
					return Validationf(op, "candidate %d: vulnerability id must not be empty", i)
				}
				if c.Evaluation.Component.ID == "" {
					return Validationf(op, "candidate %d: component id must not be empty", i)
				}
				out, err := matching.Evaluate(c.Evaluation)
				if err != nil {
					return ValidationError(op, fmt.Errorf("candidate %d: %w", i, err))
				}
				// The outcome flows into the match row verbatim: the
				// method-led triple (method/confidence/score derived by
				// the engine through the ADR-015 mapping), the composite
				// rule_version the outcome was computed under, and the
				// decision-rule state (reasons, the referencing rule, the
				// auto_* preservation of an override — nil for a purely
				// computed outcome).
				rec := MatchRecord{
					VulnerabilityID: c.VulnerabilityID,
					ComponentID:     c.Evaluation.Component.ID,
					Method:          out.Method,
					Confidence:      out.Confidence,
					Score:           out.Score,
					RuleVersion:     out.RuleVersion,
					Reasons:         out.Reasons,
					DecisionRuleID:  out.DecisionRuleID,
					AutoMethod:      out.AutoMethod,
					AutoConfidence:  out.AutoConfidence,
					AutoScore:       out.AutoScore,
				}
				if _, err := s.matches.Insert(ctx, tx, rec, now); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return RunMatchingResult{}, err
		}
		res.Transactions++
	}
	return res, nil
}
