package application

// This file implements the matching.rebuild run of WP-3.08 (ARCH-003 §5,
// ADR-012, DEV-064): MatchingRunner.RebuildMatching executes the job the
// inventory commit of DEV-060 enqueues — the inventory-driven walk that
// recomputes every match of the current inventory under the current
// ruleset.
//
// Direction (ADR-012 point 2 — the reason matching.rebuild exists): the
// walk is inventory-driven and bounded by the component set. No CVE
// population is ever iterated, no per-CVE work is fanned out: the run
// walks the components in keyset pages of matchingComponentPageSize
// (guide 500), resolves — per page — the candidate CVEs of the page's
// normalised (vendor, product) name pairs through the reverse side of
// the WP-3.07 candidate pre-filter (MatchingVulnerabilityRepo.ListByPairs
// over the pair set, each pair expanded through the symmetric one-hop
// alias closure of both axes), intersects the returned rows with each
// component's own closed pair set, assembles the MatchCandidates of the
// page (the component read model converted to the domain engine input —
// componentForMatch) and commits them through RunMatching, whose bounded
// transactions (matchingBatchSize) give the page its incremental commit:
// a crash mid-run leaves every committed page in place and the re-claimed
// job resumes at the next page — the idempotent match insert (UQ
// (vulnerability_id, component_id, rule_version)) makes the re-run of an
// already-committed page a no-op (TR-012).
//
// Exactly one job per rebuild: the enqueue side derives the job's dedupe
// key from the rule version and the inventory snapshot hash (DEV-060),
// and the outbox UQ holds for the whole job lifetime (ADR-012 point 4) —
// this run does not check the key again, it simply re-derives the same
// matches whenever it runs.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/xpera/risksignal/internal/application/normalise"
)

// rebuildPageResult is the assembled candidate batch of one component
// page plus the page bookkeeping of the run.
type rebuildPageResult struct {
	components int
	candidates []MatchCandidate
	afterID    string // id of the last walked row; "" when the page was empty
}

// RebuildMatching executes one matching.rebuild job (ARCH-003 §5): walk
// the components in bounded pages, resolve the candidate CVEs of each
// page's name pairs through the reverse pre-filter read, assemble the
// candidates and commit them through the matching core. A page whose
// candidate resolution or component conversion fails aborts the run at
// that page — the earlier pages stay committed and the re-claimed job
// resumes there (the idempotent match insert absorbs the overlap).
// An empty inventory is a successful no-op: zero pages, zero candidates,
// zero transactions. Inputs that violate the job contract (missing rule
// version or inventory snapshot — a payload the enqueue side never
// writes) are validation errors, i.e. permanent job failures.
func (r *MatchingRunner) RebuildMatching(ctx context.Context, in RebuildMatchingInput) (RebuildMatchingResult, error) {
	const op = "matching_rebuild"

	if in.RuleVersion == "" {
		return RebuildMatchingResult{}, Validationf(op, "rebuild job carries no rule_version")
	}
	if in.InventorySnapshot == "" {
		return RebuildMatchingResult{}, Validationf(op, "rebuild job carries no inventory_snapshot")
	}
	st, err := r.ruleState(ctx, op)
	if err != nil {
		return RebuildMatchingResult{}, err
	}
	if st.ruleVersion != in.RuleVersion {
		// A ruleset change between the enqueue and this run: the rule
		// change enqueues its own fresh rebuild under the new version,
		// and the idempotent match insert makes this run's overlap with
		// it harmless — run under the live rules, log the skew.
		r.logger.Warn("matching.rebuild run under a ruleset newer than the job payload",
			slog.String("job_rule_version", in.RuleVersion),
			slog.String("live_rule_version", st.ruleVersion))
	}
	now := r.clk.Now()

	var res RebuildMatchingResult
	afterID := ""
	for {
		page, err := r.rebuildPage(ctx, afterID, st, now)
		if err != nil {
			return RebuildMatchingResult{}, err
		}
		res.Components += page.components
		if len(page.candidates) == 0 {
			if page.components == 0 {
				return res, nil // the walk reached the end of the inventory
			}
			// A full page whose components all resolved no candidates:
			// commit nothing, continue with the next page.
			afterID = page.afterID
			continue
		}
		run, err := r.core.RunMatching(ctx, page.candidates)
		if err != nil {
			return RebuildMatchingResult{}, err
		}
		res.Candidates += run.Candidates
		res.Transactions += run.Transactions
		afterID = page.afterID
	}
}

// rebuildPage resolves and assembles the candidates of one component
// page of the walk (matchingComponentPageSize rows, ascending by id,
// starting after afterID). It returns the walked component count, the
// assembled candidates and the id cursor of the next page (the id of the
// last walked row; "" when the page was empty, i.e. the walk is done).
func (r *MatchingRunner) rebuildPage(ctx context.Context, afterID string, st matchingRuleState, now time.Time) (rebuildPageResult, error) {
	const op = "matching_rebuild"

	comps, err := r.components.ListComponentsPage(ctx, afterID, matchingComponentPageSize)
	if err != nil {
		return rebuildPageResult{}, InfraError(op, fmt.Errorf("list component page after %q: %w", afterID, err))
	}
	res := rebuildPageResult{components: len(comps)}
	if len(comps) == 0 {
		return res, nil // the walk is done
	}
	res.afterID = comps[len(comps)-1].ID

	// Per-page candidate resolution (ADR-012 — bound the work by the
	// component set): derive the raw name pair of every component of the
	// page, expand each pair through the symmetric alias closure of both
	// axes and resolve the vulnerabilities whose raw affected-name pairs
	// meet any closed pair. One reverse read per page — never per CVE,
	// never per component with the same pair twice.
	type pageComponent struct {
		comp Component
		raw  VendorProductPair
		vc   map[string]struct{} // closed vendor keys of the component's pair
		pc   map[string]struct{} // closed product keys
	}
	pageComps := make([]pageComponent, 0, len(comps))
	querySet := make(map[VendorProductPair]struct{})
	for i := range comps {
		raw, ok := componentNamePair(comps[i])
		if !ok {
			continue // no name identity — resolves no name-level candidates
		}
		closed := closedNamePairs(raw, st.aliasRules)
		entry := pageComponent{
			comp: comps[i],
			raw:  raw,
			vc:   make(map[string]struct{}, len(closed)),
			pc:   make(map[string]struct{}, len(closed)),
		}
		for _, p := range closed {
			entry.vc[p.Vendor] = struct{}{}
			entry.pc[p.Product] = struct{}{}
			querySet[p] = struct{}{}
		}
		pageComps = append(pageComps, entry)
	}
	var rows []VulnerabilityMatch
	if len(querySet) > 0 {
		rows, err = r.vulns.ListByPairs(ctx, sortedPairs(querySet))
		if err != nil {
			return rebuildPageResult{}, InfraError(op, fmt.Errorf("resolve candidate CVEs of the page: %w", err))
		}
	}

	// Intersect: a row is a candidate of a component when one of its raw
	// affected-name pairs lies inside the component's closed pair set
	// (the exact mirror of the pre-filter semi-join, ARCH-003 §4). The
	// intersection keeps the candidate resolution symmetric — a canonical
	// name and its aliases meet whether the CVE side or the component
	// side carries the variant — while the engine decides the actual
	// evidence tier per pair.
	candidates := make([]MatchCandidate, 0)
	for ci := range pageComps {
		pc := &pageComps[ci]
		for ri := range rows {
			if !rowMeetsComponent(rows[ri], pc.vc, pc.pc) {
				continue
			}
			dc, err := componentForMatch(pc.comp)
			if err != nil {
				return rebuildPageResult{}, ValidationError(op, fmt.Errorf("component %s of the page: %w", pc.comp.ID, err))
			}
			candidates = append(candidates, MatchCandidate{
				VulnerabilityID: rows[ri].ID,
				Evaluation:      candidateInput(rows[ri], dc, st, now),
			})
		}
	}
	res.candidates = candidates
	return res, nil
}

// rowMeetsComponent reports whether one vulnerability row is a candidate
// of a component whose closed name keys are vc/pc: at least one raw
// affected-name pair of the row must carry a vendor key inside vc and a
// product key inside pc (the row's raw pair is a member of the
// component's closed pair set).
func rowMeetsComponent(row VulnerabilityMatch, vc, pc map[string]struct{}) bool {
	for i := range row.Statements {
		s := &row.Statements[i]
		if s.Vendor == "" || s.Product == "" {
			continue
		}
		if _, ok := vc[normalise.NormaliseKey(s.Vendor)]; !ok {
			continue
		}
		if _, ok := pc[normalise.NormaliseKey(s.Product)]; !ok {
			continue
		}
		return true
	}
	return false
}
