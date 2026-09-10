package application

// This file feeds epss_history from the EPSS run (ARCH-003 §7, ADR-013,
// ch. 8.4, WP-3.10/DEV-053): after a run has swapped epss_current
// (TRUNCATE + COPY), the loader appends one observed score row per run day
// for exactly the CVEs with inventory relevance — the candidate pre-filter's
// set (ARCH-003 §4) — and only for those. History is append-only and
// relevant-only: an irrelevant CVE leaves no row, and re-running the same
// day appends nothing twice (UQ (cve_id, observed_on) + ON CONFLICT DO
// NOTHING of the generated statement).
//
// The relevance direction is the ADR-012 inversion ("build once, use
// twice"): the daily EPSS file holds the whole CVE population, while the
// inventory holds a few hundred distinct normalised products, so the loader
// resolves the relevant CVEs once — never per CVE — through the reverse side
// of the WP-3.07 candidate pre-filter (MatchingVulnerabilityRepo.ListByPairs
// over the closed name pairs of the inventory, DEV-065) and keeps the rows
// whose CVE is in the run's set. Each surviving row is then confirmed
// through CandidateComponentIDs over its decomposed affected-name pairs —
// the same pre-filter the matcher and matching.recompute call (DEV-062) — so
// "relevant" means exactly "≥1 candidate component" (ARCH-003 §4/§7). The
// loader reuses the matching runner's ports (MatchingRuleRepo,
// MatchingComponents, MatchingVulnerabilityRepo): nothing is re-implemented,
// the closure and the semi-join stay the one shared seam.
//
// The loader is bound to the pass transaction of the EPSS run (the same one
// the TRUNCATE + COPY load commits on), so the history append commits
// atomically with the daily-set swap: a failing history write aborts the
// pass and rolls the swap back (ch. 8.1 step 5). A source whose pass is
// wired without a loader (the additive, nil-safe ServiceDeps.EpssHistory —
// a non-EPSS composition root or a unit test) appends nothing.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/application/normalise"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// EpssHistoryObservation is one row of the run's daily set as the history
// append consumes it (ARCH-003 §7): the natural key plus the raw EPSS
// values of the daily file — the COPY-ready decimals the bulk writer
// already parsed (epss_bulk.go). observed_on and model_version are run
// context, stamped by the loader, not per-row values.
type EpssHistoryObservation struct {
	CVEID      string
	Score      pgtype.Numeric
	Percentile pgtype.Numeric
}

// EpssHistoryRecord is one row appended to epss_history: the run's
// observed_on date (the run date, injected clock, UTC), the observed
// score/percentile and the model_version of the daily file (its date).
type EpssHistoryRecord struct {
	CVEID        string
	ObservedOn   time.Time
	Score        pgtype.Numeric
	Percentile   pgtype.Numeric
	ModelVersion string
}

// EpssHistoryRepo appends one observed EPSS history row on the caller's
// transaction — the append-only write of epss_history (ADR-013: no foreign
// keys onto epss_current; the row survives the daily swaps by cve_id alone).
// The natural key (cve_id, observed_on) makes a repeated append of the same
// day a no-op.
type EpssHistoryRepo interface {
	Append(ctx context.Context, tx Tx, rec EpssHistoryRecord) error
}

// EpssHistoryAppender is the seam the EPSS run drives (the finish step of
// sourcePassInput, source_pass.go): append the relevant-only history of one
// run on the pass transaction. *EpssHistoryLoader implements it; the
// Service holds the optional dependency so a pass without inventory
// relevance still loads epss_current unchanged.
type EpssHistoryAppender interface {
	AppendRelevant(ctx context.Context, tx Tx, observations []EpssHistoryObservation, observedOn time.Time, modelVersion string) (int, error)
}

// EpssHistoryLoader is the application-side feeder of epss_history
// (WP-3.10/DEV-053). It runs on the matching runner's read surface — the
// rule state (the effective alias rules of the current ruleset), the
// inventory (the bounded component walk that builds the closed pair set and
// the product-index semi-join of the pre-filter) and the reverse pair read —
// plus the append-only history write.
type EpssHistoryLoader struct {
	rules      MatchingRuleRepo
	components MatchingComponents
	vulns      MatchingVulnerabilityRepo
	history    EpssHistoryRepo
}

// NewEpssHistoryLoader assembles the epss_history loader. Every dependency
// must not be nil (a nil dependency is a programming error reported here,
// mirroring NewMatchingRunner).
func NewEpssHistoryLoader(rules MatchingRuleRepo, components MatchingComponents, vulns MatchingVulnerabilityRepo, history EpssHistoryRepo) (*EpssHistoryLoader, error) {
	if rules == nil {
		return nil, fmt.Errorf("application: epss history loader: rule repo must not be nil")
	}
	if components == nil {
		return nil, fmt.Errorf("application: epss history loader: components repo must not be nil")
	}
	if vulns == nil {
		return nil, fmt.Errorf("application: epss history loader: vulnerability repo must not be nil")
	}
	if history == nil {
		return nil, fmt.Errorf("application: epss history loader: history repo must not be nil")
	}
	return &EpssHistoryLoader{rules: rules, components: components, vulns: vulns, history: history}, nil
}

// AppendRelevant appends the observed history of one EPSS run for the CVEs
// with inventory relevance and returns the number of appended rows.
//
// The relevant CVEs are the run's rows whose CVE the reverse pre-filter read
// resolves off the inventory pair set — the ADR-012 inversion, bounded by
// the component set, never by the daily CVE population — and whose
// decomposed affected-name pairs yield at least one candidate component
// through CandidateComponentIDs. An empty inventory, a run without rows or a
// run whose CVEs meet no component yields zero rows and no error (no
// relevance ⇒ no history, ADR-012). Rows are appended in ascending CVE order
// for a deterministic write sequence; the append is idempotent per
// (cve_id, observed_on).
func (l *EpssHistoryLoader) AppendRelevant(ctx context.Context, tx Tx, observations []EpssHistoryObservation, observedOn time.Time, modelVersion string) (int, error) {
	const op = "epss_history"

	if len(observations) == 0 {
		return 0, nil
	}
	byCVE := make(map[string]EpssHistoryObservation, len(observations))
	for _, obs := range observations {
		if obs.CVEID == "" {
			continue // a row without a CVE names nothing — it appends no history
		}
		byCVE[obs.CVEID] = obs // the daily set carries unique cve ids (UQ cve_id); last wins defensively
	}
	if len(byCVE) == 0 {
		return 0, nil
	}

	// The effective alias rules of the current ruleset (the closure of both
	// the component side and the CVE side is the pre-filter's, ARCH-003 §2);
	// a chained ruleset is a data error surfaced here instead of poisoning
	// every closure (normalise.ValidateAliasRules).
	aliasRules, err := l.rules.EffectiveAliasRules(ctx)
	if err != nil {
		return 0, err
	}
	if err := normalise.ValidateAliasRules(aliasRules); err != nil {
		return 0, ValidationError(op, err)
	}

	// The closed name pairs of the whole inventory — the reverse read's
	// query set (the same shape the rebuild page builds, here over all
	// components). An empty inventory resolves no relevant CVE.
	pairs, err := l.inventoryClosedPairs(ctx, aliasRules)
	if err != nil {
		return 0, InfraError(op, fmt.Errorf("resolve the inventory product index: %w", err))
	}
	if len(pairs) == 0 {
		return 0, nil
	}

	rows, err := l.vulns.ListByPairs(ctx, sortedPairs(pairs))
	if err != nil {
		return 0, InfraError(op, fmt.Errorf("resolve relevant CVEs of the run: %w", err))
	}

	// Keep only the resolved rows whose CVE is in the run's set, in
	// ascending CVE order (deterministic appends). A row the SQL pre-filter
	// let through but whose decomposition carries no name pair resolves no
	// candidate and is dropped by the pre-filter gate below.
	relevant := make([]VulnerabilityMatch, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for i := range rows {
		if _, ok := byCVE[rows[i].CVEID]; !ok {
			continue
		}
		if _, dup := seen[rows[i].CVEID]; dup {
			continue
		}
		seen[rows[i].CVEID] = struct{}{}
		relevant = append(relevant, rows[i])
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].CVEID < relevant[j].CVEID })

	appended := 0
	for i := range relevant {
		row := &relevant[i]
		pairs := statementNamePairs(row.Statements)
		if len(pairs) == 0 {
			continue // no name-level candidates to resolve — no history
		}
		compIDs, err := CandidateComponentIDs(ctx, pairs, aliasRules, l.components)
		if err != nil {
			return 0, InfraError(op, fmt.Errorf("resolve candidate components of %s (%s): %w", row.CVEID, row.ID, err))
		}
		if len(compIDs) == 0 {
			continue // the pre-filter gate: no candidate component ⇒ no history (ADR-012)
		}
		obs := byCVE[row.CVEID]
		if err := l.history.Append(ctx, tx, EpssHistoryRecord{
			CVEID:        row.CVEID,
			ObservedOn:   observedOn,
			Score:        obs.Score,
			Percentile:   obs.Percentile,
			ModelVersion: modelVersion,
		}); err != nil {
			return 0, err
		}
		appended++
	}
	return appended, nil
}

// inventoryClosedPairs builds the reverse read's query set: every closed
// (vendor, product) name pair of the inventory (the alias closure of each
// component's raw pair, ARCH-003 §2), accumulated over the bounded keyset
// walk of the components page read. A component without a name identity
// (a pure image-reference row) contributes no pair — it resolves no
// name-level candidate, the same contract as the rebuild page.
func (l *EpssHistoryLoader) inventoryClosedPairs(ctx context.Context, aliasRules []domain.AliasRule) (map[VendorProductPair]struct{}, error) {
	set := make(map[VendorProductPair]struct{})
	afterID := ""
	for {
		comps, err := l.components.ListComponentsPage(ctx, afterID, matchingComponentPageSize)
		if err != nil {
			return nil, err
		}
		if len(comps) == 0 {
			return set, nil // the walk reached the end of the inventory
		}
		for i := range comps {
			raw, ok := componentNamePair(comps[i])
			if !ok {
				continue
			}
			for _, p := range closedNamePairs(raw, aliasRules) {
				set[p] = struct{}{}
			}
		}
		next := comps[len(comps)-1].ID
		if next == "" || next == afterID {
			return set, nil // defensive: an id-less page cannot advance the cursor
		}
		afterID = next
	}
}
