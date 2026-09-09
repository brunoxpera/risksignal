package application

// This file is the shared surface of the WP-3.08 bulk matching jobs
// (ARCH-003 §5, DEV-064): the read ports the matching.rebuild and
// matching.recompute runs program against, the MatchingRunner that
// executes the runs on top of the DEV-063 RunMatching core, and the pure
// helpers both runs share — the candidate-name derivation of a component
// row, the application.Component → domain.Component conversion the
// handlers assemble their engine inputs from, and the rule-state read of
// a run.
//
// Division of labour with the DEV-063 core: RunMatching (matching_run.go)
// computes and writes one candidate batch in bounded transactions of
// matchingBatchSize and owns the idempotent match insert (UQ
// (vulnerability_id, component_id, rule_version)). The runs of this file
// own the candidate resolution and assembly: the inventory-driven walk of
// matching.rebuild and the pre-filtered CVE batch of
// matching.recompute. A run reads the rule state (effective alias and
// decision rules of the current ruleset plus the two version counters)
// once, resolves the candidate pairs of its direction, assembles the
// MatchCandidates (this is where the persisted application.Component read
// model becomes the domain.Component engine input) and hands the batch to
// RunMatching — which commits it incrementally, so a crash mid-run
// resumes at the next batch and a re-claimed job (expired lease, TR-012)
// re-runs without double effect.
//
// The read ports are deliberately narrow and the adapter wiring is the
// later work package's seam (WP-3.09/DEV-052 owns the decomposed
// vulnerability-side statement store and its adapters; this task ships
// the port contracts and the fake-driven runs). Every port returns
// deterministic orderings so a re-run of the same job derives the same
// candidates and therefore the same matches.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/xpera/risksignal/internal/application/matching"
	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// Batch-size guides of the bulk matching runs (ARCH-003 §5: "guide 500").
// Rebuild walks the components in pages of matchingComponentPageSize and
// commits each page through RunMatching (which further bounds every
// transaction to matchingBatchSize candidates); recompute accepts at most
// matchingRecomputeMaxIDs vulnerability ids per job.
const (
	matchingComponentPageSize = 500
	matchingRecomputeMaxIDs   = 500
)

// VulnerabilityMatch is the vulnerability-side read model of a matching
// run (ARCH-003 §3): the persisted row identities of one vulnerability —
// ID is the row id the match rows reference (matches.vulnerability_id),
// CVEID is the natural key the decision-rule targets and the engine
// input carries — plus the affected-product statements the run evaluates
// and the candidate pre-filter resolves over. Statements is the
// decomposed, normalised form of the stored vulnerability statement data
// (the WP-3.07 decomposition of the NVD cpe_config; empty for a
// vulnerability without statements — a skeleton row resolves no
// candidates and spawns no work).
type VulnerabilityMatch struct {
	ID         string
	CVEID      string
	Statements []matching.AffectedProduct
}

// MatchingRuleRepo resolves the rule state a matching run evaluates under
// (ARCH-003 §1.4/§3): the effective alias and decision rules of the
// current ruleset version — enabled, unrevoked, with their monotonic
// version counters — read once per run. Both rulesets are versioned; the
// composite effective rule version (domain.RulesetVersion over the two
// counters) is what a run's matches are stamped with. A ruleset without
// rules yields empty slices and zero counters, never an error.
type MatchingRuleRepo interface {
	// EffectiveAliasRules returns the enabled alias rules of the current
	// alias ruleset version (both scopes), sorted deterministically.
	EffectiveAliasRules(ctx context.Context) ([]domain.AliasRule, error)

	// EffectiveDecisionRules returns the unrevoked decision rules of the
	// current decision ruleset version, sorted deterministically (the
	// engine re-sorts by (version, id) before applying them).
	EffectiveDecisionRules(ctx context.Context) ([]domain.DecisionRule, error)

	// AliasVersion returns the current alias ruleset version counter
	// (COALESCE(max(version), 0) of alias_rules).
	AliasVersion(ctx context.Context) (int, error)

	// DecisionVersion returns the current decision ruleset version
	// counter (COALESCE(max(version), 0) of decision_rules).
	DecisionVersion(ctx context.Context) (int, error)
}

// MatchingComponents is the component-side read surface of a matching
// run: the inventory product index lookup of the candidate pre-filter
// (ComponentNormLister — ADR-012, ARCH-003 §4), the keyset page walk of
// the matching.rebuild inventory loop and the by-id row read that turns
// pre-filter component ids into full candidate rows. Every read returns
// full I3 rows (the application.Component read model with the raw
// identifier originals, the normalised comparison keys, the version
// scheme and the natural key) in a deterministic order.
type MatchingComponents interface {
	ComponentNormLister

	// ListComponentsPage returns the components whose id is greater than
	// afterID ("" = the first page), ascending by id, at most limit rows
	// — the bounded inventory walk of matching.rebuild (ARCH-003 §5:
	// components in batches of 500). Deactivated rows are returned like
	// active ones (ARCH-003 §1.2 — a deactivated component stays
	// referenceable).
	ListComponentsPage(ctx context.Context, afterID string, limit int) ([]Component, error)

	// ListComponentsByIDs returns the full rows of the given component
	// ids, ascending by id (the candidate rows of one recompute CVE). An
	// id without a row is a not-found error — the pre-filter resolved the
	// ids off the very same inventory, so a missing row is a torn read.
	ListComponentsByIDs(ctx context.Context, ids []string) ([]Component, error)
}

// MatchingVulnerabilityRepo is the vulnerability-side read surface of a
// matching run: the two directions of the candidate resolution seam. The
// postgres adapter of this port reads the decomposed vulnerability
// statement store (the WP-3.09/DEV-052 wiring of the NVD statement
// pipeline); the runs of this task are fake-driven.
type MatchingVulnerabilityRepo interface {
	// ListByIDs returns the rows of the given vulnerability ids in
	// ascending id order — the recompute read: the pre-filtered batch of
	// the job, resolved into statement-bearing rows. A row whose id is
	// absent is a not-found error (vulnerabilities are never deleted — a
	// missing id is an enqueuer bug, a permanent job error).
	ListByIDs(ctx context.Context, ids []string) ([]VulnerabilityMatch, error)

	// ListByPairs returns the vulnerabilities whose affected-name pairs
	// include at least one of the given raw normalised pairs (a raw
	// pair = one affected-product statement carrying both name keys) —
	// the rebuild read: the reverse of the candidate pre-filter over the
	// inventory-driven pair set of a component page. Each row appears
	// once, rows are ordered ascending by id. The alias closure is the
	// caller's job (the run queries the closure-expanded pair set); the
	// implementation matches the raw stored pairs, so a CVE whose raw
	// pair is an alias variant is found through the closed query pair of
	// its canonical. The returned rows are the superset of the page's
	// candidates — the run intersects them with each component's closed
	// pair set before assembling candidates.
	ListByPairs(ctx context.Context, pairs []VendorProductPair) ([]VulnerabilityMatch, error)
}

// MatchingCore is the compute-and-write core a bulk matching run drives
// (DEV-063): *application.Service implements it through RunMatching.
type MatchingCore interface {
	RunMatching(ctx context.Context, batch []MatchCandidate) (RunMatchingResult, error)
}

// MatchingRunner executes the bulk matching runs of WP-3.08
// (ARCH-003 §5): RebuildMatching (inventory-driven walk, matching
// matching.rebuild) and RecomputeMatching (pre-filtered CVE batch,
// matching matching.recompute) on top of the injected MatchingCore. The
// runs are deliberately not methods of the application Service: they need
// their own narrow read surface (rules, components, vulnerability
// statements) whose adapters arrive with the WP-3.09 statement store, so
// they are assembled at the composition root next to the Service that
// provides the core. The runner is safe for use from one goroutine (the
// relay dispatches sequentially); the data ports it reads are
// pool-scoped.
type MatchingRunner struct {
	core       MatchingCore
	rules      MatchingRuleRepo
	components MatchingComponents
	vulns      MatchingVulnerabilityRepo
	clk        Clock
	logger     *slog.Logger
}

// NewMatchingRunner assembles the bulk matching runner. core, rules,
// components, vulns and clk must not be nil (a nil dependency is a
// programming error reported here, mirroring application.NewService); a
// nil logger falls back to a silent logger.
func NewMatchingRunner(core MatchingCore, rules MatchingRuleRepo, components MatchingComponents, vulns MatchingVulnerabilityRepo, clk Clock, logger *slog.Logger) (*MatchingRunner, error) {
	if core == nil {
		return nil, fmt.Errorf("application: matching runner: core must not be nil")
	}
	if rules == nil {
		return nil, fmt.Errorf("application: matching runner: rule repo must not be nil")
	}
	if components == nil {
		return nil, fmt.Errorf("application: matching runner: components repo must not be nil")
	}
	if vulns == nil {
		return nil, fmt.Errorf("application: matching runner: vulnerability repo must not be nil")
	}
	if clk == nil {
		return nil, fmt.Errorf("application: matching runner: clock must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &MatchingRunner{
		core:       core,
		rules:      rules,
		components: components,
		vulns:      vulns,
		clk:        clk,
		logger:     logger,
	}, nil
}

// RebuildMatchingInput is the matching.rebuild job payload as the runner
// consumes it (ARCH-003 §5): the composite rule version and the
// deterministic inventory snapshot hash of the job's dedupe key. The
// runner evaluates under the rule state it reads at run time (the
// current ruleset — see ruleState) and treats RuleVersion as the job
// identity half of the dedupe key; a job whose payload version differs
// from the live composite (the ruleset changed between enqueue and run —
// its own rebuild was enqueued) is logged and still runs under the live
// rules: the idempotent match insert absorbs the overlap.
type RebuildMatchingInput struct {
	RuleVersion       string
	InventorySnapshot string
}

// RebuildMatchingResult reports one matching.rebuild run: the walked
// component count (all pages), the assembled candidate count and the
// committed RunMatching transactions across the pages.
type RebuildMatchingResult struct {
	Components   int
	Candidates   int
	Transactions int
}

// RecomputeMatchingInput is the matching.recompute job payload as the
// runner consumes it (ARCH-003 §5): the pre-filtered vulnerability id
// batch (≤ matchingRecomputeMaxIDs) and the component scope / rule
// version of the job's dedupe key. ComponentScope is informational in
// I3 (the batch was pre-filtered to the scope's products at enqueue
// time); resolution runs from the rows themselves.
type RecomputeMatchingInput struct {
	VulnerabilityIDs []string
	ComponentScope   string
	RuleVersion      string
}

// RecomputeMatchingResult reports one matching.recompute run: the
// processed vulnerability count, the assembled candidate count and the
// committed RunMatching transactions.
type RecomputeMatchingResult struct {
	Vulnerabilities int
	Candidates      int
	Transactions    int
}

// matchingRuleState is the rule state of one matching run: the effective
// rules and version counters of the current ruleset, read once per run
// (the composite rule version the run's matches are stamped with is
// derived from the counters through domain.RulesetVersion).
type matchingRuleState struct {
	aliasRules      []domain.AliasRule
	decisionRules   []domain.DecisionRule
	aliasVersion    int
	decisionVersion int
	ruleVersion     string
}

// ruleState reads the rule state of a run through the rule repo. The
// reads are best-effort consistent: the matching runs of I3 execute while
// rule configuration writes are not yet live (the rule CRUD use cases
// arrive with the rule-management work package), so the four reads of one
// run observe one ruleset in practice; a concurrent rule change between
// the reads would only shift the boundary by one run, which the
// idempotent match insert absorbs. The alias rules are validated against
// chains before any candidate is resolved (normalise.ValidateAliasRules —
// chained rules are a data error, ARCH-003 §2) so a broken ruleset fails
// the run up front instead of poisoning every closure.
func (r *MatchingRunner) ruleState(ctx context.Context, op string) (matchingRuleState, error) {
	aliasRules, err := r.rules.EffectiveAliasRules(ctx)
	if err != nil {
		return matchingRuleState{}, err
	}
	decisionRules, err := r.rules.EffectiveDecisionRules(ctx)
	if err != nil {
		return matchingRuleState{}, err
	}
	aliasVersion, err := r.rules.AliasVersion(ctx)
	if err != nil {
		return matchingRuleState{}, err
	}
	decisionVersion, err := r.rules.DecisionVersion(ctx)
	if err != nil {
		return matchingRuleState{}, err
	}
	if err := normalise.ValidateAliasRules(aliasRules); err != nil {
		return matchingRuleState{}, ValidationError(op, err)
	}
	ruleVersion, err := domain.RulesetVersion(aliasVersion, decisionVersion)
	if err != nil {
		return matchingRuleState{}, InfraError(op, err)
	}
	return matchingRuleState{
		aliasRules:      aliasRules,
		decisionRules:   decisionRules,
		aliasVersion:    aliasVersion,
		decisionVersion: decisionVersion,
		ruleVersion:     ruleVersion,
	}, nil
}

// candidateInput assembles the engine input of one (component,
// vulnerability) candidate pair: the vulnerability row identities, the
// statement set, the component converted from its persisted read-model
// row into the domain engine input, the rule state of the run and the
// injected clock instant for the decision-rule validity windows.
func candidateInput(row VulnerabilityMatch, comp domain.Component, st matchingRuleState, now time.Time) matching.Input {
	return matching.Input{
		CVEID:           row.CVEID,
		Statements:      row.Statements,
		Component:       comp,
		AliasRules:      st.aliasRules,
		DecisionRules:   st.decisionRules,
		AliasVersion:    st.aliasVersion,
		DecisionVersion: st.decisionVersion,
		Now:             now,
	}
}

// componentForMatch is the application.Component → domain.Component
// conversion of the WP-3.08 candidate assembly (DEV-063 review forward
// note): the persisted read model of one component row becomes the
// domain value object the engine evaluates. The raw identifier originals
// travel verbatim and the already-normalised comparison keys
// (vendor_norm/product_norm/version_norm) and the stored scheme pass
// through — the domain constructor re-validates the shape (identifier
// presence, scheme validity) and re-derives the deterministic natural
// key, so a stored row that violates the I3 contract (no identifier,
// unknown scheme) is surfaced here as a validation error of the run —
// a stored component row the import contract would never have written is
// a permanent job error, never a silent skip. A deactivated component
// converts like an active one: deactivated rows stay referenceable and
// remain matchable (ARCH-003 §1.2 — the read ports return them).
func componentForMatch(c Component) (domain.Component, error) {
	ids := domain.ComponentIdentifiers{
		Vendor:  c.Vendor,
		Product: c.Product,
		Version: c.Version,
		CPE:     c.CPE,
		PURL:    c.PURL,
		Image:   c.Image,
		Digest:  c.Digest,
	}
	return domain.NewComponent(c.ID, c.AssetID, ids, c.VendorNorm, c.ProductNorm, c.VersionNorm, c.VersionScheme)
}

// componentNamePair derives the raw normalised (vendor, product) name
// pair of a component row — the candidate-resolution key of the
// inventory side (ADR-012: the semi-join is driven by the normalised
// name keys). The stored comparison keys are the first source (the I3
// write path always stores them); a row whose comparison keys are empty
// falls back to the identity-carrying exact identifier, decomposed from
// its CPE (vendor/product) then its purl (namespace/name) and folded
// with the same NFKC + trim + lowercase fold the keys are stored under.
// ok is false when the row carries no name identity at all — a pure
// image-reference component (repository + digest) — which resolves no
// name candidates (the container_digest identity tier of the engine is
// served by the statement side of a candidate pair, never by the name
// index; ARCH-003 §4 names the pair index as the I3 pre-filter bound).
func componentNamePair(c Component) (VendorProductPair, bool) {
	vendor, product := c.VendorNorm, c.ProductNorm
	if vendor == "" || product == "" {
		if c.CPE != "" {
			if cpe, err := normalise.ParseCPE23(c.CPE); err == nil {
				if cpe.Vendor != "" && cpe.Vendor != "*" && cpe.Vendor != "-" &&
					cpe.Product != "" && cpe.Product != "*" && cpe.Product != "-" {
					vendor, product = cpe.Vendor, cpe.Product
				}
			}
		}
	}
	if vendor == "" || product == "" {
		if c.PURL != "" {
			if p, err := normalise.ParsePURL(c.PURL); err == nil {
				vendor, product = p.Namespace, p.Name
			}
		}
	}
	if vendor == "" || product == "" {
		return VendorProductPair{}, false
	}
	return VendorProductPair{Vendor: normalise.NormaliseKey(vendor), Product: normalise.NormaliseKey(product)}, true
}

// closedNamePairs expands one raw pair through the symmetric one-hop
// alias closure of both axes (normalise.AliasClosure — ARCH-003 §2 item
// 2) into the sorted, deduplicated cross product of the closed vendor
// and product values: the set of raw pairs a candidate's raw pair may be
// a member of for the pair to meet this component. Both the CVE side and
// the component side are closed before the semi-join, so a canonical
// name and its aliases meet symmetrically.
func closedNamePairs(pair VendorProductPair, rules []domain.AliasRule) []VendorProductPair {
	vendors := normalise.AliasClosure(domain.AliasScopeVendor, pair.Vendor, rules)
	products := normalise.AliasClosure(domain.AliasScopeProduct, pair.Product, rules)
	set := make(map[VendorProductPair]struct{}, len(vendors)*len(products))
	for _, v := range vendors {
		for _, p := range products {
			set[VendorProductPair{Vendor: v, Product: p}] = struct{}{}
		}
	}
	out := make([]VendorProductPair, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Product < out[j].Product
	})
	return out
}

// statementNamePairs extracts the raw normalised (vendor, product) name
// pairs of a vulnerability's affected-product statements — the pair set
// the candidate pre-filter closes and semi-joins (ADR-012). A statement
// whose identity is carried by an exact CPE/purl or an image digest
// alone (no name keys) contributes no pair and therefore no name-level
// candidates; the returned slice preserves statement order and may hold
// duplicates (the pre-filter deduplicates its result).
func statementNamePairs(statements []matching.AffectedProduct) []VendorProductPair {
	pairs := make([]VendorProductPair, 0, len(statements))
	for i := range statements {
		s := &statements[i]
		if s.Vendor != "" && s.Product != "" {
			pairs = append(pairs, VendorProductPair{Vendor: normalise.NormaliseKey(s.Vendor), Product: normalise.NormaliseKey(s.Product)})
		}
	}
	return pairs
}

// sortedPairs orders a pair set for a deterministic query.
func sortedPairs(set map[VendorProductPair]struct{}) []VendorProductPair {
	out := make([]VendorProductPair, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Product < out[j].Product
	})
	return out
}
