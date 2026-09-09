package matching

import (
	"fmt"
	"strings"

	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// This file implements the method computation of ARCH-003 §3 (ch. 9.2,
// ADR-015): for each affected-product statement of a vulnerability the
// engine establishes the evidence tier of the pair — image repository +
// immutable digest, exact CPE/purl identifier, canonical (normalised)
// product name, controlled-alias-only name, or no relation at all — and
// maps tier + affected-version relation onto exactly one MatchMethod
// (see the ladder in the package doc). The method is authoritative;
// confidence and score are derived through the versioned ADR-015 mapping
// (domain.MatchMethod.Derive) and never set independently.

// evidenceTier is the identity strength of one (statement, component)
// pair.
type evidenceTier int

const (
	// tierNone: no identity or name relation — only weak name similarity
	// (candidate) is left.
	tierNone evidenceTier = iota
	// tierAlias: vendor/product only meet through the controlled alias
	// closure (an alias rule was required on at least one axis).
	tierAlias
	// tierCanonical: the normalised vendor/product names are directly
	// equal (no alias rule needed).
	tierCanonical
	// tierIdentifier: the statement pins a CPE or purl whose identity
	// (part/vendor/product resp. type/namespace/name) equals the
	// component's identifier — stronger than a name comparison.
	tierIdentifier
	// tierDigest: image repository and immutable digest both match — the
	// strongest identity (the digest pins the artifact).
	tierDigest
)

// statementResult is the computed method evidence of one statement.
type statementResult struct {
	method     domain.MatchMethod
	similarity int // the computed candidate similarity; read only for candidate
	reasons    []string
}

// preparedComponent is the defensively normalised component view the
// evaluation reads: the comparison keys re-folded (idempotent), the
// version and scheme extracted, the image origin resolved and the CPE /
// purl identities parsed. Building the view once keeps the per-statement
// evaluation free of re-parsing.
type preparedComponent struct {
	vendor  string // NormaliseKey(Component.VendorNorm)
	product string // NormaliseKey(Component.ProductNorm)
	version string // componentVersion(Component)
	scheme  domain.VersionScheme

	imageOrigin string // registry-qualified image repository, "" when absent
	imageDigest string // immutable digest of the component, "" when absent

	cpe  *cpeIdentity  // parsed, concrete CPE identity; nil when absent/unparseable/wildcard
	purl *purlIdentity // parsed purl identity; nil when absent/unparseable
}

// cpeIdentity is the identity-carrying part of a CPE 2.3 string: part,
// vendor and product, folded (CPE is case-insensitive by spec). The CPE
// version is deliberately excluded — it flows into the affected-version
// relation, not into the identity.
type cpeIdentity struct {
	part, vendor, product string
}

// cpeIdentityFrom parses a CPE identity out of a CPE 2.3 string. ok is
// false when the string is absent, malformed, or carries a wildcard
// vendor/product ("*" ANY or "-" NA) — a criteria naming any product is
// a name-level statement and never forms an identifier match.
func cpeIdentityFrom(s string) (*cpeIdentity, bool) {
	c, err := normalise.ParseCPE23(strings.TrimSpace(s))
	if err != nil {
		return nil, false
	}
	if c.Vendor == "" || c.Vendor == "*" || c.Vendor == "-" {
		return nil, false
	}
	if c.Product == "" || c.Product == "*" || c.Product == "-" {
		return nil, false
	}
	return &cpeIdentity{
		part:    strings.ToLower(c.Part),
		vendor:  strings.ToLower(c.Vendor),
		product: strings.ToLower(c.Product),
	}, true
}

// purlIdentity is the identity-carrying part of a package URL: type,
// namespace and name, verbatim (purl namespace/name are case-sensitive
// per ecosystem). The purl version is deliberately excluded — it flows
// into the affected-version relation.
type purlIdentity struct {
	typ, namespace, name string
}

// purlIdentityFrom parses a purl identity out of a package URL. ok is
// false when the string is absent or malformed.
func purlIdentityFrom(s string) (*purlIdentity, bool) {
	p, err := normalise.ParsePURL(strings.TrimSpace(s))
	if err != nil {
		return nil, false
	}
	return &purlIdentity{typ: p.Type, namespace: p.Namespace, name: p.Name}, true
}

// prepareComponent folds the component's comparison keys defensively (the
// fold is idempotent — already-normalised keys pass through unchanged),
// resolves the version, the image origin and the identifier identities.
func prepareComponent(c domain.Component) preparedComponent {
	p := preparedComponent{
		vendor:  normalise.NormaliseKey(c.VendorNorm),
		product: normalise.NormaliseKey(c.ProductNorm),
		version: componentVersion(c),
		scheme:  c.VersionScheme,
	}
	digest := strings.TrimSpace(c.Digest)
	if img := strings.TrimSpace(c.Image); img != "" {
		if ref, err := normalise.ParseImageRef(img); err == nil {
			p.imageOrigin = imageOrigin(ref.Registry, ref.Repository)
			if digest == "" {
				digest = ref.Digest
			}
		}
	}
	if digest != "" {
		p.imageDigest = strings.ToLower(digest)
	}
	p.cpe, _ = cpeIdentityFrom(c.CPE)
	p.purl, _ = purlIdentityFrom(c.PURL)
	return p
}

// imageOrigin is the registry-qualified origin of an image repository:
// "registry/repository" when the reference carries a registry, the bare
// repository path otherwise. No registry is ever defaulted (docker.io is
// a pull-time concern, normalise.ParseImageRef never invents one), so two
// references with the same repository but different explicit registries
// stay distinct origins.
func imageOrigin(registry, repository string) string {
	if registry != "" {
		return registry + "/" + repository
	}
	return repository
}

// normalizeStatement folds one statement defensively: the name keys
// through NormaliseKey (idempotent), the identifiers trimmed, the digest
// lowercased (digests are canonically lowercase hex) and the version
// bounds trimmed. The caller's Input slice is never mutated — the slices
// of the statement are copied.
func normalizeStatement(a AffectedProduct) AffectedProduct {
	out := a
	out.Vendor = normalise.NormaliseKey(a.Vendor)
	out.Product = normalise.NormaliseKey(a.Product)
	out.CPE = strings.TrimSpace(a.CPE)
	out.PURL = strings.TrimSpace(a.PURL)
	out.Repository = strings.TrimSpace(a.Repository)
	out.Digest = strings.ToLower(strings.TrimSpace(a.Digest))
	out.ExactVersions = append([]string(nil), a.ExactVersions...)
	for i, v := range out.ExactVersions {
		out.ExactVersions[i] = strings.TrimSpace(v)
	}
	out.Ranges = append([]domain.VersionRange(nil), a.Ranges...)
	for i := range out.Ranges {
		out.Ranges[i].Start = strings.TrimSpace(out.Ranges[i].Start)
		out.Ranges[i].End = strings.TrimSpace(out.Ranges[i].End)
	}
	return out
}

// Evaluate computes the raw match outcome of one (vulnerability,
// component) pair (Input): every affected-product statement of the
// vulnerability is evaluated against the component and the strongest
// evidence wins (see below). The outcome carries the composite ruleset
// version (domain.RulesetVersion over the input's counters, zero-padded)
// and the auditable TR-007 reasons of the winning evidence; decision
// rules are applied on top by applyDecisionRules (decision.go).
//
// Aggregation across statements: each statement contributes its method
// evidence; the outcome is the evidence with the highest derived score
// (candidate similarities are 1–54 and therefore always below the fixed
// ranks — a provable negative, no_match score 0, only wins when no other
// statement yields any evidence). Statements whose evidence ties in
// method and score all contribute their reasons, so a product with
// several affected windows keeps the full audit trail. The evaluation is
// deterministic: statement order is the only tie-break input and is
// preserved.
func Evaluate(in Input) (Outcome, error) {
	if err := in.validate(); err != nil {
		return Outcome{}, err
	}
	if err := normalise.ValidateAliasRules(in.AliasRules); err != nil {
		return Outcome{}, err
	}
	ruleVersion, err := domain.RulesetVersion(in.AliasVersion, in.DecisionVersion)
	if err != nil {
		return Outcome{}, err
	}

	comp := prepareComponent(in.Component)

	var best statementResult
	for i := range in.Statements {
		res, err := evaluateStatement(normalizeStatement(in.Statements[i]), comp, in.AliasRules)
		if err != nil {
			return Outcome{}, err
		}
		better, err := dominates(res, best)
		if err != nil {
			return Outcome{}, err
		}
		switch {
		case better > 0:
			best = res
		case better == 0:
			// Same method and score: keep the audit trail of both.
			best.reasons = append(best.reasons, res.reasons...)
		}
	}

	conf, score, err := best.method.Derive(best.similarity)
	if err != nil {
		return Outcome{}, err
	}
	raw := Outcome{
		Method:      best.method,
		Confidence:  conf,
		Score:       score,
		RuleVersion: ruleVersion,
		Reasons:     best.reasons,
	}
	return applyDecisionRules(raw, in)
}

// dominates compares two statement results by their derived ADR-015
// score: positive means res outranks best, zero means an exact tie (same
// method and same score — the fixed ranks are unique below candidate, so
// an equal score implies an equal method), negative means res is weaker.
// no_match (score 0) is the weakest evidence; candidate similarities
// (1–54) always outrank it.
func dominates(res, best statementResult) (int, error) {
	if best.method == "" {
		return 1, nil // first statement with evidence
	}
	_, resScore, err := res.method.Derive(res.similarity)
	if err != nil {
		return 0, err
	}
	_, bestScore, err := best.method.Derive(best.similarity)
	if err != nil {
		return 0, err
	}
	switch {
	case resScore > bestScore:
		return 1, nil
	case resScore < bestScore:
		return -1, nil
	default:
		return 0, nil // equal score implies equal method (candidate never ties a fixed rank)
	}
}

// evaluateStatement computes the method evidence of one statement against
// one prepared component: the evidence tier first (digest, identifier,
// canonical name, alias name — the strongest that holds wins), then the
// tier-specific mapping of the affected-version relation onto the method
// (package doc ladder). A pair with no relation at all is a candidate
// whose score is the computed name similarity (band [1, 54]) — fuzzy
// matching yields candidates only and can never produce high confidence.
func evaluateStatement(a AffectedProduct, comp preparedComponent, aliasRules []domain.AliasRule) (statementResult, error) {
	exacts := statementExactVersions(a)

	// 1. Container digest — the immutable digest pins the artifact; no
	// version window is evaluated on top of it.
	if a.Repository != "" && a.Digest != "" {
		if origin, ok := statementImageOrigin(a.Repository); ok &&
			comp.imageOrigin != "" && comp.imageDigest != "" &&
			origin == comp.imageOrigin && a.Digest == comp.imageDigest {
			return statementResult{
				method: domain.MatchMethodContainerDigest,
				reasons: []string{fmt.Sprintf(
					"image repository %s with digest %s matches the affected container image",
					comp.imageOrigin, comp.imageDigest)},
			}, nil
		}
	}

	// 2. Exact identifier (CPE/purl): the identity fields decide; the
	// identifier's own version flows into the affected-version relation.
	if stmtCPE, ok := cpeIdentityFrom(a.CPE); ok && comp.cpe != nil &&
		*comp.cpe == *stmtCPE {
		return identifierResult("CPE", comp, exacts, a.Ranges,
			fmt.Sprintf("component CPE %s/%s matches the affected CPE", comp.cpe.vendor, comp.cpe.product)), nil
	}
	if stmtPURL, ok := purlIdentityFrom(a.PURL); ok && comp.purl != nil &&
		*comp.purl == *stmtPURL {
		desc := stmtPURL.typ + "/" + stmtPURL.name
		if stmtPURL.namespace != "" {
			desc = stmtPURL.typ + "/" + stmtPURL.namespace + "/" + stmtPURL.name
		}
		return identifierResult("purl", comp, exacts, a.Ranges,
			fmt.Sprintf("component purl %s matches the affected purl", desc)), nil
	}

	// 3./4. Name tiers over the alias closure.
	canonical := comp.vendor != "" && comp.product != "" &&
		a.Vendor == comp.vendor && a.Product == comp.product
	aliasOnly := false
	if !canonical && a.Vendor != "" && a.Product != "" && comp.vendor != "" && comp.product != "" {
		aliasOnly = namesOverlap(domain.AliasScopeVendor, a.Vendor, comp.vendor, aliasRules) &&
			namesOverlap(domain.AliasScopeProduct, a.Product, comp.product, aliasRules)
	}
	switch {
	case canonical:
		return nameTierResult(domain.MatchMethodCanonicalProductRange, domain.MatchMethodProductUncertainVersion,
			comp, exacts, a.Ranges,
			fmt.Sprintf("product %s/%s matches the affected product %s/%s", comp.vendor, comp.product, a.Vendor, a.Product)), nil
	case aliasOnly:
		return nameTierResult(domain.MatchMethodAliasExactVersion, domain.MatchMethodControlledAliasOnly,
			comp, exacts, a.Ranges,
			fmt.Sprintf("product %s/%s matches the affected product %s/%s through a controlled alias", comp.vendor, comp.product, a.Vendor, a.Product)), nil
	}

	// 5. No relation: a candidate over the weak name similarity.
	sim := domain.CandidateSimilarity(a.Product, comp.product)
	return statementResult{
		method:     domain.MatchMethodCandidate,
		similarity: sim,
		reasons: []string{fmt.Sprintf(
			"product name %q is only weakly similar to the component product %q (candidate similarity %d) — a candidate, not a confirmed assignment",
			a.Product, comp.product, sim)},
	}, nil
}

// statementImageOrigin resolves the registry-qualified origin of the
// statement's repository string (a bare "[registry/]repository"
// reference parses with the strict image parser — no tag, no digest). ok
// is false when the string does not parse (a caller error the engine
// refuses to guess around).
func statementImageOrigin(repository string) (string, bool) {
	ref, err := normalise.ParseImageRef(repository)
	if err != nil {
		return "", false
	}
	return imageOrigin(strings.ToLower(ref.Registry), ref.Repository), true
}

// namesOverlap reports whether the alias closures of two normalised names
// of one scope share a value (ARCH-003 §2 item 2: both the CVE side and
// the component side are closed before the semi-join, so a canonical name
// and its aliases meet symmetrically). AliasClosure returns a sorted set,
// so the overlap is a deterministic two-pointer walk.
func namesOverlap(scope domain.AliasScope, a, b string, rules []domain.AliasRule) bool {
	ca := normalise.AliasClosure(scope, a, rules)
	cb := normalise.AliasClosure(scope, b, rules)
	i, j := 0, 0
	for i < len(ca) && j < len(cb) {
		switch {
		case ca[i] == cb[j]:
			return true
		case ca[i] < cb[j]:
			i++
		default:
			j++
		}
	}
	return false
}

// identifierResult maps the affected-version relation of an exact
// identifier match onto the method: affected → exact_identifier, provably
// not affected → no_match, and a missing/ambiguous version or a statement
// without any version expression → product_uncertain_version (a version
// is never fabricated into an affected window, ARCH-003 §2).
func identifierResult(kind string, comp preparedComponent, exacts []string, ranges []domain.VersionRange, evidenceNote string) statementResult {
	rel := classifyVersion(comp.version, comp.scheme, exacts, ranges)
	switch rel.state {
	case versionAffectedExact, versionAffectedRange:
		return statementResult{
			method:  domain.MatchMethodExactIdentifier,
			reasons: []string{evidenceNote + "; " + versionAffectedNote(rel)},
		}
	case versionProvablyNotAffected:
		return statementResult{
			method:  domain.MatchMethodNoMatch,
			reasons: []string{evidenceNote + "; version " + comp.version + " is outside every affected window — provably not affected"},
		}
	default:
		return statementResult{
			method:  domain.MatchMethodProductUncertainVersion,
			reasons: []string{uncertainReason(evidenceNote, rel, comp.scheme)},
		}
	}
}

// nameTierResult maps the affected-version relation of a name-tier match
// (canonical or alias) onto the method: affected → the tier's affected
// method (canonical_product_range resp. alias_exact_version), provably
// not affected → no_match, and missing/ambiguous/no-expression → the
// tier's uncertain method (product_uncertain_version resp.
// controlled_alias_only — a product that only meets through an alias and
// has no established version relation never rises above the alias-only
// evidence).
func nameTierResult(affectedMethod, uncertainMethod domain.MatchMethod, comp preparedComponent, exacts []string, ranges []domain.VersionRange, evidenceNote string) statementResult {
	rel := classifyVersion(comp.version, comp.scheme, exacts, ranges)
	switch rel.state {
	case versionAffectedExact, versionAffectedRange:
		return statementResult{
			method:  affectedMethod,
			reasons: []string{evidenceNote + "; " + versionAffectedNote(rel)},
		}
	case versionProvablyNotAffected:
		return statementResult{
			method:  domain.MatchMethodNoMatch,
			reasons: []string{evidenceNote + "; version " + comp.version + " is outside every affected window — provably not affected"},
		}
	default:
		return statementResult{
			method:  uncertainMethod,
			reasons: []string{uncertainReason(evidenceNote, rel, comp.scheme)},
		}
	}
}

// uncertainReason renders the TR-007 reason of a match whose version
// relation could not be established: the version is missing, the window
// could not be evaluated under the component's scheme, or the statement
// carries no version expression at all.
func uncertainReason(evidenceNote string, rel versionRelation, scheme domain.VersionScheme) string {
	switch rel.state {
	case versionMissing:
		return evidenceNote + "; the component carries no version — affected status unconfirmed"
	case versionAmbiguous:
		return evidenceNote + "; the affected window cannot be evaluated for the component's version scheme " + string(scheme) + " — affected status unconfirmed"
	default: // versionNoExpression
		return evidenceNote + "; the affected product statement names no affected version — affected status unconfirmed"
	}
}
