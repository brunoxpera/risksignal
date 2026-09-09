// Package matching implements the I3 matching engine of ARCH-003 §3
// (WP-3.06 / DEV-049): the pure computation of the full ADR-015
// MatchMethod set over one (vulnerability-side affected product,
// inventory component) pair, the candidate similarity of weak name
// matches, and the application of the versioned decision_rules (exclude →
// a visible no_match referencing the rule; override → the forced
// method/confidence/score with the computed starting point preserved in
// the auto_* fields).
//
// Everything in this package is pure, deterministic and network-free:
// no database, no clock, no I/O. The only inputs are the domain values
// and normalised identifiers of the two sides plus the effective rule
// sets (the persistence reads — components, the decomposed affected
// products of a vulnerability, the alias/decision rules of the current
// ruleset version — belong to the rebuild/recompute use case, WP-3.08).
// The clock instant for decision-rule validity windows is an input
// (Input.Now), never read from a wall clock, so the engine is fully
// deterministic: the same inputs always yield the same Outcome.
//
// The engine consumes the DEV-044 domain semantics and the DEV-047
// normalisation layer and never re-implements either:
//
//   - the ADR-015 method → confidence/score mapping (domain.MatchMethod.
//     Derive) — the method is authoritative, confidence and score are
//     derived, never set independently;
//   - the pure version comparators and the NVD range evaluator
//     (domain.StrategyFor / domain.InRange) — an ordering is never
//     fabricated (an unknown version scheme demotes instead);
//   - the CPE 2.3 / purl / image decomposers and the NFKC comparison-key
//     fold (normalise.ParseCPE23 / ParsePURL / ParseImageRef /
//     NormaliseKey) — identifiers are never compared as raw strings;
//   - the symmetric one-hop alias closure and its chain rejection
//     (normalise.AliasClosure / ValidateAliasRules);
//   - the composite ruleset-version derivation
//     (domain.RulesetVersion, zero-padded so multi-digit rule versions
//     order correctly) — every outcome stamps the ruleset it was
//     computed under;
//   - the bounded Damerau-Levenshtein + token-Jaccard candidate
//     similarity (domain.CandidateSimilarity, band [1, 54]) — the one
//     score that carries real information and can never produce high
//     confidence.
//
// Method computation (ch. 9.2, ADR-015) — per affected-product statement
// the engine determines the evidence tier of the pair, then maps the
// tier and the affected-version relation onto exactly one method:
//
//	evidence tier            affected   provably not   missing / ambiguous /
//	                         version    affected       no version expression
//	image repo + digest      container_digest           (digest pins the artifact)
//	CPE / purl identity      exact_identifier  no_match  product_uncertain_version
//	canonical product name   canonical_product_range  no_match  product_uncertain_version
//	controlled alias only    alias_exact_version  no_match  controlled_alias_only
//	no identity / name       candidate (band similarity; never high)
//
// A statement whose version expression (exact affected versions and/or
// NVD ranges) proves the component version outside every window yields
// no_match — the one provable negative. A missing component version or
// an unevaluable window (unknown scheme) never fabricates an ordering:
// the match demotes to product_uncertain_version (canonical identity) or
// controlled_alias_only (alias identity). A pair without any identity or
// name relation is a candidate whose score is the computed similarity —
// fuzzy matching yields candidates only (ADR-015). When a vulnerability
// carries several affected products the strongest evidence wins (see
// Evaluate); every Outcome carries the auditable TR-007 Reasons of the
// winning evidence.
//
// The package is a leaf of the application layer: it imports domain and
// the normalise subpackage only and is imported by the matching use case
// (WP-3.08); internal/domain never imports it (architecture gate).
package matching
