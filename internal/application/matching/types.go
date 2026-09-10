package matching

import (
	"fmt"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// AffectedProduct is the vulnerability side of one match evaluation
// (ARCH-003 §3): one affected product statement of a vulnerability, as
// WP-3.07 decomposes it from the NVD configurations block (and WP-3.08
// reads for the rebuild/recompute loops). A statement identifies the
// product through normalised name keys, an exact CPE/purl identifier
// and/or a container repository + immutable digest, and carries the
// affected-version expression (exact versions and/or NVD ranges) of the
// statement.
//
// Vendor/Product are the normalised comparison keys of the CVE side
// (already NFKC + trim + lowercase — the same fold as
// components.vendor_norm/product_norm; the engine re-folds defensively,
// the fold is idempotent). CPE/PURL/Repository/Digest are verbatim
// originals (the engine parses them with the strict DEV-047 parsers).
// Empty fields are absent; at least one identity must be present (the
// vendor/product pair, a CPE, a purl or the repository+digest pair) —
// a statement naming nothing is a configuration error (validate).
type AffectedProduct struct {
	Vendor  string // normalised vendor key; "" when the identity comes from an exact identifier
	Product string // normalised product key; "" when absent

	CPE  string // original CPE 2.3 string; "" when absent
	PURL string // original package URL; "" when absent

	// Repository is the container image repository of the statement
	// ("[registry/]repository", no tag, no digest) and Digest the
	// immutable digest it pins ("sha256:…"). Both must be present for
	// the container_digest method.
	Repository string
	Digest     string

	// ExactVersions lists the versions named as exactly affected; a
	// concrete (non-wildcard) version carried by the statement's own CPE
	// or purl counts as an exact affected version too.
	ExactVersions []string
	// Ranges are the NVD affected windows (versionStart/EndIncluding/
	// Excluding semantics, domain.VersionRange). An unbounded range
	// (empty bounds) covers every version.
	Ranges []domain.VersionRange
}

// hasIdentity reports whether the statement names at least one product
// identity (the vendor/product pair, an exact identifier, or the image
// repository + digest pair). A statement without any identity can never
// be related to a component and is a caller error, not a silent no-op.
func (a AffectedProduct) hasIdentity() bool {
	if strings.TrimSpace(a.Vendor) != "" && strings.TrimSpace(a.Product) != "" {
		return true
	}
	if strings.TrimSpace(a.CPE) != "" || strings.TrimSpace(a.PURL) != "" {
		return true
	}
	return strings.TrimSpace(a.Repository) != "" && strings.TrimSpace(a.Digest) != ""
}

// Input is one matching evaluation: a vulnerability (identified by its
// CVE id) with its affected-product statements against one inventory
// component, under the effective alias and decision rules of the current
// ruleset version. Everything the engine reads is passed in — there is no
// database, clock or other hidden state (package doc).
//
// Statements must not be empty and every statement must name an identity.
// AliasRules are the enabled alias rules of the current ruleset (the
// engine validates them against chains before closing over them);
// DecisionRules the rules of the current ruleset version the engine
// applies to the computed outcome (revocation and the validity window are
// evaluated against Now). AliasVersion/DecisionVersion are the two
// monotonic ruleset counters the outcome's rule_version is derived from
// (domain.RulesetVersion). Now is the clock instant for the decision-rule
// validity windows — the caller supplies the injected clock reading, the
// engine never reads one; a zero Now is the epoch.
type Input struct {
	CVEID      string // the vulnerability's CVE id (decision-rule target)
	Statements []AffectedProduct
	Component  domain.Component

	AliasRules      []domain.AliasRule
	DecisionRules   []domain.DecisionRule
	AliasVersion    int
	DecisionVersion int
	Now             time.Time // clock instant for decision-rule validity windows
}

// validate checks the structural invariants of an evaluation input: at
// least one statement, every statement with an identity and non-empty
// exact versions, and a component carrying at least one identifier. The
// ruleset counters are validated by domain.RulesetVersion during the
// evaluation; alias-rule chains by normalise.ValidateAliasRules.
func (in Input) validate() error {
	if len(in.Statements) == 0 {
		return fmt.Errorf("matching: at least one affected-product statement is required")
	}
	for i := range in.Statements {
		a := &in.Statements[i]
		if !a.hasIdentity() {
			return fmt.Errorf("matching: statement %d names no product identity (need vendor+product, a CPE or purl, or repository+digest)", i)
		}
		for j, v := range a.ExactVersions {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("matching: statement %d exact version %d must not be empty", i, j)
			}
		}
	}
	return nil
}

// Outcome is the result of one evaluation: the method-led match state of
// ARCH-003 §3 (ADR-015) without the persistence identities — the
// vulnerability/component ids and the database-assigned match id belong to
// the use case (WP-3.08) and the matches insert. The method is
// authoritative; Confidence and Score were derived from it through
// domain.MatchMethod.Derive (the candidate score is the actually computed
// similarity). RuleVersion is the composite ruleset version the outcome
// was computed under (domain.RulesetVersion, zero-padded). Reasons is the
// auditable TR-007 rationale list of the winning evidence — never nil
// after a successful evaluation.
//
// The decision-rule state mirrors the matches columns (ARCH-003 §3):
// DecisionRuleID is set when a decision rule produced this outcome (an
// exclusion or an override; nil = purely computed) and
// AutoMethod/AutoConfidence/AutoScore preserve the raw computed triple
// when a decision rule overrode it (nil when no rule overrode).
type Outcome struct {
	Method      domain.MatchMethod
	Confidence  domain.Confidence
	Score       int
	RuleVersion string

	Reasons        []string
	DecisionRuleID *string

	AutoMethod     *domain.MatchMethod
	AutoConfidence *domain.Confidence
	AutoScore      *int
}
