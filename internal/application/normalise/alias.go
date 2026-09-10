package normalise

import (
	"fmt"
	"sort"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file implements the match-time alias closure of ARCH-003 §2 item 2:
// controlled vendor/product aliases (alias_rules) resolve at match time —
// never at write time — through a symmetric one-hop closure. For a given
// (scope, value) the matcher expands to
//
//	{value} ∪ {to_value | from_value = value} ∪ {from_value | to_value = value}
//
// so a canonical name and its aliases meet symmetrically whether the CVE
// side or the component side carries the variant (both sides are closed
// before the semi-join). The closure is one hop by construction: it only
// follows rules whose from_value or to_value equals the queried value and
// never iterates its own result. Chained rulesets (a→b with b→c, or a
// cycle) are a data error (ARCH-003 §2: "chains are a data error surfaced
// in validate") — ValidateAliasRules rejects them, because on chained data
// the symmetric one-hop expansion of the middle value would silently merge
// all three names. The closure itself stays a pure function of the rules
// the caller read through the port (application.AliasRuleRepo, WP-3.06
// wires the adapter); disabled rules are inert and rules of other scopes
// never apply.

// AliasClosure expands one (scope, value) to the symmetric one-hop alias
// set of ARCH-003 §2 item 2 over the effective alias rules: value itself
// plus, per enabled rule of the same scope, the to_value of every rule
// whose from_value equals value and the from_value of every rule whose
// to_value equals value. The result is sorted and de-duplicated (a
// deterministic set — the matcher semi-joins on it, so order must not
// depend on rule order). value is returned even when no rule touches it,
// and an empty value closes to the empty string (there are no empty
// from/to values in valid rules). The caller passes the normalised value
// and the effective ruleset (enabled rules of the current ruleset version
// — see application.AliasRuleRepo); this function does not fold or filter
// beyond scope and enabled state. Rule sets that chain must be rejected
// with ValidateAliasRules before matching: on chained data the expansion
// of a value that is both a from and a to would follow both incident
// edges and silently treat the chain as one equivalence class.
func AliasClosure(scope domain.AliasScope, value string, rules []domain.AliasRule) []string {
	set := map[string]struct{}{value: {}}
	for _, r := range rules {
		if !r.Enabled || r.Scope != scope {
			continue
		}
		if r.From == value {
			set[r.To] = struct{}{}
		}
		if r.To == value {
			set[r.From] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ValidateAliasRules rejects alias rulesets whose data would make the
// one-hop closure unsound (ARCH-003 §2: chains are a data error surfaced
// in validate). The rules are the effective set of one ruleset version
// (both scopes allowed — each scope is validated independently). It
// errors when:
//
//   - an enabled rule has an empty from_value or to_value, or maps a value
//     to itself (a self-loop is never a rule);
//   - an enabled rule chains: a value that is the from_value of one
//     enabled rule is also the to_value of another enabled rule of the
//     same scope (a→b with b→c — including the two-cycle a→b with b→a).
//
// Disabled rules are inert and skipped — a disabled historical variant
// must not poison the current ruleset. Multiple aliases of one canonical
// (a→c with b→c) are not a chain and stay valid.
func ValidateAliasRules(rules []domain.AliasRule) error {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.From == "" {
			return fmt.Errorf("normalise: alias rule %s: from_value must not be empty", r.ID)
		}
		if r.To == "" {
			return fmt.Errorf("normalise: alias rule %s: to_value must not be empty", r.ID)
		}
		if r.From == r.To {
			return fmt.Errorf("normalise: alias rule %s: alias %q must not map to itself", r.ID, r.From)
		}
	}
	// Chain detection: within one scope, no value may be both a from and a
	// to of the enabled rules (a vendor from-value and a product to-value
	// are unrelated and never chain). Report the first offending value in
	// rule order so the error names the rule an operator must fix.
	fromOf := map[domain.AliasScope]map[string]string{} // scope -> value -> first rule id with it as from
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if fromOf[r.Scope] == nil {
			fromOf[r.Scope] = map[string]string{}
		}
		if _, seen := fromOf[r.Scope][r.From]; !seen {
			fromOf[r.Scope][r.From] = r.ID
		}
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if id, chained := fromOf[r.Scope][r.To]; chained {
			return fmt.Errorf("normalise: alias rule %s (scope %s): to_value %q is also the from_value of rule %s — alias rules must not chain (one hop only, ARCH-003 §2)", r.ID, r.Scope, r.To, id)
		}
	}
	return nil
}
