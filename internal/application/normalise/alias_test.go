package normalise

import (
	"reflect"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Alias-closure tests (ARCH-003 §2 item 2): the match-time symmetric
// one-hop expansion {value} ∪ {to | from=value} ∪ {from | to=value} and
// its chain rejection (chains are a data error). Rules are built through
// domain.NewAliasRule — the same value object the alias_rules table maps
// into.

func aliasRule(t *testing.T, id string, scope domain.AliasScope, from, to string) domain.AliasRule {
	t.Helper()
	r, err := domain.NewAliasRule(id, scope, from, to, "", 1)
	if err != nil {
		t.Fatalf("NewAliasRule(%s): %v", id, err)
	}
	return r
}

func TestAliasClosureNoRules(t *testing.T) {
	got := AliasClosure(domain.AliasScopeVendor, "acme", nil)
	if want := []string{"acme"}; !reflect.DeepEqual(got, want) {
		t.Errorf("AliasClosure without rules = %v, want %v", got, want)
	}
	if got := AliasClosure(domain.AliasScopeProduct, "", nil); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("AliasClosure of empty value = %v, want [\"\"]", got)
	}
}

// TestAliasClosureSymmetric asserts the canonical side and the alias side
// meet: closing on the canonical includes the alias, closing on the alias
// includes the canonical (both the CVE side and the component side are
// closed before the semi-join, ARCH-003 §2).
func TestAliasClosureSymmetric(t *testing.T) {
	rules := []domain.AliasRule{
		aliasRule(t, "r1", domain.AliasScopeVendor, "microsooft", "microsoft"),
		aliasRule(t, "r2", domain.AliasScopeVendor, "adbe", "adobe"),
	}
	want := []string{"microsoft", "microsooft"}
	onCanonical := AliasClosure(domain.AliasScopeVendor, "microsoft", rules)
	if !sameSet(onCanonical, want) {
		t.Errorf("closing on canonical = %v, want the set %v", onCanonical, want)
	}
	onAlias := AliasClosure(domain.AliasScopeVendor, "microsooft", rules)
	if !sameSet(onAlias, want) {
		t.Errorf("closing on alias = %v, want the set %v", onAlias, want)
	}
}

// sameSet compares two slices as unordered sets (closure results are
// sorted, but the assertion reads better without depending on the exact
// byte order of near-identical spellings).
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, v := range a {
		count[v]++
	}
	for _, v := range b {
		if count[v] == 0 {
			return false
		}
		count[v]--
	}
	return true
}

// TestAliasClosureScopeIsolation asserts rules of the other scope and
// disabled rules never expand the set.
func TestAliasClosureScopeIsolation(t *testing.T) {
	disabled := aliasRule(t, "r1", domain.AliasScopeVendor, "microsooft", "microsoft").Disable()
	rules := []domain.AliasRule{
		disabled,
		aliasRule(t, "r2", domain.AliasScopeProduct, "visual studio", "visualstudio"),
	}
	got := AliasClosure(domain.AliasScopeVendor, "acme", rules)
	if want := []string{"acme"}; !reflect.DeepEqual(got, want) {
		t.Errorf("vendor closure must ignore disabled and product rules, got %v", got)
	}
	got = AliasClosure(domain.AliasScopeProduct, "visual studio", rules)
	if want := []string{"visual studio", "visualstudio"}; !reflect.DeepEqual(got, want) {
		t.Errorf("product closure = %v, want %v", got, want)
	}
}

// TestAliasClosureOneHop asserts the closure is exactly one hop: only
// rules whose from or to equals the queried value are followed, the result
// is never iterated again. On chain-free data the expansion is the full
// equivalence of alias and canonical.
func TestAliasClosureOneHop(t *testing.T) {
	// a->b and b->c is chained data (rejected by ValidateAliasRules); the
	// closure still shows its one-hop character: closing on a or c follows
	// exactly the incident rule, it does not walk to the far end.
	chained := []domain.AliasRule{
		aliasRule(t, "r1", domain.AliasScopeVendor, "a", "b"),
		aliasRule(t, "r2", domain.AliasScopeVendor, "b", "c"),
	}
	if got := AliasClosure(domain.AliasScopeVendor, "a", chained); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("one hop from a = %v, want [a b]", got)
	}
	if got := AliasClosure(domain.AliasScopeVendor, "c", chained); !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Errorf("one hop from c = %v, want [b c]", got)
	}
}

// TestAliasClosureDeterministic asserts the result is sorted regardless of
// rule order — the matcher semi-joins on the set, so its order must never
// depend on rule insertion order.
func TestAliasClosureDeterministic(t *testing.T) {
	a := []domain.AliasRule{
		aliasRule(t, "r1", domain.AliasScopeVendor, "zz", "canonical"),
		aliasRule(t, "r2", domain.AliasScopeVendor, "aa", "canonical"),
	}
	b := []domain.AliasRule{
		aliasRule(t, "r2", domain.AliasScopeVendor, "aa", "canonical"),
		aliasRule(t, "r1", domain.AliasScopeVendor, "zz", "canonical"),
	}
	gotA := AliasClosure(domain.AliasScopeVendor, "canonical", a)
	gotB := AliasClosure(domain.AliasScopeVendor, "canonical", b)
	if want := []string{"aa", "canonical", "zz"}; !reflect.DeepEqual(gotA, want) {
		t.Errorf("closure = %v, want %v", gotA, want)
	}
	if !reflect.DeepEqual(gotA, gotB) {
		t.Errorf("closure must not depend on rule order: %v vs %v", gotA, gotB)
	}
}

func TestValidateAliasRules(t *testing.T) {
	t.Run("valid multiple aliases of one canonical", func(t *testing.T) {
		rules := []domain.AliasRule{
			aliasRule(t, "r1", domain.AliasScopeVendor, "adbe", "adobe"),
			aliasRule(t, "r2", domain.AliasScopeVendor, "adob", "adobe"),
		}
		if err := ValidateAliasRules(rules); err != nil {
			t.Errorf("multi-alias ruleset must be valid, got %v", err)
		}
	})
	t.Run("chain rejected", func(t *testing.T) {
		rules := []domain.AliasRule{
			aliasRule(t, "r1", domain.AliasScopeVendor, "a", "b"),
			aliasRule(t, "r2", domain.AliasScopeVendor, "b", "c"),
		}
		err := ValidateAliasRules(rules)
		if err == nil {
			t.Fatal("chained ruleset must be rejected")
		}
		for _, id := range []string{"r1", "r2"} {
			if !strings.Contains(err.Error(), id) {
				t.Errorf("error %q should name rule %s", err, id)
			}
		}
	})
	t.Run("two-cycle rejected", func(t *testing.T) {
		rules := []domain.AliasRule{
			aliasRule(t, "r1", domain.AliasScopeVendor, "a", "b"),
			aliasRule(t, "r2", domain.AliasScopeVendor, "b", "a"),
		}
		if err := ValidateAliasRules(rules); err == nil {
			t.Fatal("two-cycle must be rejected")
		}
	})
	t.Run("disabled chain is inert", func(t *testing.T) {
		rules := []domain.AliasRule{
			aliasRule(t, "r1", domain.AliasScopeVendor, "a", "b"),
			aliasRule(t, "r2", domain.AliasScopeVendor, "b", "c").Disable(),
		}
		if err := ValidateAliasRules(rules); err != nil {
			t.Errorf("disabled chained rule must be inert, got %v", err)
		}
	})
	t.Run("cross-scope values never chain", func(t *testing.T) {
		rules := []domain.AliasRule{
			aliasRule(t, "r1", domain.AliasScopeVendor, "a", "b"),
			aliasRule(t, "r2", domain.AliasScopeProduct, "b", "c"),
		}
		if err := ValidateAliasRules(rules); err != nil {
			t.Errorf("vendor and product scopes are independent, got %v", err)
		}
	})
	t.Run("self loop rejected", func(t *testing.T) {
		rules := []domain.AliasRule{{ID: "r1", Scope: domain.AliasScopeVendor, From: "a", To: "a", Version: 1, Enabled: true}}
		if err := ValidateAliasRules(rules); err == nil {
			t.Fatal("self-loop must be rejected")
		}
	})
	t.Run("empty values rejected", func(t *testing.T) {
		rules := []domain.AliasRule{{ID: "r1", Scope: domain.AliasScopeVendor, From: "", To: "b", Version: 1, Enabled: true}}
		if err := ValidateAliasRules(rules); err == nil {
			t.Fatal("empty from_value must be rejected")
		}
		rules = []domain.AliasRule{{ID: "r1", Scope: domain.AliasScopeVendor, From: "a", To: "", Version: 1, Enabled: true}}
		if err := ValidateAliasRules(rules); err == nil {
			t.Fatal("empty to_value must be rejected")
		}
	})
}
