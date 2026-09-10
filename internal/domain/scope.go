package domain

import "fmt"

// Scope is the object-scope of a permission grant (ARCH-005 §3, §5; §12.2).
// It says *how far* a role's permission reaches:
//
//   - ScopeAll      — unconditional; the role may act on any object.
//   - ScopeAssigned — object-scoped; the role may act only on the objects
//     assigned to it (signals/assets where owner_id = principal.id). In the
//     MVP the Analyst's "own cases" use the same owner-scoped filter; the
//     distinct ScopeOwn value is kept for §12.2 fidelity.
//   - ScopeOwn      — object-scoped to the principal's own objects.
//   - ScopeNone     — no permission at all (the deny-by-default cell).
//
// Scope is ordered all > assigned > own > none (see rank); Authorize compares
// a grant against the scope a use case requests. The zero value is the empty
// string, which is not Valid — never a default grant.
type Scope string

// Allowed Scope values (ARCH-005 §3).
const (
	ScopeAll      Scope = "all"
	ScopeAssigned Scope = "assigned"
	ScopeOwn      Scope = "own"
	ScopeNone     Scope = "none"
)

// Valid reports whether s is an allowed Scope value.
func (s Scope) Valid() bool {
	switch s {
	case ScopeAll, ScopeAssigned, ScopeOwn, ScopeNone:
		return true
	}
	return false
}

// rank orders scopes by breadth (all=3 > assigned=2 > own=1 > none=0). An
// unknown scope ranks below none so it can never widen a grant.
func (s Scope) rank() int {
	switch s {
	case ScopeAll:
		return 3
	case ScopeAssigned:
		return 2
	case ScopeOwn:
		return 1
	}
	return 0
}

// ParseScope parses s into a Scope. Unknown values error.
func ParseScope(s string) (Scope, error) {
	v := Scope(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Scope %q", s)
	}
	return v, nil
}

// objectScoped reports whether the scope restricts a grant to the principal's
// own objects (assigned or own). Such grants are checked against the object
// owner in Authorize (ARCH-005 §5).
func (s Scope) objectScoped() bool {
	return s == ScopeAssigned || s == ScopeOwn
}
