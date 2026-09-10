package domain

import "fmt"

// Authorize is the pure, deny-by-default authorisation decision of ARCH-005
// §5. It answers one question: may a principal holding `roles` exercise
// `perm` at object `scope`?
//
// Inputs:
//   - roles       — the principal's current roles (re-read from user_roles at
//     authorise time, not taken from the token). An empty list denies.
//   - perm        — the permission the use case requires.
//   - scope       — the breadth the use case operates at (ScopeAll for a
//     global operation, ScopeAssigned/ScopeOwn for a per-object one).
//   - ownerID     — the owner of the concrete object being acted on
//     (empty when the operation is not object-bound).
//   - principalID — the principal's internal id (users.id).
//
// Decision (deny-by-default):
//  1. Unknown permission or scope ⇒ error, deny — fail closed.
//  2. No roles, or only unknown roles, or no role grants perm ⇒ deny.
//  3. The effective grant is the broadest scope any role grants for perm. It
//     must be at least as broad as the requested scope (all > assigned > own),
//     otherwise deny: a scoped role cannot perform an unconditional operation.
//  4. An object-scoped grant (assigned/own) additionally requires the object
//     to belong to the principal: ownerID must be non-empty and equal to
//     principalID.
//
// The function is deterministic, network-free and clock-free: same inputs ⇒
// same output.
func Authorize(roles []Role, perm Permission, scope Scope, ownerID, principalID string) (bool, error) {
	if !perm.Valid() {
		return false, fmt.Errorf("domain: unknown permission %q", perm)
	}
	if !scope.Valid() {
		return false, fmt.Errorf("domain: unknown scope %q", scope)
	}

	granted := ScopeNone
	for _, r := range roles {
		if !r.Valid() {
			continue // an unknown role grants nothing
		}
		gs, ok := rolePermissions[r][perm]
		if !ok {
			continue
		}
		if gs.rank() > granted.rank() {
			granted = gs
		}
	}

	// deny-by-default: no role grants this permission.
	if granted == ScopeNone {
		return false, nil
	}

	// A scoped grant cannot serve a broader operation than the scope it holds.
	if granted.rank() < scope.rank() {
		return false, nil
	}

	// Object-scoped grants apply only to the principal's own objects.
	if granted.objectScoped() {
		if ownerID == "" || ownerID != principalID {
			return false, nil
		}
	}

	return true, nil
}
