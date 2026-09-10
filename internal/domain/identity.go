package domain

import "time"

// Identity is the minimal, IdP-owned identity derived from a verified OIDC
// token (ARCH-005 §1, §2): the external subject, a display name and an
// optional e-mail. RiskSignal stores no password, no MFA secret and no other
// profile PII (ch. 12, FR-028, NFR-014, §11.1 data minimisation; deactivate,
// never delete — ADR-014).
type Identity struct {
	// SubjectID is the issuer-qualified external OIDC subject
	// ("<issuer>::<sub>") — the unique login key (users.subject_id).
	SubjectID string
	// DisplayName is denormalised into audit rows at event time.
	DisplayName string
	// Email is optional and used only as a notification recipient — never as
	// the login key.
	Email string
}

// Principal is an authenticated Identity resolved to an internal user and
// enriched with the *current* authorisation state at authorise time
// (ARCH-005 §1, §5): the internal users.id, the roles re-read from
// user_roles, and the deactivation instant.
type Principal struct {
	Identity
	// InternalID is the stable internal user id (users.id) — the value
	// audit_events.actor_id stores for user actors and the key
	// audit.reveal_identity resolves on.
	InternalID string
	// Roles is the current role set (re-read at authorise time — never taken
	// from the token; ARCH-005 §2, §5). Zero roles ⇒ deny-by-default.
	Roles []Role
	// DeactivatedAt is the deactivation instant; the zero value means the
	// principal is active.
	DeactivatedAt time.Time
}

// Deactivated reports whether the principal has been deactivated. A
// deactivated user still resolves in the audit trail (ADR-014) but holds no
// rights.
func (p Principal) Deactivated() bool {
	return !p.DeactivatedAt.IsZero()
}

// HasPermission reports whether the active principal holds perm in at least
// one role, at any scope (deny-by-default; a deactivated principal holds
// nothing). It is the scope-agnostic membership check used for the per-route
// permission declaration (ARCH-005 §5); the scope- and object-aware decision
// lives in Authorize.
func (p Principal) HasPermission(perm Permission) bool {
	if p.Deactivated() {
		return false
	}
	return p.GrantedScope(perm) != ScopeNone
}

// GrantedScope returns the broadest scope any of the principal's roles grants
// for perm (all > assigned > own), or ScopeNone when no role grants it (or
// the principal is deactivated). The application uses it to inject the
// owner-scoped filter for scoped reads (ARCH-005 §5) and to pass the correct
// scope to Authorize.
func (p Principal) GrantedScope(perm Permission) Scope {
	if p.Deactivated() || !perm.Valid() {
		return ScopeNone
	}
	granted := ScopeNone
	for _, r := range p.Roles {
		if !r.Valid() {
			continue
		}
		gs, ok := rolePermissions[r][perm]
		if !ok {
			continue
		}
		if gs.rank() > granted.rank() {
			granted = gs
		}
	}
	return granted
}
