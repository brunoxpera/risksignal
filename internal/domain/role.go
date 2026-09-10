package domain

import "fmt"

// Role is an internal authorisation role (ARCH-005 §1, §3; ch. 3, §12.2). The
// five roles are a fixed domain vocabulary (also a DB CHECK on
// user_roles.role), not config data. A user holds zero or more roles; zero
// roles means deny-by-default on everything (role.go / Authorize).
type Role string

// Allowed Role values (ARCH-005 §3). The string values are the machine keys
// stored in user_roles.role.
const (
	RoleSecurityAnalyst   Role = "security_analyst"   // Security Analyst
	RoleSystemResponsible Role = "system_responsible" // Systemverantwortliche
	RoleAdministrator     Role = "administrator"      // Administrator
	RoleAuditor           Role = "auditor"            // Auditor / Reviewer
	RoleProductOwner      Role = "product_owner"      // Product Owner
)

// Valid reports whether r is an allowed Role value.
func (r Role) Valid() bool {
	switch r {
	case RoleSecurityAnalyst,
		RoleSystemResponsible,
		RoleAdministrator,
		RoleAuditor,
		RoleProductOwner:
		return true
	}
	return false
}

// ParseRole parses s into a Role. Unknown values error (ARCH-005 §2: an
// unknown roles-claim value maps to no roles, fail closed).
func ParseRole(s string) (Role, error) {
	v := Role(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Role %q", s)
	}
	return v, nil
}

// AllRoles returns every Role in canonical order (Security Analyst,
// Systemverantwortliche, Administrator, Auditor, Product Owner).
func AllRoles() []Role {
	return []Role{
		RoleSecurityAnalyst,
		RoleSystemResponsible,
		RoleAdministrator,
		RoleAuditor,
		RoleProductOwner,
	}
}

// Permissions returns the role's permission→scope grant map: the ARCH-005 §3
// / §12.2 matrix, cell-for-cell. A permission absent from the map is denied
// (deny-by-default). The matrix is pure data — the single source of truth —
// so it can be audited against the concept and tested exhaustively.
//
// The returned map is a copy; mutating it does not affect the matrix.
func (r Role) Permissions() map[Permission]Scope {
	src := rolePermissions[r]
	out := make(map[Permission]Scope, len(src))
	for p, s := range src {
		out[p] = s
	}
	return out
}

// rolePermissions is the ARCH-005 §3 / §12.2 matrix as data. Every role is
// listed explicitly (even when empty) so AllRoles × the table is total.
//
// §12.2 rules encoded here:
//   - rules.manage is the only extension and is Administrator-only (§3).
//   - Administrators hold no signals.triage / signals.override — admin never
//     auto-grants fachliche Entscheidungsrechte (§12.2).
//   - audit.reveal_identity is Auditor + Product Owner only, never Admin
//     (ADR-014, §12.2).
//   - Systemverantwortliche hold assigned scope on signals.read/triage,
//     inventory.read, audit.read and exports.create (§12.2 "Zugeordnet").
//   - The Analyst's audit.read is own ("Eigene Fälle"); all other cell scopes
//     are all.
var rolePermissions = map[Role]map[Permission]Scope{
	RoleSecurityAnalyst: {
		PermissionSignalsRead:     ScopeAll,
		PermissionSignalsTriage:   ScopeAll,
		PermissionSignalsOverride: ScopeAll,
		PermissionInventoryRead:   ScopeAll,
		PermissionAuditRead:       ScopeOwn,
		PermissionExportsCreate:   ScopeAll,
	},
	RoleSystemResponsible: {
		PermissionSignalsRead:   ScopeAssigned,
		PermissionSignalsTriage: ScopeAssigned,
		PermissionInventoryRead: ScopeAssigned,
		PermissionAuditRead:     ScopeAssigned,
		PermissionExportsCreate: ScopeAssigned,
	},
	RoleAdministrator: {
		PermissionSignalsRead:      ScopeAll,
		PermissionInventoryRead:    ScopeAll,
		PermissionInventoryManage:  ScopeAll,
		PermissionSourcesManage:    ScopeAll,
		PermissionRulesManage:      ScopeAll,
		PermissionUsersRolesManage: ScopeAll,
		PermissionAuditRead:        ScopeAll,
		PermissionExportsCreate:    ScopeAll,
		// No signals.triage / signals.override; no audit.reveal_identity.
	},
	RoleAuditor: {
		PermissionSignalsRead:         ScopeAll,
		PermissionInventoryRead:       ScopeAll,
		PermissionAuditRead:           ScopeAll,
		PermissionExportsCreate:       ScopeAll,
		PermissionAuditRevealIdentity: ScopeAll,
	},
	RoleProductOwner: {
		PermissionSignalsRead:         ScopeAll,
		PermissionInventoryRead:       ScopeAll,
		PermissionAuditRead:           ScopeAll,
		PermissionExportsCreate:       ScopeAll,
		PermissionSettingsApprove:     ScopeAll,
		PermissionAuditRevealIdentity: ScopeAll,
	},
}
