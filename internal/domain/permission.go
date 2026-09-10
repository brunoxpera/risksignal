package domain

// Permission is a named authorisation right (ARCH-005 §3; §12.2 verbatim plus
// the flagged extensions rules.manage and, from I6, retention.manage).
// Permissions are the vocabulary the
// use-case-level authorisation checks against (ARCH-005 §5); a permission is
// never implied by another — the role→permission→scope matrix (role.go) is
// the single source of truth.
type Permission string

// Allowed Permission values (ARCH-005 §3, §12.2 + the rules.manage and
// retention.manage extensions, ARCH-007 §9).
const (
	// PermissionSignalsRead reads risk signals.
	PermissionSignalsRead Permission = "signals.read"
	// PermissionSignalsTriage is the fachliche triage decision right
	// (transition/acknowledge/assign/comment/pause/resume).
	PermissionSignalsTriage Permission = "signals.triage"
	// PermissionSignalsOverride is the C-4 manual priority override/revert
	// right (ARCH-004 §3).
	PermissionSignalsOverride Permission = "signals.override"
	// PermissionInventoryRead reads the inventory (assets/components).
	PermissionInventoryRead Permission = "inventory.read"
	// PermissionInventoryManage writes the inventory (preview/validate/
	// import/commit, asset correction).
	PermissionInventoryManage Permission = "inventory.manage"
	// PermissionSourcesManage manages sources (CRUD, run/status, quarantine).
	PermissionSourcesManage Permission = "sources.manage"
	// PermissionRulesManage manages rules (PublishPriorityRules, alias/
	// decision rule maintenance). Extension of §12.2 (ARCH-005 §3).
	PermissionRulesManage Permission = "rules.manage"
	// PermissionUsersRolesManage manages users and their role grants.
	PermissionUsersRolesManage Permission = "users.roles.manage"
	// PermissionAuditRead reads audit events (scope per matrix).
	PermissionAuditRead Permission = "audit.read"
	// PermissionExportsCreate creates and downloads exports.
	PermissionExportsCreate Permission = "exports.create"
	// PermissionSettingsApprove approves settings (Product Owner only) —
	// including the four-eyes approval of a retention dry-run that authorises
	// the deletion job (ARCH-007 §9).
	PermissionSettingsApprove Permission = "settings.approve"
	// PermissionRetentionManage runs the retention lifecycle (dry-run,
	// pseudonymisation, execute) and manages legal holds (ARCH-007 §9).
	// Administrator only.
	PermissionRetentionManage Permission = "retention.manage"
	// PermissionAuditRevealIdentity is the governed identity-reveal act
	// (ADR-014) — Auditor and Product Owner only, never Administrator.
	PermissionAuditRevealIdentity Permission = "audit.reveal_identity"
)

// Valid reports whether p is an allowed Permission value.
func (p Permission) Valid() bool {
	switch p {
	case PermissionSignalsRead,
		PermissionSignalsTriage,
		PermissionSignalsOverride,
		PermissionInventoryRead,
		PermissionInventoryManage,
		PermissionSourcesManage,
		PermissionRulesManage,
		PermissionUsersRolesManage,
		PermissionAuditRead,
		PermissionExportsCreate,
		PermissionSettingsApprove,
		PermissionRetentionManage,
		PermissionAuditRevealIdentity:
		return true
	}
	return false
}

// AllPermissions returns every Permission in canonical (§12.2 table) order.
func AllPermissions() []Permission {
	return []Permission{
		PermissionSignalsRead,
		PermissionSignalsTriage,
		PermissionSignalsOverride,
		PermissionInventoryRead,
		PermissionInventoryManage,
		PermissionSourcesManage,
		PermissionRulesManage,
		PermissionUsersRolesManage,
		PermissionAuditRead,
		PermissionExportsCreate,
		PermissionSettingsApprove,
		PermissionRetentionManage,
		PermissionAuditRevealIdentity,
	}
}
