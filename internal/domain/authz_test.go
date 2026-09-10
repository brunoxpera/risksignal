package domain

import (
	"testing"
	"time"
)

// authzMatrix is the ARCH-005 §3 / §12.2 permission matrix as literal data,
// written cell-for-cell (—“ = ScopeNone). The test below compares it against
// Role.Permissions() for every role × every permission.
func authzMatrix() map[Role]map[Permission]Scope {
	return map[Role]map[Permission]Scope{
		RoleSecurityAnalyst: {
			PermissionSignalsRead:         ScopeAll,
			PermissionSignalsTriage:       ScopeAll,
			PermissionSignalsOverride:     ScopeAll,
			PermissionInventoryRead:       ScopeAll,
			PermissionInventoryManage:     ScopeNone,
			PermissionSourcesManage:       ScopeNone,
			PermissionRulesManage:         ScopeNone,
			PermissionUsersRolesManage:    ScopeNone,
			PermissionAuditRead:           ScopeOwn,
			PermissionExportsCreate:       ScopeAll,
			PermissionSettingsApprove:     ScopeNone,
			PermissionAuditRevealIdentity: ScopeNone,
		},
		RoleSystemResponsible: {
			PermissionSignalsRead:         ScopeAssigned,
			PermissionSignalsTriage:       ScopeAssigned,
			PermissionSignalsOverride:     ScopeNone,
			PermissionInventoryRead:       ScopeAssigned,
			PermissionInventoryManage:     ScopeNone,
			PermissionSourcesManage:       ScopeNone,
			PermissionRulesManage:         ScopeNone,
			PermissionUsersRolesManage:    ScopeNone,
			PermissionAuditRead:           ScopeAssigned,
			PermissionExportsCreate:       ScopeAssigned,
			PermissionSettingsApprove:     ScopeNone,
			PermissionAuditRevealIdentity: ScopeNone,
		},
		RoleAdministrator: {
			PermissionSignalsRead:         ScopeAll,
			PermissionSignalsTriage:       ScopeNone, // admin holds no fachliche triage right
			PermissionSignalsOverride:     ScopeNone, // admin holds no override right
			PermissionInventoryRead:       ScopeAll,
			PermissionInventoryManage:     ScopeAll,
			PermissionSourcesManage:       ScopeAll,
			PermissionRulesManage:         ScopeAll, // §3 extension
			PermissionUsersRolesManage:    ScopeAll,
			PermissionAuditRead:           ScopeAll,
			PermissionExportsCreate:       ScopeAll,
			PermissionSettingsApprove:     ScopeNone,
			PermissionAuditRevealIdentity: ScopeNone, // never Admin (ADR-014)
		},
		RoleAuditor: {
			PermissionSignalsRead:         ScopeAll,
			PermissionSignalsTriage:       ScopeNone,
			PermissionSignalsOverride:     ScopeNone,
			PermissionInventoryRead:       ScopeAll,
			PermissionInventoryManage:     ScopeNone,
			PermissionSourcesManage:       ScopeNone,
			PermissionRulesManage:         ScopeNone,
			PermissionUsersRolesManage:    ScopeNone,
			PermissionAuditRead:           ScopeAll,
			PermissionExportsCreate:       ScopeAll,
			PermissionSettingsApprove:     ScopeNone,
			PermissionAuditRevealIdentity: ScopeAll,
		},
		RoleProductOwner: {
			PermissionSignalsRead:         ScopeAll,
			PermissionSignalsTriage:       ScopeNone,
			PermissionSignalsOverride:     ScopeNone,
			PermissionInventoryRead:       ScopeAll,
			PermissionInventoryManage:     ScopeNone,
			PermissionSourcesManage:       ScopeNone,
			PermissionRulesManage:         ScopeNone,
			PermissionUsersRolesManage:    ScopeNone,
			PermissionAuditRead:           ScopeAll,
			PermissionExportsCreate:       ScopeAll,
			PermissionSettingsApprove:     ScopeAll,
			PermissionAuditRevealIdentity: ScopeAll,
		},
	}
}

// cell resolves a permission in a Role.Permissions() map, defaulting to
// ScopeNone when the permission is absent (deny-by-default).
func cell(m map[Permission]Scope, p Permission) Scope {
	if s, ok := m[p]; ok {
		return s
	}
	return ScopeNone
}

// TestRolePermissionMatrix is the §12.2 cell-for-cell proof: for every role
// and every permission the matrix must equal the concept, including the
// rules.manage extension (Admin) and audit.reveal_identity = {Auditor, PO}.
func TestRolePermissionMatrix(t *testing.T) {
	want := authzMatrix()
	for _, role := range AllRoles() {
		got := role.Permissions()
		for _, perm := range AllPermissions() {
			if g, w := cell(got, perm), cell(want[role], perm); g != w {
				t.Errorf("matrix[%s][%s] = %q, want %q", role, perm, g, w)
			}
		}
		// No extra cells beyond the §12.2 vocabulary.
		for perm := range got {
			if !perm.Valid() {
				t.Errorf("matrix[%s] holds unknown permission %q", role, perm)
			}
		}
	}
}

// TestRolePermissionMatrixSpecialRules pins the rules that §3 calls out
// explicitly.
func TestRolePermissionMatrixSpecialRules(t *testing.T) {
	// audit.reveal_identity: Auditor + Product Owner only, never Administrator.
	for _, role := range AllRoles() {
		granted := cell(role.Permissions(), PermissionAuditRevealIdentity) != ScopeNone
		want := role == RoleAuditor || role == RoleProductOwner
		if granted != want {
			t.Errorf("reveal_identity for %s: granted=%v, want %v", role, granted, want)
		}
	}
	// Administrators hold no signals.triage / signals.override.
	admin := RoleAdministrator.Permissions()
	if cell(admin, PermissionSignalsTriage) != ScopeNone {
		t.Error("administrator must not hold signals.triage")
	}
	if cell(admin, PermissionSignalsOverride) != ScopeNone {
		t.Error("administrator must not hold signals.override")
	}
	// rules.manage is Administrator-only.
	for _, role := range AllRoles() {
		granted := cell(role.Permissions(), PermissionRulesManage) != ScopeNone
		if granted != (role == RoleAdministrator) {
			t.Errorf("rules.manage for %s: granted=%v, want %v", role, granted, role == RoleAdministrator)
		}
	}
}

// TestRolePermissionsReturnsCopy: mutating the returned map must not affect
// the matrix (the matrix is read-only data).
func TestRolePermissionsReturnsCopy(t *testing.T) {
	m := RoleSecurityAnalyst.Permissions()
	m[PermissionSignalsRead] = ScopeNone
	delete(m, PermissionSignalsTriage)
	if got := cell(RoleSecurityAnalyst.Permissions(), PermissionSignalsRead); got != ScopeAll {
		t.Errorf("matrix mutated through returned map: signals.read = %q", got)
	}
	if got := cell(RoleSecurityAnalyst.Permissions(), PermissionSignalsTriage); got != ScopeAll {
		t.Errorf("matrix mutated through returned map: signals.triage = %q", got)
	}
}

// TestRoleValidAndParse covers the five-role vocabulary.
func TestRoleValidAndParse(t *testing.T) {
	for _, want := range AllRoles() {
		got, err := ParseRole(string(want))
		if err != nil {
			t.Errorf("ParseRole(%q): unexpected error: %v", want, err)
		}
		if got != want || !want.Valid() {
			t.Errorf("ParseRole(%q) = %q, Valid=%v", want, got, want.Valid())
		}
	}
	for _, s := range []string{"", "analyst", "ADMIN", "admin", "security_analyst ", "root", "owner"} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q): want error, got nil", s)
		}
	}
	if Role("").Valid() {
		t.Error("zero-value Role must not be Valid")
	}
}

// TestScopeValid covers the four-scope vocabulary.
func TestScopeValid(t *testing.T) {
	for _, s := range []Scope{ScopeAll, ScopeAssigned, ScopeOwn, ScopeNone} {
		if !s.Valid() {
			t.Errorf("Scope %q: Valid() = false, want true", s)
		}
		if _, err := ParseScope(string(s)); err != nil {
			t.Errorf("ParseScope(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range []string{"", "global", "ALL", "assigned ", "self"} {
		if _, err := ParseScope(s); err == nil {
			t.Errorf("ParseScope(%q): want error, got nil", s)
		}
	}
	if Scope("").Valid() {
		t.Error("zero-value Scope must not be Valid")
	}
}

// TestPermissionValid covers the twelve-permission vocabulary.
func TestPermissionValid(t *testing.T) {
	all := AllPermissions()
	if len(all) != 12 {
		t.Errorf("len(AllPermissions()) = %d, want 12", len(all))
	}
	for _, p := range all {
		if !p.Valid() {
			t.Errorf("Permission %q: Valid() = false, want true", p)
		}
	}
	for _, s := range []string{"", "signals", "SIGNALS.READ", "signals.read ", "audit.reveal"} {
		if Permission(s).Valid() {
			t.Errorf("Permission(%q).Valid() = true, want false", s)
		}
	}
}

// TestAuthorizeDenyByDefault: no roles, unknown roles and permissions a role
// does not hold all deny; an unknown permission errors.
func TestAuthorizeDenyByDefault(t *testing.T) {
	const owner = "user-1"
	// No roles at all, or only unknown roles.
	for _, roles := range [][]Role{nil, {}, {Role("root")}, {Role("nope"), otherRole()}} {
		ok, err := Authorize(roles, PermissionSignalsRead, ScopeAll, "", owner)
		if err != nil {
			t.Errorf("Authorize(%v): unexpected error: %v", roles, err)
		}
		if ok {
			t.Errorf("Authorize(%v, signals.read): want deny, got allow", roles)
		}
	}
	// A role that does not grant the permission.
	if ok, _ := Authorize([]Role{RoleAuditor}, PermissionSignalsTriage, ScopeAll, "", owner); ok {
		t.Error("auditor signals.triage: want deny, got allow")
	}
	if ok, _ := Authorize([]Role{RoleAdministrator}, PermissionSignalsTriage, ScopeAssigned, owner, owner); ok {
		t.Error("admin signals.triage: want deny, got allow")
	}
	if ok, _ := Authorize([]Role{RoleAdministrator}, PermissionAuditRevealIdentity, ScopeAll, "", owner); ok {
		t.Error("admin audit.reveal_identity: want deny, got allow")
	}
	if ok, _ := Authorize([]Role{otherRole()}, PermissionSignalsRead, ScopeAll, "", owner); ok {
		t.Error("unknown role: want deny, got allow")
	}
	// Unknown permission is a programming error (fail closed).
	if ok, err := Authorize([]Role{RoleAdministrator}, Permission("nope"), ScopeAll, "", owner); err == nil || ok {
		t.Errorf("unknown permission: got (%v, %v), want (false, error)", ok, err)
	}
	// Unknown scope is a programming error (fail closed).
	if ok, err := Authorize([]Role{RoleAdministrator}, PermissionSignalsRead, Scope("global"), "", owner); err == nil || ok {
		t.Errorf("unknown scope: got (%v, %v), want (false, error)", ok, err)
	}
}

// otherRole is a syntactically-unknown but non-zero Role for the unknown-role
// cases.
func otherRole() Role { return Role("security_lead") }

// TestAuthorizeObjectScope: an assigned/own grant applies only to the
// principal's own objects (ownerID must be non-empty and equal principalID).
func TestAuthorizeObjectScope(t *testing.T) {
	const (
		p          = "user-1"
		ownerOther = "user-2"
	)
	// Systemverantwortliche hold assigned scope: matching owner allows, a
	// different owner (or none) denies.
	if ok, err := Authorize([]Role{RoleSystemResponsible}, PermissionSignalsTriage, ScopeAssigned, p, p); err != nil || !ok {
		t.Errorf("assigned/own object: got (%v, %v), want allow", ok, err)
	}
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionSignalsTriage, ScopeAssigned, ownerOther, p); ok {
		t.Error("assigned, foreign owner: want deny, got allow")
	}
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionSignalsTriage, ScopeAssigned, "", p); ok {
		t.Error("assigned, empty owner: want deny, got allow")
	}
	// Systemverantwortliche own-scoped read (audit.read) behaves the same.
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionAuditRead, ScopeOwn, p, p); !ok {
		t.Error("assigned grant serving own scope: want allow, got deny")
	}
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionAuditRead, ScopeOwn, ownerOther, p); ok {
		t.Error("assigned grant, foreign owner at own scope: want deny, got allow")
	}
	// An unconditional grant ignores the owner entirely.
	if ok, _ := Authorize([]Role{RoleSecurityAnalyst}, PermissionSignalsTriage, ScopeAll, ownerOther, p); !ok {
		t.Error("analyst (all) on foreign object: want allow, got deny")
	}
	// A union of roles takes the broadest grant (all wins over assigned).
	if ok, _ := Authorize([]Role{RoleSystemResponsible, RoleSecurityAnalyst}, PermissionSignalsRead, ScopeAll, ownerOther, p); !ok {
		t.Error("assigned ∪ all: want allow (all wins), got deny")
	}
}

// TestAuthorizeScopeCoverage: a scoped grant cannot serve an operation
// broader than the scope it holds; a scoped principal must operate at its own
// scope.
func TestAuthorizeScopeCoverage(t *testing.T) {
	const p = "user-1"
	// Systemverantwortliche hold assigned, not all: a global read is denied,
	// a self-scoped (assigned) read is allowed.
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionSignalsRead, ScopeAll, p, p); ok {
		t.Error("assigned grant at all scope: want deny, got allow")
	}
	if ok, _ := Authorize([]Role{RoleSystemResponsible}, PermissionSignalsRead, ScopeAssigned, p, p); !ok {
		t.Error("assigned grant at assigned scope: want allow, got deny")
	}
	// The Analyst's audit.read is own: an own-scoped read is allowed, a global
	// read is denied.
	if ok, _ := Authorize([]Role{RoleSecurityAnalyst}, PermissionAuditRead, ScopeOwn, p, p); !ok {
		t.Error("own grant at own scope: want allow, got deny")
	}
	if ok, _ := Authorize([]Role{RoleSecurityAnalyst}, PermissionAuditRead, ScopeAll, "", p); ok {
		t.Error("own grant at all scope: want deny, got allow")
	}
}

// TestAuthorizeAgainstMatrix drives Authorize for every role × permission at
// the granted scope (owner matched): the decision must match the matrix.
func TestAuthorizeAgainstMatrix(t *testing.T) {
	const (
		p     = "user-1"
		owner = "user-1"
	)
	want := authzMatrix()
	for _, role := range AllRoles() {
		for _, perm := range AllPermissions() {
			granted := cell(want[role], perm)
			scope := granted
			if scope == ScopeNone {
				scope = ScopeAll
			}
			got, err := Authorize([]Role{role}, perm, scope, owner, p)
			if err != nil {
				t.Errorf("Authorize(%s, %s, %s): unexpected error: %v", role, perm, scope, err)
			}
			if wantAllow := granted != ScopeNone; got != wantAllow {
				t.Errorf("Authorize(%s, %s, %s) = %v, want %v (grant %q)", role, perm, scope, got, wantAllow, granted)
			}
		}
	}
}

// TestPrincipalHasPermissionAndDeactivated: HasPermission is the scope-
// agnostic membership check; a deactivated principal holds nothing.
func TestPrincipalHasPermissionAndDeactivated(t *testing.T) {
	active := Principal{
		Identity:   Identity{SubjectID: "iss::1", DisplayName: "Alice", Email: "a@example.com"},
		InternalID: "user-1",
		Roles:      []Role{RoleSecurityAnalyst, RoleAuditor},
	}
	if active.Deactivated() {
		t.Error("active principal: Deactivated() = true, want false")
	}
	for _, perm := range []Permission{PermissionSignalsTriage, PermissionAuditRevealIdentity} {
		if !active.HasPermission(perm) {
			t.Errorf("active principal: HasPermission(%s) = false, want true", perm)
		}
	}
	if active.HasPermission(PermissionUsersRolesManage) {
		t.Error("active principal: HasPermission(users.roles.manage) = true, want false")
	}
	if got := active.GrantedScope(PermissionAuditRead); got != ScopeAll {
		t.Errorf("GrantedScope(audit.read) = %q, want all", got)
	}

	deactivated := active
	deactivated.DeactivatedAt = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	if !deactivated.Deactivated() {
		t.Error("deactivated principal: Deactivated() = false, want true")
	}
	for _, perm := range AllPermissions() {
		if deactivated.HasPermission(perm) {
			t.Errorf("deactivated principal: HasPermission(%s) = true, want false", perm)
		}
		if got := deactivated.GrantedScope(perm); got != ScopeNone {
			t.Errorf("deactivated principal: GrantedScope(%s) = %q, want none", perm, got)
		}
	}
}
