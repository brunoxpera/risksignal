package application_test

// Unit tests of the I5b user/role administration use cases (WP-5b.03 /
// DEV-099, ARCH-006 §3.3): ListUsers, ListRoles, GrantRole, RevokeRole and
// DeactivateUser — the users.roles.manage gate (deny-by-default), the
// audit events (users.role_granted / users.role_revoked / users.deactivated)
// and the deactivate-never-delete rule (ADR-014). All run against the
// in-memory fakes; no database.

import (
	"context"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

func TestListUsersRequiresPermissionAndPaginates(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("u-a", "Alice", domain.RoleSecurityAnalyst)
	h.users.add("u-b", "Bob", domain.RoleAuditor)
	h.users.add("u-c", "Carol")

	page, err := h.svc.ListUsers(context.Background(), application.ListUsersInput{Actor: userActor("admin"), Limit: 2})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(page.Users) != 2 || page.NextCursor == "" {
		t.Fatalf("page = %d users, cursor %q, want 2 / non-empty", len(page.Users), page.NextCursor)
	}
	// Ordered by display name: Admin, Alice first.
	if page.Users[0].DisplayName != "Admin" || page.Users[1].DisplayName != "Alice" {
		t.Fatalf("page order = %q, %q", page.Users[0].DisplayName, page.Users[1].DisplayName)
	}
	if page.Users[1].Roles[0] != domain.RoleSecurityAnalyst {
		t.Fatalf("Alice roles = %v, want [security_analyst]", page.Users[1].Roles)
	}

	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	if _, err := h.svc.ListUsers(context.Background(), application.ListUsersInput{Actor: userActor("analyst")}); err == nil {
		t.Fatal("ListUsers by a non-manager must be forbidden")
	}
}

func TestListRolesReturnsTheCatalogue(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)

	roles, err := h.svc.ListRoles(context.Background(), application.ListRolesInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != len(domain.AllRoles()) {
		t.Fatalf("catalogue = %d roles, want %d", len(roles), len(domain.AllRoles()))
	}
	byRole := map[domain.Role]application.RoleDescriptor{}
	for _, r := range roles {
		byRole[r.Role] = r
	}
	if scopeOf(byRole[domain.RoleAdministrator], domain.PermissionUsersRolesManage) != domain.ScopeAll {
		t.Fatal("administrator must grant users.roles.manage at all scope")
	}
	if scopeOf(byRole[domain.RoleSecurityAnalyst], domain.PermissionSignalsOverride) != domain.ScopeAll {
		t.Fatal("security_analyst must grant signals.override at all scope")
	}
	// Administrator holds no fachliche triage right (ARCH-005 §12.2).
	if scopeOf(byRole[domain.RoleAdministrator], domain.PermissionSignalsTriage) != domain.ScopeNone {
		t.Fatal("administrator must not grant signals.triage")
	}

	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	if _, err := h.svc.ListRoles(context.Background(), application.ListRolesInput{Actor: userActor("analyst")}); err == nil {
		t.Fatal("ListRoles by a non-manager must be forbidden")
	}
}

func TestGrantRoleAuditsAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("target", "Target", domain.RoleSecurityAnalyst)

	got, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "target", Role: domain.RoleAuditor, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if !hasRole(got.Roles, domain.RoleAuditor) {
		t.Fatalf("granted roles = %v, want auditor", got.Roles)
	}
	if !hasAuditAction(h, application.AuditActionUserRoleGranted) {
		t.Fatal("users.role_granted audit event missing")
	}
	audits := len(h.db.auditEvents)

	// Re-granting a held role is a no-op: no new audit row.
	if _, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "target", Role: domain.RoleAuditor, Actor: userActor("admin")}); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if len(h.db.auditEvents) != audits {
		t.Fatalf("re-grant wrote %d extra audit rows, want 0", len(h.db.auditEvents)-audits)
	}
}

func TestRevokeRoleAudits(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("target", "Target", domain.RoleSecurityAnalyst, domain.RoleAuditor)

	got, err := h.svc.RevokeRole(context.Background(), application.RevokeRoleInput{UserID: "target", Role: domain.RoleAuditor, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	if hasRole(got.Roles, domain.RoleAuditor) {
		t.Fatalf("revoked roles = %v, auditor must be gone", got.Roles)
	}
	if !hasRole(got.Roles, domain.RoleSecurityAnalyst) {
		t.Fatalf("revoked roles = %v, security_analyst must remain", got.Roles)
	}
	if !hasAuditAction(h, application.AuditActionUserRoleRevoked) {
		t.Fatal("users.role_revoked audit event missing")
	}
}

func TestDeactivateUserAuditsAndNeverDeletes(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("target", "Target", domain.RoleSecurityAnalyst)

	got, err := h.svc.DeactivateUser(context.Background(), application.DeactivateUserInput{UserID: "target", Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
	if got.DeactivatedAt.IsZero() {
		t.Fatal("deactivated_at not returned")
	}
	if !hasAuditAction(h, application.AuditActionUserDeactivated) {
		t.Fatal("users.deactivated audit event missing")
	}
	// Deactivate, never delete: the user still resolves.
	if _, err := h.users.GetUserByID(context.Background(), "target"); err != nil {
		t.Fatalf("deactivated user must still resolve: %v", err)
	}
	// A second deactivation is a conflict (guarded transition).
	_, err = h.svc.DeactivateUser(context.Background(), application.DeactivateUserInput{UserID: "target", Actor: userActor("admin")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("re-deactivate = %v (%s), want conflict", err, kind)
	}
}

func TestUserAdminErrors(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("gone", "Gone", domain.RoleAuditor)
	h.users.deactivate("gone", fixedNow)

	// Unknown user: not-found.
	if _, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "missing", Role: domain.RoleAuditor, Actor: userActor("admin")}); err == nil {
		t.Fatal("granting to a missing user must be not-found")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("missing user = %v (%s), want not-found", err, kind)
	}
	// Deactivated user: conflict.
	if _, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "gone", Role: domain.RoleAuditor, Actor: userActor("admin")}); err == nil {
		t.Fatal("granting to a deactivated user must conflict")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("deactivated user = %v (%s), want conflict", err, kind)
	}
	// Invalid role: validation.
	if _, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "admin", Role: domain.Role("wizard"), Actor: userActor("admin")}); err == nil {
		t.Fatal("an invalid role must be rejected")
	}
}

func TestUserAdminDeniesNonManager(t *testing.T) {
	h := newHarness(t)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.add("target", "Target", domain.RoleAuditor)

	if _, err := h.svc.GrantRole(context.Background(), application.GrantRoleInput{UserID: "target", Role: domain.RoleAdministrator, Actor: userActor("analyst")}); err == nil {
		t.Fatal("grant by a non-manager must be forbidden")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("non-manager grant = %v (%s), want forbidden", err, kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("denied grant opened %d transactions, want 0", len(h.runner.txs))
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatalf("denied grant wrote %d audit rows, want 0", len(h.db.auditEvents))
	}
}

func hasRole(roles []domain.Role, want domain.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func scopeOf(d application.RoleDescriptor, perm domain.Permission) domain.Scope {
	for _, g := range d.Permissions {
		if g.Permission == perm {
			return g.Scope
		}
	}
	return domain.ScopeNone
}
