package repo

// Integration test for the I5a identity persistence (users.sql +
// user_roles.sql, WP-5a.03 / DEV-089): the first-login create-or-read by
// subject, the by-id read, the role grant/revoke + per-user re-read, the
// guarded deactivation and the last-login touch — the DEV-089 acceptance
// criterion end to end.
//
// It runs against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded migration set (the shared
// newI4TestPool helper of i4_integration_test.go, same package). When no
// database is reachable the test skips, so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// countUsersBySubject counts the persisted rows for one subject — the
// create-or-read must never leave a second row behind.
func countUsersBySubject(t *testing.T, ctx context.Context, q *gen.Queries, subject string) int {
	t.Helper()
	rows, err := q.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.SubjectID == subject {
			n++
		}
	}
	return n
}

// TestUserPersistenceIntegration exercises the I5a identity persistence paths
// against a real database (the DEV-089 acceptance criterion).
func TestUserPersistenceIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := gen.New(pool)
	users := NewUserRepo(q)

	const subject = "https://idp.example/realms/main::alice"
	now := time.Now().UTC().Truncate(time.Microsecond)

	// 1. First login creates the user by subject.
	var created gen.User
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		created, err = users.UpsertBySubject(ctx, tx, subject, "Alice Example", "alice@example.test", now)
		return err
	}); err != nil {
		t.Fatalf("first-login upsert: %v", err)
	}
	if !created.ID.Valid || uuidString(created.ID) == "" {
		t.Fatalf("created user id = %v, want a valid uuid", created.ID)
	}
	if created.SubjectID != subject || created.DisplayName != "Alice Example" {
		t.Fatalf("created user = %+v, want subject %q display %q", created, subject, "Alice Example")
	}
	if !created.Email.Valid || created.Email.String != "alice@example.test" {
		t.Fatalf("created email = %v, want alice@example.test", created.Email)
	}
	if !created.LastLoginAt.Valid || !created.LastLoginAt.Time.Equal(now) {
		t.Fatalf("created last_login_at = %v, want %v", created.LastLoginAt, now)
	}
	if created.DeactivatedAt.Valid {
		t.Fatalf("a freshly created user must be active, got deactivated_at %v", created.DeactivatedAt)
	}
	if !created.CreatedAt.Valid || !created.UpdatedAt.Valid {
		t.Fatal("created_at/updated_at must be set on the create branch")
	}

	// 2. A later login by the same subject is a read, not a second row: the
	// stable id is returned and the profile fields + last_login_at refresh;
	// created_at keeps the original registration instant.
	later := now.Add(2 * time.Hour)
	var relogin gen.User
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		relogin, err = users.UpsertBySubject(ctx, tx, subject, "Alice B. Example", "", later)
		return err
	}); err != nil {
		t.Fatalf("second-login upsert: %v", err)
	}
	if relogin.ID != created.ID {
		t.Fatalf("second login id = %v, want the first-login id %v", relogin.ID, created.ID)
	}
	if relogin.DisplayName != "Alice B. Example" {
		t.Fatalf("second login display_name = %q, want the refreshed %q", relogin.DisplayName, "Alice B. Example")
	}
	if relogin.Email.Valid {
		t.Fatalf("second login email = %v, want NULL (the claim carried none)", relogin.Email)
	}
	if !relogin.LastLoginAt.Time.Equal(later) {
		t.Fatalf("second login last_login_at = %v, want %v", relogin.LastLoginAt, later)
	}
	if !relogin.CreatedAt.Time.Equal(created.CreatedAt.Time) {
		t.Fatalf("created_at moved on relogin: %v → %v", created.CreatedAt.Time, relogin.CreatedAt.Time)
	}
	if n := countUsersBySubject(t, ctx, q, subject); n != 1 {
		t.Fatalf("users rows for subject = %d, want exactly 1 (create-or-read)", n)
	}

	// 3. GetByID round-trips the same row.
	got, err := users.GetByID(ctx, uuidString(created.ID))
	if err != nil {
		t.Fatalf("get user by id: %v", err)
	}
	if got.ID != created.ID || got.SubjectID != subject {
		t.Fatalf("GetByID = %+v, want id %v subject %q", got, created.ID, subject)
	}
	if _, err := users.GetByID(ctx, "00000000-0000-4000-8000-0000000000ff"); err == nil {
		t.Fatal("GetByID on an unknown id succeeded, want not-found")
	}

	// 4. Grant two roles; the re-read returns them ordered by role. A
	// repeated grant is idempotent (still two rows).
	userID := uuidString(created.ID)
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if err := users.GrantRole(ctx, tx, userID, domain.RoleSecurityAnalyst, now, "claim"); err != nil {
			return err
		}
		return users.GrantRole(ctx, tx, userID, domain.RoleAuditor, now, "claim")
	}); err != nil {
		t.Fatalf("grant roles: %v", err)
	}
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return users.GrantRole(ctx, tx, userID, domain.RoleSecurityAnalyst, later, "claim")
	}); err != nil {
		t.Fatalf("re-grant role: %v", err)
	}
	roles, err := users.ListRolesByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("roles = %d (%v), want 2 after the idempotent re-grant", len(roles), roles)
	}
	if roles[0].Role != string(domain.RoleAuditor) || roles[1].Role != string(domain.RoleSecurityAnalyst) {
		t.Fatalf("roles = [%s %s], want [auditor security_analyst] (ordered by role)", roles[0].Role, roles[1].Role)
	}
	if !roles[0].GrantedBy.Valid || roles[0].GrantedBy.String != "claim" {
		t.Fatalf("granted_by = %v, want claim", roles[0].GrantedBy)
	}

	// 5. Revoke one role; the re-read returns one.
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return users.RevokeRole(ctx, tx, userID, domain.RoleAuditor)
	}); err != nil {
		t.Fatalf("revoke role: %v", err)
	}
	roles, err = users.ListRolesByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list roles after revoke: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != string(domain.RoleSecurityAnalyst) {
		t.Fatalf("roles after revoke = %v, want [security_analyst]", roles)
	}
	// Revoking a role not held is a no-op, not an error.
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return users.RevokeRole(ctx, tx, userID, domain.RoleAdministrator)
	}); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}

	// 6. Deactivate sets deactivated_at; a repeated deactivation is a
	// conflict (the guard did not match) and never deletes the row.
	deactivatedAt := now.Add(3 * time.Hour)
	var deactivated gen.User
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		deactivated, err = users.Deactivate(ctx, tx, userID, deactivatedAt)
		return err
	}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if !deactivated.DeactivatedAt.Valid || !deactivated.DeactivatedAt.Time.Equal(deactivatedAt) {
		t.Fatalf("deactivated_at = %v, want %v", deactivated.DeactivatedAt, deactivatedAt)
	}
	reread, err := users.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get after deactivate: %v", err)
	}
	if !reread.DeactivatedAt.Valid || !reread.DeactivatedAt.Time.Equal(deactivatedAt) {
		t.Fatalf("re-read deactivated_at = %v, want %v", reread.DeactivatedAt, deactivatedAt)
	}
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := users.Deactivate(ctx, tx, userID, deactivatedAt)
		return err
	}); err == nil {
		t.Fatal("second deactivate succeeded, want a conflict (guard did not match)")
	}
	if n := countUsersBySubject(t, ctx, q, subject); n != 1 {
		t.Fatalf("users rows after deactivate = %d, want 1 (deactivate, never delete)", n)
	}

	// 7. TouchLastLogin advances last_login_at on the resolved user.
	touchedAt := now.Add(4 * time.Hour)
	var touched gen.User
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		touched, err = users.TouchLastLogin(ctx, tx, userID, touchedAt)
		return err
	}); err != nil {
		t.Fatalf("touch last login: %v", err)
	}
	if !touched.LastLoginAt.Time.Equal(touchedAt) {
		t.Fatalf("touched last_login_at = %v, want %v", touched.LastLoginAt, touchedAt)
	}
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := users.TouchLastLogin(ctx, tx, "00000000-0000-4000-8000-0000000000ff", touchedAt)
		return err
	}); err == nil {
		t.Fatal("TouchLastLogin on an unknown id succeeded, want not-found")
	}

	// 8. ListUsers returns the seeded identities plus ours, ordered by
	// display_name (the migration seed backs the role-matrix/demo tests).
	all, err := users.List(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(all) < 7 {
		t.Fatalf("ListUsers = %d rows, want at least the 6 seeded + this user", len(all))
	}
	for i := 1; i < len(all); i++ {
		prev, cur := all[i-1], all[i]
		if prev.DisplayName > cur.DisplayName {
			t.Fatalf("ListUsers not ordered by display_name: %q before %q", prev.DisplayName, cur.DisplayName)
		}
	}
	seeded, err := users.ListRolesByUser(ctx, "e5a00000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("list seeded local-developer roles: %v", err)
	}
	if len(seeded) != 5 {
		t.Fatalf("local-developer roles = %d, want 5 (the multi-role seed)", len(seeded))
	}
}
