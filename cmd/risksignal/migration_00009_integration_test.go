package main

// Integration test of the WP-5a.02 migration 00009 at the composition root
// (DEV-088, ARCH-005 §1): the I5a identity schema (users + user_roles) and
// its seed must land on top of the I1b–I4 schema without touching a single
// existing row. cmd/risksignal is the composition root that may wire the
// embedded migration set (db/migrations) together with the runner, so the
// real files are exercised here.
//
// The test migrates a scratch database up to 00008 (the I4 schema, applied
// from the real embedded files), seeds one prior row that must survive (an
// audit_events row — the table whose actor_id becomes users.id from I5a,
// ARCH-005 §6, plus the four 00007 priority_rules rows), applies the
// remaining embedded migration (00009) and asserts the identity surface of
// ARCH-005 §1:
//
//   - users / user_roles exist with the exact column shapes (NOT NULL vs.
//     nullable, per §1) and the named constraints: UQ subject_id, the
//     five-role CHECK, the ON DELETE CASCADE foreign key, PK (user_id, role)
//     and the reverse IX (role);
//   - the checksum log records version 9 with the embedded file hash, and a
//     rerun is a no-op;
//   - the seed carries the six identities with the correct roles: the
//     multi-role local-developer (all five) and one single-role user per
//     role, every grant granted_by = 'seed', every subject_id "local::<slug>";
//   - the constraints bite: an unknown role, a duplicate subject_id, a
//     duplicate (user_id, role) and an unknown user_id are all rejected, and
//     deleting a user cascades to its role rows;
//   - the prior rows are untouched (the migration is purely additive).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
)

func TestMigration00009AddsI5aIdentitySchemaAndSeed(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: apply the real I1b–I4 schema (00001..00008).
	runner, err := migrate.Open(ctx, dbURL, migrationFSUpTo(t, 8))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 8 {
		t.Fatalf("apply I1b–I4 migrations: res=%+v err=%v", res, err)
	}
	_ = runner.Close()

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Step 2: seed prior rows that must survive the additive migration: one
	// audit_events row (the table I5a changes the *semantics* of, not the
	// schema) and the four 00007 priority_rules rows (asserted by count).
	var priorAudit string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id,
		                          actor_display_name, action, occurred_at, correlation_id)
		VALUES ('risk_signal', '11111111-1111-4111-8111-111111111111', 'system', 'pre-i5a-seed',
		        NULL, 'signal.created', now(), 'corr-pre-i5a')
		RETURNING id::text`).Scan(&priorAudit); err != nil {
		t.Fatalf("seed prior audit_events row: %v", err)
	}
	var rulesBefore int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM priority_rules`).Scan(&rulesBefore); err != nil {
		t.Fatalf("count priority_rules before 00009: %v", err)
	}
	if rulesBefore != 4 {
		t.Fatalf("priority_rules rows before 00009 = %d, want the 4 seeded 00007 snapshots", rulesBefore)
	}

	// Step 3: apply migration 00009 (pinned to version 9) and prove the
	// checksum log records it; a rerun is a no-op.
	runner, err = migrate.Open(ctx, dbURL, migrationFSUpTo(t, 9))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("apply 00009: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 9 {
		t.Fatalf("applied = %+v, want exactly version 9", res.Applied)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 0 {
		t.Fatalf("rerun after 00009 = %+v, %v; want a no-op", res, err)
	}

	// The checksum log records 00009 with the hash of the embedded file.
	var fileHash string
	if err := db.QueryRowContext(ctx,
		`SELECT file_hash FROM schema_migration_log WHERE version = 9`).Scan(&fileHash); err != nil {
		t.Fatalf("read checksum log for version 9: %v", err)
	}
	embedded, err := fs.ReadFile(migrations.FS, "00009_i5a_users_roles.sql")
	if err != nil {
		t.Fatalf("read embedded 00009: %v", err)
	}
	sum := sha256.Sum256(embedded)
	if want := hex.EncodeToString(sum[:]); fileHash != want {
		t.Fatalf("checksum log file_hash = %q, want sha256 of the embedded 00009 (%q)", fileHash, want)
	}

	// Step 4: the tables exist with the exact §1 column shapes.
	for _, col := range []string{"subject_id", "display_name", "created_at", "updated_at"} {
		if columnNullable(t, ctx, db, "users", col) {
			t.Fatalf("users.%s must be NOT NULL", col)
		}
	}
	for _, col := range []string{"email", "deactivated_at", "last_login_at"} {
		if !columnNullable(t, ctx, db, "users", col) {
			t.Fatalf("users.%s must be nullable", col)
		}
	}
	for _, col := range []string{"user_id", "role", "granted_at"} {
		if columnNullable(t, ctx, db, "user_roles", col) {
			t.Fatalf("user_roles.%s must be NOT NULL", col)
		}
	}
	if !columnNullable(t, ctx, db, "user_roles", "granted_by") {
		t.Fatal("user_roles.granted_by must be nullable")
	}

	// Step 5: the named constraints exist and enforce the §1 invariants.
	if def := constraintDef(t, ctx, db, "users", "users_subject_id_key"); !strings.Contains(def, "UNIQUE") {
		t.Fatalf("users_subject_id_key = %q, want a UNIQUE constraint on subject_id", def)
	}
	roleCheck := constraintDef(t, ctx, db, "user_roles", "user_roles_role_check")
	for _, role := range []string{"security_analyst", "system_responsible", "administrator", "auditor", "product_owner"} {
		if !strings.Contains(roleCheck, role) {
			t.Fatalf("user_roles_role_check = %q, missing role %q", roleCheck, role)
		}
	}
	fkDef := constraintDef(t, ctx, db, "user_roles", "user_roles_user_id_fkey")
	if !strings.Contains(fkDef, "FOREIGN KEY") || !strings.Contains(fkDef, "users(id)") || !strings.Contains(fkDef, "ON DELETE CASCADE") {
		t.Fatalf("user_roles_user_id_fkey = %q, want a FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE", fkDef)
	}
	if def := constraintDef(t, ctx, db, "user_roles", "user_roles_pkey"); !strings.Contains(def, "PRIMARY KEY") ||
		!strings.Contains(def, "user_id") || !strings.Contains(def, "role") {
		t.Fatalf("user_roles_pkey = %q, want PRIMARY KEY (user_id, role)", def)
	}
	var indexDef string
	if err := db.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = 'user_roles' AND indexname = 'user_roles_role_idx'`).Scan(&indexDef); err != nil {
		t.Fatalf("user_roles_role_idx missing: %v", err)
	}
	if !strings.Contains(indexDef, "(role)") {
		t.Fatalf("user_roles_role_idx = %q, want an index on (role)", indexDef)
	}

	// Step 6: the seed — six identities, correct id/display_name/subject_id,
	// and the exact role sets (local-developer = all five, others = one).
	seedUsers := []struct {
		id          string
		subjectID   string
		displayName string
		roles       []string
	}{
		{"e5a00000-0000-4000-8000-000000000001", "local::local-developer", "Local Developer",
			[]string{"administrator", "auditor", "product_owner", "security_analyst", "system_responsible"}},
		{"e5a00000-0000-4000-8000-000000000002", "local::security-analyst", "Security Analyst", []string{"security_analyst"}},
		{"e5a00000-0000-4000-8000-000000000003", "local::system-responsible", "System Responsible", []string{"system_responsible"}},
		{"e5a00000-0000-4000-8000-000000000004", "local::administrator", "Administrator", []string{"administrator"}},
		{"e5a00000-0000-4000-8000-000000000005", "local::auditor", "Auditor", []string{"auditor"}},
		{"e5a00000-0000-4000-8000-000000000006", "local::product-owner", "Product Owner", []string{"product_owner"}},
	}
	var userCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != len(seedUsers) {
		t.Fatalf("users = %d, want %d seeded identities", userCount, len(seedUsers))
	}
	for _, want := range seedUsers {
		var id, sub, name string
		if err := db.QueryRowContext(ctx,
			`SELECT id::text, subject_id, display_name FROM users WHERE subject_id = $1`, want.subjectID).
			Scan(&id, &sub, &name); err != nil {
			t.Fatalf("read user %s: %v", want.subjectID, err)
		}
		if id != want.id || name != want.displayName {
			t.Fatalf("user %s = id %s name %q, want id %s name %q", want.subjectID, id, name, want.id, want.displayName)
		}
		roles, err := rolesOf(ctx, db, id)
		if err != nil {
			t.Fatalf("roles of %s: %v", want.subjectID, err)
		}
		if !reflect.DeepEqual(roles, want.roles) {
			t.Fatalf("roles of %s = %v, want %v", want.subjectID, roles, want.roles)
		}
		for _, r := range roles {
			var grantedBy string
			if err := db.QueryRowContext(ctx,
				`SELECT granted_by FROM user_roles WHERE user_id = $1::uuid AND role = $2`, id, r).Scan(&grantedBy); err != nil {
				t.Fatalf("read granted_by for %s/%s: %v", want.subjectID, r, err)
			}
			if grantedBy != "seed" {
				t.Fatalf("granted_by for %s/%s = %q, want 'seed'", want.subjectID, r, grantedBy)
			}
		}
	}

	// Step 7: the constraints bite.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role, granted_at, granted_by)
		VALUES ('e5a00000-0000-4000-8000-000000000002', 'root', now(), 'test')`); err == nil {
		t.Fatal("an unknown role must be rejected by user_roles_role_check")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (subject_id, display_name, created_at, updated_at)
		VALUES ('local::local-developer', 'Dupe', now(), now())`); err == nil {
		t.Fatal("a duplicate subject_id must be rejected by users_subject_id_key")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role, granted_at, granted_by)
		VALUES ('e5a00000-0000-4000-8000-000000000002', 'security_analyst', now(), 'test')`); err == nil {
		t.Fatal("a duplicate (user_id, role) must be rejected by the primary key")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role, granted_at, granted_by)
		VALUES ('99999999-9999-4999-8999-999999999999', 'auditor', now(), 'test')`); err == nil {
		t.Fatal("an unknown user_id must be rejected by user_roles_user_id_fkey")
	}

	// ON DELETE CASCADE: a hard delete (test-only; production deactivates)
	// removes the role rows with the user.
	var tmpUser string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO users (subject_id, display_name, created_at, updated_at)
		VALUES ('local::throwaway', 'Throwaway', now(), now())
		RETURNING id::text`).Scan(&tmpUser); err != nil {
		t.Fatalf("insert throwaway user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role, granted_at, granted_by)
		VALUES ($1::uuid, 'auditor', now(), 'test')`, tmpUser); err != nil {
		t.Fatalf("grant throwaway role: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1::uuid`, tmpUser); err != nil {
		t.Fatalf("delete throwaway user: %v", err)
	}
	var leftover int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE user_id = $1::uuid`, tmpUser).Scan(&leftover); err != nil {
		t.Fatalf("count throwaway roles: %v", err)
	}
	if leftover != 0 {
		t.Fatalf("role rows after user delete = %d, want 0 (ON DELETE CASCADE)", leftover)
	}

	// Step 8: the migration is purely additive — the prior rows survive
	// untouched and no user actor rewrote the pre-I5a audit row.
	var action, actorID string
	if err := db.QueryRowContext(ctx,
		`SELECT action, actor_id FROM audit_events WHERE id = $1::uuid`, priorAudit).Scan(&action, &actorID); err != nil {
		t.Fatalf("read prior audit row: %v", err)
	}
	if action != "signal.created" || actorID != "pre-i5a-seed" {
		t.Fatalf("prior audit row = action %q actor_id %q, want unchanged", action, actorID)
	}
	var rulesAfter int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM priority_rules`).Scan(&rulesAfter); err != nil {
		t.Fatalf("count priority_rules after 00009: %v", err)
	}
	if rulesAfter != rulesBefore {
		t.Fatalf("priority_rules rows after 00009 = %d, want %d (unchanged)", rulesAfter, rulesBefore)
	}
}

// rolesOf returns the role keys of a user in ascending order.
func rolesOf(ctx context.Context, db *sql.DB, userID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT role FROM user_roles WHERE user_id = $1::uuid ORDER BY role`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}
