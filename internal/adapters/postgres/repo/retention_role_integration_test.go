package repo

// Integration test for the DEV-128 dedicated retention role (ARCH-007 §7
// control 3a amendment, migration 00015): the governed retention and
// pseudonymisation acts delete and redact rows the append-only application
// role may not touch, so they run on a separate least-privilege role
// (risksignal_retention) granted to its own login (risksignal_retention_login)
// — never the runtime login and never via SET ROLE.
//
// It follows the runtime-role integration-test pattern
// (runtime_role_integration_test.go): a real short-lived PostgreSQL database
// created per run, migrated with the on-disk set (the adapters layer may not
// import db/migrations; go-arch-lint), a login role granted only the group
// role, and a pool connected as that login. It skips when no database is
// reachable (Postgres on 127.0.0.1:5432, override with
// RISKSIGNAL_TEST_DATABASE_URL).
//
// Coverage:
//   - the exact migration-00015 grant matrix for a login granted only
//     risksignal_retention, the explicit non-grants (nothing on users/outbox/
//     epss_current/schema_migration_log; no TRUNCATE/REFERENCES/TRIGGER; no
//     CREATE on public; not superuser), and the NOLOGIN/LOGIN role shape with
//     the group granted to the dedicated login;
//   - the retention role running an approved retention run (ExecuteRetention)
//     and a standalone pseudonymisation (PseudonymizeIdentity) end to end on
//     its own connection — the deletes and the in-place redactions the app
//     role is denied;
//   - risksignal_app still getting SQLSTATE 42501 when it tries to rewrite the
//     append-only audit trail (UPDATE/DELETE/TRUNCATE).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// seededAdministratorID is the fixed id of the migration-seeded
// local::administrator user (00009), the retention.manage principal used as
// the pseudonymisation actor.
const seededAdministratorID = "e5a00000-0000-4000-8000-000000000004"

// retentionRolePrivs is one row of the expected grant matrix for
// risksignal_retention (migration 00015).
type retentionRolePrivs struct {
	table              string
	sel, ins, upd, del bool
}

// retentionRoleExpected is the documented matrix of migration 00015. Every
// other data privilege (TRUNCATE, REFERENCES, TRIGGER) must be absent for every
// table.
var retentionRoleExpected = []retentionRolePrivs{
	// The retention.* append, the §2.3 delete of a signal's trail and the §3
	// redaction in place.
	{"audit_events", true, true, true, true},
	// The signal timeline: the candidate/scan read, the §3 override redaction
	// and the §2.3 delete.
	{"risk_signals", true, false, true, true},
	// SELECT is required in addition to the UPDATE/DELETE the row predicates
	// read (PostgreSQL checks SELECT on the columns named in an UPDATE/DELETE
	// WHERE clause).
	{"comments", true, false, true, true},
	{"sla_clocks", true, false, false, true},
	{"matches", true, false, false, true},
	{"notifications", true, false, false, true},
	{"retention_runs", true, false, true, false},
	{"legal_holds", true, false, false, false},
}

// retentionRoleNever is the documented non-grant set: the tables the retention
// role must never touch at all. Every data privilege on them must be absent.
var retentionRoleNever = []string{"users", "outbox", "epss_current", "schema_migration_log"}

// openRoleLoginPool creates a login role on the admin pool's database, grants
// it exactly groupRole and returns a pool connected as that login. It skips
// when the test login cannot be created (the connecting user lacks CREATEROLE).
func openRoleLoginPool(t *testing.T, admin *pgxpool.Pool, groupRole string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	var dbName string
	if err := admin.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatalf("current_database: %v", err)
	}

	login := fmt.Sprintf("risksignal_%s_%d", groupRole, time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE ROLE "`+login+`" LOGIN PASSWORD 'rt'`); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42501" || pgErr.Code == "42502") {
			t.Skipf("cannot create the %s login (insufficient privilege): %v", groupRole, err)
		}
		t.Fatalf("create %s login: %v", groupRole, err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, `DROP ROLE IF EXISTS "`+login+`"`); err != nil {
			t.Errorf("drop login %s: %v", login, err)
		}
	})

	if _, err := admin.Exec(ctx, `GRANT `+groupRole+` TO "`+login+`"`); err != nil {
		t.Fatalf("grant %s to %s: %v", groupRole, login, err)
	}

	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = i4TestDBURL
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	u.User = url.UserPassword(login, "rt")
	u.Path = "/" + dbName

	pool, err := postgres.OpenPool(ctx, u.String())
	if err != nil {
		t.Fatalf("open pool as %s: %v", login, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestRetentionRoleLeastPrivilegeGrants asserts the exact migration-00015
// grant matrix for a login granted only risksignal_retention, the explicit
// non-grants, and the role shape (NOLOGIN group role granted to the dedicated
// LOGIN, never to risksignal_app).
func TestRetentionRoleLeastPrivilegeGrants(t *testing.T) {
	admin := newI4TestPool(t)
	ret := openRoleLoginPool(t, admin, "risksignal_retention")
	ctx := context.Background()

	for _, want := range retentionRoleExpected {
		var sel, ins, upd, del, trunc, refs, trig bool
		if err := ret.QueryRow(ctx, `
			SELECT has_table_privilege(current_user, $1, 'SELECT'),
			       has_table_privilege(current_user, $1, 'INSERT'),
			       has_table_privilege(current_user, $1, 'UPDATE'),
			       has_table_privilege(current_user, $1, 'DELETE'),
			       has_table_privilege(current_user, $1, 'TRUNCATE'),
			       has_table_privilege(current_user, $1, 'REFERENCES'),
			       has_table_privilege(current_user, $1, 'TRIGGER')`,
			want.table).Scan(&sel, &ins, &upd, &del, &trunc, &refs, &trig); err != nil {
			t.Fatalf("has_table_privilege(%s): %v", want.table, err)
		}
		got := retentionRolePrivs{want.table, sel, ins, upd, del}
		if got != want {
			t.Errorf("privileges on %s = %+v, want %+v", want.table, got, want)
		}
		if trunc || refs || trig {
			t.Errorf("%s: TRUNCATE=%t REFERENCES=%t TRIGGER=%t, want all false", want.table, trunc, refs, trig)
		}
	}

	// The explicit non-grants: no privilege at all on these tables.
	for _, table := range retentionRoleNever {
		var sel, ins, upd, del, trunc, refs, trig bool
		if err := ret.QueryRow(ctx, `
			SELECT has_table_privilege(current_user, $1, 'SELECT'),
			       has_table_privilege(current_user, $1, 'INSERT'),
			       has_table_privilege(current_user, $1, 'UPDATE'),
			       has_table_privilege(current_user, $1, 'DELETE'),
			       has_table_privilege(current_user, $1, 'TRUNCATE'),
			       has_table_privilege(current_user, $1, 'REFERENCES'),
			       has_table_privilege(current_user, $1, 'TRIGGER')`,
			table).Scan(&sel, &ins, &upd, &del, &trunc, &refs, &trig); err != nil {
			t.Fatalf("has_table_privilege(%s): %v", table, err)
		}
		if sel || ins || upd || del || trunc || refs || trig {
			t.Errorf("%s: privileges (sel=%t ins=%t upd=%t del=%t trunc=%t refs=%t trig=%t), want none",
				table, sel, ins, upd, del, trunc, refs, trig)
		}
	}

	// USAGE on public (to reach the tables) but no CREATE, and not a superuser.
	var usage, canCreate, isSuper bool
	if err := ret.QueryRow(ctx, `
		SELECT has_schema_privilege(current_user, 'public', 'USAGE'),
		       has_schema_privilege(current_user, 'public', 'CREATE'),
		       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).
		Scan(&usage, &canCreate, &isSuper); err != nil {
		t.Fatalf("schema/role attributes: %v", err)
	}
	if !usage {
		t.Error("public USAGE = false, want true (the retention role must reach the tables)")
	}
	if canCreate {
		t.Error("public CREATE = true, want false (the retention role must not own schema changes)")
	}
	if isSuper {
		t.Error("rolsuper = true, want false")
	}

	// The role shape: risksignal_retention is a NOLOGIN group role granted to
	// the dedicated risksignal_retention_login (LOGIN), and never to the
	// application runtime role.
	var retentionLogin, retentionSuper, loginLogin, loginSuper bool
	if err := ret.QueryRow(ctx, `
		SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'risksignal_retention'),
		       (SELECT rolsuper   FROM pg_roles WHERE rolname = 'risksignal_retention'),
		       (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'risksignal_retention_login'),
		       (SELECT rolsuper   FROM pg_roles WHERE rolname = 'risksignal_retention_login')`).
		Scan(&retentionLogin, &retentionSuper, &loginLogin, &loginSuper); err != nil {
		t.Fatalf("role shape: %v", err)
	}
	if retentionLogin {
		t.Error("risksignal_retention is LOGIN = true, want false (a NOLOGIN group role)")
	}
	if retentionSuper || loginSuper {
		t.Error("a retention role is a superuser, want neither")
	}
	if !loginLogin {
		t.Error("risksignal_retention_login is LOGIN = false, want true (the dedicated login)")
	}
	var loginIsMember, loginIsAppMember, appIsMember bool
	if err := ret.QueryRow(ctx, `
		SELECT pg_has_role('risksignal_retention_login', 'risksignal_retention', 'member'),
		       pg_has_role('risksignal_retention_login', 'risksignal_app', 'member'),
		       pg_has_role('risksignal_app', 'risksignal_retention', 'member')`).
		Scan(&loginIsMember, &loginIsAppMember, &appIsMember); err != nil {
		t.Fatalf("role membership: %v", err)
	}
	if !loginIsMember {
		t.Error("risksignal_retention_login is not a member of risksignal_retention, want it granted")
	}
	if loginIsAppMember || appIsMember {
		t.Error("the retention role and the app role are cross-granted, want them disjoint")
	}
}

// TestRetentionRoleRunsRetentionAndPseudonymisationEndToEnd drives the
// application retention use cases on the dedicated retention connection: an
// approved retention run deletes a due signal's chain and a standalone
// pseudonymisation redacts an identity in place — the writes risksignal_app is
// refused. It then proves the app role is still denied on the audit trail.
func TestRetentionRoleRunsRetentionAndPseudonymisationEndToEnd(t *testing.T) {
	admin := newI4TestPool(t)
	ret := openRoleLoginPool(t, admin, "risksignal_retention")
	app := openRoleLoginPool(t, admin, "risksignal_app")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sixYearsAgo := time.Now().UTC().AddDate(-6, 0, 0)

	// Signal A: due for retention (resolved, closed six years ago), with a
	// comment and an audit row authored by the seeded administrator.
	a := seedRetentionSignal(t, ctx, admin, "retA", "resolved", &sixYearsAgo, seededAdministratorID)
	// Signal B: not due (new), carrying the identity's rows the standalone
	// pseudonymisation must redact.
	b := seedRetentionSignal(t, ctx, admin, "retB", "new", nil, seededAdministratorID)

	// The app role records the four-eyes approval (dry-run/approve stay on the
	// app-role connection; the retention role holds no INSERT on retention_runs).
	var runID string
	if err := app.QueryRow(ctx, `
		INSERT INTO retention_runs (policy_id, stage, cutoff, partition_key, status, approved_by, approved_at, approval_reason)
		VALUES ('closed-signals-5y', 'delete', now(), 'it-partition', 'approved', $1, now(), 'integration test')
		RETURNING id`, seededAdministratorID).Scan(&runID); err != nil {
		t.Fatalf("seed approved retention run: %v", err)
	}

	// The retention-bound service: every port on the retention pool; the
	// identity read port stays on the app-role pool (the authoriser's
	// principal re-read; the retention role has no grant on users).
	retQ := gen.New(ret)
	svc := application.NewService(application.ServiceDeps{
		Signals:         NewSignalRepo(retQ),
		Audit:           NewAuditRepo(retQ),
		Outbox:          NewOutboxRepo(retQ),
		Vulnerabilities: NewVulnerabilityRepo(retQ),
		Matches:         NewMatchRepo(retQ),
		SourceRuns:      NewSourceRunRepo(retQ),
		RawRecords:      NewRawRecordRepo(retQ),
		Sources:         NewSourceRepo(retQ),
		Quarantine:      NewQuarantineRepo(retQ),
		Components:      NewComponentRepo(retQ),
		Inventory:       NewInventoryRepo(retQ),
		Users:           NewUserRepo(gen.New(app)),
		Retention:       NewRetentionRepo(retQ),
		Clock:           clock.RealClock{},
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, ret, fn)
		},
	})

	// --- ExecuteRetention under the retention role --------------------------
	res, err := svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{
		RunID: runID,
		Actor: application.Actor{Type: application.ActorTypeSystem, ID: "retention-it"},
	})
	if err != nil {
		t.Fatalf("ExecuteRetention: %v", err)
	}
	if res.Status != application.RetentionStatusCompleted || res.Deleted != 1 {
		lastErr := retentionText(t, ctx, admin, `SELECT COALESCE(last_error, '') FROM retention_runs WHERE id = $1`, runID)
		t.Fatalf("ExecuteRetention result = %+v (last_error %q), want completed with 1 deleted", res, lastErr)
	}
	if n := retentionCount(t, ctx, admin, `SELECT count(*) FROM risk_signals WHERE id = $1`, a); n != 0 {
		t.Fatalf("due signal rows = %d, want 0 (deleted)", n)
	}
	if n := retentionCount(t, ctx, admin, `SELECT count(*) FROM comments WHERE signal_id = $1`, a); n != 0 {
		t.Fatalf("due signal comments = %d, want 0 (deleted)", n)
	}
	if n := retentionCount(t, ctx, admin,
		`SELECT count(*) FROM audit_events WHERE aggregate_type = 'risk_signal' AND aggregate_id = $1`, a); n != 0 {
		t.Fatalf("due signal audit rows = %d, want 0 (deleted)", n)
	}
	if n := retentionCount(t, ctx, admin,
		`SELECT count(*) FROM audit_events WHERE action = 'retention.executed'`); n < 1 {
		t.Fatalf("retention.executed audit rows = %d, want >= 1", n)
	}

	// --- PseudonymizeIdentity under the retention role ----------------------
	actor, err := svc.ResolveActor(ctx, domain.Identity{SubjectID: "local::administrator"})
	if err != nil {
		t.Fatalf("ResolveActor: %v", err)
	}
	if actor.ID != seededAdministratorID {
		t.Fatalf("resolved actor = %+v, want the seeded administrator", actor)
	}
	ps, err := svc.PseudonymizeIdentity(ctx, application.PseudonymizeIdentityInput{
		UserID: seededAdministratorID,
		Reason: "integration test",
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("PseudonymizeIdentity: %v", err)
	}
	if ps.DryRun {
		t.Fatal("PseudonymizeIdentity ran as a dry run, want the real redaction")
	}
	if ps.Redaction.DisplayNamesCleared < 1 || ps.Redaction.CommentBodiesRedacted < 1 || ps.Redaction.OverrideReasonsRedacted < 1 {
		t.Fatalf("redaction = %+v, want at least one display name, comment body and override reason redacted", ps.Redaction)
	}
	// The retained signal B's comment body and override reason are redacted,
	// its audit display name cleared; the comment row itself survives.
	if body := retentionText(t, ctx, admin, `SELECT body FROM comments WHERE signal_id = $1`, b); body != application.RetentionRedactionMarker {
		t.Fatalf("comment body = %q, want the redaction marker", body)
	}
	if reason := retentionText(t, ctx, admin, `SELECT override_reason FROM risk_signals WHERE id = $1`, b); reason != application.RetentionRedactionMarker {
		t.Fatalf("override reason = %q, want the redaction marker", reason)
	}
	// Signal B's own audit row (the identity's event) has its display name
	// cleared; the pseudonymisation's own self-audit row legitimately carries
	// the act's actor display name, so it is excluded by the aggregate filter.
	if n := retentionCount(t, ctx, admin,
		`SELECT count(*) FROM audit_events WHERE aggregate_id = $1 AND actor_display_name IS NOT NULL`, b); n != 0 {
		t.Fatalf("identity audit rows still carrying the actor display name = %d, want 0", n)
	}

	// --- the app role is still denied on the append-only audit trail --------
	for _, stmt := range []string{
		`UPDATE audit_events SET action = 'tampered'`,
		`DELETE FROM audit_events`,
		`TRUNCATE audit_events`,
	} {
		_, err := app.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if err == nil {
			t.Errorf("risksignal_app allowed %q, want insufficient_privilege", stmt)
			continue
		}
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("risksignal_app %q error = %v, want SQLSTATE 42501", stmt, err)
		}
	}
}

// seedRetentionSignal seeds one asset/component/vulnerability/match/risk_signals
// chain (unique per ext) with the given status/closed_at and returns the signal
// id; it also seeds a comment and an audit row authored by actorID so the
// retention delete and the identity redaction have rows to act on, plus an
// override on the signal.
func seedRetentionSignal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext, status string, closedAt *time.Time, actorID string) string {
	t.Helper()
	cve := "CVE-2026-9" + ext
	var signalID string
	err := pool.QueryRow(ctx, `
		WITH a AS (
		    INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure)
		    VALUES ($1, 'retention-role-it', 'server', $1, 'prod', 'critical', 'internet')
		    RETURNING id
		), c AS (
		    INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme)
		    SELECT id, 'acme', $2, '1.0', 'acme', $2, 'cpe:acme:' || $2 || ':1.0', 'generic' FROM a
		    RETURNING id
		), v AS (
		    INSERT INTO vulnerabilities (cve_id, summary, published_at)
		    VALUES ($3, 'retention seed ' || $3, now())
		    RETURNING id
		), m AS (
		    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		    SELECT v.id, c.id, 'exact_version', 100, 'high', 'i1b-1', now() FROM v, c
		    RETURNING id
		), rs AS (
		    INSERT INTO risk_signals (match_id, priority, status, rule_version, factors, created_at, closed_at)
		    SELECT m.id, 'P2', $4, 'i1b-1', '{}'::jsonb, now(), $5 FROM m
		    RETURNING id
		)
		SELECT id FROM rs`, ext, "prod-"+ext, cve, status, closedAt).Scan(&signalID)
	if err != nil {
		t.Fatalf("seed signal %s: %v", ext, err)
	}

	// A comment and an audit row authored by the identity, plus an override.
	if _, err := pool.Exec(ctx, `
		INSERT INTO comments (signal_id, actor_id, body, created_at)
		VALUES ($1, $2, 'sensitive free text', now())`, signalID, actorID); err != nil {
		t.Fatalf("seed comment %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, correlation_id)
		VALUES ('risk_signal', $1::uuid, 'user', $2, 'Administrator', 'signal.created', now(), $3)`,
		signalID, actorID, "retention-"+ext); err != nil {
		t.Fatalf("seed audit %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE risk_signals
		SET auto_priority = 'P3', override_reason = 'documented override', override_actor_id = $2, override_at = now()
		WHERE id = $1`, signalID, actorID); err != nil {
		t.Fatalf("seed override %s: %v", ext, err)
	}
	return signalID
}

// retentionCount is a small scalar-count helper on the admin pool.
func retentionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// retentionText reads one non-null text column on the admin pool.
func retentionText(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(ctx, query, args...).Scan(&s); err != nil {
		t.Fatalf("read %q: %v", query, err)
	}
	return s
}
