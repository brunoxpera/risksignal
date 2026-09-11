package repo

// Integration test for the DEV-126 runtime-role grants (ARCH-007 §7 control
// 3a, WP-6.10): migration 00014 grants risksignal_app least-privilege access
// to the ~26 tables the earlier migrations created, so a login granted ONLY
// risksignal_app can boot the server and worker against a freshly migrated
// schema — while the append-only audit_events restriction of migration 00013
// stays intact (UPDATE/DELETE/TRUNCATE still denied with SQLSTATE 42501).
//
// It follows the audit-role integration-test pattern: a real short-lived
// PostgreSQL database created per run, migrated with the on-disk set (the
// adapters layer may not import db/migrations; go-arch-lint), a login role
// granted only the group role, and a pool connected as that login. The test
// skips when no database is reachable (Postgres on 127.0.0.1:5432, override
// with RISKSIGNAL_TEST_DATABASE_URL), so `go test ./...` stays green without
// the environment.

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
)

// runtimeRoleTablePrivs is one row of the expected grant matrix for
// risksignal_app (traced from db/queries/*.sql, migration 00014).
type runtimeRoleTablePrivs struct {
	table              string
	sel, ins, upd, del bool
	trunc              bool
}

// runtimeRoleExpected is the documented matrix of migration 00014. Every other
// data privilege (REFERENCES, TRIGGER) must be absent for every table.
var runtimeRoleExpected = []runtimeRoleTablePrivs{
	// SELECT, INSERT, UPDATE, DELETE — signal timeline + retention/redaction.
	{"comments", true, true, true, true, false},
	{"notifications", true, true, true, true, false},
	{"risk_signals", true, true, true, true, false},
	{"sla_clocks", true, true, true, true, false},
	// SELECT, INSERT, DELETE — matches (insert + §2.3 delete), user-role grants.
	{"matches", true, true, false, true, false},
	{"user_roles", true, true, false, true, false},
	// SELECT, INSERT, UPDATE — upserts, transparent transitions, relay lifecycle.
	{"alias_rules", true, true, true, false, false},
	{"assets", true, true, true, false, false},
	{"components", true, true, true, false, false},
	{"decision_rules", true, true, true, false, false},
	{"exports", true, true, true, false, false},
	{"inventory_imports", true, true, true, false, false},
	{"legal_holds", true, true, true, false, false},
	{"outbox", true, true, true, false, false},
	{"quarantine", true, true, true, false, false},
	{"retention_runs", true, true, true, false, false},
	{"source_runs", true, true, true, false, false},
	{"sources", true, true, true, false, false},
	{"users", true, true, true, false, false},
	{"vulnerabilities", true, true, true, false, false},
	// SELECT, INSERT, TRUNCATE — the atomic EPSS TRUNCATE + COPY swap.
	{"epss_current", true, true, false, false, true},
	// SELECT, INSERT — append-only reads/writes.
	{"evidences", true, true, false, false, false},
	{"raw_records", true, true, false, false, false},
	{"priority_rules", true, true, false, false, false},
	{"epss_history", true, true, false, false, false},
	// Append-only audit trail, unchanged from migration 00013.
	{"audit_events", true, true, false, false, false},
	// Migration bookkeeping — the runtime never touches it.
	{"schema_migration_log", false, false, false, false, false},
}

// newRuntimeRolePool creates a fresh migrated database and a login role
// granted ONLY risksignal_app, and returns a pool connected as that login. It
// skips when no database is reachable or the test login cannot be created
// (the connecting user lacks CREATEROLE).
func newRuntimeRolePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin := newI4TestPool(t) // fresh database, migrated (creates the group roles)

	var dbName string
	if err := admin.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatalf("current_database: %v", err)
	}

	login := fmt.Sprintf("risksignal_rt_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE ROLE "`+login+`" LOGIN PASSWORD 'rt'`); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42501" || pgErr.Code == "42502") {
			t.Skipf("cannot create the runtime login (insufficient privilege): %v", err)
		}
		t.Fatalf("create runtime login: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, `DROP ROLE IF EXISTS "`+login+`"`); err != nil {
			t.Errorf("drop runtime login %s: %v", login, err)
		}
	})

	if _, err := admin.Exec(ctx, `GRANT risksignal_app TO "`+login+`"`); err != nil {
		t.Fatalf("grant risksignal_app to %s: %v", login, err)
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

	rt, err := postgres.OpenPool(ctx, u.String())
	if err != nil {
		t.Fatalf("open runtime pool as %s: %v", login, err)
	}
	t.Cleanup(rt.Close)
	return rt
}

// TestRuntimeRoleLeastPrivilegeGrants asserts the exact migration-00014 grant
// matrix for a login granted only risksignal_app: the required data privileges
// are present, the forbidden ones (REFERENCES/TRIGGER, and every extra
// privilege) are absent, the role is not a superuser and cannot create in the
// public schema.
func TestRuntimeRoleLeastPrivilegeGrants(t *testing.T) {
	rt := newRuntimeRolePool(t)
	ctx := context.Background()

	for _, want := range runtimeRoleExpected {
		var sel, ins, upd, del, trunc, refs, trig bool
		if err := rt.QueryRow(ctx, `
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
		got := runtimeRoleTablePrivs{want.table, sel, ins, upd, del, trunc}
		if got != want {
			t.Errorf("privileges on %s = %+v, want %+v", want.table, got, want)
		}
		if refs || trig {
			t.Errorf("%s: REFERENCES=%t TRIGGER=%t, want both false (least privilege)", want.table, refs, trig)
		}
	}

	// The role has USAGE on public (needed to reach the tables) but no CREATE:
	// it must never own schema changes. The group role inherits USAGE from
	// PUBLIC's default grant; migration 00014 grants no schema privilege.
	var usage, canCreate, isSuper bool
	if err := rt.QueryRow(ctx, `
		SELECT has_schema_privilege(current_user, 'public', 'USAGE'),
		       has_schema_privilege(current_user, 'public', 'CREATE'),
		       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).
		Scan(&usage, &canCreate, &isSuper); err != nil {
		t.Fatalf("schema/role attributes: %v", err)
	}
	if !usage {
		t.Error("public USAGE = false, want true (the runtime must reach the tables)")
	}
	if canCreate {
		t.Error("public CREATE = true, want false (the runtime must not own schema changes)")
	}
	if isSuper {
		t.Error("rolsuper = true, want false")
	}
}

// TestRuntimeRoleBootsDomainAndAuditStaysAppendOnly proves a login granted ONLY
// risksignal_app can run the server and worker read/write paths against a
// freshly migrated schema — touching every table of the matrix with the
// operations those processes issue — and that the append-only audit_events
// restriction is unchanged: SELECT + INSERT pass, UPDATE/DELETE/TRUNCATE fail
// with SQLSTATE 42501.
func TestRuntimeRoleBootsDomainAndAuditStaysAppendOnly(t *testing.T) {
	rt := newRuntimeRolePool(t)
	ctx := context.Background()

	exec := func(what, sql string, args ...any) {
		t.Helper()
		if _, err := rt.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	retID := func(what, sql string, args ...any) string {
		t.Helper()
		var id string
		if err := rt.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return id
	}
	count := func(what, sql string, args ...any) int {
		t.Helper()
		var n int
		if err := rt.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return n
	}

	// --- server readiness (HealthCheck) -------------------------------------
	if got := count("server health SELECT 1", `SELECT 1`); got != 1 {
		t.Fatalf("health check = %d, want 1", got)
	}

	// --- sources / source_runs / raw_records --------------------------------
	sourceID := retID("sources upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO sources (type, name) VALUES ('runtime-role-it', 'runtime-role-it')
		 ON CONFLICT (type, name) DO UPDATE SET enabled = EXCLUDED.enabled
		 RETURNING id`)
	runID := retID("source_runs insert",
		`INSERT INTO source_runs (source_id, started_at, status) VALUES ($1, now(), 'running') RETURNING id`, sourceID)
	exec("source_runs update (complete)",
		`UPDATE source_runs SET status = 'succeeded', finished_at = now() WHERE id = $1`, runID)
	if got := count("source_runs read", `SELECT count(*) FROM source_runs WHERE source_id = $1`, sourceID); got != 1 {
		t.Fatalf("source_runs read = %d, want 1", got)
	}
	rawID := retID("raw_records insert",
		`INSERT INTO raw_records (source_id, external_id, content_hash, payload, fetched_at)
		 VALUES ($1, 'rt-doc', 'rt-hash', decode('00','hex'), now())
		 ON CONFLICT (source_id, external_id, content_hash) DO NOTHING RETURNING id`, sourceID)

	// --- vulnerabilities / evidences ----------------------------------------
	vulnID := retID("vulnerabilities upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO vulnerabilities (cve_id, summary, published_at)
		 VALUES ('CVE-RUNTIME-ROLE-IT', 'runtime role it', now())
		 ON CONFLICT (cve_id) DO UPDATE SET summary = EXCLUDED.summary RETURNING id`)
	exec("evidences insert",
		`INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
		 VALUES ($1, $2, 'cvss', '{"score":9.9}'::jsonb, 'rt-vh', now())
		 ON CONFLICT (raw_record_id, type, value_hash) DO NOTHING`, vulnID, rawID)
	if got := count("evidences read", `SELECT count(*) FROM evidences WHERE vulnerability_id = $1`, vulnID); got != 1 {
		t.Fatalf("evidences read = %d, want 1", got)
	}

	// --- assets / components -------------------------------------------------
	assetID := retID("assets upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, updated_at)
		 VALUES ('rt-a1', 'runtime-role-it', 'server', 'rt-a1', 'prod', 'critical', 'internet', now())
		 ON CONFLICT (source, external_id) DO UPDATE SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at
		 RETURNING id`)
	exec("assets update (verify)",
		`UPDATE assets SET verified_at = now(), updated_at = now() WHERE id = $1`, assetID)
	compID := retID("components upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme, updated_at)
		 VALUES ($1, 'acme', 'widget', '1.0', 'acme', 'widget', 'rt-nk', 'unknown', now())
		 ON CONFLICT (asset_id, natural_key) DO UPDATE SET version = EXCLUDED.version, updated_at = EXCLUDED.updated_at
		 RETURNING id`, assetID)

	// --- matches / risk_signals ---------------------------------------------
	matchID := retID("matches insert",
		`INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		 VALUES ($1, $2, 'exact_version', 100, 'high', 'rt-1', now())
		 ON CONFLICT (vulnerability_id, component_id, rule_version) DO NOTHING RETURNING id`, vulnID, compID)
	sigID := retID("risk_signals insert",
		`INSERT INTO risk_signals (match_id, priority, rule_version, factors, created_at)
		 VALUES ($1, 'P1', 'rt-1', '{"method":"exact_version"}'::jsonb, now()) RETURNING id`, matchID)
	exec("risk_signals update (close)",
		`UPDATE risk_signals SET status = 'resolved', closed_at = now(), version = version + 1 WHERE id = $1`, sigID)
	if got := count("risk_signals read", `SELECT count(*) FROM risk_signals WHERE id = $1`, sigID); got != 1 {
		t.Fatalf("risk_signals read = %d, want 1", got)
	}

	// --- comments / sla_clocks / notifications (write, redact, delete) ------
	commentID := retID("comments insert",
		`INSERT INTO comments (signal_id, actor_id, body, created_at) VALUES ($1, 'analyst', 'body', now()) RETURNING id`, sigID)
	exec("comments update (redact)", `UPDATE comments SET body = '[redacted]' WHERE id = $1`, commentID)
	exec("comments delete", `DELETE FROM comments WHERE id = $1`, commentID)

	slaID := retID("sla_clocks upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		 VALUES ($1, 'assessment', now(), now() + interval '1 day')
		 ON CONFLICT (signal_id, target) DO UPDATE SET deadline_at = EXCLUDED.deadline_at RETURNING id`, sigID)
	exec("sla_clocks update (fulfil)", `UPDATE sla_clocks SET fulfilled_at = now() WHERE id = $1`, slaID)
	exec("sla_clocks delete", `DELETE FROM sla_clocks WHERE id = $1`, slaID)

	notifID := retID("notifications insert",
		`INSERT INTO notifications (signal_id, channel, kind, status, outbox_event_id, created_at)
		 VALUES ($1, 'in_app', 'signal.created', 'pending', 'rt-evt', now())
		 ON CONFLICT (outbox_event_id, channel) DO NOTHING RETURNING id`, sigID)
	exec("notifications update (deliver)",
		`UPDATE notifications SET status = 'delivered', delivered_at = now() WHERE id = $1`, notifID)
	exec("notifications delete", `DELETE FROM notifications WHERE id = $1`, notifID)

	// --- outbox (append, claim, ack) ----------------------------------------
	outboxID := retID("outbox insert",
		`INSERT INTO outbox (type, payload, status, available_at, dedupe_key, created_at)
		 VALUES ('rt.job', '{}'::jsonb, 'pending', now(), 'rt-dedupe', now()) RETURNING id`)
	exec("outbox update (claim/ack)",
		`UPDATE outbox SET status = 'done', lease_until = now() + interval '1 minute' WHERE id = $1`, outboxID)
	if got := count("outbox read", `SELECT count(*) FROM outbox WHERE id = $1`, outboxID); got != 1 {
		t.Fatalf("outbox read = %d, want 1", got)
	}

	// --- quarantine ----------------------------------------------------------
	quarID := retID("quarantine insert",
		`INSERT INTO quarantine (source_id, position, reason, payload_hash, status, created_at, updated_at)
		 VALUES ($1, 'p0', 'parse.invalid', 'rt-qh', 'new', now(), now()) RETURNING id`, sourceID)
	exec("quarantine update (resolve)",
		`UPDATE quarantine SET status = 'resolved', resolved_at = now(), updated_at = now() WHERE id = $1`, quarID)

	// --- EPSS current (TRUNCATE + load) + history ---------------------------
	exec("epss_current truncate", `TRUNCATE epss_current`)
	exec("epss_current load",
		`INSERT INTO epss_current (cve_id, score, percentile, model_version, loaded_at)
		 VALUES ('CVE-RUNTIME-ROLE-IT', 0.5, 0.9, 'v1', now())`)
	if got := count("epss_current read", `SELECT count(*) FROM epss_current`); got != 1 {
		t.Fatalf("epss_current read = %d, want 1", got)
	}
	exec("epss_history append",
		`INSERT INTO epss_history (cve_id, observed_on, score, percentile, model_version)
		 VALUES ('CVE-RUNTIME-ROLE-IT', current_date, 0.5, 0.9, 'v1')
		 ON CONFLICT (cve_id, observed_on) DO NOTHING`)
	if got := count("epss_history read", `SELECT count(*) FROM epss_history`); got != 1 {
		t.Fatalf("epss_history read = %d, want 1", got)
	}

	// --- rule tables ---------------------------------------------------------
	aliasID := retID("alias_rules insert",
		`INSERT INTO alias_rules (scope, from_value, to_value, version, enabled, reason, created_at, updated_at)
		 VALUES ('vendor', 'a', 'b', 1, true, 'rt', now(), now()) RETURNING id`)
	exec("alias_rules update (disable)", `UPDATE alias_rules SET enabled = false, updated_at = now() WHERE id = $1`, aliasID)

	decisionID := retID("decision_rules insert",
		`INSERT INTO decision_rules (type, target_scope, action, reason, actor_id, version, created_at, updated_at)
		 VALUES ('exclude', '{}'::jsonb, NULL, 'rt', 'rt', 1, now(), now()) RETURNING id`)
	exec("decision_rules update (revoke)", `UPDATE decision_rules SET revoked_at = now(), updated_at = now() WHERE id = $1`, decisionID)

	// 00007 seeds the P1..P4 ruleset at version 1, so the runtime's own write
	// is a fresh copy-on-write snapshot at the next version.
	exec("priority_rules insert (new snapshot)",
		`INSERT INTO priority_rules (rule_id, version, definition, enabled, effective_from, reason, actor_id, created_at)
		 VALUES ('runtime-role-it', 1, '{}'::jsonb, true, now(), 'rt', 'rt', now())`)
	if got := count("priority_rules read", `SELECT count(*) FROM priority_rules WHERE rule_id = 'runtime-role-it'`); got != 1 {
		t.Fatalf("priority_rules read = %d, want 1", got)
	}

	// --- identity ------------------------------------------------------------
	userID := retID("users upsert (INSERT+UPDATE+RETURNING)",
		`INSERT INTO users (subject_id, display_name, email, created_at, updated_at)
		 VALUES ('rt-subject', 'RT', 'rt@example.test', now(), now())
		 ON CONFLICT (subject_id) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = EXCLUDED.updated_at
		 RETURNING id`)
	exec("users update (touch login)", `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, userID)
	exec("user_roles insert",
		`INSERT INTO user_roles (user_id, role, granted_at) VALUES ($1, 'administrator', now())
		 ON CONFLICT (user_id, role) DO NOTHING`, userID)
	if got := count("user_roles read", `SELECT count(*) FROM user_roles WHERE user_id = $1`, userID); got != 1 {
		t.Fatalf("user_roles read = %d, want 1", got)
	}
	exec("user_roles delete (revoke)", `DELETE FROM user_roles WHERE user_id = $1 AND role = 'administrator'`, userID)

	// --- inventory imports ---------------------------------------------------
	importID := retID("inventory_imports insert",
		`INSERT INTO inventory_imports (status, file, actor_id, created_at)
		 VALUES ('pending', decode('00','hex'), 'rt', now()) RETURNING id`)
	exec("inventory_imports update (commit)",
		`UPDATE inventory_imports SET status = 'committed', committed_at = now() WHERE id = $1`, importID)

	// --- governed operations -------------------------------------------------
	holdID := retID("legal_holds insert",
		`INSERT INTO legal_holds (aggregate_type, aggregate_id, reason, actor_id, created_at)
		 VALUES ('risk_signal', $1::uuid, 'rt', 'rt', now()) RETURNING id`, sigID)
	exec("legal_holds update (release)", `UPDATE legal_holds SET released_at = now() WHERE id = $1`, holdID)

	retentionID := retID("retention_runs insert",
		`INSERT INTO retention_runs (policy_id, stage, cutoff, partition_key, status)
		 VALUES ('rt-policy', 'delete', now(), 'rt-part', 'dry_run') RETURNING id`)
	exec("retention_runs update (approve)",
		`UPDATE retention_runs SET status = 'approved', approved_by = 'rt', approved_at = now(), approval_reason = 'rt' WHERE id = $1`, retentionID)

	exportID := retID("exports insert",
		`INSERT INTO exports (status, filter, format, created_by, created_at)
		 VALUES ('pending', '{}'::jsonb, 'csv', 'rt', now()) RETURNING id`)
	exec("exports update (complete)",
		`UPDATE exports SET status = 'completed', row_count = 0 WHERE id = $1`, exportID)

	// --- the §2.3 retention delete of a signal's non-shared dependents ------
	exec("risk_signals delete", `DELETE FROM risk_signals WHERE id = $1`, sigID)
	exec("matches delete", `DELETE FROM matches WHERE id = $1`, matchID)

	// --- audit_events: append + read allowed, rewrite denied (42501) ---------
	exec("audit_events append",
		`INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, action, occurred_at, correlation_id)
		 VALUES ('risk_signal', $1::uuid, 'system', 'rt', 'rt.created', now(), 'rt-corr')`, sigID)
	if got := count("audit_events read", `SELECT count(*) FROM audit_events`); got != 1 {
		t.Fatalf("audit_events read = %d, want 1", got)
	}
	for _, stmt := range []string{
		`UPDATE audit_events SET action = 'tampered'`,
		`DELETE FROM audit_events`,
		`TRUNCATE audit_events`,
	} {
		_, err := rt.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if err == nil {
			t.Errorf("runtime role allowed %q, want insufficient_privilege", stmt)
			continue
		}
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("runtime role %q error = %v, want SQLSTATE 42501", stmt, err)
		}
	}
}
