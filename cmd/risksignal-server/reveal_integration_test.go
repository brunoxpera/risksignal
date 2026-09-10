package main

// Integration test of the governed identity-reveal endpoint (ARCH-005 §7,
// WP-5a.07 / DEV-094, ADR-014) against the real server stack: the generated
// client drives POST /api/v1/audit-events/{id}/reveal-actor through the real
// composition root (newHandler) behind the I5a authentication middleware
// (local bypass), over a migrated database with seeded audit events.
//
// It skips when no PostgreSQL is reachable, like the other composition-root
// integration tests.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
)

// revealAuditorUser is the fixed id of the migration-seeded local::auditor
// user (00009).
const revealAuditorUser = "e5a00000-0000-4000-8000-000000000005"

const seedEventID = "00000000-0000-4000-8000-0000000000f1"

func TestRevealActorEndpointAgainstRealDatabase(t *testing.T) {
	t.Parallel()
	dbURL := newServerTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_events
		   (id, aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, correlation_id)
		 VALUES ($1, 'risk_signal', 'e5a00000-0000-4000-8000-00000000bbbb', 'user', $2, 'Auditor', 'signal.created', now(), 'seed')`,
		seedEventID, revealAuditorUser); err != nil {
		t.Fatalf("seed user audit event: %v", err)
	}

	// Bypass principal local-developer (all roles) — the seeded multi-role
	// user; the reveal is allowed.
	handler, err := newHandler(testConfig(dbURL), pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := gen.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("gen.NewClientWithResponses: %v", err)
	}

	body := gen.RevealActorRequest{Reason: "subject access request"}
	resp, err := client.RevealAuditEventActorWithResponse(ctx, seedEventID, body, withRequestID(t, "reveal-e2e-1"))
	if err != nil {
		t.Fatalf("RevealAuditEventActorWithResponse: %v", err)
	}
	if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
		t.Fatalf("status = %d, JSON200 = %v; body: %s", resp.StatusCode(), resp.JSON200, resp.Body)
	}
	got := resp.JSON200
	if !got.IsUser || got.UserId == nil || *got.UserId != revealAuditorUser ||
		got.SubjectId == nil || *got.SubjectId != "local::auditor" || got.Label != "Auditor" {
		t.Fatalf("body = %+v, want the resolved auditor identity", got)
	}
	if n := revealAuditCount(t, ctx, pool); n != 1 {
		t.Fatalf("self-audit rows = %d, want exactly 1", n)
	}

	// A blank reason is the declared 400 and writes nothing.
	blank, err := client.RevealAuditEventActorWithResponse(ctx, seedEventID, gen.RevealActorRequest{Reason: "   "}, withRequestID(t, "reveal-e2e-blank"))
	if err != nil {
		t.Fatalf("blank reveal: %v", err)
	}
	if blank.StatusCode() != http.StatusBadRequest {
		t.Fatalf("blank reason status = %d, want 400 (body: %s)", blank.StatusCode(), blank.Body)
	}
	if n := revealAuditCount(t, ctx, pool); n != 1 {
		t.Fatalf("blank-reason reveal wrote a self-audit (rows = %d, want 1)", n)
	}

	// An unknown event is the declared 404.
	notFound, err := client.RevealAuditEventActorWithResponse(ctx, "00000000-0000-4000-8000-0000000000ff", body, withRequestID(t, "reveal-e2e-404"))
	if err != nil {
		t.Fatalf("unknown-event reveal: %v", err)
	}
	if notFound.StatusCode() != http.StatusNotFound || notFound.JSON404 == nil {
		t.Fatalf("unknown event status = %d, want 404", notFound.StatusCode())
	}

	// The Administrator bypass principal is denied (403) and writes nothing.
	adminCfg := testConfig(dbURL)
	adminCfg.Auth.BypassPrincipal = "administrator"
	adminHandler, err := newHandler(adminCfg, pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler (admin): %v", err)
	}
	adminSrv := httptest.NewServer(adminHandler)
	t.Cleanup(adminSrv.Close)
	adminClient, err := gen.NewClientWithResponses(adminSrv.URL)
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	denied, err := adminClient.RevealAuditEventActorWithResponse(ctx, seedEventID, body, withRequestID(t, "reveal-e2e-403"))
	if err != nil {
		t.Fatalf("admin reveal: %v", err)
	}
	if denied.StatusCode() != http.StatusForbidden {
		t.Fatalf("admin status = %d, want 403 (body: %s)", denied.StatusCode(), denied.Body)
	}
	if n := revealAuditCount(t, ctx, pool); n != 1 {
		t.Fatalf("denied reveal wrote a self-audit (rows = %d, want 1)", n)
	}
}

// revealAuditCount counts the audit.identity_revealed rows.
func revealAuditCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'audit.identity_revealed'`).Scan(&n); err != nil {
		t.Fatalf("count reveal audits: %v", err)
	}
	return n
}
