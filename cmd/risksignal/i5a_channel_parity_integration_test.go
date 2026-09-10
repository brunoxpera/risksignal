package main

// I5a exit-criterion proof: API/CLI channel parity for the reference
// operation (ARCH-005 §8, NFR-013).
//
// One reference operation — acknowledge + override — is run through the API
// (the generated POST /api/v1/signals/{signal_id}/commands, threaded with the
// HTTP identity → actor resolution) and through the CLI (`risksignal signal
// acknowledge|override`, threaded with the --as subject → actor resolution)
// against the same migrated schema, and the two channels must produce the
// same state (status/priority/version), the same permission denials for a
// forbidden role and the same audit evidence (actor_id = users.id,
// actor_type = 'user').
//
// Each channel runs against its own scratch database so the two runs start
// from an identical, independent baseline; the same fixtures, the same
// application service wiring (newAppService) and the real permission gates
// make the comparison meaningful. It skips when no PostgreSQL is reachable,
// like the other integration tests.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// parityAnalystUser is the fixed id of the migration-seeded local::security-analyst
// user (00009) — the acting principal of the allowed reference runs.
const parityAnalystUser = "e5a00000-0000-4000-8000-000000000002"

// paritySignalState is the observable outcome of one reference run.
type paritySignalState struct {
	Status   domain.SignalStatus
	Priority domain.Priority
	Version  int
}

// parityAuditRow is one audit row of a signal (action + actor evidence).
type parityAuditRow struct {
	Action    string
	ActorType string
	ActorID   string
}

// parityFixture migrates a scratch database and seeds one P1/new signal
// through the real CreateSignal command, returning the pool, the database URL
// (for the CLI channel) and the signal.
func parityFixture(t *testing.T) (*pgxpool.Pool, string, domain.RiskSignal) {
	t.Helper()
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit = %d, want 0 (stderr: %s)", code, stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	at := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	matchID := seedCreateSignalFixture(t, pool, at)
	created, err := newAppService(pool, clock.NewFakeClock(at)).CreateSignal(ctx, faultTestInput(matchID))
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	return pool, dbURL, created.Signal
}

// parityAPIHandler builds the real HTTP stack of the reference endpoint for
// one bypass principal: the generated routes behind the per-route permission
// gate, wrapped in the I5a authentication middleware (local bypass).
func parityAPIHandler(t *testing.T, pool *pgxpool.Pool, bypassPrincipal string) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := newAppService(pool, clock.RealClock{})
	mux := http.NewServeMux()
	gate := httpapi.NewPermissionGate(nil, logger)
	gate.Declare("POST /api/v1/signals/{signal_id}/commands", domain.PermissionSignalsTriage)
	httpapi.RegisterAPIRoutes(gate.Decorate(mux), httpapi.NewAPIHandler(svc, svc, svc, logger))
	auth := httpapi.AuthenticationMiddleware(nil, nil, httpapi.AuthOptions{
		BypassEnabled:   true,
		BypassPrincipal: bypassPrincipal,
	})
	srv := httptest.NewServer(auth(mux))
	t.Cleanup(srv.Close)
	return srv
}

// parityReadState reads the stored status/priority/version of a signal.
func parityReadState(t *testing.T, pool *pgxpool.Pool, signalID string) paritySignalState {
	t.Helper()
	return paritySignalState{
		Status:   readSignalStatus(t, pool, signalID),
		Priority: readSignalPriority(t, pool, signalID),
		Version:  readSignalVersion(t, pool, signalID),
	}
}

// parityReadAudits reads a signal's audit rows in commit order.
func parityReadAudits(t *testing.T, pool *pgxpool.Pool, signalID string) []parityAuditRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT action, actor_type, actor_id FROM audit_events WHERE aggregate_id = $1 ORDER BY occurred_at, id`,
		signalID)
	if err != nil {
		t.Fatalf("read audits: %v", err)
	}
	defer rows.Close()
	var out []parityAuditRow
	for rows.Next() {
		var r parityAuditRow
		if err := rows.Scan(&r.Action, &r.ActorType, &r.ActorID); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audits: %v", err)
	}
	return out
}

// TestI5aExitCriteriaChannelParity is the ARCH-005 §8 channel-parity proof.
func TestI5aExitCriteriaChannelParity(t *testing.T) {
	// --- The API channel ---------------------------------------------------
	apiPool, _, apiSig := parityFixture(t)
	srv := parityAPIHandler(t, apiPool, "security-analyst")
	client, err := gen.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("gen.NewClientWithResponses: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ack, err := client.SignalCommandWithResponse(ctx, apiSig.ID, gen.SignalCommandRequest{
		Command: gen.Acknowledge, ExpectedVersion: ptrInt(apiSig.Version),
	})
	if err != nil {
		t.Fatalf("API acknowledge: %v", err)
	}
	if ack.StatusCode() != http.StatusOK || ack.JSON200 == nil {
		t.Fatalf("API acknowledge status = %d (body %s), want 200", ack.StatusCode(), ack.Body)
	}
	override, err := client.SignalCommandWithResponse(ctx, apiSig.ID, gen.SignalCommandRequest{
		Command: gen.OverridePriority, ExpectedVersion: ptrInt(ack.JSON200.Version),
		Priority: ptrPriority(gen.P3), Reason: ptrString("decommissioned"),
	})
	if err != nil {
		t.Fatalf("API override: %v", err)
	}
	if override.StatusCode() != http.StatusOK || override.JSON200 == nil {
		t.Fatalf("API override status = %d (body %s), want 200", override.StatusCode(), override.Body)
	}
	apiState := parityReadState(t, apiPool, apiSig.ID)
	apiAudits := parityReadAudits(t, apiPool, apiSig.ID)

	// A forbidden role (Administrator) is denied by the API and writes nothing.
	adminSrv := parityAPIHandler(t, apiPool, "administrator")
	adminClient, err := gen.NewClientWithResponses(adminSrv.URL)
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	auditsBefore := len(parityReadAudits(t, apiPool, apiSig.ID))
	denied, err := adminClient.SignalCommandWithResponse(ctx, apiSig.ID, gen.SignalCommandRequest{
		Command: gen.Acknowledge, ExpectedVersion: ptrInt(apiState.Version),
	})
	if err != nil {
		t.Fatalf("admin API acknowledge: %v", err)
	}
	if denied.StatusCode() != http.StatusForbidden {
		t.Fatalf("admin API status = %d, want 403 (body %s)", denied.StatusCode(), denied.Body)
	}
	if got := len(parityReadAudits(t, apiPool, apiSig.ID)); got != auditsBefore {
		t.Fatalf("denied API command wrote an audit row (%d -> %d)", auditsBefore, got)
	}

	// --- The CLI channel ---------------------------------------------------
	cliPool, cliDBURL, cliSig := parityFixture(t)
	env := cliDBEnv(cliDBURL)

	if code, _, stderr := runCLI(t, env, "signal", "acknowledge",
		"--signal", cliSig.ID, "--version", strconv.Itoa(cliSig.Version),
		"--as", "local::security-analyst", "--output", "json"); code != exitOK {
		t.Fatalf("CLI acknowledge exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	// The override takes the version the acknowledge produced.
	ackedVersion := readSignalVersion(t, cliPool, cliSig.ID)
	if code, _, stderr := runCLI(t, env, "signal", "override",
		"--signal", cliSig.ID, "--priority", "P3", "--reason", "decommissioned",
		"--version", strconv.Itoa(ackedVersion), "--as", "local::security-analyst", "--output", "json"); code != exitOK {
		t.Fatalf("CLI override exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	cliState := parityReadState(t, cliPool, cliSig.ID)
	cliAudits := parityReadAudits(t, cliPool, cliSig.ID)

	// A forbidden role (Administrator) is denied by the CLI (exit 4, no write).
	cliAuditsBefore := len(parityReadAudits(t, cliPool, cliSig.ID))
	if code, _, _ := runCLI(t, env, "signal", "acknowledge",
		"--signal", cliSig.ID, "--version", strconv.Itoa(cliState.Version),
		"--as", "local::administrator", "--output", "json"); code != exitAuthorisation {
		t.Fatalf("admin CLI acknowledge exit = %d, want %d", code, exitAuthorisation)
	}
	if got := len(parityReadAudits(t, cliPool, cliSig.ID)); got != cliAuditsBefore {
		t.Fatalf("denied CLI command wrote an audit row (%d -> %d)", cliAuditsBefore, got)
	}

	// --- Parity assertions -------------------------------------------------
	if apiState != cliState {
		t.Fatalf("channel state diverged: API %+v, CLI %+v", apiState, cliState)
	}
	if want := (paritySignalState{Status: domain.SignalStatusInReview, Priority: domain.PriorityP3, Version: 3}); apiState != want {
		t.Fatalf("final state = %+v, want %+v (acknowledge + override)", apiState, want)
	}
	if len(apiAudits) != len(cliAudits) {
		t.Fatalf("audit row counts diverged: API %d, CLI %d", len(apiAudits), len(cliAudits))
	}
	for i := range apiAudits {
		if apiAudits[i] != cliAudits[i] {
			t.Fatalf("audit row %d diverged: API %+v, CLI %+v", i, apiAudits[i], cliAudits[i])
		}
	}
	// The reference commands are audited as the acting user principal
	// (actor_type = 'user', actor_id = users.id): create (system) + ack +
	// override (both user).
	last := apiAudits[len(apiAudits)-1]
	if last.ActorType != application.ActorTypeUser || last.ActorID != parityAnalystUser {
		t.Fatalf("override audit actor = %s/%s, want user/%s", last.ActorType, last.ActorID, parityAnalystUser)
	}
	ackRow := apiAudits[len(apiAudits)-2]
	if ackRow.ActorType != application.ActorTypeUser || ackRow.ActorID != parityAnalystUser {
		t.Fatalf("acknowledge audit actor = %s/%s, want user/%s", ackRow.ActorType, ackRow.ActorID, parityAnalystUser)
	}
}

// ptrPriority, ptrString and ptrInt build the optional request fields.
func ptrPriority(p gen.Priority) *gen.Priority { return &p }
func ptrString(s string) *string               { return &s }
func ptrInt(i int) *int                        { return &i }
