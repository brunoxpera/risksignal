package main

// I6 exit-criteria consolidation (ARCH-007 §5/§12 NFR-010, WP-6.12 /
// DEV-134): the end-to-end request → job → audit → notification correlation
// join as an `I6ExitCriteria`-named gate. It closes the DEV-120 review
// follow-up ("audit-leg correlation proven at boundary, not end-to-end DB") by
// driving the real components over one live database and one correlation id.
//
// The same correlation id is shown to join:
//   - the request   — the HTTP middleware adopts the inbound X-Request-ID and
//                     the access log line carries it;
//   - the audit     — the signal.created and signal.acknowledged audit rows;
//   - the job       — the signal.created outbox payload and the relay's
//                     job.dispatch span (correlation-id-as-trace-id);
//   - the notification — the notify handler delivers the in-app notification
//                     under that same correlation scope.
//
// The test skips when no PostgreSQL is reachable (newTestDB), like every other
// composition-root integration test.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
	"github.com/brunoxpera/risksignal/internal/platform/logging"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

// i6CorrelationJoinID is the single correlation id the join test threads
// through every leg.
const i6CorrelationJoinID = "corr-i6-join"

// i6SpanRecorder captures ended spans for the trace-leg assertion.
type i6SpanRecorder struct{ spans []tracing.EndedSpan }

func (r *i6SpanRecorder) Export(_ context.Context, span tracing.EndedSpan) {
	r.spans = append(r.spans, span)
}

// TestI6ExitCriteriaObservabilityCorrelationJoin is the NFR-010 acceptance
// case: one correlation id joins request → job → audit → notification against
// the real components, and the process registry renders the §16.2 families.
func TestI6ExitCriteriaObservabilityCorrelationJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dbURL := newTestDB(t)

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	clk := clock.NewFakeClock(time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	cfg := config.Defaults()
	svc := newAppService(&cfg, pool, clk)

	matches, err := seedDemoScenarioChain(ctx, pool, clk.Now())
	if err != nil {
		t.Fatalf("seed scenario chain: %v", err)
	}

	// --- the job leg's relay: real notify handler + tracer + metrics ---
	relay, err := newDemoNotifyRelay(pool, clk)
	if err != nil {
		t.Fatalf("build notify relay: %v", err)
	}
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	spans := &i6SpanRecorder{}
	relay.SetObservability(reg, tracing.New(spans))

	// --- the command (its correlation id is the request's effective id) ---
	actor := application.Actor{Type: application.ActorTypeSystem, ID: demoScenarioActorID}
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matches.lifecycle, CveID: demoScenarioCVELifecycle,
		Factors: demoScenarioP1Factors(), Actor: actor,
		CorrelationID: i6CorrelationJoinID,
	})
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	signalID := created.Signal.ID

	// --- audit leg: the creation audit row carries the correlation id ---
	if n := i6Count(t, ctx, pool,
		`SELECT count(*) FROM audit_events WHERE correlation_id = $1 AND action = $2`,
		i6CorrelationJoinID, application.EventTypeSignalCreated); n != 1 {
		t.Fatalf("signal.created audit rows with the correlation id = %d, want 1", n)
	}
	// --- job leg: the outbox payload carries it ---
	var payloadCorr string
	if err := pool.QueryRow(ctx,
		`SELECT payload->>'correlation_id' FROM outbox WHERE type = $1 AND payload->>'signal_id' = $2`,
		application.EventTypeSignalCreated, signalID).Scan(&payloadCorr); err != nil {
		t.Fatalf("read outbox payload correlation: %v", err)
	}
	if payloadCorr != i6CorrelationJoinID {
		t.Fatalf("outbox payload correlation_id = %q, want %q", payloadCorr, i6CorrelationJoinID)
	}

	// --- drain the job: notification leg + trace leg ---
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("relay.Drain: %v", err)
	}
	if delivered, err := demoNotificationDelivered(ctx, pool, signalID); err != nil || !delivered {
		t.Fatalf("notification delivered = %v (err %v), want the in-app signal.created delivery", delivered, err)
	}
	if len(spans.spans) == 0 {
		t.Fatal("no job.dispatch span exported by the relay")
	}
	wantTrace := tracing.TraceIDForCorrelation(i6CorrelationJoinID)
	var sawDispatch bool
	for _, s := range spans.spans {
		if s.Name == "job.dispatch" && s.TraceID == wantTrace {
			sawDispatch = true
		}
	}
	if !sawDispatch {
		t.Fatalf("no job.dispatch span with the correlation-derived trace id %s (got %+v)", wantTrace, spans.spans)
	}

	// --- metrics leg: the families are declared and the request recorded ---
	exp := reg.Prometheus()
	for _, want := range []string{
		"# TYPE http_requests_total counter",
		"# TYPE notifications_failures_total counter",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("metrics exposition lacks %q", want)
		}
	}

	// --- request leg: an HTTP command carrying the same id joins the log ---
	logBuf := &bytes.Buffer{}
	logger := logging.New(logging.Options{Service: "risksignal-server", Environment: "local", Writer: logBuf})
	apiURL := i6ObservabilityStack(t, svc, logger, reg, tracing.New(spans))

	body, _ := json.Marshal(map[string]any{"command": "acknowledge", "expected_version": created.Signal.Version})
	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/v1/signals/"+signalID+"/commands", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpapi.HeaderRequestID, i6CorrelationJoinID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post command: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledge status = %d, want 200 (body %s; log %s)", resp.StatusCode, raw, logBuf.String())
	}
	if got := resp.Header.Get(httpapi.HeaderRequestID); got != i6CorrelationJoinID {
		t.Fatalf("response correlation header = %q, want the effective %q", got, i6CorrelationJoinID)
	}
	if resp.Header.Get("Traceparent") == "" {
		t.Error("no traceparent response header on the traced request")
	}
	if !strings.Contains(logBuf.String(), "correlation_id="+i6CorrelationJoinID) {
		t.Errorf("access log does not carry the correlation id:\n%s", logBuf.String())
	}
	// The request's audit row carries the same id (end-to-end DB).
	if n := i6Count(t, ctx, pool,
		`SELECT count(*) FROM audit_events WHERE correlation_id = $1 AND action = $2`,
		i6CorrelationJoinID, application.EventTypeSignalAcknowledged); n != 1 {
		t.Fatalf("signal.acknowledged audit rows with the correlation id = %d, want 1", n)
	}
}

// i6Count runs a single-count query.
func i6Count(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

// i6ObservabilityStack builds the API over svc behind the correlation, access
// log, trace and metrics middlewares — the observability chain the composition
// root wires — and returns its base URL.
func i6ObservabilityStack(t *testing.T, svc *application.Service, logger *slog.Logger, reg *metrics.Registry, tracer *tracing.Tracer) string {
	t.Helper()
	mux := http.NewServeMux()
	gate := httpapi.NewPermissionGate(nil, logger)
	httpapi.RegisterAPIRoutes(gate.Decorate(mux), httpapi.NewAPIHandler(svc, svc, svc, logger,
		httpapi.APISurfaces{Inventory: svc, Assets: svc, Users: svc, Exports: svc, Retention: svc, LegalHolds: svc}))
	// The command surface requires signals.triage; the local bypass principal
	// "security-analyst" maps to the seeded analyst holding it ScopeAll (the
	// administrator role deliberately holds no fachliche triage right).
	auth := httpapi.AuthenticationMiddleware(nil, nil, httpapi.AuthOptions{BypassEnabled: true, BypassPrincipal: "security-analyst"})
	chain := httpapi.Chain(
		httpapi.CorrelationID,
		httpapi.AccessLog(logger),
		httpapi.TraceMiddleware(tracer),
		httpapi.MetricsMiddleware(reg),
	)
	srv := httptest.NewServer(chain(auth(mux)))
	t.Cleanup(srv.Close)
	return srv.URL
}
