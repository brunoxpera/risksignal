package main

// End-to-end integration test of the WP-4.06 notify relay handler at the
// composition root (cmd/risksignal-worker is where the embedded migration set
// is wired together with the postgres adapter and the worker relay, so the
// full chain is exercised here against a real, short-lived PostgreSQL).
//
// The test drives the ARCH-004 §6.3 notification flow through the real
// postgres repositories: a P1 signal.created event is dispatched to the
// registered notify handler, which stores exactly one notification row per
// configured channel (in_app + smtp + webhook, keyed on the immutable outbox
// event id), delivers each through the NotifyPort (the in-app row, a recording
// SMTP mailer and a real signed webhook against an httptest server that
// verifies the HMAC signature) and fulfils the signal's `notification` SLA
// clock on the delivered P1. A redelivery finds the stored terminal rows and
// neither re-inserts nor re-delivers (FR-023). A permanent SMTP rejection is
// recorded failed with last_error and dead-letters the event.
//
// The outbox store is a scripted in-memory store (the relay's SQL claim/ack is
// covered by relay_integration_test.go) so the same event can be redelivered
// on demand; every write below the handler is the real postgres repository on
// postgres.WithTx. The test skips when no PostgreSQL is reachable
// (newTestDB).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

var notifyITTime = time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)

// scriptedStore is an in-memory worker.OutboxStore that returns the same
// event(s) on every claim, so a redelivery can be forced by draining twice.
type scriptedStore struct {
	events  []worker.ClaimedEvent
	acked   []string
	dead    []string
	deadErr []string
}

func (s *scriptedStore) ClaimBatch(context.Context, int) ([]worker.ClaimedEvent, error) {
	return s.events, nil
}
func (s *scriptedStore) Ack(_ context.Context, id string) error {
	s.acked = append(s.acked, id)
	return nil
}
func (s *scriptedStore) DeadLetter(_ context.Context, id, lastError string) error {
	s.dead = append(s.dead, id)
	s.deadErr = append(s.deadErr, lastError)
	return nil
}

// recordMailer is a notify.Mailer that records calls and returns a fixed
// error (nil accepts the message; a *textproto.Error 5xx is a permanent
// rejection).
type recordMailer struct {
	calls int
	err   error
}

func (m *recordMailer) Send(string, []string, []byte) error {
	m.calls++
	return m.err
}

// seedNotifySignalFixture seeds the rows a risk_signals row needs behind its
// foreign keys (asset -> component, vulnerability -> match) and inserts one
// P1 signal with an open `notification` SLA clock. It returns the signal id
// and the match id.
func seedNotifySignalFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, at time.Time) string {
	t.Helper()
	q := gen.New(pool)

	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "notify-asset", Source: "demo", Type: "server_vm", Name: "Notify",
		Environment: "production", Criticality: "critical", Exposure: "internet", Owner: pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	vendorNorm := "acme"
	productNorm := "notify"
	naturalKey, err := domain.ComponentNaturalKey(domain.ComponentIdentifiers{Vendor: "acme", Product: "notify", Version: "1.0"}, vendorNorm, productNorm, "")
	if err != nil {
		t.Fatalf("ComponentNaturalKey: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID: assetID, Vendor: "acme", Product: "notify", Version: "1.0",
		VendorNorm: vendorNorm, ProductNorm: productNorm,
		VersionScheme: string(domain.VersionSchemeUnknown), NaturalKey: naturalKey,
		UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true},
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2026-9001", Summary: "Notify IT",
		PublishedAt: pgtype.Timestamptz{Time: at.AddDate(0, 0, -30), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: at.AddDate(0, 0, -1), Valid: true},
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID, ComponentID: componentID, Method: "exact_identifier",
		Score: 100, Confidence: "high", RuleVersion: "i1b-1",
		CreatedAt: pgtype.Timestamptz{Time: at, Valid: true}, Reasons: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("InsertMatch: %v", err)
	}

	var signalID pgtype.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO risk_signals (match_id, priority, status, rule_version, factors, created_at)
		 VALUES ($1, 'P1', 'new', 'p0000000001', '{}'::jsonb, $2) RETURNING id`,
		matchID, at).Scan(&signalID); err != nil {
		t.Fatalf("insert signal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		 VALUES ($1, 'notification', $2, $3)`,
		signalID, at, at.Add(5*time.Minute)); err != nil {
		t.Fatalf("insert notification clock: %v", err)
	}
	return uuidStr(signalID)
}

// appendNotifyOutbox appends one signal.created P1 outbox row for signalID and
// returns the claimed event whose ID is the real outbox row id (the channel
// idempotency key).
func appendNotifyOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID string, at time.Time) worker.ClaimedEvent {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"event_id": "evt-" + signalID, "type": application.EventTypeSignalCreated,
		"signal_id": signalID, "priority": "P1", "occurred_at": at, "correlation_id": "corr-it",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	row, err := gen.New(pool).AppendOutbox(ctx, gen.AppendOutboxParams{
		Type: application.EventTypeSignalCreated, Payload: payload,
		AvailableAt: pgtype.Timestamptz{Time: at, Valid: true},
		DedupeKey:   "signal.created:" + signalID,
		CreatedAt:   pgtype.Timestamptz{Time: at, Valid: true},
	})
	if err != nil {
		t.Fatalf("append outbox: %v", err)
	}
	return worker.ClaimedEvent{ID: uuidStr(row.ID), Type: application.EventTypeSignalCreated, Payload: payload, Attempts: 1}
}

// newNotifyRelay wires the notify handler on the real postgres repositories
// with the given port and policy.
func newNotifyRelay(t *testing.T, pool *pgxpool.Pool, store worker.OutboxStore, port notify.NotifyPort, policy worker.NotifyPolicy) *worker.Relay {
	t.Helper()
	q := gen.New(pool)
	jobs, err := worker.NewNotifyJobs(worker.NotifyJobsDeps{
		Notifications: repo.NewNotificationRepo(q),
		SlaClocks:     repo.NewSlaClockRepo(q),
		Port:          port,
		Policy:        policy,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
		Clock:  clock.NewFakeClock(notifyITTime),
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewNotifyJobs: %v", err)
	}
	relay, err := worker.NewRelay(store, discardLogger())
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay
}

// countNotificationsByChannel returns the notification count of one signal and
// channel read straight from the database.
func countNotificationsByChannel(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID, channel string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM notifications WHERE signal_id = $1 AND channel = $2`,
		signalID, channel).Scan(&n); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	return n
}

// readNotification returns the status/attempts/last_error of one (signal,
// channel) notification row.
func readNotification(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID, channel string) (string, int, string, *time.Time) {
	t.Helper()
	var status, lastError string
	var attempts int
	var deliveredAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT status, attempts, coalesce(last_error, ''), delivered_at FROM notifications WHERE signal_id = $1 AND channel = $2`,
		signalID, channel).Scan(&status, &attempts, &lastError, &deliveredAt); err != nil {
		t.Fatalf("read notification %s/%s: %v", signalID, channel, err)
	}
	return status, attempts, lastError, deliveredAt
}

func readNotificationClockFulfilled(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID string) *time.Time {
	t.Helper()
	var fulfilledAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT fulfilled_at FROM sla_clocks WHERE signal_id = $1 AND target = 'notification'`,
		signalID).Scan(&fulfilledAt); err != nil {
		t.Fatalf("read notification clock: %v", err)
	}
	return fulfilledAt
}

// TestNotifyHandlerP1CreateDeliveryIdempotencyAndClockFulfilment proves the
// exit path of WP-4.06 end to end: a P1 create stores and delivers exactly one
// notification per channel (in_app + smtp + webhook, the webhook's signature
// verified by the receiving server), fulfils the notification SLA clock, and a
// redelivery of the same event is a no-op (no duplicate row, no re-delivery).
func TestNotifyHandlerP1CreateDeliveryIdempotencyAndClockFulfilment(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	signalID := seedNotifySignalFixture(t, ctx, pool, notifyITTime)
	event := appendNotifyOutbox(t, ctx, pool, signalID, notifyITTime)

	const secret = "s3cr3t-it"
	var webhookCalls, badSig int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookCalls, 1)
		body, _ := io.ReadAll(r.Body)
		if !notify.VerifySignature(secret, body, r.Header.Get("X-RiskSignal-Signature")) {
			atomic.AddInt32(&badSig, 1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	mailer := &recordMailer{}
	smtp, err := notify.NewSMTPPort(mailer, "risk@example.test", "analyst@example.test")
	if err != nil {
		t.Fatalf("NewSMTPPort: %v", err)
	}
	webhook, err := notify.NewWebhookPort(srv.URL, secret, srv.Client())
	if err != nil {
		t.Fatalf("NewWebhookPort: %v", err)
	}
	port := notify.NewDispatcher(map[notify.NotifyChannel]notify.NotifyPort{
		notify.ChannelInApp: notify.NewInAppPort(), notify.ChannelSMTP: smtp, notify.ChannelWebhook: webhook,
	})
	policy := worker.NotifyPolicy{P2Active: true, SMTPEnabled: true, SMTPTo: "analyst@example.test", WebhookEnabled: true, WebhookURL: srv.URL}

	store := &scriptedStore{events: []worker.ClaimedEvent{event}}
	relay := newNotifyRelay(t, pool, store, port, policy)

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if len(store.acked) != 1 || len(store.dead) != 0 {
		t.Fatalf("acked=%v dead=%v, want the event acked once", store.acked, store.dead)
	}
	for _, ch := range []string{"in_app", "smtp", "webhook"} {
		if n := countNotificationsByChannel(t, ctx, pool, signalID, ch); n != 1 {
			t.Fatalf("%s notifications = %d, want exactly 1", ch, n)
		}
		status, attempts, lastError, deliveredAt := readNotification(t, ctx, pool, signalID, ch)
		if status != "delivered" || deliveredAt == nil || lastError != "" {
			t.Fatalf("%s notification = %s/attempts %d/error %q, want delivered", ch, status, attempts, lastError)
		}
	}
	if fulfilledAt := readNotificationClockFulfilled(t, ctx, pool, signalID); fulfilledAt == nil {
		t.Fatal("notification clock not fulfilled on the delivered P1 create")
	}
	if mailer.calls != 1 {
		t.Fatalf("smtp deliveries = %d, want 1", mailer.calls)
	}
	if got := atomic.LoadInt32(&webhookCalls); got != 1 {
		t.Fatalf("webhook calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&badSig); got != 0 {
		t.Fatalf("webhook signature mismatches = %d, want 0", got)
	}

	// Redelivery: the same event is claimed again (lease expiry, at-least-once)
	// and must be a no-op — no duplicate row, no second delivery.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	for _, ch := range []string{"in_app", "smtp", "webhook"} {
		if n := countNotificationsByChannel(t, ctx, pool, signalID, ch); n != 1 {
			t.Fatalf("%s notifications after redelivery = %d, want 1 (no duplicate)", ch, n)
		}
	}
	if mailer.calls != 1 {
		t.Fatalf("smtp deliveries after redelivery = %d, want 1 (no re-delivery)", mailer.calls)
	}
	if got := atomic.LoadInt32(&webhookCalls); got != 1 {
		t.Fatalf("webhook calls after redelivery = %d, want 1 (no re-delivery)", got)
	}
}

// TestNotifyHandlerPermanentSMTPRejection proves the failure classification on
// the real schema: a permanent SMTP rejection is recorded failed with the
// error text and dead-letters the event (never a retry loop), while the in-app
// row of the same event still delivers.
func TestNotifyHandlerPermanentSMTPRejection(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	signalID := seedNotifySignalFixture(t, ctx, pool, notifyITTime)
	event := appendNotifyOutbox(t, ctx, pool, signalID, notifyITTime)

	mailer := &recordMailer{err: &textproto.Error{Code: 550, Msg: "mailbox unavailable"}}
	smtp, err := notify.NewSMTPPort(mailer, "risk@example.test", "analyst@example.test")
	if err != nil {
		t.Fatalf("NewSMTPPort: %v", err)
	}
	port := notify.NewDispatcher(map[notify.NotifyChannel]notify.NotifyPort{
		notify.ChannelInApp: notify.NewInAppPort(), notify.ChannelSMTP: smtp,
	})
	policy := worker.NotifyPolicy{SMTPEnabled: true, SMTPTo: "analyst@example.test"}

	store := &scriptedStore{events: []worker.ClaimedEvent{event}}
	relay := newNotifyRelay(t, pool, store, port, policy)

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(store.dead) != 1 || store.dead[0] != event.ID {
		t.Fatalf("dead-letter = %v, want the event dead-lettered on the permanent rejection", store.dead)
	}
	if got := store.deadErr[0]; got == "" {
		t.Fatal("dead-letter last_error is empty, want the SMTP rejection text")
	}
	if status, attempts, lastError, _ := readNotification(t, ctx, pool, signalID, "smtp"); status != "failed" || lastError == "" || attempts != 1 {
		t.Fatalf("smtp notification = %s/attempts %d/error %q, want failed with last_error", status, attempts, lastError)
	}
	if status, _, _, _ := readNotification(t, ctx, pool, signalID, "in_app"); status != "delivered" {
		t.Fatalf("in_app notification = %s, want delivered", status)
	}
}

func uuidStr(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
