package worker

// Tests of the WP-4.06 notify relay handler (notify.go, ARCH-004 §6.3): the
// channel policy, the idempotent per-channel delivery (exactly one
// notification per event and channel, FR-023), the delivery-receipt recording
// (delivered/failed + attempts + last_error), the permanent/temporary failure
// classification and the notification-clock fulfilment on a delivered P1
// create/escalate. The relay dispatch, ack and dead-letter transitions are
// exercised through the real relay on the fake store; the notification store,
// the SLA clock store and the NotifyPort are in-memory fakes.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

var notifyFixedNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// fakeNotifyRepo is an in-memory application.NotificationRepo: the insert
// dedupes on (outbox_event_id, channel) exactly like the UQ, so the handler's
// idempotency is exercised without a database.
type fakeNotifyRepo struct {
	application.NotificationRepo
	mu   sync.Mutex
	rows []application.Notification
	seq  int
}

func (f *fakeNotifyRepo) Insert(_ context.Context, _ application.Tx, signalID, channel, kind, recipient, status, outboxEventID string, createdAt time.Time) (application.Notification, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.findLocked(outboxEventID, channel); ok {
		return application.Notification{}, false, nil
	}
	f.seq++
	row := application.Notification{
		ID: fmt.Sprintf("n-%d", f.seq), SignalID: signalID, Channel: channel, Kind: kind,
		Recipient: recipient, Status: status, Attempts: 0, OutboxEventID: outboxEventID, CreatedAt: createdAt,
	}
	f.rows = append(f.rows, row)
	return row, true, nil
}

func (f *fakeNotifyRepo) GetByEventChannel(_ context.Context, _ application.Tx, outboxEventID, channel string) (application.Notification, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.findLocked(outboxEventID, channel)
	return row, ok, nil
}

func (f *fakeNotifyRepo) findLocked(outboxEventID, channel string) (application.Notification, bool) {
	for _, r := range f.rows {
		if r.OutboxEventID == outboxEventID && r.Channel == channel {
			return r, true
		}
	}
	return application.Notification{}, false
}

func (f *fakeNotifyRepo) UpdateDelivery(_ context.Context, _ application.Tx, id, status string, attempts int, lastError string, deliveredAt *time.Time) (application.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rows {
		if f.rows[i].ID == id {
			f.rows[i].Status = status
			f.rows[i].Attempts = attempts
			f.rows[i].LastError = lastError
			f.rows[i].DeliveredAt = deliveredAt
			return f.rows[i], nil
		}
	}
	return application.Notification{}, fmt.Errorf("notification %s not found", id)
}

func (f *fakeNotifyRepo) ListBySignal(_ context.Context, signalID string) ([]application.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []application.Notification
	for _, r := range f.rows {
		if r.SignalID == signalID {
			out = append(out, r)
		}
	}
	return out, nil
}

// snapshot returns a copy of the stored rows for assertions.
func (f *fakeNotifyRepo) snapshot() []application.Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]application.Notification(nil), f.rows...)
}

// fakeSlaClocks is an in-memory application.SlaClockRepo implementing only the
// Fulfil path the notify handler uses; the embedded interface satisfies the
// rest of the port (the handler never calls the others).
type fakeSlaClocks struct {
	application.SlaClockRepo
	mu       sync.Mutex
	fulfiled map[string]bool
	calls    int
}

func newFakeSlaClocks() *fakeSlaClocks {
	return &fakeSlaClocks{fulfiled: map[string]bool{}}
}

func (f *fakeSlaClocks) Fulfil(_ context.Context, _ application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	key := signalID + "/" + string(target)
	if f.fulfiled[key] {
		return domain.SlaClock{}, false, nil
	}
	f.fulfiled[key] = true
	return domain.SlaClock{
		SignalID: signalID, Target: target, StartedAt: at, DeadlineAt: at.Add(time.Minute), FulfilledAt: at,
	}, true, nil
}

// scriptedPort is a NotifyPort whose per-channel outcome the test fixes. A
// nil result for a channel is a delivered receipt.
type scriptedPort struct {
	mu      sync.Mutex
	calls   map[notify.NotifyChannel]int
	results map[notify.NotifyChannel]error
}

func newScriptedPort() *scriptedPort {
	return &scriptedPort{calls: map[notify.NotifyChannel]int{}, results: map[notify.NotifyChannel]error{}}
}

func (p *scriptedPort) Deliver(_ context.Context, n application.Notification) (notify.DeliveryReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch := notify.NotifyChannel(n.Channel)
	p.calls[ch]++
	if err, ok := p.results[ch]; ok && err != nil {
		return notify.DeliveryReceipt{Channel: ch, Attempts: 1, Error: err.Error()}, err
	}
	return notify.DeliveryReceipt{Channel: ch, Delivered: true, Attempts: 1}, nil
}

func (p *scriptedPort) callCount(ch notify.NotifyChannel) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[ch]
}

// txNoop runs fn with a nil transaction: the fakes ignore the handle (the SQL
// transaction boundary is the postgres adapter's concern, covered by the
// integration test).
func txNoop(_ context.Context, fn func(tx application.Tx) error) error { return fn(nil) }

// notifyHarness bundles the fakes a notify test asserts on.
type notifyHarness struct {
	jobs   *NotifyJobs
	repo   *fakeNotifyRepo
	clocks *fakeSlaClocks
	port   *scriptedPort
}

func newNotifyHarness(t *testing.T, policy NotifyPolicy) *notifyHarness {
	t.Helper()
	repo := &fakeNotifyRepo{}
	clocks := newFakeSlaClocks()
	port := newScriptedPort()
	jobs, err := NewNotifyJobs(NotifyJobsDeps{
		Notifications: repo,
		SlaClocks:     clocks,
		Port:          port,
		Policy:        policy,
		RunTx:         txNoop,
		Clock:         clock.NewFakeClock(notifyFixedNow),
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewNotifyJobs: %v", err)
	}
	return &notifyHarness{jobs: jobs, repo: repo, clocks: clocks, port: port}
}

// notificationEvent renders a claimed notification event whose payload mirrors
// what the command layer enqueues.
func notificationEvent(id, kind, signalID, priority string) ClaimedEvent {
	payload, err := json.Marshal(map[string]any{
		"event_id": "evt-" + id, "type": kind, "signal_id": signalID, "priority": priority,
		"occurred_at": notifyFixedNow, "correlation_id": "corr-1",
	})
	if err != nil {
		panic(err)
	}
	return ClaimedEvent{ID: id, Type: kind, Payload: payload, Attempts: 1}
}

// notifyRelay wires a relay on the fake store with the notify handlers
// registered.
func notifyRelay(t *testing.T, h *notifyHarness, store OutboxStore) *Relay {
	t.Helper()
	relay := newRelay(t, store)
	if err := h.jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay
}

func fullPolicy() NotifyPolicy {
	return NotifyPolicy{P2Active: true, SMTPEnabled: true, SMTPTo: "analyst@example.test", WebhookEnabled: true, WebhookURL: "http://hook.test"}
}

// TestNotifyPolicyChannels pins the active/passive channel decision (ARCH-004
// §6.3): P1/P2 (and escalation/reminder) are active, P3/P4 creates and the
// reopen proposal are in-app only, and P2 is active only per FR-023.
func TestNotifyPolicyChannels(t *testing.T) {
	active := fullPolicy()
	passive := NotifyPolicy{P2Active: false, SMTPEnabled: true, SMTPTo: "a@b", WebhookEnabled: true, WebhookURL: "http://hook.test"}

	channels := func(p NotifyPolicy, kind, priority string) []string {
		var out []string
		for _, tgt := range p.targets(kind, priority) {
			out = append(out, string(tgt.channel))
		}
		return out
	}

	cases := []struct {
		name     string
		policy   NotifyPolicy
		kind     string
		priority string
		want     []string
	}{
		{"p1_create_active", active, application.EventTypeSignalCreated, "P1", []string{"in_app", "smtp", "webhook"}},
		{"p2_create_active_fr023", active, application.EventTypeSignalCreated, "P2", []string{"in_app", "smtp", "webhook"}},
		{"p2_create_passive", passive, application.EventTypeSignalCreated, "P2", []string{"in_app"}},
		{"p3_create_in_app_only", active, application.EventTypeSignalCreated, "P3", []string{"in_app"}},
		{"p4_create_in_app_only", active, application.EventTypeSignalCreated, "P4", []string{"in_app"}},
		{"escalation_active", active, application.EventTypeSignalEscalated, "P1", []string{"in_app", "smtp", "webhook"}},
		{"reminder_active", active, application.EventTypeSignalReminder, "P1", []string{"in_app", "smtp", "webhook"}},
		{"reopen_passive", active, application.EventTypeSignalReopenProposed, "", []string{"in_app"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := channels(tc.policy, tc.kind, tc.priority)
			if len(got) != len(tc.want) {
				t.Fatalf("channels(%s, %s) = %v, want %v", tc.kind, tc.priority, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("channels(%s, %s) = %v, want %v", tc.kind, tc.priority, got, tc.want)
				}
			}
		})
	}
}

// TestNotifyHandlerP1CreateDeliversOnePerChannelAndFulfilsClock: a P1 create
// writes exactly one notification per configured channel (in_app + smtp +
// webhook), delivers each, records them delivered and fulfils the signal's
// notification SLA clock — the event is acked.
func TestNotifyHandlerP1CreateDeliversOnePerChannelAndFulfilsClock(t *testing.T) {
	h := newNotifyHarness(t, fullPolicy())
	store := &fakeStore{events: []ClaimedEvent{notificationEvent("evt-1", application.EventTypeSignalCreated, "sig-1", "P1")}}
	relay := notifyRelay(t, h, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || store.acked[0] != "evt-1" {
		t.Fatalf("acked = %v, want evt-1 acked", store.acked)
	}
	rows := h.repo.snapshot()
	if len(rows) != 3 {
		t.Fatalf("notification rows = %d (%+v), want 3 (in_app + smtp + webhook)", len(rows), rows)
	}
	seen := map[string]application.Notification{}
	for _, r := range rows {
		seen[r.Channel] = r
	}
	for _, ch := range []string{"in_app", "smtp", "webhook"} {
		r, ok := seen[ch]
		if !ok {
			t.Fatalf("missing %s notification", ch)
		}
		if r.Status != "delivered" || r.DeliveredAt == nil {
			t.Errorf("%s notification = status %q delivered_at %v, want delivered", ch, r.Status, r.DeliveredAt)
		}
	}
	if seen["smtp"].Recipient != "analyst@example.test" {
		t.Errorf("smtp recipient = %q, want the configured target", seen["smtp"].Recipient)
	}
	if h.clocks.calls == 0 {
		t.Error("notification clock was never fulfilled on a delivered P1")
	}
	if !h.clocks.fulfiled["sig-1/notification"] {
		t.Error("notification clock of sig-1 was not fulfilled on delivered P1")
	}
}

// TestNotifyHandlerRedeliveryIsNoOp: a redelivered event (at-least-once) finds
// the stored terminal rows and neither re-inserts nor re-delivers — exactly
// one notification per (event, channel) (FR-023).
func TestNotifyHandlerRedeliveryIsNoOp(t *testing.T) {
	h := newNotifyHarness(t, fullPolicy())
	store := &fakeStore{events: []ClaimedEvent{notificationEvent("evt-1", application.EventTypeSignalCreated, "sig-1", "P1")}}
	relay := notifyRelay(t, h, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	afterFirst := h.port.callCount(notify.ChannelInApp)
	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	if got := len(h.repo.snapshot()); got != 3 {
		t.Fatalf("notification rows after redelivery = %d, want 3 (no duplicate)", got)
	}
	if got := h.port.callCount(notify.ChannelInApp); got != afterFirst {
		t.Fatalf("in_app deliveries after redelivery = %d, want %d (no re-delivery)", got, afterFirst)
	}
}

// TestNotifyHandlerTemporaryFailureStaysPendingAndRetries: a temporary
// delivery failure records the row pending with the error and leaves the event
// claimed (Retry); a redelivery retries the still-pending channel and, on
// success, marks it delivered — the delivered channels are not re-sent.
func TestNotifyHandlerTemporaryFailureStaysPendingAndRetries(t *testing.T) {
	h := newNotifyHarness(t, NotifyPolicy{SMTPEnabled: true, SMTPTo: "analyst@example.test"})
	tempErr := fmt.Errorf("dial tcp: connection refused")
	h.port.results[notify.ChannelSMTP] = tempErr
	event := notificationEvent("evt-1", application.EventTypeSignalCreated, "sig-1", "P1")

	store := &fakeStore{events: []ClaimedEvent{event}}
	relay := notifyRelay(t, h, store)
	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked=%v dead=%v, want the temporary failure left claimed", store.acked, store.dead)
	}
	smtp := rowForChannel(t, h.repo.snapshot(), "smtp")
	if smtp.Status != "pending" || smtp.Attempts != 1 || smtp.LastError == "" {
		t.Fatalf("smtp row = %+v, want pending/attempts 1/with error", smtp)
	}

	// The transient failure clears: the redelivery retries smtp and succeeds.
	h.port.results[notify.ChannelSMTP] = nil
	store.events = []ClaimedEvent{event}
	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	if len(store.acked) != 1 {
		t.Fatalf("acked = %v, want the event acked after the retry succeeded", store.acked)
	}
	smtp = rowForChannel(t, h.repo.snapshot(), "smtp")
	if smtp.Status != "delivered" || smtp.Attempts != 2 || smtp.LastError != "" {
		t.Fatalf("smtp row after retry = %+v, want delivered/attempts 2/clean", smtp)
	}
	if h.port.callCount(notify.ChannelInApp) != 1 {
		t.Fatalf("in_app deliveries = %d, want 1 (the delivered channel is not re-sent)", h.port.callCount(notify.ChannelInApp))
	}
}

// TestNotifyHandlerPermanentFailureRecordsAndDeadLetters: a permanent delivery
// failure (an SMTP 5xx / webhook 4xx) is recorded failed with the error and
// dead-letters the event — never a retry loop.
func TestNotifyHandlerPermanentFailureRecordsAndDeadLetters(t *testing.T) {
	h := newNotifyHarness(t, NotifyPolicy{SMTPEnabled: true, SMTPTo: "analyst@example.test"})
	h.port.results[notify.ChannelSMTP] = notify.Permanent(fmt.Errorf("550 mailbox unavailable"))
	store := &fakeStore{events: []ClaimedEvent{notificationEvent("evt-1", application.EventTypeSignalCreated, "sig-1", "P1")}}
	relay := notifyRelay(t, h, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.dead) != 1 || store.dead[0].id != "evt-1" {
		t.Fatalf("dead-letter = %+v, want evt-1 dead-lettered", store.dead)
	}
	if !contains(store.dead[0].lastError, "550") {
		t.Fatalf("dead-letter last_error = %q, want the SMTP rejection text", store.dead[0].lastError)
	}
	smtp := rowForChannel(t, h.repo.snapshot(), "smtp")
	if smtp.Status != "failed" || smtp.LastError == "" {
		t.Fatalf("smtp row = %+v, want failed with last_error", smtp)
	}
}

// TestNotifyHandlerMalformedPayloadIsPermanent: a payload that cannot be
// decoded, a type mismatch and a missing signal id are permanent — the event
// dead-letters instead of retrying.
func TestNotifyHandlerMalformedPayloadIsPermanent(t *testing.T) {
	h := newNotifyHarness(t, fullPolicy())
	cases := []struct {
		name  string
		event ClaimedEvent
	}{
		{"malformed", ClaimedEvent{ID: "e1", Type: application.EventTypeSignalCreated, Payload: []byte(`{"signal_id":`)}},
		{"type_mismatch", ClaimedEvent{ID: "e2", Type: application.EventTypeSignalCreated, Payload: []byte(`{"type":"signal.escalated","signal_id":"s"}`)}},
		{"missing_signal", ClaimedEvent{ID: "e3", Type: application.EventTypeSignalCreated, Payload: []byte(`{"type":"signal.created"}`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{events: []ClaimedEvent{tc.event}}
			relay := notifyRelay(t, h, store)
			if err := relay.Drain(context.Background()); err != nil {
				t.Fatalf("Drain: %v", err)
			}
			if len(store.dead) != 1 {
				t.Fatalf("dead-letter = %+v, want the malformed event dead-lettered", store.dead)
			}
		})
	}
}

// TestNotifyHandlerFulfilsOnlyP1CreateOrEscalate: the notification clock is
// fulfilled only for a delivered P1 signal.created/signal.escalated — a P2
// create or a reminder does not fulfil it (the reminder consumer stays P1 but
// the target is the acknowledgement escalation, not the notification clock).
func TestNotifyHandlerFulfilsOnlyP1CreateOrEscalate(t *testing.T) {
	cases := []struct {
		kind     string
		priority string
		want     bool
	}{
		{application.EventTypeSignalCreated, "P1", true},
		{application.EventTypeSignalEscalated, "P1", true},
		{application.EventTypeSignalCreated, "P2", false},
		{application.EventTypeSignalCreated, "P3", false},
		{application.EventTypeSignalReminder, "P1", false},
		{application.EventTypeSignalReopenProposed, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.priority, func(t *testing.T) {
			h := newNotifyHarness(t, fullPolicy())
			event := notificationEvent("evt-1", tc.kind, "sig-1", tc.priority)
			if err := h.jobs.handle(context.Background(), event); err != nil {
				t.Fatalf("handle: %v", err)
			}
			if got := h.clocks.fulfiled["sig-1/notification"]; got != tc.want {
				t.Fatalf("notification clock fulfilled = %v, want %v", got, tc.want)
			}
		})
	}
}

func rowForChannel(t *testing.T, rows []application.Notification, channel string) application.Notification {
	t.Helper()
	for _, r := range rows {
		if r.Channel == channel {
			return r
		}
	}
	t.Fatalf("no %s notification in %+v", channel, rows)
	return application.Notification{}
}
