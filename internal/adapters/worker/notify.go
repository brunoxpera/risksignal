package worker

// The notify relay handler (WP-4.06 / DEV-081, ARCH-004 §6.3): the relay
// handler of the notification outbox kinds, registered on the type-keyed
// dispatch registry in place of the I1b signal.created sink (sink.go, removed
// here). It consumes the four notification event kinds — signal.created,
// signal.escalated, signal.reopen_proposed and reminder — and, per event,
// decides the active/passive channel set from the payload priority, stores
// one notification row per channel (idempotent on the immutable outbox event
// id), delivers each through the NotifyPort (dispatched by channel) and
// records the delivery receipt (status/attempts/last_error/delivered_at). On
// a delivered signal.created/signal.escalated P1 notification it fulfils the
// signal's `notification` SLA clock (ARCH-004 §4.3).
//
// Idempotency and determinism reuse the UQ (outbox_event_id, channel): a
// redelivery (lease expiry, at-least-once) finds the stored row, skips a
// terminal one and only retries a still-pending one, so exactly one
// notification exists per (event, channel) (FR-023). Delivery is post-commit
// and never rolls back signal state (ch. 5.1): an infrastructure failure of
// the store or the transport is classified temporary (Retry — the expired
// lease redelivers) and a permanent delivery failure (an SMTP 5xx, a webhook
// 4xx, an unconfigured channel) is recorded and dead-letters the event with
// last_error.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// Notification delivery-state and kind vocabulary. The statuses mirror the
// notifications_status_check constraint; the kinds are the four outbox types
// the handler consumes (notifications_kind_check).
const (
	notificationStatusPending   = "pending"
	notificationStatusDelivered = "delivered"
	notificationStatusFailed    = "failed"
)

// notifyPayload is the shared envelope the handler decodes from any of the
// four notification outbox kinds. The payloads differ per kind (the created
// payload carries match/cve, the SLA payload carries the breached target and
// the reminder index, the reopen payload carries the priority transition) but
// all four carry the event identity, the type discriminator, the signal id
// and — except the reopen proposal — the priority. The handler only needs
// those shared fields; the rest stays opaque (never free text, ch. 3.3).
type notifyPayload struct {
	EventID  string `json:"event_id"`
	Type     string `json:"type"`
	SignalID string `json:"signal_id"`
	Priority string `json:"priority"`
}

// notificationKind reports whether kind is one of the four notification
// outbox kinds the handler consumes.
func notificationKind(kind string) bool {
	switch kind {
	case application.EventTypeSignalCreated,
		application.EventTypeSignalEscalated,
		application.EventTypeSignalReopenProposed,
		application.EventTypeSignalReminder:
		return true
	default:
		return false
	}
}

// NotifyPolicy is the config-derived active/passive channel decision
// (ARCH-004 §6.3): which channels a notification of a given kind and
// priority uses. P1 always notifies actively; P2 is active only when the
// operator enabled it (FR-023); P3/P4 and the reopen proposal are in-app
// only (passive). The SMTP and webhook channels join an active notification
// only when configured, and carry the configured recipient.
type NotifyPolicy struct {
	// P2Active activates outbound P2 notifications (FR-023: "users can
	// configure notifications for new P1/P2 signals"). P1 is always active.
	P2Active bool
	// SMTPEnabled adds the SMTP channel to an active notification.
	SMTPEnabled bool
	// SMTPTo is the SMTP recipient recorded on the notification row.
	SMTPTo string
	// WebhookEnabled adds the webhook channel to an active notification.
	WebhookEnabled bool
	// WebhookURL is the webhook target recorded on the notification row.
	WebhookURL string
}

// notifyTarget is one channel a notification is stored and delivered on, and
// the recipient recorded for it ("" for the in-app surface).
type notifyTarget struct {
	channel   notify.NotifyChannel
	recipient string
}

// targets returns the channel set of one notification: the in-app row is
// always written (it is the surface every notification has), and an active
// notification additionally uses the configured SMTP and webhook channels.
func (p NotifyPolicy) targets(kind, priority string) []notifyTarget {
	out := []notifyTarget{{channel: notify.ChannelInApp}}
	if !p.active(kind, priority) {
		return out
	}
	if p.SMTPEnabled {
		out = append(out, notifyTarget{channel: notify.ChannelSMTP, recipient: p.SMTPTo})
	}
	if p.WebhookEnabled {
		out = append(out, notifyTarget{channel: notify.ChannelWebhook, recipient: p.WebhookURL})
	}
	return out
}

// active reports whether a notification of kind/priority is an active
// (paging) notification: escalations and reminders always, a signal.created
// at P1 always and at P2 per FR-023. Everything else — P3/P4 creates and the
// non-P1 reopen proposal (ARCH-004 §5) — is in-app only.
func (p NotifyPolicy) active(kind, priority string) bool {
	switch kind {
	case application.EventTypeSignalEscalated, application.EventTypeSignalReminder:
		return true
	case application.EventTypeSignalCreated:
		switch strings.ToUpper(strings.TrimSpace(priority)) {
		case string(domain.PriorityP1):
			return true
		case string(domain.PriorityP2):
			return p.P2Active
		default:
			return false
		}
	default:
		return false
	}
}

// NotifyJobs is the dispatch state of the notify relay handler: the
// notification delivery-state store, the SLA clock store (the fulfil
// target), the NotifyPort dispatcher, the channel policy, the transaction
// runner, the injected clock and the logger. It is safe for use from one
// goroutine (the relay dispatches sequentially); handlers are registered at
// wiring time, before the scheduler loop starts.
type NotifyJobs struct {
	notifications application.NotificationRepo
	slaClocks     application.SlaClockRepo
	port          notify.NotifyPort
	policy        NotifyPolicy
	runTx         application.TxRunner
	clk           clock.Clock
	logger        *slog.Logger
}

// NotifyJobsDeps are the notify handler's dependencies. Notifications,
// SlaClocks, Port and RunTx are mandatory (a missing one is a wiring error);
// a nil Clock falls back to the real clock and a nil Logger to a silent one.
type NotifyJobsDeps struct {
	Notifications application.NotificationRepo
	SlaClocks     application.SlaClockRepo
	Port          notify.NotifyPort
	Policy        NotifyPolicy
	RunTx         application.TxRunner
	Clock         clock.Clock
	Logger        *slog.Logger
}

// NewNotifyJobs assembles the notify handler. It reports a wiring error when
// a mandatory dependency is missing.
func NewNotifyJobs(deps NotifyJobsDeps) (*NotifyJobs, error) {
	if deps.Notifications == nil {
		return nil, fmt.Errorf("worker: notify jobs: notification store must not be nil")
	}
	if deps.SlaClocks == nil {
		return nil, fmt.Errorf("worker: notify jobs: sla clock store must not be nil")
	}
	if deps.Port == nil {
		return nil, fmt.Errorf("worker: notify jobs: notify port must not be nil")
	}
	if deps.RunTx == nil {
		return nil, fmt.Errorf("worker: notify jobs: transaction runner must not be nil")
	}
	clk := deps.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &NotifyJobs{
		notifications: deps.Notifications,
		slaClocks:     deps.SlaClocks,
		port:          deps.Port,
		policy:        deps.Policy,
		runTx:         deps.RunTx,
		clk:           clk,
		logger:        logger,
	}, nil
}

// RegisterHandlers binds the notify handler to the four notification outbox
// kinds on the relay's dispatch registry (ARCH-004 §6.3). It replaces the
// I1b signal.created sink on the same key; a type already registered is a
// wiring error.
func (j *NotifyJobs) RegisterHandlers(relay *Relay) error {
	kinds := []string{
		application.EventTypeSignalCreated,
		application.EventTypeSignalEscalated,
		application.EventTypeSignalReopenProposed,
		application.EventTypeSignalReminder,
	}
	for _, kind := range kinds {
		if err := relay.Register(kind, j.handle); err != nil {
			return fmt.Errorf("worker: register %s notify handler: %w", kind, err)
		}
	}
	return nil
}

// handle delivers one notification event: decode the payload, resolve the
// channel set and store/deliver each channel, then map the aggregate outcome
// onto the relay semantics. A malformed payload, a type mismatch or a
// missing signal id is permanent; a temporary delivery/store failure is
// Retry; a permanent delivery failure (or a temporary one alongside no
// temporary failure) dead-letters the event.
func (j *NotifyJobs) handle(ctx context.Context, event ClaimedEvent) error {
	if !notificationKind(event.Type) {
		return fmt.Errorf("notify: outbox type %q is not a notification kind", event.Type) // permanent
	}
	var p notifyPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("notify: decode event payload: %w", err) // permanent: malformed payload
	}
	if p.Type != "" && p.Type != event.Type {
		return fmt.Errorf("notify: payload type %q does not match the outbox type %q", p.Type, event.Type) // permanent
	}
	if p.SignalID == "" {
		return fmt.Errorf("notify: %s event carries no signal_id", event.Type) // permanent
	}

	var sawTemporary, sawPermanent error
	for _, tgt := range j.policy.targets(event.Type, p.Priority) {
		err := j.deliverChannel(ctx, event, p, tgt)
		if err == nil {
			continue
		}
		if notify.IsPermanent(err) {
			sawPermanent = err
			continue
		}
		sawTemporary = err
	}
	switch {
	case sawTemporary != nil:
		if isRetryable(sawTemporary) {
			return sawTemporary
		}
		return Retry(sawTemporary)
	case sawPermanent != nil:
		return sawPermanent
	default:
		return nil
	}
}

// deliverChannel stores the notification row of one channel (idempotent on
// the outbox event id + channel), delivers it when it is still open and
// records the receipt. A terminal stored row (delivered/failed) is a no-op —
// the redelivery path. On a delivered signal.created/signal.escalated P1 the
// notification clock is fulfilled in the same transaction as the delivery
// receipt (ARCH-004 §4.3; adversarial review C-3): the terminal delivery
// state and the fulfil commit atomically, so a transient failure of that tx
// rolls both back and the redelivery re-delivers and re-fulfils the clock.
func (j *NotifyJobs) deliverChannel(ctx context.Context, event ClaimedEvent, p notifyPayload, tgt notifyTarget) error {
	now := j.clk.Now()

	var stored application.Notification
	mustDeliver := false
	if err := j.runTx(ctx, func(tx application.Tx) error {
		existing, found, err := j.notifications.GetByEventChannel(ctx, tx, event.ID, string(tgt.channel))
		if err != nil {
			return err
		}
		if found {
			stored = existing
			mustDeliver = existing.Status == notificationStatusPending
			return nil
		}
		row, inserted, err := j.notifications.Insert(ctx, tx, p.SignalID, string(tgt.channel), event.Type, tgt.recipient, notificationStatusPending, event.ID, now)
		if err != nil {
			return err
		}
		if inserted {
			stored = row
			mustDeliver = true
			return nil
		}
		// A concurrent worker inserted the row between the read and the
		// insert: read it back and decide from its state.
		row, found, err = j.notifications.GetByEventChannel(ctx, tx, event.ID, string(tgt.channel))
		if err != nil {
			return err
		}
		if !found {
			return application.InfraError("notify", errors.New("notification insert conflicted without a stored row"))
		}
		stored = row
		mustDeliver = row.Status == notificationStatusPending
		return nil
	}); err != nil {
		return classifyApplicationError(err)
	}

	if !mustDeliver {
		j.logger.Debug("notification already terminal; delivery is a no-op",
			slog.String("event_id", event.ID),
			slog.String("channel", string(tgt.channel)),
			slog.String("status", stored.Status))
		return nil
	}

	receipt, deliveryErr := j.port.Deliver(ctx, stored)

	status := notificationStatusDelivered
	lastError := ""
	var deliveredAt *time.Time
	if deliveryErr != nil {
		if notify.IsPermanent(deliveryErr) {
			status = notificationStatusFailed
		} else {
			status = notificationStatusPending // stays open for the lease retry
		}
		lastError = deliveryErr.Error()
	} else {
		at := now
		deliveredAt = &at
	}
	if lastError == "" && receipt.Error != "" {
		lastError = receipt.Error
	}

	if err := j.runTx(ctx, func(tx application.Tx) error {
		if _, err := j.notifications.UpdateDelivery(ctx, tx, stored.ID, status, stored.Attempts+1, lastError, deliveredAt); err != nil {
			return err
		}
		// A delivered signal.created/signal.escalated P1 fulfils the signal's
		// `notification` clock in this same transaction (ARCH-004 §4.3): the
		// receipt and the fulfil commit or roll back together (C-3). The
		// helper is a no-op for every other kind/priority and is idempotent,
		// so a second delivered channel cannot re-open the clock.
		if status == notificationStatusDelivered {
			return j.fulfilNotificationClock(ctx, tx, event.Type, p, now)
		}
		return nil
	}); err != nil {
		return classifyApplicationError(err)
	}

	if deliveryErr != nil {
		if notify.IsPermanent(deliveryErr) {
			j.logger.Warn("notification delivery failed permanently",
				slog.String("event_id", event.ID),
				slog.String("channel", string(tgt.channel)),
				slog.Any("error", deliveryErr))
			return deliveryErr
		}
		j.logger.Warn("notification delivery failed; will retry after the lease expires",
			slog.String("event_id", event.ID),
			slog.String("channel", string(tgt.channel)),
			slog.Any("error", deliveryErr))
		return deliveryErr
	}

	j.logger.Info("notification delivered",
		slog.String("event_id", event.ID),
		slog.String("kind", event.Type),
		slog.String("channel", string(tgt.channel)),
		slog.String("priority", p.Priority))

	return nil
}

// fulfilNotificationClock fulfils the signal's `notification` SLA clock when
// a signal.created/signal.escalated P1 notification was delivered (ARCH-004
// §4.3: "notification on technical delivery"). It runs on the caller's
// transaction — the delivery-receipt tx of deliverChannel — so the terminal
// delivery state and the fulfil commit atomically (adversarial review C-3).
// The kind/P1 guard is applied here, so it is a no-op for every other
// event/priority; Fulfil is idempotent, so a second delivered channel cannot
// re-open an already-fulfilled clock.
func (j *NotifyJobs) fulfilNotificationClock(ctx context.Context, tx application.Tx, kind string, p notifyPayload, at time.Time) error {
	if kind != application.EventTypeSignalCreated && kind != application.EventTypeSignalEscalated {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(p.Priority), string(domain.PriorityP1)) {
		return nil
	}
	_, fulfilled, err := j.slaClocks.Fulfil(ctx, tx, p.SignalID, domain.SLATargetNotification, at)
	if err != nil {
		return err
	}
	if fulfilled {
		j.logger.Info("notification SLA clock fulfilled",
			slog.String("signal_id", p.SignalID),
			slog.String("kind", kind))
	}
	return nil
}
