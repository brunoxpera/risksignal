// Package notify is the I4 notification delivery port and its adapters
// (ARCH-004 §6.1, WP-4.06 / DEV-081). It defines the NotifyPort the relay
// notify handler drives — Deliver one prepared notification and report a
// delivery receipt — the NotifyChannel vocabulary, the delivery-error
// classification (temporary vs permanent) and the channel dispatcher the
// handler holds. The concrete adapters are the in-app surface (the
// notification row itself), the SMTP relay (a local mail test server in the
// local environment, D-004) and the signed fake webhook; there is no
// production mail or webhook target in I4 (iterations.md fallback).
//
// The port follows the house shape of the other adapter ports: it depends on
// the application layer's prepared Notification value (models.go) and the
// context only, and it never touches a database — persistence of the
// delivery state (status/attempts/last_error/delivered_at) is the relay
// handler's job through the application.NotificationRepo port. A delivery is
// post-commit and never rolls back signal state (ch. 5.1).
package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// NotifyChannel is one notification delivery channel (ARCH-004 §6.1): the
// in-app surface, the SMTP relay, the signed webhook. The values are the
// notifications.channel vocabulary the schema constrains
// (notifications_channel_check).
type NotifyChannel string

const (
	// ChannelInApp is the in-app surface: the notifications row itself,
	// rendered by the signal detail view in I5b.
	ChannelInApp NotifyChannel = "in_app"
	// ChannelSMTP is the SMTP relay (Mailpit in the local environment).
	ChannelSMTP NotifyChannel = "smtp"
	// ChannelWebhook is the signed outbound webhook (ChatOps/automation).
	ChannelWebhook NotifyChannel = "webhook"
)

// Valid reports whether c is one of the three channels the schema accepts.
func (c NotifyChannel) Valid() bool {
	switch c {
	case ChannelInApp, ChannelSMTP, ChannelWebhook:
		return true
	default:
		return false
	}
}

// DeliveryReceipt records the outcome of one Deliver call: which channel
// answered, whether the message was accepted and the number of transport
// attempts the adapter made. Error carries the human-readable failure text
// ("" on success), mirroring notifications.last_error. A failed delivery is
// classified by the accompanying error (a *PermanentError is terminal; any
// other non-nil error is temporary and retryable).
type DeliveryReceipt struct {
	Channel   NotifyChannel
	Delivered bool
	Attempts  int
	Error     string
}

// NotifyPort delivers one prepared notification (ARCH-004 §6.1). Deliver is
// idempotent on the immutable outbox event id the notification carries
// (n.OutboxEventID): a redelivery of the same event must not produce a
// second message. It returns a receipt on success and on a classified
// failure; the error is a *PermanentError for a failure that must not be
// retried, and any other non-nil error is a temporary failure the relay
// retries after the lease expires (ch. 14.2).
type NotifyPort interface {
	Deliver(ctx context.Context, n application.Notification) (DeliveryReceipt, error)
}

// PermanentError marks a delivery failure that must never be retried: a
// permanent SMTP rejection (5xx), a webhook endpoint that refuses the
// request (4xx) or an unconfigured channel — the "dead-letter with
// last_error" class of ARCH-004 §6.3.
type PermanentError struct{ err error }

// Error renders the wrapped failure.
func (e *PermanentError) Error() string { return e.err.Error() }

// Unwrap exposes the wrapped failure for errors.Is/As.
func (e *PermanentError) Unwrap() error { return e.err }

// Permanent wraps err as a PermanentError. A nil error stays nil, so a
// classifier can call Permanent(derr) unconditionally.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{err: err}
}

// IsPermanent reports whether err — or any error it wraps — was marked
// permanent. A plain (unmarked) error is temporary by default: the relay
// retries it after the lease expires.
func IsPermanent(err error) bool {
	var target *PermanentError
	return errors.As(err, &target)
}

// Dispatcher routes a notification to the port registered for its channel.
// It is the single NotifyPort the relay handler holds: the policy decides
// which channels a notification uses, and the dispatcher resolves the
// channel's adapter. A channel without a registered port is a wiring gap and
// is reported as a permanent failure (it can never succeed by retrying).
//
// The dispatcher is also the notification adapter's delivery event point
// (implementation concept ch. 16.2, ARCH-007 §5, WP-6.12 follow-up /
// DEV-142): it records the outcome of every delivery attempt — a success in
// notifications_deliveries_total, a failure (of any class) in
// notifications_failures_total — on the optional process registry wired with
// SetMetrics.
type Dispatcher struct {
	ports map[NotifyChannel]NotifyPort
	reg   *metrics.Registry // nil: delivery metrics recording disabled
}

// NewDispatcher builds a dispatcher over the given per-channel ports. A nil
// port for a channel is dropped; an empty dispatcher is valid but every
// delivery then fails permanently.
func NewDispatcher(ports map[NotifyChannel]NotifyPort) *Dispatcher {
	clean := make(map[NotifyChannel]NotifyPort, len(ports))
	for ch, port := range ports {
		if port != nil {
			clean[ch] = port
		}
	}
	return &Dispatcher{ports: clean}
}

// SetMetrics wires the optional process registry the dispatcher records its
// delivery outcomes on (ARCH-007 §5, DEV-142). A nil registry disables the
// recording (the tests and the composition roots that do not expose
// /metrics). It is called once at the composition root, before the relay
// serves events.
func (d *Dispatcher) SetMetrics(reg *metrics.Registry) { d.reg = reg }

// Deliver routes n to the port of its channel and records the delivery
// outcome on the wired registry. An unknown or unconfigured channel yields a
// PermanentError, never a retry loop, and counts as a failure.
func (d *Dispatcher) Deliver(ctx context.Context, n application.Notification) (DeliveryReceipt, error) {
	ch := NotifyChannel(n.Channel)
	port, ok := d.ports[ch]
	if !ok {
		err := Permanent(fmt.Errorf("notify: no port configured for channel %q", n.Channel))
		d.record(err)
		return DeliveryReceipt{Channel: ch}, err
	}
	receipt, err := port.Deliver(ctx, n)
	d.record(err)
	return receipt, err
}

// record counts one delivery attempt: err == nil is a delivery
// (notifications_deliveries_total), any non-nil delivery error is a failure
// (notifications_failures_total). The dispatcher is the single point every
// channel's delivery passes, so the two families count each attempt exactly
// once.
func (d *Dispatcher) record(err error) {
	if d.reg == nil {
		return
	}
	if err == nil {
		d.reg.Counter(metrics.NameNotificationsDeliveries, metrics.HelpNotificationsDeliveries).Inc()
		return
	}
	d.reg.Counter(metrics.NameNotificationsFailures, metrics.HelpNotificationsFailures).Inc()
}

// MetricFamilies returns the §16.2 families the notification adapter records
// on the process registry. It is the writer declaration the NFR-010 coverage
// guard reads (DEV-142). The slice is a copy.
func MetricFamilies() []string {
	return []string{
		metrics.NameNotificationsDeliveries,
		metrics.NameNotificationsFailures,
	}
}
