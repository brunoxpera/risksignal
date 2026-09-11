package notify

// Unit tests of the notify port (notify.go): the channel vocabulary, the
// delivery-error classification and the channel dispatcher. The concrete
// adapters are covered by smtp_test.go and webhook_test.go.

import (
	"context"
	"errors"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// stubPort is a NotifyPort whose outcome the test fixes.
type stubPort struct {
	receipt DeliveryReceipt
	err     error
	calls   int
}

func (p *stubPort) Deliver(context.Context, application.Notification) (DeliveryReceipt, error) {
	p.calls++
	return p.receipt, p.err
}

func TestNotifyChannelValid(t *testing.T) {
	for _, c := range []NotifyChannel{ChannelInApp, ChannelSMTP, ChannelWebhook} {
		if !c.Valid() {
			t.Errorf("%q.Valid() = false, want true", c)
		}
	}
	if NotifyChannel("pigeon").Valid() {
		t.Error("unknown channel reported valid")
	}
}

func TestPermanentClassification(t *testing.T) {
	if Permanent(nil) != nil {
		t.Error("Permanent(nil) must stay nil")
	}
	base := errors.New("boom")
	if IsPermanent(base) {
		t.Error("a plain error must be temporary, not permanent")
	}
	wrapped := Permanent(base)
	if !IsPermanent(wrapped) {
		t.Error("Permanent(err) is not reported permanent")
	}
	if !errors.Is(wrapped, base) {
		t.Error("Permanent(err) does not wrap the cause")
	}
}

func TestDispatcherRoutesToChannelPort(t *testing.T) {
	inApp := &stubPort{receipt: DeliveryReceipt{Channel: ChannelInApp, Delivered: true}}
	webhook := &stubPort{receipt: DeliveryReceipt{Channel: ChannelWebhook, Delivered: true}}
	d := NewDispatcher(map[NotifyChannel]NotifyPort{
		ChannelInApp:   inApp,
		ChannelWebhook: webhook,
	})

	if _, err := d.Deliver(context.Background(), application.Notification{Channel: "in_app"}); err != nil {
		t.Fatalf("Deliver(in_app): %v", err)
	}
	if inApp.calls != 1 || webhook.calls != 0 {
		t.Fatalf("calls in_app=%d webhook=%d, want 1/0", inApp.calls, webhook.calls)
	}
	if _, err := d.Deliver(context.Background(), application.Notification{Channel: "webhook"}); err != nil {
		t.Fatalf("Deliver(webhook): %v", err)
	}
	if webhook.calls != 1 {
		t.Fatalf("webhook calls = %d, want 1", webhook.calls)
	}
}

func TestDispatcherUnknownChannelIsPermanent(t *testing.T) {
	d := NewDispatcher(map[NotifyChannel]NotifyPort{ChannelInApp: &stubPort{}})
	_, err := d.Deliver(context.Background(), application.Notification{Channel: "smtp"})
	if !IsPermanent(err) {
		t.Fatalf("Deliver on an unconfigured channel error = %v, want permanent", err)
	}
}

func TestInAppPortDelivers(t *testing.T) {
	receipt, err := NewInAppPort().Deliver(context.Background(), application.Notification{Channel: "in_app"})
	if err != nil {
		t.Fatalf("InAppPort.Deliver: %v", err)
	}
	if !receipt.Delivered || receipt.Channel != ChannelInApp {
		t.Fatalf("receipt = %+v, want delivered in_app", receipt)
	}
}

// TestDispatcherRecordsDeliveriesAndFailures proves the DEV-142 delivery
// event recording: a successful delivery counts in
// notifications_deliveries_total and every failure — a transport failure or
// an unconfigured channel — counts in notifications_failures_total.
func TestDispatcherRecordsDeliveriesAndFailures(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)

	ok := &stubPort{receipt: DeliveryReceipt{Channel: ChannelInApp, Delivered: true}}
	bad := &stubPort{err: errors.New("transport down")}
	d := NewDispatcher(map[NotifyChannel]NotifyPort{ChannelInApp: ok, ChannelSMTP: bad})
	d.SetMetrics(reg)

	if _, err := d.Deliver(context.Background(), application.Notification{Channel: "in_app"}); err != nil {
		t.Fatalf("Deliver(in_app): %v", err)
	}
	if _, err := d.Deliver(context.Background(), application.Notification{Channel: "smtp"}); err == nil {
		t.Fatal("Deliver(smtp) = nil error, want the transport failure")
	}
	// An unconfigured channel is a failure too (no port = permanent).
	if _, err := d.Deliver(context.Background(), application.Notification{Channel: "webhook"}); !IsPermanent(err) {
		t.Fatalf("Deliver(webhook) = %v, want permanent", err)
	}

	got := map[string]float64{}
	for _, s := range reg.Snapshot() {
		got[s.Name] = s.Value
	}
	if got[metrics.NameNotificationsDeliveries] != 1 {
		t.Errorf("notifications_deliveries_total = %v, want 1", got[metrics.NameNotificationsDeliveries])
	}
	if got[metrics.NameNotificationsFailures] != 2 {
		t.Errorf("notifications_failures_total = %v, want 2", got[metrics.NameNotificationsFailures])
	}
}
