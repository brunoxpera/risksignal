package worker

import (
	"context"
	"log/slog"
)

// SignalCreatedSink returns the I1b signal.created sink handler (ARCH-001
// §2): a no-op standing in for the I4 notification adapter. It accepts the
// event and reports success, so its observable delivery effect is the
// terminal claimed -> done transition of the outbox row — the walking
// skeleton proves the relay mechanics without delivering anywhere
// (notification delivery is I4). I4 replaces this handler on the same
// registry key with the real notification.deliver adapter (ch. 14.3), which
// uses the immutable outbox.id as its channel idempotency key.
func SignalCreatedSink(logger *slog.Logger) Handler {
	return func(ctx context.Context, event ClaimedEvent) error {
		if logger != nil {
			logger.Debug("signal.created sink: event accepted (no-op delivery)",
				slog.String("event_id", event.ID),
				slog.String("event_type", event.Type),
				slog.Int("attempts", event.Attempts))
		}
		return nil
	}
}
