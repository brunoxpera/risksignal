package application

import "context"

// GetSignal returns the readable detail view of one signal — the signal
// joined with its match, vulnerability, component and asset (ARCH-001 §4
// getSignal). An unknown id is a not-found error (the HTTP layer maps it to
// a 404 ProblemDetails).
func (s *Service) GetSignal(ctx context.Context, id string) (Signal, error) {
	if id == "" {
		return Signal{}, Validationf("get_signal", "signal id must not be empty")
	}
	return s.signals.GetByID(ctx, id)
}
