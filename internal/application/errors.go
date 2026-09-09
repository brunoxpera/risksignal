package application

import (
	"errors"
	"fmt"
)

// ErrorKind is the error class of the application layer (implementation
// concept ch. 5.2 "Fehlerbehandlung"): callers map the kind onto their
// protocol — a validation error is a client mistake (4xx), a conflict is an
// optimistic-lock or uniqueness clash (409), not-found maps to 404 and
// everything else is infrastructure trouble (5xx). The classes are kept
// distinct so that no caller has to guess from a message string.
type ErrorKind string

const (
	// KindValidation: the caller supplied something invalid (empty identity,
	// unknown enum value, out-of-range factor, malformed cursor). Retrying
	// with the same input cannot succeed.
	KindValidation ErrorKind = "validation"
	// KindConflict: the change conflicts with the current state — a unique
	// violation (risk_signals.match_id, outbox.dedupe_key) or, from I4, an
	// optimistic-lock version mismatch (ch. 7.3).
	KindConflict ErrorKind = "conflict"
	// KindNotFound: the requested row does not exist (getSignal of an
	// unknown id).
	KindNotFound ErrorKind = "not_found"
	// KindInfra: persistence or infrastructure failure; the operation may
	// succeed when retried.
	KindInfra ErrorKind = "infrastructure"
)

// Error is the typed error of the application layer. Repositories return it
// (translating driver errors in the adapters layer), use cases construct it
// for validation failures, and — because postgres.WithTx returns the
// transaction body's error unwrapped (internal/adapters/postgres/tx.go) —
// it crosses transaction boundaries with its class intact.
type Error struct {
	Kind ErrorKind
	Op   string // operation that failed, e.g. "create_signal"
	Err  error  // cause; may be nil for simple validation messages
}

// Error implements error.
func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("application: %s: %s", e.Op, e.Kind)
	}
	return fmt.Sprintf("application: %s: %s: %v", e.Op, e.Kind, e.Err)
}

// Unwrap exposes the cause for errors.Is/errors.As chains.
func (e *Error) Unwrap() error { return e.Err }

// ValidationError returns a validation-class error wrapping err.
func ValidationError(op string, err error) error {
	return &Error{Kind: KindValidation, Op: op, Err: err}
}

// Validationf returns a validation-class error with a formatted message.
func Validationf(op, format string, args ...any) error {
	return &Error{Kind: KindValidation, Op: op, Err: fmt.Errorf(format, args...)}
}

// ConflictError returns a conflict-class error wrapping err.
func ConflictError(op string, err error) error {
	return &Error{Kind: KindConflict, Op: op, Err: err}
}

// NotFoundError returns a not-found-class error wrapping err.
func NotFoundError(op string, err error) error {
	return &Error{Kind: KindNotFound, Op: op, Err: err}
}

// InfraError returns an infrastructure-class error wrapping err.
func InfraError(op string, err error) error {
	return &Error{Kind: KindInfra, Op: op, Err: err}
}

// ErrorKindOf reports the class of err. Errors not carrying an application
// Error — a bare driver or programming error that slipped through — are
// reported as infrastructure: that is the safe default for callers that map
// errors onto protocol responses. ok is false for nil errors.
func ErrorKindOf(err error) (kind ErrorKind, ok bool) {
	if err == nil {
		return "", false
	}
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr.Kind, true
	}
	return KindInfra, true
}
