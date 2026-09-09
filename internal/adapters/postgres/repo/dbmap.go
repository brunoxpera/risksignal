package repo

import (
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/application"
)

// mapDBError translates a driver error into the typed application error of
// its ch. 5.2 class. Errors that already carry the class pass through
// untouched; pgx.ErrNoRows (a :one query without a row) is not-found; the
// PostgreSQL error codes below classify the rest. Anything unrecognised is
// infrastructure — the safe default for a caller mapping onto a protocol
// response.
func mapDBError(op string, err error) error {
	if err == nil {
		return nil
	}
	var appErr *application.Error
	if errors.As(err, &appErr) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return application.NotFoundError(op, err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation: risk_signals.match_id, outbox.dedupe_key, …
			return application.ConflictError(op, err)
		case "23503": // foreign_key_violation: the command referenced a missing row
			return application.ValidationError(op, err)
		case "23502", "23514", "22P02": // not_null / check / invalid input syntax
			return application.ValidationError(op, err)
		}
	}
	return application.InfraError(op, err)
}

// toUUID parses a canonical uuid string into the pgtype.UUID the generated
// queries use for uuid columns. A malformed id is a caller mistake and is
// reported as a validation error by the callers.
func toUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

// uuidString formats a pgtype.UUID canonically. An invalid uuid yields "".
func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// toTS wraps a time into a valid timestamptz.
func toTS(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// toTSPtr maps a time onto a timestamptz; the zero time means NULL (used for
// the nullable modified_at of the I1b vulnerability upsert).
func toTSPtr(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// toTextOpt maps a string onto a nullable text column; "" means NULL.
func toTextOpt(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
