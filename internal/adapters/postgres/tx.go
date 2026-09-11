package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTx runs fn inside a single database transaction and enforces the
// transaction boundary of the implementation concept ch. 5.1: one domain
// command, one transaction. State change, audit event and the matching
// outbox event of a command are stored atomically; external delivery happens
// only after commit.
//
// The transaction commits when fn returns nil and rolls back when fn returns
// an error. fn's error is returned unchanged — never wrapped — so the
// application layer keeps its error classification (validation, conflict,
// infrastructure; concept ch. 5.2). Only failures of the transaction itself
// (begin/commit) are wrapped as infrastructure errors. fn must not commit or
// roll back the transaction itself, and must not spawn nested transactions.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		// A begin failure is a transaction-boundary error (DEV-142).
		IncTransactionError()
		return fmt.Errorf("postgres: begin transaction: %w", err)
	}
	// Best-effort rollback on every path that does not commit: a failed fn,
	// a failed commit, or a panic inside fn. Rolling back an already
	// committed transaction is a no-op returning pgx.ErrTxClosed.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		// A commit failure is a transaction-boundary error (DEV-142).
		IncTransactionError()
		return fmt.Errorf("postgres: commit transaction: %w", err)
	}
	return nil
}
