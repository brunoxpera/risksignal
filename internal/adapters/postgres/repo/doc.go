// Package repo implements the application ports of WP-1b.04 (DEV-018)
// against the sqlc-generated query layer (internal/adapters/postgres/gen,
// ADR-009): one repository per aggregate, mapping the generated models onto
// the domain types and application records of the ports.
//
// Repositories are bound to one *gen.Queries — the pool-scoped query set
// read operations run on. Every write method additionally receives the
// application transaction handle (application.Tx, an alias of pgx.Tx) and
// rebinds the queries with Queries.WithTx(tx), so the write runs on exactly
// the transaction the caller opened with postgres.WithTx (ARCH-001 §2: one
// domain command, one transaction). Driver errors are translated to the
// typed application errors of concept ch. 5.2 (dbmap.go): unique violations
// become conflicts, missing rows not-found, constraint mistakes validation
// and everything else infrastructure.
//
// The package is pure mapping code: no SQL, no business rules. Domain
// values are scanned back into the plain structs the domain package
// sanctions ("the persistence layer scans rows back into plain structs").
package repo
