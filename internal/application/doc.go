// Package application holds the use cases and port interfaces of the
// walking skeleton (WP-1b.04, ARCH-001): CreateSignal (the atomic
// signal + audit + outbox command of ch. 5.1/§2), ListSignals and GetSignal
// (the §4 read endpoints' logic) and RunSyntheticSource (the §3 run
// orchestration). WP-2.01 (ARCH-002) adds the shared source adapter
// contract — SourcePort and its source type/kind/cursor vocabulary,
// fetch/normalise input-output types and the NormalizeSink/RecordError
// seam (source_port.go) — the port the I2 NVD/KEV/EPSS adapters implement.
// WP-2.04 (DEV-030) adds the use cases that drive the port: FetchSource /
// NormalizeSource / RunSource (the fetch and normalise halves of a source
// run with cursor-on-commit bookkeeping, source_port.go's run companions
// fetch_source.go / normalize_source.go / run_source.go) and the
// quarantine review commands QuarantineList / QuarantineAck /
// QuarantineReprocess (quarantine.go, ARCH-002 §4 state machine with one
// audit event per transition). WP-4.04a (DEV-075) adds the I4 signal-triage
// and SLA commands — TransitionSignal / AssignOwner / AddComment /
// AcknowledgeSignal / OverridePriority / RevertPriority / PauseSla /
// ResumeSla (signal_triage.go, ARCH-004 §2/§3/§4) — each writing its state
// change, audit event and outbox event in one transaction.
//
// The layer depends only on the domain and on platform infrastructure
// (.go-arch-lint.yml): every persistence concern sits behind the repository
// ports declared in ports.go and is implemented in internal/adapters/postgres.
// The transaction boundary is a port too — TxRunner, wired to the adapters'
// postgres.WithTx at the composition root — so the use cases can run the
// writes of a command on one real transaction without importing any
// adapter. Errors are classified per concept ch. 5.2 (validation, conflict,
// not found, infrastructure) as typed *Error values.
package application
