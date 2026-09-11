package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// EventTypeBackupRestored is the audit action recorded when a restore test
// completes successfully (ARCH-007 §4, concept ch. 13.2 "Backup/Restore").
const EventTypeBackupRestored = "backup.restored"

// backupAggregateType is the audit aggregate type of the backup lifecycle
// events (the polymorphic audit_events.aggregate_type).
const backupAggregateType = "backup"

// RestoreAudit is the minimised, secret-free record of one successful restore
// test (counts and integrity verdicts only — never business content, ch. 13.5).
type RestoreAudit struct {
	// BackupFile is the artifact basename the restore reproduced.
	BackupFile string `json:"backup_file"`
	// RestoredTo is the throwaway instance the restore targeted (a descriptor,
	// no credentials).
	RestoredTo string `json:"restored_to"`
	// Tables is the number of compared base tables.
	Tables int `json:"tables"`
	// Rows is the summed source row count.
	Rows int64 `json:"rows"`
	// OpenSignals is the open-signal count.
	OpenSignals int64 `json:"open_signals"`
	// AuditRows is the audit-trail row count.
	AuditRows int64 `json:"audit_rows"`
	// ChainVerified reports whether a populated audit hash chain verified.
	ChainVerified bool `json:"chain_verified"`
	// ActorID is the operator identity that ran the restore test.
	ActorID string `json:"actor_id"`
	// Reason is an optional operator note.
	Reason string `json:"reason,omitempty"`
}

// RecordRestoreAudit appends one `backup.restored` audit event on the source
// database. It is a single append-only INSERT (the audit_events write path);
// the event survives with the audit trail and is the operational record that
// the restore test ran (ARCH-007 §4).
func RecordRestoreAudit(ctx context.Context, sourceURL string, a RestoreAudit, occurredAt time.Time, correlationID string) error {
	snapshot, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("backup: encode restore audit: %w", err)
	}
	db, err := sql.Open("pgx", sourceURL)
	if err != nil {
		return fmt.Errorf("backup: open audit connection: %w", err)
	}
	defer db.Close()
	_, err = db.ExecContext(ctx,
		`INSERT INTO audit_events
		   (aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, before, after, correlation_id)
		 VALUES ($1, gen_random_uuid(), $2, $3, NULL, $4, $5, NULL, $6, $7)`,
		backupAggregateType, "system", a.ActorID, EventTypeBackupRestored, occurredAt, snapshot, correlationID)
	if err != nil {
		return fmt.Errorf("backup: record restore audit: %w", err)
	}
	return nil
}
