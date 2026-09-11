package application_test

// Fakes for the I6 retention and pseudonymisation use cases (ARCH-007 §2/§3,
// WP-6.05 / DEV-116): the retention repository over the shared fakeDB. The run
// lifecycle, the legal holds, the in-place redactions and the referentially-safe
// deletions are staged on the fake transaction and applied at commit, so the
// commit/rollback semantics hold (a denied command stages nothing). The candidate
// seed and the dependent rows (comments, audit events, signals, SLA clocks,
// matches, notifications, priority factors) are seeded directly by the test.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// retentionPriorityFactor is one seeded priority_factors row (the fake models
// only the signal-scoped identity the retention deletion needs).
type retentionPriorityFactor struct{ signalID string }

// retentionHoldRelease is one staged legal-hold release.
type retentionHoldRelease struct {
	id string
	at time.Time
}

// retentionRedaction is one staged in-place pseudonymisation: a signal-scoped
// redaction (target "signal") or an identity-scoped one (target "identity").
type retentionRedaction struct {
	target string
	id     string
}

// retentionDeletion is one staged per-table deletion of a signal's dependent
// rows (table is sla_clocks/comments/matches/notifications/priority_factors/
// audit_events/risk_signals).
type retentionDeletion struct {
	table    string
	signalID string
}

// ---------------------------------------------------------------------------
// fakeDB retained-state helpers

func (d *fakeDB) runByID(id string) (application.RetentionRun, bool) {
	for _, r := range d.retentionRuns {
		if r.ID == id {
			return r, true
		}
	}
	return application.RetentionRun{}, false
}

func (d *fakeDB) applyRetentionRun(r application.RetentionRun) {
	for i := range d.retentionRuns {
		if d.retentionRuns[i].ID == r.ID {
			d.retentionRuns[i] = r
			return
		}
	}
	d.retentionRuns = append(d.retentionRuns, r)
}

func (d *fakeDB) applyHoldRelease(rel retentionHoldRelease) {
	for i := range d.legalHolds {
		if d.legalHolds[i].ID == rel.id {
			d.legalHolds[i].ReleasedAt = rel.at
		}
	}
}

// redactReasonJSON replaces the free-text "reason" key of a snapshot with the
// redaction marker, leaving every structured key untouched.
func redactReasonJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if v, ok := m["reason"].(string); ok && strings.TrimSpace(v) != "" {
		m["reason"] = application.RetentionRedactionMarker
		b, err := json.Marshal(m)
		if err != nil {
			return raw
		}
		return b
	}
	return raw
}

// hasReason reports whether a snapshot carries a non-empty free-text "reason".
func hasReason(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	v, ok := m["reason"].(string)
	return ok && strings.TrimSpace(v) != ""
}

func (d *fakeDB) applyRetentionRedaction(red retentionRedaction) {
	switch red.target {
	case "signal":
		for i := range d.comments {
			if d.comments[i].SignalID == red.id {
				d.comments[i].Body = application.RetentionRedactionMarker
			}
		}
		for i := range d.signalRows {
			if d.signalRows[i].sig.ID == red.id {
				d.signalRows[i].sig.OverrideReason = ""
			}
		}
		for i := range d.auditEvents {
			ev := &d.auditEvents[i]
			if ev.AggregateType == application.AuditAggregateRiskSignal && ev.AggregateID == red.id {
				ev.ActorDisplayName = ""
				ev.Before = redactReasonJSON(ev.Before)
				ev.After = redactReasonJSON(ev.After)
			}
		}
	case "identity":
		for i := range d.auditEvents {
			ev := &d.auditEvents[i]
			if ev.ActorID == red.id {
				ev.ActorDisplayName = ""
				ev.Before = redactReasonJSON(ev.Before)
				ev.After = redactReasonJSON(ev.After)
			}
		}
		for i := range d.comments {
			if d.comments[i].ActorID == red.id {
				d.comments[i].Body = application.RetentionRedactionMarker
			}
		}
		for i := range d.signalRows {
			if d.signalRows[i].sig.OverrideActorID == red.id {
				d.signalRows[i].sig.OverrideReason = ""
			}
		}
	}
}

func (d *fakeDB) applyRetentionDeletion(del retentionDeletion) {
	switch del.table {
	case "sla_clocks":
		kept := make([]domain.SlaClock, 0, len(d.slaClocks))
		for _, c := range d.slaClocks {
			if c.SignalID != del.signalID {
				kept = append(kept, c)
			}
		}
		d.slaClocks = kept
	case "comments":
		kept := make([]domain.Comment, 0, len(d.comments))
		for _, c := range d.comments {
			if c.SignalID != del.signalID {
				kept = append(kept, c)
			}
		}
		d.comments = kept
	case "matches":
		matchID := d.matchIDOfSignal(del.signalID)
		kept := make([]storedMatch, 0, len(d.matchRows))
		for _, m := range d.matchRows {
			if m.id != matchID {
				kept = append(kept, m)
			}
		}
		d.matchRows = kept
	case "notifications":
		kept := make([]application.Notification, 0, len(d.notifications))
		for _, n := range d.notifications {
			if n.SignalID != del.signalID {
				kept = append(kept, n)
			}
		}
		d.notifications = kept
	case "priority_factors":
		kept := make([]retentionPriorityFactor, 0, len(d.priorityFactors))
		for _, p := range d.priorityFactors {
			if p.signalID != del.signalID {
				kept = append(kept, p)
			}
		}
		d.priorityFactors = kept
	case "audit_events":
		kept := make([]application.AuditEvent, 0, len(d.auditEvents))
		for _, ev := range d.auditEvents {
			if ev.AggregateType == application.AuditAggregateRiskSignal && ev.AggregateID == del.signalID {
				continue
			}
			kept = append(kept, ev)
		}
		d.auditEvents = kept
	case "risk_signals":
		kept := make([]storedSignal, 0, len(d.signalRows))
		for _, s := range d.signalRows {
			if s.sig.ID != del.signalID {
				kept = append(kept, s)
			}
		}
		d.signalRows = kept
		// Mirror the real candidate scan: a deleted signal no longer appears
		// as a retention candidate, so a re-run (resumable) naturally skips it.
		keptCandidates := make([]application.RetentionCandidate, 0, len(d.retentionCandidates))
		for _, c := range d.retentionCandidates {
			if c.SignalID != del.signalID {
				keptCandidates = append(keptCandidates, c)
			}
		}
		d.retentionCandidates = keptCandidates
	}
}

func (d *fakeDB) matchIDOfSignal(signalID string) string {
	for _, s := range d.signalRows {
		if s.sig.ID == signalID {
			return s.sig.MatchID
		}
	}
	return ""
}

func (d *fakeDB) countDeletion(table, signalID string) int {
	switch table {
	case "sla_clocks":
		var n int
		for _, c := range d.slaClocks {
			if c.SignalID == signalID {
				n++
			}
		}
		return n
	case "comments":
		var n int
		for _, c := range d.comments {
			if c.SignalID == signalID {
				n++
			}
		}
		return n
	case "matches":
		matchID := d.matchIDOfSignal(signalID)
		var n int
		for _, m := range d.matchRows {
			if m.id == matchID {
				n++
			}
		}
		return n
	case "notifications":
		var n int
		for _, x := range d.notifications {
			if x.SignalID == signalID {
				n++
			}
		}
		return n
	case "priority_factors":
		var n int
		for _, p := range d.priorityFactors {
			if p.signalID == signalID {
				n++
			}
		}
		return n
	case "audit_events":
		var n int
		for _, ev := range d.auditEvents {
			if ev.AggregateType == application.AuditAggregateRiskSignal && ev.AggregateID == signalID {
				n++
			}
		}
		return n
	case "risk_signals":
		var n int
		for _, s := range d.signalRows {
			if s.sig.ID == signalID {
				n++
			}
		}
		return n
	}
	return 0
}

func (d *fakeDB) countSignalRedaction(signalID string) application.RetentionRedaction {
	var c application.RetentionRedaction
	for _, ev := range d.auditEvents {
		if ev.AggregateType == application.AuditAggregateRiskSignal && ev.AggregateID == signalID {
			if strings.TrimSpace(ev.ActorDisplayName) != "" {
				c.DisplayNamesCleared++
			}
			if hasReason(ev.Before) {
				c.SnapshotReasonsRedacted++
			}
			if hasReason(ev.After) {
				c.SnapshotReasonsRedacted++
			}
		}
	}
	for _, cm := range d.comments {
		if cm.SignalID == signalID && cm.Body != "" && cm.Body != application.RetentionRedactionMarker {
			c.CommentBodiesRedacted++
		}
	}
	for _, s := range d.signalRows {
		if s.sig.ID == signalID && strings.TrimSpace(s.sig.OverrideReason) != "" && s.sig.OverrideReason != application.RetentionRedactionMarker {
			c.OverrideReasonsRedacted++
		}
	}
	return c
}

func (d *fakeDB) countIdentityRedaction(userID string) application.RetentionRedaction {
	var c application.RetentionRedaction
	for _, ev := range d.auditEvents {
		if ev.ActorID == userID {
			if strings.TrimSpace(ev.ActorDisplayName) != "" {
				c.DisplayNamesCleared++
			}
			if hasReason(ev.Before) {
				c.SnapshotReasonsRedacted++
			}
			if hasReason(ev.After) {
				c.SnapshotReasonsRedacted++
			}
		}
	}
	for _, cm := range d.comments {
		if cm.ActorID == userID && cm.Body != "" && cm.Body != application.RetentionRedactionMarker {
			c.CommentBodiesRedacted++
		}
	}
	for _, s := range d.signalRows {
		if s.sig.OverrideActorID == userID && strings.TrimSpace(s.sig.OverrideReason) != "" && s.sig.OverrideReason != application.RetentionRedactionMarker {
			c.OverrideReasonsRedacted++
		}
	}
	return c
}

// ---------------------------------------------------------------------------
// fakeRetentionRepo (application.RetentionRepo)

type fakeRetentionRepo struct {
	db *fakeDB
	// failDelete, when set, makes the named deletion table fail — the batch
	// fault seam. failPseudonymiseSignal arms a PseudonymiseSignal failure.
	// failDeleteSignal, when set, makes the deletion of the named signal fail
	// (before any table is touched) — the per-signal batch-fault seam that lets
	// one batch fail while the run continues with the next.
	failDelete             map[string]error
	failDeleteSignal       map[string]error
	failPseudonymiseSignal error
}

var _ application.RetentionRepo = (*fakeRetentionRepo)(nil)

func (f *fakeRetentionRepo) ScanRetentionCandidates(_ context.Context, cutoff time.Time) ([]application.RetentionCandidate, error) {
	active := map[string]string{}
	for _, h := range f.db.legalHolds {
		if h.Active() {
			active[h.AggregateType+"/"+h.AggregateID] = h.Reason
		}
	}
	var out []application.RetentionCandidate
	for _, c := range f.db.retentionCandidates {
		if c.ClosedAt.After(cutoff) {
			continue
		}
		cand := c
		if reason, ok := active[application.AuditAggregateRiskSignal+"/"+c.SignalID]; ok {
			cand.Held = true
			cand.HoldReason = reason
		}
		out = append(out, cand)
	}
	return out, nil
}

func (f *fakeRetentionRepo) InsertRun(ctx context.Context, tx application.Tx, rec application.RetentionRunRecord) (application.RetentionRun, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.RetentionRun{}, err
	}
	ftx.record("retention.run.insert")
	counts := rec.Counts
	row := application.RetentionRun{
		ID:           uuid.New(),
		PolicyID:     rec.PolicyID,
		Stage:        rec.Stage,
		Cutoff:       rec.Cutoff,
		PartitionKey: rec.PartitionKey,
		Status:       application.RetentionStatusDryRun,
		DryRun:       &counts,
	}
	ftx.staged.retentionRunInserts = append(ftx.staged.retentionRunInserts, row)
	return row, nil
}

func (f *fakeRetentionRepo) GetRun(_ context.Context, id string) (application.RetentionRun, error) {
	if r, ok := f.db.runByID(id); ok {
		return r, nil
	}
	return application.RetentionRun{}, application.NotFoundError("retention.get_run", fmt.Errorf("run %s not found", id))
}

func (f *fakeRetentionRepo) ListRuns(_ context.Context) ([]application.RetentionRun, error) {
	out := make([]application.RetentionRun, len(f.db.retentionRuns))
	copy(out, f.db.retentionRuns)
	// Mirror the SQL order: newest cutoff first (cutoff DESC, then id).
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Cutoff.Equal(out[j].Cutoff) {
			return out[i].Cutoff.After(out[j].Cutoff)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *fakeRetentionRepo) mutateRun(tx application.Tx, id string, mutate func(*application.RetentionRun) error) (application.RetentionRun, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.RetentionRun{}, err
	}
	cur, ok := f.db.runByID(id)
	if !ok {
		return application.RetentionRun{}, application.NotFoundError("retention.run", fmt.Errorf("run %s not found", id))
	}
	if err := mutate(&cur); err != nil {
		return application.RetentionRun{}, err
	}
	ftx.staged.retentionRunUpdates = append(ftx.staged.retentionRunUpdates, cur)
	return cur, nil
}

func (f *fakeRetentionRepo) ApproveRun(ctx context.Context, tx application.Tx, id, approvedBy, reason string, at time.Time) (application.RetentionRun, error) {
	return f.mutateRun(tx, id, func(r *application.RetentionRun) error {
		if r.Status != application.RetentionStatusDryRun {
			return application.ConflictError("retention.approve", fmt.Errorf("run %s is %s, not dry_run", id, r.Status))
		}
		r.Status = application.RetentionStatusApproved
		r.ApprovedBy = approvedBy
		r.ApprovedAt = at
		r.ApprovalReason = reason
		return nil
	})
}

func (f *fakeRetentionRepo) RejectRun(ctx context.Context, tx application.Tx, id, reason string, at time.Time) (application.RetentionRun, error) {
	return f.mutateRun(tx, id, func(r *application.RetentionRun) error {
		if r.Status != application.RetentionStatusDryRun {
			return application.ConflictError("retention.reject", fmt.Errorf("run %s is %s, not dry_run", id, r.Status))
		}
		r.Status = application.RetentionStatusRejected
		r.ApprovalReason = reason
		r.ApprovedAt = at
		return nil
	})
}

func (f *fakeRetentionRepo) StartRun(ctx context.Context, tx application.Tx, id string, at time.Time) (application.RetentionRun, error) {
	return f.mutateRun(tx, id, func(r *application.RetentionRun) error {
		if r.Status != application.RetentionStatusApproved {
			return application.ConflictError("retention.start", fmt.Errorf("run %s is %s, not approved", id, r.Status))
		}
		r.Status = application.RetentionStatusExecuting
		r.StartedAt = at
		return nil
	})
}

func (f *fakeRetentionRepo) CompleteRun(ctx context.Context, tx application.Tx, id string, counts application.RetentionRunCounts, at time.Time) (application.RetentionRun, error) {
	return f.mutateRun(tx, id, func(r *application.RetentionRun) error {
		if r.Status != application.RetentionStatusExecuting {
			return application.ConflictError("retention.complete", fmt.Errorf("run %s is %s, not executing", id, r.Status))
		}
		r.Status = application.RetentionStatusCompleted
		r.FinishedAt = at
		r.Pseudonymised = counts.Pseudonymised
		r.Deleted = counts.Deleted
		r.Failed = counts.Failed
		return nil
	})
}

func (f *fakeRetentionRepo) FailRun(ctx context.Context, tx application.Tx, id string, counts application.RetentionRunCounts, at time.Time) (application.RetentionRun, error) {
	return f.mutateRun(tx, id, func(r *application.RetentionRun) error {
		if r.Status != application.RetentionStatusApproved && r.Status != application.RetentionStatusExecuting {
			return application.ConflictError("retention.fail", fmt.Errorf("run %s is %s, not executable", id, r.Status))
		}
		r.Status = application.RetentionStatusFailed
		r.FinishedAt = at
		r.Pseudonymised = counts.Pseudonymised
		r.Deleted = counts.Deleted
		r.Failed = counts.Failed
		r.LastError = counts.LastError
		return nil
	})
}

func (f *fakeRetentionRepo) HasActiveHold(_ context.Context, aggregateType, aggregateID string) (bool, error) {
	for _, h := range f.db.legalHolds {
		if h.Active() && h.AggregateType == aggregateType && h.AggregateID == aggregateID {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeRetentionRepo) CreateHold(ctx context.Context, tx application.Tx, rec application.HoldRecord) (application.LegalHold, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.LegalHold{}, err
	}
	ftx.record("retention.hold.insert")
	row := application.LegalHold{
		ID:            uuid.New(),
		AggregateType: rec.AggregateType,
		AggregateID:   rec.AggregateID,
		Reason:        rec.Reason,
		ActorID:       rec.ActorID,
		CreatedAt:     rec.CreatedAt,
	}
	ftx.staged.holdInserts = append(ftx.staged.holdInserts, row)
	return row, nil
}

func (f *fakeRetentionRepo) ReleaseHold(ctx context.Context, tx application.Tx, id string, at time.Time) (application.LegalHold, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.LegalHold{}, err
	}
	ftx.record("retention.hold.release")
	for _, h := range f.db.legalHolds {
		if h.ID != id {
			continue
		}
		if !h.Active() {
			return application.LegalHold{}, application.ConflictError("retention.release_hold", fmt.Errorf("hold %s already released", id))
		}
		ftx.staged.holdReleases = append(ftx.staged.holdReleases, retentionHoldRelease{id: id, at: at})
		h.ReleasedAt = at
		return h, nil
	}
	return application.LegalHold{}, application.NotFoundError("retention.release_hold", fmt.Errorf("hold %s not found", id))
}

func (f *fakeRetentionRepo) ListHolds(_ context.Context, filter application.HoldFilter) ([]application.LegalHold, error) {
	var out []application.LegalHold
	for _, h := range f.db.legalHolds {
		if filter.AggregateType != "" && h.AggregateType != filter.AggregateType {
			continue
		}
		if filter.AggregateID != "" && h.AggregateID != filter.AggregateID {
			continue
		}
		if filter.Active != nil && h.Active() != *filter.Active {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (f *fakeRetentionRepo) PseudonymiseSignal(ctx context.Context, tx application.Tx, signalID string) (application.RetentionRedaction, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.RetentionRedaction{}, err
	}
	ftx.record("retention.pseudonymise_signal")
	if f.failPseudonymiseSignal != nil {
		return application.RetentionRedaction{}, f.failPseudonymiseSignal
	}
	counts := f.db.countSignalRedaction(signalID)
	ftx.staged.redactions = append(ftx.staged.redactions, retentionRedaction{target: "signal", id: signalID})
	return counts, nil
}

func (f *fakeRetentionRepo) PseudonymiseIdentity(ctx context.Context, tx application.Tx, userID string) (application.RetentionRedaction, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.RetentionRedaction{}, err
	}
	ftx.record("retention.pseudonymise_identity")
	counts := f.db.countIdentityRedaction(userID)
	ftx.staged.redactions = append(ftx.staged.redactions, retentionRedaction{target: "identity", id: userID})
	return counts, nil
}

func (f *fakeRetentionRepo) PreviewPseudonymiseIdentity(_ context.Context, userID string) (application.RetentionRedaction, error) {
	return f.db.countIdentityRedaction(userID), nil
}

func (f *fakeRetentionRepo) delete(ctx context.Context, tx application.Tx, table, signalID string) (int, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return 0, err
	}
	ftx.record("retention.delete_" + table)
	if f.failDelete != nil {
		if err, ok := f.failDelete[table]; ok && err != nil {
			return 0, err
		}
	}
	if f.failDeleteSignal != nil {
		if err, ok := f.failDeleteSignal[signalID]; ok && err != nil {
			return 0, err
		}
	}
	n := f.db.countDeletion(table, signalID)
	ftx.staged.deletions = append(ftx.staged.deletions, retentionDeletion{table: table, signalID: signalID})
	return n, nil
}

func (f *fakeRetentionRepo) DeleteSlaClocks(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "sla_clocks", signalID)
}

func (f *fakeRetentionRepo) DeleteComments(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "comments", signalID)
}

func (f *fakeRetentionRepo) DeleteMatches(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "matches", signalID)
}

func (f *fakeRetentionRepo) DeleteNotifications(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "notifications", signalID)
}

func (f *fakeRetentionRepo) DeletePriorityFactors(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "priority_factors", signalID)
}

func (f *fakeRetentionRepo) DeleteAuditEvents(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "audit_events", signalID)
}

func (f *fakeRetentionRepo) DeleteSignal(ctx context.Context, tx application.Tx, signalID string) (int, error) {
	return f.delete(ctx, tx, "risk_signals", signalID)
}
