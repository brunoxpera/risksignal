package repo

// Integration test for the DEV-117 RetentionRepo adapter (ARCH-007 §2/§3,
// WP-6.02/6.05): the candidate scan (held candidates surfaced with their
// reason), the retention-run lifecycle (dry_run → approved → executing →
// completed, plus rejected/failed and the status gates), the legal-hold CRUD,
// the in-place pseudonymisation redaction target set (display name cleared,
// comment body / override reason / snapshot reason redacted, actor_id
// retained) and the referentially-safe §2.3 deletion order with its per-table
// primitives.
//
// It runs against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded set (the shared newI4TestPool helper of
// i4_integration_test.go, same package). When no database is reachable the
// test skips, so `go test ./...` stays green without the environment.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// retentionSeedSignal inserts a closed signal (via the shared i6Seed chain)
// with the full dependent set the §2.3 deletion order and the redaction need:
// a risk_signal override quartet, one comment, one SLA clock, one
// notification and one signal-scoped audit row carrying a free-text reason.
// It returns the signal id and its match id.
func retentionSeedSignal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext, product, cve, actorID, displayName, commentBody, reason string, closedAt time.Time) (signalID, matchID string) {
	t.Helper()

	signalID = i6Seed(t, ctx, pool, ext, i6SignalSeed{
		assetType: "server", product: product, cve: cve,
		priority: "P2", status: "resolved", owner: "alice",
		createdAt: mustTime("2026-01-01T00:00:00Z"), closedAt: closedAt,
	})
	if err := pool.QueryRow(ctx, `SELECT match_id FROM risk_signals WHERE id = $1`, signalID).Scan(&matchID); err != nil {
		t.Fatalf("read match id %s: %v", ext, err)
	}
	// The override quartet, all-set (risk_signals_override_check).
	if _, err := pool.Exec(ctx, `
		UPDATE risk_signals
		SET auto_priority = 'P3', override_reason = $2, override_actor_id = $3, override_at = $4
		WHERE id = $1`, signalID, commentBody+" (override)", actorID, mustTime("2026-02-01T00:00:00Z")); err != nil {
		t.Fatalf("seed override %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO comments (signal_id, actor_id, body, created_at)
		VALUES ($1, $2, $3, $4)`, signalID, actorID, commentBody, mustTime("2026-02-02T00:00:00Z")); err != nil {
		t.Fatalf("seed comment %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		VALUES ($1, 'assessment', $2, $3)`, signalID, mustTime("2026-01-02T00:00:00Z"), mustTime("2026-01-10T00:00:00Z")); err != nil {
		t.Fatalf("seed sla clock %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO notifications (signal_id, channel, kind, status, outbox_event_id, created_at)
		VALUES ($1, 'in_app', 'signal.created', 'delivered', $2, $3)`, signalID, "ob-"+ext, mustTime("2026-01-03T00:00:00Z")); err != nil {
		t.Fatalf("seed notification %s: %v", ext, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, before, after, correlation_id)
		VALUES ('risk_signal', $1, 'user', $2, $3, 'signal.transitioned', $4, NULL, $5, $6)`,
		signalID, actorID, displayName, mustTime("2026-02-03T00:00:00Z"),
		[]byte(`{"reason":"`+reason+`","status":"resolved","priority":"P2"}`), "corr-"+ext); err != nil {
		t.Fatalf("seed audit %s: %v", ext, err)
	}
	return signalID, matchID
}

// retentionWithTx runs fn on one real transaction (postgres.WithTx) and fails
// the test on error.
func retentionWithTx(t *testing.T, pool *pgxpool.Pool, fn func(tx application.Tx) error) {
	t.Helper()
	if err := postgres.WithTx(context.Background(), pool, fn); err != nil {
		t.Fatalf("transaction: %v", err)
	}
}

// countRows runs a COUNT(*) with the given query/args.
func countRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestRetentionRepoIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := NewRetentionRepo(gen.New(pool))

	cutoff := mustTime("2026-03-15T00:00:00Z")

	// --- seed: one due signal with the full dependent set, one held signal ---
	s1, m1 := retentionSeedSignal(t, ctx, pool, "i117-a", "widget", "CVE-2026-2001", "u1", "Alice", "personal note", "closing the case", mustTime("2026-02-01T00:00:00Z"))
	s2, _ := retentionSeedSignal(t, ctx, pool, "i117-b", "gizmo", "CVE-2026-2002", "u2", "Bob", "held note", "held reason", mustTime("2026-02-05T00:00:00Z"))

	// Hold s2 (its reason must be surfaced by the candidate scan).
	var holdID string
	retentionWithTx(t, pool, func(tx application.Tx) error {
		h, err := r.CreateHold(ctx, tx, application.HoldRecord{
			AggregateType: application.AuditAggregateRiskSignal, AggregateID: s2,
			Reason: "litigation 2026-05", ActorID: "admin", CreatedAt: mustTime("2026-03-01T00:00:00Z"),
		})
		if err != nil {
			return err
		}
		holdID = h.ID
		if h.ReleasedAt.IsZero() != true {
			t.Error("fresh hold is not active")
		}
		return nil
	})
	if active, err := r.HasActiveHold(ctx, application.AuditAggregateRiskSignal, s2); err != nil || !active {
		t.Fatalf("HasActiveHold(s2) = %v (err %v), want true", active, err)
	}

	// --- 1. candidate scan surfaces the held candidate with its reason ---
	cands, err := r.ScanRetentionCandidates(ctx, cutoff)
	if err != nil {
		t.Fatalf("ScanRetentionCandidates: %v", err)
	}
	if len(cands) != 2 || cands[0].SignalID != s1 || cands[1].SignalID != s2 {
		t.Fatalf("candidates = %+v, want [%s %s]", cands, s1, s2)
	}
	if cands[0].Held || cands[0].HoldReason != "" {
		t.Fatalf("s1 wrongly held: %+v", cands[0])
	}
	if !cands[1].Held || cands[1].HoldReason != "litigation 2026-05" {
		t.Fatalf("s2 = %+v, want held with the documented reason", cands[1])
	}

	// --- 2. legal-hold list + release (set-once) ---
	yes := true
	holds, err := r.ListHolds(ctx, application.HoldFilter{Active: &yes})
	if err != nil || len(holds) != 1 || holds[0].ID != holdID {
		t.Fatalf("ListHolds(active) = %+v (err %v), want the one active hold", holds, err)
	}
	retentionWithTx(t, pool, func(tx application.Tx) error {
		rel, err := r.ReleaseHold(ctx, tx, holdID, mustTime("2026-03-02T00:00:00Z"))
		if err != nil {
			return err
		}
		if rel.ReleasedAt.IsZero() {
			t.Error("released hold has no released_at")
		}
		return nil
	})
	// A second release matches no row → not-found.
	retentionWithTx(t, pool, func(tx application.Tx) error {
		if _, err := r.ReleaseHold(ctx, tx, holdID, mustTime("2026-03-03T00:00:00Z")); err == nil {
			t.Error("re-releasing a released hold did not error")
		}
		return nil
	})
	if active, err := r.HasActiveHold(ctx, application.AuditAggregateRiskSignal, s2); err != nil || active {
		t.Fatalf("HasActiveHold(s2) after release = %v (err %v), want false", active, err)
	}

	// --- 3. run lifecycle: dry_run → rejected (separate run) / approved →
	//        executing → completed, with the status gates ---
	var mainRun, rejectedRun application.RetentionRun
	retentionWithTx(t, pool, func(tx application.Tx) error {
		var err error
		mainRun, err = r.InsertRun(ctx, tx, application.RetentionRunRecord{
			PolicyID: application.RetentionPolicyClosedSignals, Stage: application.RetentionStageDelete,
			Cutoff: cutoff, PartitionKey: "2026-03", Counts: application.RetentionCounts{Candidates: 2, Held: 1, ToDelete: 2},
		})
		if err != nil {
			return err
		}
		rejectedRun, err = r.InsertRun(ctx, tx, application.RetentionRunRecord{
			PolicyID: application.RetentionPolicyClosedSignals, Stage: application.RetentionStagePseudonymise,
			Cutoff: cutoff, PartitionKey: "2026-04", Counts: application.RetentionCounts{Candidates: 0},
		})
		return err
	})
	if mainRun.Status != application.RetentionStatusDryRun || mainRun.DryRun == nil || mainRun.DryRun.Held != 1 {
		t.Fatalf("inserted run = %+v, want dry_run with the counts report", mainRun)
	}
	// Reject the second run (dry_run → rejected) and prove it is set-once.
	retentionWithTx(t, pool, func(tx application.Tx) error {
		rej, err := r.RejectRun(ctx, tx, rejectedRun.ID, "not now", mustTime("2026-03-16T00:00:00Z"))
		if err != nil {
			return err
		}
		if rej.Status != application.RetentionStatusRejected {
			t.Errorf("rejected status = %q, want rejected", rej.Status)
		}
		return nil
	})
	retentionWithTx(t, pool, func(tx application.Tx) error {
		if _, err := r.RejectRun(ctx, tx, rejectedRun.ID, "again", mustTime("2026-03-16T01:00:00Z")); !isConflict(err) {
			t.Errorf("re-reject err = %v, want conflict", err)
		}
		return nil
	})
	// The execution gate: an un-approved (here rejected) run cannot start.
	retentionWithTx(t, pool, func(tx application.Tx) error {
		if _, err := r.StartRun(ctx, tx, rejectedRun.ID, mustTime("2026-03-16T02:00:00Z")); !isConflict(err) {
			t.Errorf("start un-approved run err = %v, want conflict", err)
		}
		return nil
	})
	// Approve → start the main run.
	retentionWithTx(t, pool, func(tx application.Tx) error {
		appr, err := r.ApproveRun(ctx, tx, mainRun.ID, "po", "due for retention", mustTime("2026-03-17T00:00:00Z"))
		if err != nil {
			return err
		}
		if appr.Status != application.RetentionStatusApproved || appr.ApprovedBy != "po" {
			t.Errorf("approved run = %+v, want approved by po", appr)
		}
		return nil
	})
	retentionWithTx(t, pool, func(tx application.Tx) error {
		st, err := r.StartRun(ctx, tx, mainRun.ID, mustTime("2026-03-17T01:00:00Z"))
		if err != nil {
			return err
		}
		if st.Status != application.RetentionStatusExecuting {
			t.Errorf("started run = %+v, want executing", st)
		}
		return nil
	})

	// --- 4. pseudonymise s1 in place (signal-scoped redaction target set) ---
	var red application.RetentionRedaction
	retentionWithTx(t, pool, func(tx application.Tx) error {
		var err error
		red, err = r.PseudonymiseSignal(ctx, tx, s1)
		return err
	})
	if red.DisplayNamesCleared != 1 || red.CommentBodiesRedacted != 1 || red.OverrideReasonsRedacted != 1 || red.SnapshotReasonsRedacted != 1 {
		t.Fatalf("signal redaction = %+v, want 1 per target", red)
	}
	var displayName, body, override, after string
	var actorID string
	if err := pool.QueryRow(ctx, `
		SELECT coalesce(actor_display_name, ''), actor_id, after::text
		FROM audit_events WHERE aggregate_id = $1 AND aggregate_type = 'risk_signal'`, s1).Scan(&displayName, &actorID, &after); err != nil {
		t.Fatalf("read redacted audit: %v", err)
	}
	if displayName != "" || actorID != "u1" {
		t.Fatalf("audit row = name %q actor %q, want name cleared and actor_id retained", displayName, actorID)
	}
	if err := pool.QueryRow(ctx, `SELECT body FROM comments WHERE signal_id = $1`, s1).Scan(&body); err != nil {
		t.Fatalf("read redacted comment: %v", err)
	}
	if body != application.RetentionRedactionMarker {
		t.Fatalf("comment body = %q, want the redaction marker", body)
	}
	if err := pool.QueryRow(ctx, `SELECT override_reason FROM risk_signals WHERE id = $1`, s1).Scan(&override); err != nil {
		t.Fatalf("read redacted override: %v", err)
	}
	if override != application.RetentionRedactionMarker {
		t.Fatalf("override reason = %q, want the redaction marker", override)
	}
	var snap map[string]any
	if err := json.Unmarshal([]byte(after), &snap); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap["reason"] != application.RetentionRedactionMarker || snap["status"] != "resolved" {
		t.Fatalf("snapshot = %v, want redacted reason with structured keys retained", snap)
	}

	// --- 5. referentially-safe §2.3 deletion of s1 ---
	var deletes [7]int
	retentionWithTx(t, pool, func(tx application.Tx) error {
		var err error
		if deletes[0], err = r.DeleteSlaClocks(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[1], err = r.DeleteComments(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[2], err = r.DeleteMatches(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[3], err = r.DeleteNotifications(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[4], err = r.DeletePriorityFactors(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[5], err = r.DeleteAuditEvents(ctx, tx, s1); err != nil {
			return err
		}
		if deletes[6], err = r.DeleteSignal(ctx, tx, s1); err != nil {
			return err
		}
		return nil
	})
	if deletes[0] != 1 || deletes[1] != 1 || deletes[3] != 1 || deletes[5] != 1 || deletes[6] != 1 {
		t.Fatalf("delete counts = %v, want 1 for sla/comments/notifications/audit/signal", deletes)
	}
	if deletes[2] != 0 || deletes[4] != 0 {
		t.Fatalf("delete counts = %v, want 0 for matches (FK-guarded) and priority_factors (inline)", deletes)
	}
	if countRows(t, ctx, pool, `SELECT count(*) FROM risk_signals WHERE id = $1`, s1) != 0 {
		t.Fatal("the signal survived")
	}
	if countRows(t, ctx, pool, `SELECT count(*) FROM matches WHERE id = $1`, m1) != 0 {
		t.Fatal("the signal's match was not removed with the signal")
	}
	if countRows(t, ctx, pool, `SELECT count(*) FROM comments WHERE signal_id = $1`, s1) != 0 ||
		countRows(t, ctx, pool, `SELECT count(*) FROM sla_clocks WHERE signal_id = $1`, s1) != 0 ||
		countRows(t, ctx, pool, `SELECT count(*) FROM notifications WHERE signal_id = $1`, s1) != 0 ||
		countRows(t, ctx, pool, `SELECT count(*) FROM audit_events WHERE aggregate_id = $1 AND aggregate_type = 'risk_signal'`, s1) != 0 {
		t.Fatal("a non-shared dependent survived the deletion")
	}
	// Shared data (the vulnerability the match referenced) is untouched.
	if countRows(t, ctx, pool, `SELECT count(*) FROM vulnerabilities`) == 0 {
		t.Fatal("shared vulnerability data was deleted")
	}
	// The held signal s2 is untouched (its hold was released *after* the
	// dry-run, so a hold set between dry-run and execution is honoured by the
	// use case's per-candidate re-check — here we assert the adapter leaves it).
	if countRows(t, ctx, pool, `SELECT count(*) FROM risk_signals WHERE id = $1`, s2) != 1 {
		t.Fatal("the other signal was wrongly deleted")
	}

	// --- 6. the report survives, closed with the final counts ---
	retentionWithTx(t, pool, func(tx application.Tx) error {
		done, err := r.CompleteRun(ctx, tx, mainRun.ID, application.RetentionRunCounts{Pseudonymised: 1, Deleted: 1}, mustTime("2026-03-17T02:00:00Z"))
		if err != nil {
			return err
		}
		if done.Status != application.RetentionStatusCompleted || done.Deleted != 1 || done.Pseudonymised != 1 {
			t.Errorf("completed run = %+v, want completed with the final counts", done)
		}
		return nil
	})
	readRun, err := r.GetRun(ctx, mainRun.ID)
	if err != nil || readRun.Status != application.RetentionStatusCompleted || readRun.Deleted != 1 {
		t.Fatalf("GetRun = %+v (err %v), want the completed report", readRun, err)
	}
	// A missing run is a validation-free not-found.
	if _, err := r.GetRun(ctx, "11111111-1111-1111-1111-111111111111"); err == nil {
		t.Fatal("GetRun on a missing id did not error")
	}

	// --- 7. identity pseudonymisation: dry-run equals the real counts ---
	retentionSeedIdentityRows(t, ctx, pool, s2, "u5")
	preview, err := r.PreviewPseudonymiseIdentity(ctx, "u5")
	if err != nil || preview.Total() == 0 {
		t.Fatalf("preview = %+v (err %v), want a non-empty redaction", preview, err)
	}
	var real application.RetentionRedaction
	retentionWithTx(t, pool, func(tx application.Tx) error {
		var err error
		real, err = r.PseudonymiseIdentity(ctx, tx, "u5")
		return err
	})
	if real != preview {
		t.Fatalf("identity redaction %+v != preview %+v", real, preview)
	}
	var identName string
	if err := pool.QueryRow(ctx, `SELECT coalesce(actor_display_name,'') FROM audit_events WHERE actor_id = 'u5'`).Scan(&identName); err != nil {
		t.Fatalf("read identity audit: %v", err)
	}
	if identName != "" {
		t.Fatalf("identity display name = %q, want cleared", identName)
	}
	if afterPreview, err := r.PreviewPseudonymiseIdentity(ctx, "u5"); err != nil || afterPreview.Total() != 0 {
		t.Fatalf("preview after real run = %+v (err %v), want empty (idempotent)", afterPreview, err)
	}
}

// retentionSeedIdentityRows adds an audit row + comment + override for one
// identity on the given signal, for the identity-scoped redaction test.
func retentionSeedIdentityRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, signalID, actorID string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_events (aggregate_type, aggregate_id, actor_type, actor_id, actor_display_name, action, occurred_at, before, after, correlation_id)
		VALUES ('risk_signal', $1, 'user', $2, 'Carol', 'signal.commented', $3, NULL, $4, 'corr-id')`,
		signalID, actorID, mustTime("2026-02-04T00:00:00Z"), []byte(`{"reason":"identity reason","status":"resolved"}`)); err != nil {
		t.Fatalf("seed identity audit: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO comments (signal_id, actor_id, body, created_at)
		VALUES ($1, $2, 'identity comment', $3)`, signalID, actorID, mustTime("2026-02-04T01:00:00Z")); err != nil {
		t.Fatalf("seed identity comment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE risk_signals
		SET auto_priority = 'P4', override_reason = 'identity override', override_actor_id = $2, override_at = $3
		WHERE id = $1`, signalID, actorID, mustTime("2026-02-04T02:00:00Z")); err != nil {
		t.Fatalf("seed identity override: %v", err)
	}
}

// isConflict reports whether err is an application conflict Error.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	kind, ok := application.ErrorKindOf(err)
	return ok && kind == application.KindConflict
}
