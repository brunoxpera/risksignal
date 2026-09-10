package application_test

// Unit tests of the quarantine review use cases (DEV-030 / WP-2.04,
// ARCH-002 §4, ch. 13.2): QuarantineList (working list + validation),
// QuarantineAck (new -> acknowledged + audit event, one transaction) and
// QuarantineReprocess (re-run the normaliser over the raw record: clean
// pass -> resolved with the link to the new domain object + audit; still
// failing -> attempts + 1, stays retryable + audit; infrastructure failure
// -> rollback, no state change). Every transition is written atomically
// with its audit event (one command, one transaction, ch. 5.1).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// seedQuarantined fixtures one source, one raw record and one quarantined
// isolation behind the use cases under test.
func seedQuarantined(h *harness, t *testing.T) domain.Quarantine {
	t.Helper()
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID: "src-kev", Type: application.SourceTypeKEV,
	})
	h.db.rawRecords = append(h.db.rawRecords, storedRawRecord{
		id: "raw-q", sourceID: "src-kev", externalID: "kev-2026-09-09",
		contentHash: "kev-hash", contentEncoding: "json",
		payload: []byte(`[{"cveID":"CVE-2026-3001"}]`), fetchedAt: fixedNow,
	})
	q, err := domain.NewQuarantine("quar-1", "src-kev", "run-1", "raw-q", "records/0",
		"parse.invalid_cve_id: CVE id is empty", "hash-of-offending-slice")
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	h.db.quarantine = append(h.db.quarantine, q)
	return q
}

// TestQuarantineListFiltersAndValidates is the working-list read of the
// quarantine (ch. 11.3): optional status/source filters, oldest first, and
// validation-class mistakes rejected before any query.
func TestQuarantineListFiltersAndValidates(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	open, err := h.svc.QuarantineList(ctx, application.QuarantineListInput{Limit: 10})
	if err != nil || len(open) != 1 || open[0].ID != "quar-1" {
		t.Fatalf("QuarantineList(open) = %+v, %v; want the seeded row", open, err)
	}

	statusNew := domain.QuarantineStatusNew
	byStatus, err := h.svc.QuarantineList(ctx, application.QuarantineListInput{Status: &statusNew, Limit: 10})
	if err != nil || len(byStatus) != 1 {
		t.Fatalf("QuarantineList(status=new) = %+v, %v; want the seeded row", byStatus, err)
	}
	statusResolved := domain.QuarantineStatusResolved
	byResolved, err := h.svc.QuarantineList(ctx, application.QuarantineListInput{Status: &statusResolved, Limit: 10})
	if err != nil || len(byResolved) != 0 {
		t.Fatalf("QuarantineList(status=resolved) = %+v, %v; want no rows", byResolved, err)
	}
	bySource, err := h.svc.QuarantineList(ctx, application.QuarantineListInput{SourceID: "src-kev", Limit: 10})
	if err != nil || len(bySource) != 1 {
		t.Fatalf("QuarantineList(source) = %+v, %v; want the seeded row", bySource, err)
	}

	// Validation mistakes: a zero page size and an unknown status filter.
	_, limitErr := h.svc.QuarantineList(ctx, application.QuarantineListInput{Limit: 0})
	if kind, _ := application.ErrorKindOf(limitErr); kind != application.KindValidation {
		t.Fatalf("QuarantineList(limit 0) error = %v, want validation", limitErr)
	}
	bogus := domain.QuarantineStatus("gone")
	_, statusErr := h.svc.QuarantineList(ctx, application.QuarantineListInput{Status: &bogus, Limit: 10})
	if kind, _ := application.ErrorKindOf(statusErr); kind != application.KindValidation {
		t.Fatalf("QuarantineList(bogus status) error = %v, want validation", statusErr)
	}
}

// TestQuarantineAckTransitionAndAudit is the required ack behaviour: new ->
// acknowledged with the operator and the note recorded, the audit event
// written atomically with the state change, and the machine's guards
// enforced (no double ack, no ack of a resolved row).
func TestQuarantineAckTransitionAndAudit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	updated, err := h.svc.QuarantineAck(ctx, application.QuarantineAckInput{
		ID:    "quar-1",
		Note:  "reviewed: parser fix upcoming",
		Actor: systemActor("ops@example.com"),
	})
	if err != nil {
		t.Fatalf("QuarantineAck: %v", err)
	}
	if updated.Status != domain.QuarantineStatusAcknowledged ||
		updated.AcknowledgedBy != "ops@example.com" || updated.AcknowledgedNote != "reviewed: parser fix upcoming" {
		t.Fatalf("updated row = %+v, want acknowledged with operator + note", updated)
	}

	// Committed state changed; one audit event accompanies the transition
	// (quarantine.acknowledged, actor = the acknowledged_by principal).
	committed, ok := h.db.quarantineByID("quar-1")
	if !ok || committed.Status != domain.QuarantineStatusAcknowledged {
		t.Fatalf("committed row = %+v, want acknowledged", committed)
	}
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit events = %d, want 1", len(h.db.auditEvents))
	}
	ev := h.db.auditEvents[0]
	if ev.Action != application.AuditActionQuarantineAcknowledged ||
		ev.AggregateType != application.AuditAggregateQuarantine || ev.AggregateID != "quar-1" ||
		ev.ActorType != application.ActorTypeSystem || ev.ActorID != "ops@example.com" {
		t.Fatalf("audit event = %+v, want quarantine.acknowledged by ops@example.com", ev)
	}
	before := decodeJSON(t, ev.Before).(map[string]any)
	after := decodeJSON(t, ev.After).(map[string]any)
	if before["status"] != "new" || after["status"] != "acknowledged" {
		t.Fatalf("audit snapshots before/after = %v/%v, want new -> acknowledged", ev.Before, ev.After)
	}

	// The machine guards: an already acknowledged row cannot be
	// acknowledged again (validation before any write) ...
	_, ackErr := h.svc.QuarantineAck(ctx, application.QuarantineAckInput{ID: "quar-1", Note: "again", Actor: systemActor("ops@example.com")})
	if kind, _ := application.ErrorKindOf(ackErr); kind != application.KindValidation {
		t.Fatalf("second ack error = %v, want validation", err)
	}
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit events after double ack = %d, want still 1 — no event of a transition that did not happen", len(h.db.auditEvents))
	}

	// ... and an unknown id is a not-found error.
	_, missingErr := h.svc.QuarantineAck(ctx, application.QuarantineAckInput{ID: "quar-nope", Actor: systemActor("ops@example.com")})
	if kind, _ := application.ErrorKindOf(missingErr); kind != application.KindNotFound {
		t.Fatalf("ack of unknown id error = %v, want not-found", missingErr)
	}
}

// TestQuarantineReprocessResolvesWithAudit is the required reprocess
// behaviour (ARCH-002 §6 exit criterion 2): a clean pass resolves the row
// (-> resolved), links the new domain object the pass materialised and
// writes the quarantine.resolved audit event atomically with the state
// change.
func TestQuarantineReprocessResolvesWithAudit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		// The corrected parser materialises the record that was isolated.
		if err := emitVuln(ctx, sink, "CVE-2026-3001", "kev skeleton"); err != nil {
			return application.NormalizeResult{}, err
		}
		if err := emitEvidence(ctx, sink, "CVE-2026-3001", domain.EvidenceTypeKEV); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 2}, nil
	}

	result, err := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src, Actor: systemActor("ops@example.com")})
	if err != nil {
		t.Fatalf("QuarantineReprocess: %v", err)
	}
	if !result.Resolved || result.Errors != 0 || result.Records != 2 {
		t.Fatalf("result = %+v, want a resolved clean pass (records 2)", result)
	}
	if result.Quarantine.Status != domain.QuarantineStatusResolved {
		t.Fatalf("result row status = %s, want resolved", result.Quarantine.Status)
	}

	// The committed row is resolved and linked to the vulnerability the
	// pass upserted (the single-record pass link, ARCH-002 §4) and to the
	// evidence row it wrote (the AddEvidence id return, ARCH-003 §7).
	committed, _ := h.db.quarantineByID("quar-1")
	if committed.Status != domain.QuarantineStatusResolved || committed.ResolvedVulnerabilityID == "" {
		t.Fatalf("committed row = %+v, want resolved with the new vulnerability linked", committed)
	}
	if len(h.db.vulns) != 1 || h.db.vulns[0].id != committed.ResolvedVulnerabilityID {
		t.Fatalf("vulns = %+v, want the pass's vulnerability %s linked", h.db.vulns, committed.ResolvedVulnerabilityID)
	}
	if committed.ResolvedEvidenceID == "" {
		t.Fatal("committed row links no evidence, want resolved_evidence_id on the pass's new evidence")
	}
	if len(h.db.evidenceRows) != 1 || h.db.evidenceRows[0].id != committed.ResolvedEvidenceID {
		t.Fatalf("evidence rows = %+v, want the pass's evidence %s linked", h.db.evidenceRows, committed.ResolvedEvidenceID)
	}

	// The audit event of the terminal transition.
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit events = %d, want 1", len(h.db.auditEvents))
	}
	ev := h.db.auditEvents[0]
	if ev.Action != application.AuditActionQuarantineResolved || ev.AggregateID != "quar-1" {
		t.Fatalf("audit event = %+v, want quarantine.resolved of quar-1", ev)
	}
	after := decodeJSON(t, ev.After).(map[string]any)
	if after["status"] != "resolved" {
		t.Fatalf("audit after snapshot = %v, want resolved", ev.After)
	}

	// resolved is terminal: a further reprocess is rejected without a write.
	_, ackErr := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src})
	if kind, _ := application.ErrorKindOf(ackErr); kind != application.KindValidation {
		t.Fatalf("reprocess of a resolved row error = %v, want validation (terminal)", err)
	}
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit events after terminal reprocess = %d, want still 1", len(h.db.auditEvents))
	}
}

// TestQuarantineReprocessStillFailingIncrementsAttempts is the required
// reprocess-failure behaviour (ARCH-002 §4: reprocess failed -> attempts +
// 1, the row stays retryable): the pass still isolates the offending record
// — which is an audited state change, never an error and never an abort.
func TestQuarantineReprocessStillFailingIncrementsAttempts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		// The record still fails: isolated again, re-addressable.
		if err := sink.RecordError(ctx, application.RecordError{
			Position:    "records/0",
			Reason:      "parse.invalid_cve_id: CVE id is empty",
			PayloadHash: "hash-of-offending-slice",
		}); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 0, Errors: 1}, nil
	}

	result, err := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src})
	if err != nil {
		t.Fatalf("QuarantineReprocess: %v", err)
	}
	if result.Resolved || result.Errors != 1 {
		t.Fatalf("result = %+v, want a failed attempt (errors 1, not resolved)", result)
	}
	committed, _ := h.db.quarantineByID("quar-1")
	if committed.Status != domain.QuarantineStatusNew || committed.Attempts != 1 {
		t.Fatalf("committed row = %+v, want still new with attempts 1 (stays retryable)", committed)
	}
	if len(h.db.auditEvents) != 1 || h.db.auditEvents[0].Action != application.AuditActionQuarantineReprocessed {
		t.Fatalf("audit events = %+v, want one quarantine.reprocessed event", h.db.auditEvents)
	}
}

// TestQuarantineReprocessInfraFailureRollsBack is the reprocess fault seam:
// an infrastructure failure of the pass rolls everything back — no partial
// domain objects, no attempts increment, no audit event — and surfaces as
// the returned error.
func TestQuarantineReprocessInfraFailureRollsBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-3001", "kev skeleton"); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{}, errors.New("reprocess: sink write failed")
	}

	_, err := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error", err)
	}
	committed, _ := h.db.quarantineByID("quar-1")
	if committed.Status != domain.QuarantineStatusNew || committed.Attempts != 0 {
		t.Fatalf("committed row = %+v, want unchanged (no state change on infra failure)", committed)
	}
	if len(h.db.vulns) != 0 || len(h.db.auditEvents) != 0 {
		t.Fatalf("vulns/audit = %d/%d, want 0 — the pass rolled back entirely", len(h.db.vulns), len(h.db.auditEvents))
	}
}

// TestQuarantineReprocessFromAcknowledgedMovesToRetryableFirst exercises
// the acknowledged -> ready_for_retry -> resolved leg of the machine: the
// reprocess of an acknowledged row moves it to the retryable state inside
// the same command before the attempt runs.
func TestQuarantineReprocessFromAcknowledgedMovesToRetryableFirst(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	// Review the row first (new -> acknowledged), then reprocess it.
	acked, err := h.svc.QuarantineAck(ctx, application.QuarantineAckInput{ID: "quar-1", Note: "reviewed", Actor: systemActor("ops@example.com")})
	if err != nil || acked.Status != domain.QuarantineStatusAcknowledged {
		t.Fatalf("QuarantineAck = %+v, %v", acked, err)
	}

	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-3001", "kev skeleton"); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 1}, nil
	}
	result, err := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src})
	if err != nil || !result.Resolved {
		t.Fatalf("QuarantineReprocess(acknowledged) = %+v, %v; want resolved", result, err)
	}
	committed, _ := h.db.quarantineByID("quar-1")
	if committed.Status != domain.QuarantineStatusResolved || committed.Attempts != 0 {
		t.Fatalf("committed row = %+v, want resolved (via ready_for_retry) with attempts 0", committed)
	}
	// One audit event for the command's terminal transition.
	if len(h.db.auditEvents) != 2 {
		t.Fatalf("audit events = %d, want 2 (acknowledged + resolved)", len(h.db.auditEvents))
	}
	if h.db.auditEvents[1].Action != application.AuditActionQuarantineResolved {
		t.Fatalf("second audit action = %q, want quarantine.resolved", h.db.auditEvents[1].Action)
	}
}

// TestQuarantineSnapshotMinimalNoSecrets pins the audit snapshot shape of
// the quarantine transitions (ch. 13.5): the before/after snapshots carry
// status and attempts only — never the payload hash, the reason text or any
// other content that could embed secret material.
func TestQuarantineSnapshotMinimalNoSecrets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	_, err := h.svc.QuarantineAck(ctx, application.QuarantineAckInput{ID: "quar-1", Note: "reviewed", Actor: systemActor("ops@example.com")})
	if err != nil {
		t.Fatalf("QuarantineAck: %v", err)
	}
	ev := h.db.auditEvents[0]
	var before, after map[string]any
	if err := json.Unmarshal(ev.Before, &before); err != nil {
		t.Fatalf("before snapshot: %v", err)
	}
	if err := json.Unmarshal(ev.After, &after); err != nil {
		t.Fatalf("after snapshot: %v", err)
	}
	for _, snap := range []map[string]any{before, after} {
		if len(snap) != 2 {
			t.Fatalf("snapshot carries %d keys, want exactly status + attempts (minimised, ch. 13.5)", len(snap))
		}
	}
	if _, has := before["payload_hash"]; has {
		t.Fatalf("snapshot leaks payload_hash: %s", ev.Before)
	}
}

// TestQuarantineReprocessLinksEvidenceOnlyForSingleEvidencePass pins the
// exactness of the resolved_evidence_id link (ARCH-003 §7, DEV-053): a
// single-vulnerability pass that writes exactly one evidence row links that
// evidence, while a pass with several evidences links only the
// vulnerability — a multi-evidence pass names no single evidence and
// resolves with the outcome note alone (mirroring the single-upsert
// vulnerability link).
func TestQuarantineReprocessLinksEvidenceOnlyForSingleEvidencePass(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedQuarantined(h, t)

	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-3001", "kev skeleton"); err != nil {
			return application.NormalizeResult{}, err
		}
		if err := emitEvidence(ctx, sink, "CVE-2026-3001", domain.EvidenceTypeKEV); err != nil {
			return application.NormalizeResult{}, err
		}
		if err := emitEvidence(ctx, sink, "CVE-2026-3001", domain.EvidenceTypeCVSS); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 3}, nil
	}

	result, err := h.svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{ID: "quar-1", Adapter: src})
	if err != nil || !result.Resolved {
		t.Fatalf("QuarantineReprocess = %+v, %v; want resolved", result, err)
	}
	committed, _ := h.db.quarantineByID("quar-1")
	if committed.ResolvedVulnerabilityID == "" {
		t.Fatal("committed row links no vulnerability, want the single upsert linked")
	}
	if committed.ResolvedEvidenceID != "" {
		t.Fatalf("committed row evidence link = %q, want an empty link — a two-evidence pass names no single evidence", committed.ResolvedEvidenceID)
	}
	if len(h.db.evidenceRows) != 2 {
		t.Fatalf("evidence rows = %d, want the pass's 2 distinct evidences", len(h.db.evidenceRows))
	}
}
