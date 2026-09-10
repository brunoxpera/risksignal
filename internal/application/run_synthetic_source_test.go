package application_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedPortalComponent seeds the inventory the run matches against: one asset
// running acme/portal 2.4.4 (the C1–C3 fixture context: critical +
// internet).
func seedPortalComponent(h *harness) {
	h.db.components = append(h.db.components, application.Component{
		ID: "comp-portal", AssetID: "asset-portal",
		Vendor: "acme", Product: "portal", Version: "2.4.4",
	})
}

// c1Case is the ARCH-001 §3 reference case C1 (P1: high confidence + KEV +
// critical/internet), expressed as the typed run input.
func c1Case() application.SyntheticCase {
	return application.SyntheticCase{
		CVEID:     "CVE-2024-0001",
		Summary:   "synthetic case one",
		Statement: "acme/portal 2.4 before 2.4.5 is affected",
		Product:   application.Product{Vendor: "acme", Product: "portal", Version: "2.4"},
		CVSS:      9.8,
		KEV:       true,
		EPSS:      0.99,
		Asset: application.SyntheticAsset{
			Criticality: domain.CriticalityCritical,
			Exposure:    domain.ExposureInternet,
		},
	}
}

// e1Case is the malformed reference case: no cve_id (concept ch. 8.1
// step 5); the run must count it as an error without aborting the others.
func e1Case() application.SyntheticCase {
	return application.SyntheticCase{
		Summary: "malformed case",
		Product: application.Product{Vendor: "acme", Product: "portal", Version: "2.4"},
		Asset: application.SyntheticAsset{
			Criticality: domain.CriticalityCritical,
			Exposure:    domain.ExposureInternet,
		},
	}
}

func runInput(cases ...application.SyntheticCase) application.RunSyntheticSourceInput {
	return application.RunSyntheticSourceInput{
		SourceID:   "source-synthetic",
		ExternalID: "synthetic-reference",
		Cases:      cases,
	}
}

// TestRunSyntheticSourceCountsE1WithoutAborting is the required run test:
// a good case produces the full chain (vulnerability, four evidences, match,
// signal + audit + outbox), the malformed E1 case is counted as a run error
// (status failed, error recorded) and does not abort the other cases.
func TestRunSyntheticSourceCountsE1WithoutAborting(t *testing.T) {
	h := newHarness(t)
	seedPortalComponent(h)
	ctx := context.Background()

	// E1 second on purpose: the good case must be processed before and
	// after the malformed one is skipped.
	res, err := h.svc.RunSyntheticSource(ctx, runInput(c1Case(), e1Case()))
	if err != nil {
		t.Fatalf("RunSyntheticSource: %v", err)
	}

	// Run outcome: completed (no error), failed status with the E1 error
	// counted and recorded (concept ch. 8.1 step 5, ARCH-001 §3 step 6).
	if res.Status != application.SourceRunStatusFailed {
		t.Fatalf("run status = %s, want failed (E1 counted)", res.Status)
	}
	if res.Counters.Records != 2 || res.Counters.Matched != 1 || res.Counters.Signals != 1 {
		t.Fatalf("counters = %+v, want records 2 matched 1 signals 1", res.Counters)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "case 1: missing cve_id") {
		t.Fatalf("run errors = %v, want the E1 case counted", res.Errors)
	}

	// One run row with the terminal state and the recorded error.
	if len(h.db.sourceRuns) != 1 {
		t.Fatalf("source runs = %d, want 1", len(h.db.sourceRuns))
	}
	run := h.db.sourceRuns[0]
	if run.status != string(application.SourceRunStatusFailed) || !strings.Contains(run.errText, "missing cve_id") {
		t.Fatalf("run row = status %q error %q, want failed with the E1 error", run.status, run.errText)
	}
	if run.counters != res.Counters {
		t.Fatalf("run row counters = %+v, want %+v", run.counters, res.Counters)
	}

	// Ingest: one document, one vulnerability (the good case only) with its
	// four immutable evidence statements.
	if len(h.db.rawRecords) != 1 {
		t.Fatalf("raw records = %d, want 1", len(h.db.rawRecords))
	}
	if len(h.db.vulns) != 1 || h.db.vulns[0].cveID != "CVE-2024-0001" {
		t.Fatalf("vulnerabilities = %+v, want the good case's CVE-2024-0001", h.db.vulns)
	}
	if len(h.db.evidenceRows) != 4 {
		t.Fatalf("evidence rows = %d, want the 4 typed statements of the good case", len(h.db.evidenceRows))
	}
	for _, e := range h.db.evidenceRows {
		sum := sha256.Sum256(e.value)
		if hex.EncodeToString(sum[:]) != e.hash {
			t.Fatalf("evidence %s: value hash %q does not match the canonical payload", e.typ, e.hash)
		}
		var v map[string]any
		if err := json.Unmarshal(e.value, &v); err != nil {
			t.Fatalf("decode evidence value: %v", err)
		}
		if v["cve_id"] != "CVE-2024-0001" {
			t.Fatalf("evidence %s value = %v, want the cve_id carried", e.typ, v)
		}
	}

	// Match + signal: one match, and the CreateSignal command wrote signal,
	// audit and outbox atomically, linked to the run's correlation id.
	if len(h.db.matchRows) != 1 {
		t.Fatalf("match rows = %d, want 1", len(h.db.matchRows))
	}
	match := h.db.matchRows[0]
	if match.rec.Method != domain.MatchMethodCanonicalProductRange || match.rec.Confidence != domain.ConfidenceHigh {
		t.Fatalf("match = %+v, want canonical_product_range/high (2.4 range covers 2.4.4)", match.rec)
	}
	if len(h.db.signalRows) != 1 || len(h.db.auditEvents) != 1 || len(h.db.outboxEvents) != 1 {
		t.Fatalf("signal/audit/outbox = %d/%d/%d, want 1/1/1",
			len(h.db.signalRows), len(h.db.auditEvents), len(h.db.outboxEvents))
	}
	sig := h.db.signalRows[0].sig
	if sig.Priority != domain.PriorityP1 {
		t.Fatalf("signal priority = %s, want P1 (ch. 9.3 for the C1 context)", sig.Priority)
	}
	if h.db.auditEvents[0].CorrelationID != res.RunID {
		t.Fatalf("audit correlation_id = %q, want the run id %q", h.db.auditEvents[0].CorrelationID, res.RunID)
	}
}

// TestRunSyntheticSourceUnmatchedCaseIsNotASignal: the C6 case — a product
// without a seeded component — is ingested (vulnerability + evidences) but
// produces no match and no signal; the run stays succeeded.
func TestRunSyntheticSourceUnmatchedCaseIsNotASignal(t *testing.T) {
	h := newHarness(t)
	seedPortalComponent(h)
	ctx := context.Background()

	unmatched := c1Case()
	unmatched.CVEID = "CVE-2024-0006"
	unmatched.Product = application.Product{Vendor: "acme", Product: "ghost", Version: "1.0"}

	res, err := h.svc.RunSyntheticSource(ctx, runInput(unmatched))
	if err != nil {
		t.Fatalf("RunSyntheticSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run status = %s, want succeeded", res.Status)
	}
	if res.Counters.Records != 1 || res.Counters.Matched != 0 || res.Counters.Signals != 0 {
		t.Fatalf("counters = %+v, want records 1 matched 0 signals 0", res.Counters)
	}
	if len(h.db.vulns) != 1 || len(h.db.evidenceRows) != 4 {
		t.Fatalf("vulns/evidences = %d/%d, want the case ingested without a match", len(h.db.vulns), len(h.db.evidenceRows))
	}
	if len(h.db.matchRows) != 0 || len(h.db.signalRows) != 0 {
		t.Fatalf("matches/signals = %d/%d, want none", len(h.db.matchRows), len(h.db.signalRows))
	}
}

// TestRunSyntheticSourceIsIdempotentOnRerun: re-running the same document is
// a no-op at every level — the natural-key upserts dedupe and the existence
// check skips signal creation (ARCH-001 §3 reproducibility guarantee).
func TestRunSyntheticSourceIsIdempotentOnRerun(t *testing.T) {
	h := newHarness(t)
	seedPortalComponent(h)
	ctx := context.Background()

	first, err := h.svc.RunSyntheticSource(ctx, runInput(c1Case()))
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.Status != application.SourceRunStatusSucceeded || first.Counters.Signals != 1 {
		t.Fatalf("first run = %+v, want succeeded with 1 signal", first)
	}

	second, err := h.svc.RunSyntheticSource(ctx, runInput(c1Case()))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("second run status = %s, want succeeded", second.Status)
	}
	if second.Counters.Records != 1 || second.Counters.Matched != 1 || second.Counters.Signals != 0 {
		t.Fatalf("second run counters = %+v, want records 1 matched 1 signals 0 (no new signals)", second.Counters)
	}

	// No duplicates anywhere: one run row per execution, one row per table.
	if len(h.db.sourceRuns) != 2 {
		t.Fatalf("source runs = %d, want 2 (one per execution)", len(h.db.sourceRuns))
	}
	if len(h.db.rawRecords) != 1 || len(h.db.vulns) != 1 || len(h.db.evidenceRows) != 4 ||
		len(h.db.matchRows) != 1 || len(h.db.signalRows) != 1 {
		t.Fatalf("duplicates after re-run: raw=%d vulns=%d evidences=%d matches=%d signals=%d, want 1/1/4/1/1",
			len(h.db.rawRecords), len(h.db.vulns), len(h.db.evidenceRows), len(h.db.matchRows), len(h.db.signalRows))
	}
	if len(h.db.auditEvents) != 1 || len(h.db.outboxEvents) != 1 {
		t.Fatalf("audit/outbox after re-run = %d/%d, want the single original event pair", len(h.db.auditEvents), len(h.db.outboxEvents))
	}
}

// TestRunSyntheticSourceInfraFailureAbortsTheRun: a signal-creation failure
// (here: the ARCH-001 §5 outbox fault) aborts the run — the run row ends
// failed with the error, the failed signal transaction left nothing behind,
// and the error propagates to the caller.
func TestRunSyntheticSourceInfraFailureAbortsTheRun(t *testing.T) {
	h := newHarness(t)
	seedPortalComponent(h)
	ctx := context.Background()

	cause := errors.New("outbox down")
	h.outbox.failpoint = application.InfraError("outbox.append", cause)

	_, err := h.svc.RunSyntheticSource(ctx, runInput(c1Case()))
	if err == nil {
		t.Fatal("RunSyntheticSource succeeded, want the outbox failure to abort the run")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want the injected cause", err)
	}
	if len(h.db.sourceRuns) != 1 {
		t.Fatalf("source runs = %d, want 1", len(h.db.sourceRuns))
	}
	run := h.db.sourceRuns[0]
	if run.status != string(application.SourceRunStatusFailed) {
		t.Fatalf("run status = %q, want failed", run.status)
	}
	// The aborted signal creation was rolled back: no signal, no audit, no
	// outbox row is observable.
	if len(h.db.signalRows) != 0 || len(h.db.auditEvents) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("signal/audit/outbox after abort = %d/%d/%d, want none",
			len(h.db.signalRows), len(h.db.auditEvents), len(h.db.outboxEvents))
	}
	// The ingest of the document itself committed before the failure.
	if len(h.db.rawRecords) != 1 || len(h.db.vulns) != 1 || len(h.db.evidenceRows) != 4 || len(h.db.matchRows) != 1 {
		t.Fatalf("ingest rows after abort = raw %d vulns %d evidences %d matches %d, want the committed ingest",
			len(h.db.rawRecords), len(h.db.vulns), len(h.db.evidenceRows), len(h.db.matchRows))
	}
}

// TestRunSyntheticSourceValidatesInput covers the command-level validation
// (missing source/external id) that precedes any run.
func TestRunSyntheticSourceValidatesInput(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for name, in := range map[string]application.RunSyntheticSourceInput{
		"empty source id":   {ExternalID: "synthetic-reference"},
		"empty external id": {SourceID: "source-synthetic"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.RunSyntheticSource(ctx, in)
			if err == nil {
				t.Fatal("RunSyntheticSource succeeded, want a validation error")
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
				t.Fatalf("error kind = %s, want validation", kind)
			}
		})
	}
}
