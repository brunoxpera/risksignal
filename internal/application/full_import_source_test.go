package application_test

// Network-free tests of the NVD full-import driver (DEV-067, WP-3.09b,
// ARCH-003 §6): FullImportSource streams the whole history of a
// cursor-less last-modified source in bounded checkpointed windows through
// the existing RunSource machinery (fetch + normalise per window,
// committed run by run), and enqueues exactly one matching.rebuild after
// the walk reached the clock's now.
//
// The tests drive the driver with a scripted last-modified SourcePort
// (application tests must not import adapters — the architecture gate);
// the real NVD adapter's multi-page walk over an in-process httptest
// server is exercised end-to-end by the real-DB acceptance test in
// cmd/risksignal (network-free, skipped without PostgreSQL).

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// windowSource is a scripted last-modified SourcePort for the driver
// tests: every fetch answers the window the run machinery derived — the
// storable slice carries the window's end as its cursor and a payload the
// normalise pass turns into one vulnerability whose cve id is derived
// from the window's To — so consecutive chunk windows produce distinct
// records and a re-fetched window dedupes on the natural key.
type windowSource struct {
	typ      application.SourceType
	plan     application.SourcePlan
	fetches  int
	limited  atomic.Bool
	normVuln bool // false: the pass emits nothing (fetch-loop tests)
}

func (s *windowSource) Type() application.SourceType { return s.typ }
func (s *windowSource) Plan() application.SourcePlan { return s.plan }
func (s *windowSource) NormalizerVersion() string    { return "test-normalizer-v1" }
func (s *windowSource) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	s.fetches++
	if s.limited.Load() {
		return application.FetchOutput{Meta: application.FetchMeta{RateLimited: true, RetryAfter: 30 * time.Second}}, nil
	}
	to := in.Window.To
	from := in.Window.From
	if from.IsZero() {
		from = to
	}
	toS := to.UTC().Format(time.RFC3339)
	cursor, _ := json.Marshal(map[string]string{"last_modified": toS})
	return application.FetchOutput{
		ExternalID:  "nvd:" + from.UTC().Format(time.RFC3339) + ":" + toS,
		Payload:     []byte(toS),
		ContentHash: "hash-" + toS,
		FetchedAt:   to,
		Cursor:      cursor,
		Meta:        application.FetchMeta{Status: 200, ContentType: "application/json"},
	}, nil
}
func (s *windowSource) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	if !s.normVuln {
		return application.NormalizeResult{}, nil
	}
	// One vulnerability per window: the cve id is derived from the window
	// end the payload carries (distinct per chunk window, stable for a
	// re-fetched window — the natural key dedupes).
	if err := sink.Vulnerability(ctx, domain.Vulnerability{CVEID: "CVE-FULL-" + string(in.Payload)}); err != nil {
		return application.NormalizeResult{}, err
	}
	return application.NormalizeResult{Records: 1}, nil
}

// fullImportSource seeds the cursor-less NVD-style source row of the
// driver tests: the import starts at config.full_import_since and walks
// config.full_import_chunk-sized windows up to the injected clock.
func fullImportSource(h *harness, since string, chunk any, normVuln bool) *windowSource {
	cfg := map[string]any{
		"full_import_since": since,
		"full_import_chunk": chunk,
		"overlap":           0.0, // the driver tests use disjoint windows
	}
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:     "src-nvd-full",
		Type:   application.SourceTypeNVD,
		Config: cfg,
	})
	return &windowSource{
		typ: application.SourceTypeNVD,
		plan: application.SourcePlan{
			Schedule: "@hourly", Kind: application.SourceKindIncremental,
			CursorKind: application.CursorKindLastModified,
		},
		normVuln: normVuln,
	}
}

// TestFullImportSourceStreamsCheckpointedWindows is the checkpointed
// streaming proof (ARCH-003 §6): the cursor-less source's history
// [2026-09-01, now] is walked in two 168 h windows; every window commits
// its own run, promotes its cursor watermark into sources.cursor and the
// final watermark equals the clock's now.
func TestFullImportSourceStreamsCheckpointedWindows(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := fullImportSource(h, "2026-09-01T00:00:00Z", "168h", true)

	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: src})
	if err != nil {
		t.Fatalf("FullImportSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded", res.Status)
	}
	// Two committed chunk windows: [09-01, 09-08] and [09-08, 09-09 09:30]
	// (the clock's now).
	if res.Chunks != 2 {
		t.Fatalf("chunks = %d, want 2 committed windows", res.Chunks)
	}
	if src.fetches != 2 {
		t.Fatalf("fetch calls = %d, want 2 (one per window)", src.fetches)
	}

	// Cursor promotion per committed step: the source row cursor holds the
	// final window's watermark — the clock's now.
	desc, err := h.sources.GetByID(ctx, "src-nvd-full")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if want := `{"last_modified":"2026-09-09T09:30:00Z"}`; string(desc.Cursor) != want {
		t.Fatalf("sources.cursor = %s, want the promoted final watermark %s", desc.Cursor, want)
	}

	// Every window committed its own succeeded run with one raw record,
	// and each window's vulnerability normalised once.
	if len(h.db.sourceRuns) != 2 {
		t.Fatalf("runs = %d, want 2 (one per checkpointed window)", len(h.db.sourceRuns))
	}
	for i, run := range h.db.sourceRuns {
		if run.status != "succeeded" || run.counters.Records != 1 {
			t.Fatalf("run %d = status %q records %d, want succeeded with 1 raw record", i, run.status, run.counters.Records)
		}
		if len(run.cursorAfter) == 0 {
			t.Fatalf("run %d committed no cursor_after", i)
		}
	}
	if len(h.db.rawRecords) != 2 || len(h.db.vulns) != 2 {
		t.Fatalf("raw records/vulnerabilities = %d/%d, want 2/2 (one per window)", len(h.db.rawRecords), len(h.db.vulns))
	}
}

// TestFullImportSourceResumesAfterRateLimit is the resume proof of the
// checkpointed walk: a rate-limited window stops the driver with the run
// recorded rate-limited (ch. 14.2) and the cursor at the last committed
// chunk end; the re-invocation resumes at the interrupted window instead
// of re-fetching the committed one.
func TestFullImportSourceResumesAfterRateLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := fullImportSource(h, "2026-09-01T00:00:00Z", "168h", true)

	// --- the first window is rate-limited (recorded rate-limited) --------
	src.limited.Store(true)
	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: src})
	if err != nil {
		t.Fatalf("FullImportSource (rate limited): %v", err)
	}
	if res.Status != application.SourceRunStatusFailed || !res.Meta.RateLimited {
		t.Fatalf("result = status %s meta %+v, want failed with Meta.RateLimited", res.Status, res.Meta)
	}
	if res.Meta.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %v, want the source's 30s backoff", res.Meta.RetryAfter)
	}
	if res.Chunks != 0 {
		t.Fatalf("chunks = %d, want 0 — the rate-limited window committed nothing", res.Chunks)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" || run.errText != application.RateLimitedErrorText {
		t.Fatalf("rate-limited run = status %q error %q, want failed recorded rate-limited", run.status, run.errText)
	}
	desc, _ := h.sources.GetByID(ctx, "src-nvd-full")
	if len(desc.Cursor) != 0 {
		t.Fatalf("sources.cursor = %s, want none — a rate-limited run never promotes", desc.Cursor)
	}

	// --- the recovered re-invocation imports both windows -----------------
	src.limited.Store(false)
	res, err = h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: src})
	if err != nil {
		t.Fatalf("FullImportSource after recovery: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Chunks != 2 {
		t.Fatalf("recovered import = status %s chunks %d, want succeeded with 2 committed windows", res.Status, res.Chunks)
	}
	desc, _ = h.sources.GetByID(ctx, "src-nvd-full")
	if want := `{"last_modified":"2026-09-09T09:30:00Z"}`; string(desc.Cursor) != want {
		t.Fatalf("sources.cursor = %s, want the promoted final watermark %s", desc.Cursor, want)
	}
	if len(h.db.sourceRuns) != 3 {
		t.Fatalf("runs = %d, want 3 (one rate-limited + two committed windows)", len(h.db.sourceRuns))
	}
}

// TestFullImportSourceEnqueuesSingleRebuildFanIn is the single-rebuild
// fan-in proof (DEV-067, ARCH-003 §6): after a completed full import over
// a seeded inventory, exactly ONE matching.rebuild is enqueued — the
// DEV-060/065 contract (payload shape, dedupe key
// matching.rebuild:<rule_version>:<inventory_snapshot>) — and the
// job-count metric of the import is ≤ 1 and ≪ the imported CVE count.
func TestFullImportSourceEnqueuesSingleRebuildFanIn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A committed inventory state (seeded directly — no prior commit, so
	// the full import's rebuild is the only matching job of the test):
	// one asset with one component, lifecycle stamps at the injected
	// clock instant, ruleset version counters 0 (no rules configured).
	h.db.assets = []fakeStoredAsset{{
		id: "asset-1", source: "cmdb", externalID: "a1", typ: "server_vm",
		name: "portal-host", updatedAt: fixedNow,
		components: []fakeStoredComponent{{
			ids:        domain.ComponentIdentifiers{Vendor: "Acme", Product: "Portal", Version: "1.0.0"},
			naturalKey: commitKey(domain.ComponentIdentifiers{Vendor: "Acme", Product: "Portal", Version: "1.0.0"}),
			scheme:     domain.VersionSchemeGeneric,
			vendorNorm: "acme", productNorm: "portal", versionNorm: "1.0.0",
			updatedAt: fixedNow,
		}},
	}}

	src := fullImportSource(h, "2026-09-01T00:00:00Z", "168h", true)
	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{
		SourceID:      "src-nvd-full",
		Adapter:       src,
		CorrelationID: "corr-dev-067-1",
	})
	if err != nil {
		t.Fatalf("FullImportSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Chunks != 2 {
		t.Fatalf("result = status %s chunks %d, want succeeded with 2 committed windows", res.Status, res.Chunks)
	}

	// Cursor promotion: the source row cursor holds the final window's
	// watermark — the clock's now.
	desc, err := h.sources.GetByID(ctx, "src-nvd-full")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if want := `{"last_modified":"2026-09-09T09:30:00Z"}`; string(desc.Cursor) != want {
		t.Fatalf("sources.cursor = %s, want the promoted final watermark %s", desc.Cursor, want)
	}

	// Single-rebuild fan-in: exactly one outbox row, a matching.rebuild
	// with the DEV-060/065 payload contract and the §5 dedupe key.
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows = %d, want exactly 1 matching.rebuild", len(h.db.outboxEvents))
	}
	job := h.db.outboxEvents[0]
	if job.Type != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox type = %q, want matching.rebuild", job.Type)
	}
	var payload application.MatchingRebuildPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatalf("decode rebuild payload: %v", err)
	}
	if payload.Type != application.EventTypeMatchingRebuild || payload.EventID == "" || payload.ImportID == "" {
		t.Fatalf("payload envelope = %+v, want type/event_id/import_id set", payload)
	}
	if payload.RuleVersion != "a0000000000d0000000000" {
		t.Fatalf("payload rule_version = %q, want a0000000000d0000000000 (no rules configured)", payload.RuleVersion)
	}
	if len(payload.InventorySnapshot) != 64 {
		t.Fatalf("payload inventory_snapshot = %q, want a 64-hex sha-256 over the seeded inventory", payload.InventorySnapshot)
	}
	if payload.CorrelationID != "corr-dev-067-1" || !payload.OccurredAt.Equal(fixedNow) {
		t.Fatalf("payload correlation/occurred_at = %q/%v, want the input id and the injected clock", payload.CorrelationID, payload.OccurredAt)
	}
	wantKey := "matching.rebuild:" + payload.RuleVersion + ":" + payload.InventorySnapshot
	if job.DedupeKey != wantKey {
		t.Fatalf("dedupe key = %q, want %q", job.DedupeKey, wantKey)
	}

	// Job-count metric (DEV-067): the full import enqueued exactly 1
	// matching job — ≤ the threshold of 1 by construction and ≪ the two
	// CVEs the import streamed (one whole-match-set rebuild, never one
	// job per CVE or per window).
	const threshold = 1
	if res.MatchingJobsEnqueued != 1 {
		t.Fatalf("matching jobs enqueued = %d, want exactly 1 rebuild", res.MatchingJobsEnqueued)
	}
	if res.MatchingJobsEnqueued > threshold {
		t.Fatalf("matching jobs enqueued = %d, want ≤ threshold %d", res.MatchingJobsEnqueued, threshold)
	}
	if len(h.db.vulns) != 2 {
		t.Fatalf("vulnerabilities = %d, want the 2 fixture CVEs", len(h.db.vulns))
	}
	if res.MatchingJobsEnqueued >= len(h.db.vulns) {
		t.Fatalf("matching jobs %d ≪ CVE count %d must hold", res.MatchingJobsEnqueued, len(h.db.vulns))
	}
	if len(h.db.assets) != 1 {
		t.Fatalf("inventory assets = %d, want the seeded 1 untouched", len(h.db.assets))
	}
}

// TestFullImportSourceRebuildFanInIsExactlyOnce is the dedupe half of the
// fan-in: re-running the full import on an already-complete source (its
// cursor already at now) enqueues nothing — the outbox UQ holds exactly
// one matching.rebuild for the (rule_version, inventory_snapshot) pair
// (ADR-012 point 4).
func TestFullImportSourceRebuildFanInIsExactlyOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := fullImportSource(h, "2026-09-01T00:00:00Z", "168h", false)

	if _, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: src}); err != nil {
		t.Fatalf("FullImportSource (run 1): %v", err)
	}
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows after run 1 = %d, want exactly 1 matching.rebuild", len(h.db.outboxEvents))
	}

	// The second invocation is a no-op walk (cursor already at now) and
	// its fan-in dedupes onto the existing job: still exactly one row.
	res, err := h.svc.FullImportSource(ctx, application.FullImportSourceInput{SourceID: "src-nvd-full", Adapter: src})
	if err != nil {
		t.Fatalf("FullImportSource (run 2): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Chunks != 0 {
		t.Fatalf("second run = status %s chunks %d, want succeeded with 0 windows", res.Status, res.Chunks)
	}
	if res.MatchingJobsEnqueued != 0 {
		t.Fatalf("matching jobs enqueued by the deduped fan-in = %d, want 0", res.MatchingJobsEnqueued)
	}
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows after run 2 = %d, want still exactly 1 matching.rebuild", len(h.db.outboxEvents))
	}
	if len(h.db.sourceRuns) != 2 {
		t.Fatalf("runs = %d, want 2 (two invocations, one walk)", len(h.db.sourceRuns))
	}
	if src.fetches != 2 {
		t.Fatalf("fetch calls = %d, want 2 — the second invocation fetches nothing", src.fetches)
	}
}
