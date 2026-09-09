package application_test

// Unit tests of the DEV-041 fetch metadata wiring (ARCH-002 §1/§2.2/§2.3,
// ch. 8.3): after a committed fetch the source's
// sources.config.last_content_hash holds the fetched content hash — so the
// next full-set fetch's NoChange detection fires on an unchanged catalog /
// daily file — and a full-set fetch's zero FetchedAt is stamped with the
// run's clock instant, so raw-record and fetch metadata are correct.

import (
	"context"
	"strings"
	"testing"

	"github.com/xpera/risksignal/internal/application"
)

// TestFetchSourceFullSetStampsFetchedAtAndMaintainsContentHash is the
// required fetch wiring for a full-set source (KEV/EPSS): the adapter
// returns the zero FetchedAt (a full-set fetch carries no time window), so
// the use case stamps the run's clock instant onto the stored raw record,
// and the terminal commit records the fetched content hash in the source's
// config for the next fetch's NoChange detection.
func TestFetchSourceFullSetStampsFetchedAtAndMaintainsContentHash(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := kevSource(h, t, "kev-2026-09-10")
	if !src.fetchOut.FetchedAt.IsZero() {
		t.Fatalf("test precondition: fetch output must start with a zero FetchedAt, got %v", src.fetchOut.FetchedAt)
	}

	res, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-kev", Adapter: src})
	if err != nil {
		t.Fatalf("FetchSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.RawRecordID == "" {
		t.Fatalf("result = %+v, want a succeeded run with a stored raw record", res)
	}

	// The stored raw record carries the run's clock instant, not the zero
	// time of the full-set fetch.
	raw := h.db.rawRecords[0]
	if !raw.fetchedAt.Equal(fixedNow) {
		t.Fatalf("raw record fetched_at = %v, want the clock instant %v", raw.fetchedAt, fixedNow)
	}

	// The terminal commit maintained sources.config.last_content_hash with
	// the fetched content hash, merging into the config (the other members
	// of the source descriptor config stay intact).
	desc := h.db.sources[0]
	if desc.Config["last_content_hash"] != "kev-hash-new" {
		t.Fatalf("config last_content_hash = %v, want the fetched hash kev-hash-new", desc.Config["last_content_hash"])
	}

	// Everything happened in the fetch run's terminal transaction: raw
	// insert, run completion, config hash update.
	tx := h.runner.last()
	log := strings.Join(tx.log, ",")
	if !strings.Contains(log, "raw,run.complete,source.hash") {
		t.Fatalf("terminal transaction log = %q, want raw insert, run completion, config hash update", tx.log)
	}
}

// TestRunSourceFullSetStampsFetchedAtAndMaintainsContentHash proves the
// same maintenance on the full cycle: the fetch+normalise run stamps the
// raw record's fetched_at, commits the content hash and reports the run
// counters.
func TestRunSourceFullSetStampsFetchedAtAndMaintainsContentHash(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := kevSource(h, t, "kev-2026-09-10")

	res, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-kev", Adapter: src})
	if err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded", res.Status)
	}
	if raw := h.db.rawRecords[0]; !raw.fetchedAt.Equal(fixedNow) {
		t.Fatalf("raw record fetched_at = %v, want the clock instant %v", raw.fetchedAt, fixedNow)
	}
	if h.db.sources[0].Config["last_content_hash"] != "kev-hash-new" {
		t.Fatalf("config last_content_hash = %v, want the fetched hash kev-hash-new", h.db.sources[0].Config["last_content_hash"])
	}
	if res.Counters.Records != 1 || res.Counters.Normalized != 0 {
		t.Fatalf("counters = %+v, want records 1 normalized 0", res.Counters)
	}
}

// TestFetchSourceUnchangedFullSetIsNoChangeNoOp is the content-hash no-op
// contract (ch. 8.3, ARCH-002 §2.2): when the stored last_content_hash
// equals the fetched hash — the adapter reports Meta.NoChange — the fetch
// closes a successful no-op run: nothing is stored, no normalize job is
// enqueued, the counters stay 0 and the config hash is left untouched.
func TestFetchSourceUnchangedFullSetIsNoChangeNoOp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := kevSource(h, t, "kev-2026-09-10")
	src.fetchOut.Meta = application.FetchMeta{Status: 200, ContentType: "application/json", NoChange: true}

	res, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-kev", Adapter: src})
	if err != nil {
		t.Fatalf("FetchSource: %v", err)
	}
	if !res.Meta.NoChange || res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("result = %+v, want the successful no-op surfaced with Meta.NoChange", res)
	}
	run := h.db.sourceRuns[0]
	if run.status != "succeeded" || run.counters.Records != 0 {
		t.Fatalf("run = status %q counters %+v, want succeeded with empty counters", run.status, run.counters)
	}
	if len(h.db.rawRecords) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("raw records/outbox = %d/%d, want 0 — a no-change fetch stores nothing and enqueues no job", len(h.db.rawRecords), len(h.db.outboxEvents))
	}
	// The no-op closes the run without rewriting the config hash: the
	// terminal transaction carries the run completion only.
	if log := strings.Join(h.runner.last().log, ","); log != "run.complete" {
		t.Fatalf("no-op transaction log = %q, want only the run completion", log)
	}
}
