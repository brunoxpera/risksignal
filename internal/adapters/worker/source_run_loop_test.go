package worker

// Network-free end-to-end tests of the WP-2.08 source.run loop (ARCH-002
// §5, DEV-042 acceptance): the scheduler scan and the manual trigger
// enqueue source.fetch jobs; the relay (loopStore over the fake database,
// jobfakes_test.go) delivers them through the source.fetch handler into
// the wired FetchSource use case — a real KEV adapter fetching from an
// in-process httptest server (ARCH-002 §6: no network) — which stores the
// raw record and enqueues the source.normalize job; the next drain
// delivers that through the source.normalize handler into NormalizeSource,
// which streams the catalog into skeleton vulnerabilities and kev
// evidences (and historises removals when a later revision drops entries).
//
// The required rate-limit semantics (ch. 14.2) are proven end-to-end: a
// 429 response leaves the fetch job claimed — neither acked nor
// dead-lettered as a source fault — and the expired lease redelivers it on
// the next cycle, which then succeeds.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/adapters/sources/kev"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// loopSourceID is the fixed source id of the run-loop tests.
const loopSourceID = "src-kev-loop"

// kevEntryJSON renders one catalog entry for the given CVE.
func kevEntryJSON(cve string) string {
	return fmt.Sprintf(`{
	  "cveID": %q,
	  "vendorProject": "Acme",
	  "product": "Widget",
	  "vulnerabilityName": "Acme Widget Command Injection",
	  "dateAdded": "2026-08-01",
	  "shortDescription": "Command injection in the Acme Widget.",
	  "requiredAction": "Apply vendor-supplied mitigations.",
	  "dueDate": "",
	  "knownRansomwareCampaignUse": false
	}`, cve)
}

// kevCatalogJSON renders one catalog document envelope (the metadata the
// fetch's external id derives from: kev-<dateReleased date>).
func kevCatalogJSON(dateReleased string, cves ...string) string {
	entries := make([]string, 0, len(cves))
	for _, cve := range cves {
		entries = append(entries, kevEntryJSON(cve))
	}
	return `{"title":"CISA Catalog of Known Exploited Vulnerabilities",` +
		`"catalogVersion":"2026.09.09",` +
		`"dateReleased":"` + dateReleased + `",` +
		`"count":` + fmt.Sprintf("%d", len(cves)) + `,` +
		`"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
}

// sha256Hex hashes b — the expected content hash of a fetched document.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newLoopRelay wires the relay of the run-loop tests: the application
// service on the fake database (jobfakes_test.go) drives the real KEV
// adapter pointed at srv, and both source job handlers are registered.
func newLoopRelay(t *testing.T, db *jobDB, clk clock.Clock, srv *httptest.Server) (*Relay, *loopStore) {
	t.Helper()
	store := newLoopStore(db, clk)
	relay, err := NewRelay(store, discardLogger())
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	svc := newJobService(db, clk)
	jobs, err := NewSourceJobs(svc, &jobSourceRepo{db: db}, map[application.SourceType]application.SourcePort{
		application.SourceTypeKEV: kev.New(srv.Client().Transport),
	}, nil, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay, store
}

// seedLoopSource registers the kev source row of the run-loop tests (the
// descriptor the adapters and use cases resolve) and optionally its
// scheduled scan row.
func seedLoopSource(db *jobDB, endpoint string, scheduled bool) {
	db.sources = []application.SourceDescriptor{{
		ID:       loopSourceID,
		Type:     application.SourceTypeKEV,
		Endpoint: endpoint,
		Config:   map[string]any{},
	}}
	if scheduled {
		db.scheduled = []application.ScheduledSource{{
			ID:       loopSourceID,
			Type:     application.SourceTypeKEV,
			Schedule: "@daily",
		}}
	}
}

// runsOf returns the committed runs ordered by start.
func runsOf(db *jobDB) []jobRun { return append([]jobRun(nil), db.runs...) }

// fetchJobsOf returns the committed source.fetch outbox rows.
func fetchJobsOf(db *jobDB) []application.OutboxEvent {
	var out []application.OutboxEvent
	for _, ev := range db.outboxEvents() {
		if ev.Type == application.EventTypeSourceFetch {
			out = append(out, ev)
		}
	}
	return out
}

// TestSourceRunLoopScheduledFetchNormalizeWithRateLimitRetry drives the
// scheduled run end-to-end: the scheduler scan enqueues the daily
// source.fetch job of the due slot; the first drain hits a rate-limited
// upstream (429 + Retry-After) — the run is recorded rate-limited and the
// job stays claimed, never dead-lettered as a source fault; after the
// lease expires the next drain redelivers the job, the fetch stores the
// raw record, commits the run and enqueues the source.normalize job, which
// the following drain delivers into the normalise pass.
func TestSourceRunLoopScheduledFetchNormalizeWithRateLimitRetry(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)
	clk := clock.NewFakeClock(start)

	catalogV1 := kevCatalogJSON("2026-09-09T04:00:00.000Z", "CVE-2026-0101", "CVE-2026-0102")
	var rateLimited atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rateLimited.Load() {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(catalogV1)); err != nil {
			t.Fatalf("serve catalog: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	db := &jobDB{}
	seedLoopSource(db, srv.URL, true)
	svc := newJobService(db, clk)
	relay, store := newLoopRelay(t, db, clk, srv)

	// --- the scheduler scan enqueues the daily slot's fetch job ----------
	res, err := svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches: %v", err)
	}
	if res.Enqueued != 1 {
		t.Fatalf("scan result = %+v, want 1 enqueued job", res)
	}
	fetchKey := "source.fetch:plan:" + loopSourceID + ":2026-09-09T00:00:00Z"
	if len(fetchJobsOf(db)) != 1 || fetchJobsOf(db)[0].DedupeKey != fetchKey {
		t.Fatalf("fetch jobs = %v, want the daily slot job %s", fetchJobsOf(db), fetchKey)
	}
	if len(db.outboxEvents()) != 1 {
		t.Fatalf("outbox events = %d, want the single fetch job", len(db.outboxEvents()))
	}

	// --- drain 1: the upstream rate-limits the fetch ---------------------
	rateLimited.Store(true)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (rate-limited): %v", err)
	}
	st := store.stateOf(fetchKey)
	if st.status != "claimed" || st.attempts != 1 {
		t.Fatalf("fetch job state after rate limit = %+v, want claimed (attempt 1) — never dead-lettered", st)
	}
	if got := runsOf(db); len(got) != 1 || got[0].status != "failed" || got[0].errText != "fetch.rate_limited" {
		t.Fatalf("runs after rate limit = %+v, want one run recorded rate-limited", got)
	}
	if len(db.raws) != 0 || len(db.outboxEvents()) != 1 {
		t.Fatalf("raws/outbox = %d/%d after rate limit, want nothing stored and no normalize job", len(db.raws), len(db.outboxEvents()))
	}

	// --- drain 2: the lease expired, the job is redelivered and succeeds -
	rateLimited.Store(false)
	clk.Advance(61 * time.Second)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (redelivery): %v", err)
	}
	st = store.stateOf(fetchKey)
	if st.status != "done" || st.attempts != 2 {
		t.Fatalf("fetch job state after redelivery = %+v, want done on the second attempt", st)
	}
	if len(db.raws) != 1 {
		t.Fatalf("raw records = %d, want the stored v1 catalog", len(db.raws))
	}
	raw := db.raws[0]
	if raw.externalID != "kev-2026-09-09" || string(raw.payload) != catalogV1 {
		t.Fatalf("raw record = %+v, want the unchanged v1 catalog document", raw)
	}
	if got := runsOf(db); len(got) != 2 || got[1].status != "succeeded" || got[1].counters.Records != 1 {
		t.Fatalf("runs after fetch = %+v, want the succeeded fetch run", got)
	}
	desc, ok := db.sourceByID(loopSourceID)
	if !ok || desc.Config["last_content_hash"] != sha256Hex([]byte(catalogV1)) {
		t.Fatalf("source config last_content_hash not committed with the run")
	}
	// The terminal commit enqueued the normalize job of the stored record,
	// keyed by raw_record_id + normalizer_version (ch. 14.1).
	normKey := "source.normalize:" + raw.id + ":kev-normalizer-v1"
	if len(db.outboxEvents()) != 2 || db.outboxEvents()[1].DedupeKey != normKey {
		t.Fatalf("outbox events = %v, want the normalize job %s", db.outboxEvents(), normKey)
	}

	// --- drain 3: the normalize job runs the normalise pass ---------------
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (normalize): %v", err)
	}
	if st := store.stateOf(normKey); st.status != "done" {
		t.Fatalf("normalize job state = %+v, want done", st)
	}
	if len(db.vulns) != 2 || evidenceCountByType(db, domain.EvidenceTypeKEV) != 2 {
		t.Fatalf("vulns/kev evidences = %d/%d, want the 2 catalog skeletons + evidences", len(db.vulns), evidenceCountByType(db, domain.EvidenceTypeKEV))
	}
	if got := runsOf(db); len(got) != 3 || got[2].status != "succeeded" ||
		got[2].counters.Records != 1 || got[2].counters.Normalized != 4 || got[2].counters.Errors != 0 {
		t.Fatalf("normalize run = %+v, want succeeded with 1 record and 4 normalised domain objects", got[2])
	}

	// A scheduler scan on the same day stays a no-op: the slot is covered.
	res, err = svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches (repeat): %v", err)
	}
	if res.Enqueued != 0 || res.AlreadyQueued != 1 {
		t.Fatalf("repeat scan = %+v, want the covered slot as already queued", res)
	}
}

// TestSourceRunLoopManualFetchBypassesSchedule drives the manual trigger
// end-to-end: source run enqueues a source.fetch job (dedupe source_id +
// request_id) that the worker delivers without any schedule — the source
// row carries no schedule at all — the fetch stores the raw record and the
// normalize job lands; a repeated trigger with the same request id
// enqueues nothing new, and a fresh request id fetches a later catalog
// revision whose dropped entry is historised as kev_removed (ch. 8.3,
// ARCH-002 §2.2).
func TestSourceRunLoopManualFetchBypassesSchedule(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	clk := clock.NewFakeClock(start)

	catalogV1 := kevCatalogJSON("2026-09-10T04:00:00.000Z", "CVE-2026-0101", "CVE-2026-0102")
	catalogV2 := kevCatalogJSON("2026-09-10T12:00:00.000Z", "CVE-2026-0101") // CVE-2026-0102 dropped
	current := catalogV1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(current)); err != nil {
			t.Fatalf("serve catalog: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	db := &jobDB{}
	seedLoopSource(db, srv.URL, false) // no schedule row at all
	svc := newJobService(db, clk)
	relay, _ := newLoopRelay(t, db, clk, srv)

	// --- manual trigger 1: the job is enqueued due immediately ------------
	manual, err := svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID: loopSourceID, RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch: %v", err)
	}
	if manual.AlreadyQueued || manual.DedupeKey != "source.fetch:manual:"+loopSourceID+":req-1" {
		t.Fatalf("manual result = %+v, want a fresh job with the manual dedupe key", manual)
	}
	if got := fetchJobsOf(db); len(got) != 1 || !got[0].AvailableAt.Equal(start) {
		t.Fatalf("fetch jobs = %v, want one job due immediately (bypassing the schedule)", got)
	}

	// Drain: fetch + normalize of the v1 catalog.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (fetch): %v", err)
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (normalize): %v", err)
	}
	if len(db.raws) != 1 || db.raws[0].externalID != "kev-2026-09-10" {
		t.Fatalf("raw records = %+v, want the stored v1 catalog", db.raws)
	}
	if len(db.vulns) != 2 || evidenceCountByType(db, domain.EvidenceTypeKEV) != 2 {
		t.Fatalf("vulns/kev evidences = %d/%d, want the 2 entries", len(db.vulns), evidenceCountByType(db, domain.EvidenceTypeKEV))
	}

	// --- a repeated trigger with the same request id is a no-op ----------
	manual, err = svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID: loopSourceID, RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch (repeat): %v", err)
	}
	if !manual.AlreadyQueued {
		t.Fatalf("repeat result = %+v, want AlreadyQueued", manual)
	}
	if got := fetchJobsOf(db); len(got) != 1 {
		t.Fatalf("fetch jobs after repeat = %d, want 1 — the dedupe held", len(got))
	}

	// --- a fresh request id fetches the dropped-entry revision -----------
	current = catalogV2
	manual, err = svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID: loopSourceID, RequestID: "req-2",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch (fresh): %v", err)
	}
	if manual.AlreadyQueued {
		t.Fatalf("fresh result = %+v, want a new job", manual)
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (fetch v2): %v", err)
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (normalize v2): %v", err)
	}
	if len(db.raws) != 2 {
		t.Fatalf("raw records = %d, want the v2 revision stored", len(db.raws))
	}
	// The dropped entry is historised: one kev_removed evidence for
	// CVE-2026-0102 attached to the v2 raw record (ch. 8.3), while the
	// v1 and v2 kev evidences both remain.
	removed := evidenceOfType(db, domain.EvidenceTypeKEVRemoved)
	if len(removed) != 1 || removed[0].rawID != db.raws[1].id {
		t.Fatalf("kev_removed evidences = %+v, want one for the v2 raw record", removed)
	}
	if got := evidenceCveIDOf(t, removed[0]); got != "CVE-2026-0102" {
		t.Fatalf("kev_removed cve = %q, want the dropped CVE-2026-0102", got)
	}
	if evidenceCountByType(db, domain.EvidenceTypeKEV) != 3 || evidenceCountByType(db, domain.EvidenceTypeKEVRemoved) != 1 {
		t.Fatalf("kev/kev_removed evidences = %d/%d, want 3 kev (v1 2 + v2 1) and 1 removal", evidenceCountByType(db, domain.EvidenceTypeKEV), evidenceCountByType(db, domain.EvidenceTypeKEVRemoved))
	}

	// Every run of the loop committed succeeded (4 runs: 2 fetches + 2
	// normalise passes).
	runs := runsOf(db)
	if len(runs) != 4 {
		t.Fatalf("runs = %d, want 4", len(runs))
	}
	for i, run := range runs {
		if run.status != "succeeded" {
			t.Fatalf("run %d = status %s, want succeeded", i, run.status)
		}
	}
}

// ---------------------------------------------------------------------------
// small read helpers

// outboxEvents returns the committed outbox rows (accessor on jobDB used by
// the tests above).
func (d *jobDB) outboxEvents() []application.OutboxEvent { return d.outbox }

// evidenceCountByType counts the evidence rows of one type.
func evidenceCountByType(db *jobDB, typ domain.EvidenceType) int {
	n := 0
	for _, e := range db.evidences {
		if e.typ == typ {
			n++
		}
	}
	return n
}

// evidenceOfType returns the evidence rows of one type.
func evidenceOfType(db *jobDB, typ domain.EvidenceType) []jobEvidence {
	var out []jobEvidence
	for _, e := range db.evidences {
		if e.typ == typ {
			out = append(out, e)
		}
	}
	return out
}

// evidenceCveIDOf reads the cve_id of one evidence's canonical value.
func evidenceCveIDOf(t *testing.T, e jobEvidence) string {
	t.Helper()
	var v struct {
		CveID string `json:"cve_id"`
	}
	if err := json.Unmarshal(e.value, &v); err != nil {
		t.Fatalf("decode evidence value %s: %v", e.value, err)
	}
	return v.CveID
}
