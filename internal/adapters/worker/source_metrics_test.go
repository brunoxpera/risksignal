package worker

// Unit tests of the DEV-043 run-loop metrics wiring (source.go, concept
// ch. 16.2): the source.fetch and source.normalize handlers record every
// completed pass on the in-process registry — pass durations, the records
// stored by fetch passes, the records isolated by normalize passes, the
// rate-limit gauge and the EPSS row counts. The use cases are scripted
// fakes (source_jobs_test.go), so the recording is exercised without a
// database; a jobs instance without a registry records nothing (the
// disable path).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/metrics"
)

// metricSample finds the sample of one metric name and source id.
func metricSample(t *testing.T, reg *metrics.Registry, name, sourceID string) metrics.Sample {
	t.Helper()
	for _, s := range reg.Snapshot() {
		if s.Name == name && s.Labels["source_id"] == sourceID {
			return s
		}
	}
	t.Fatalf("no sample for %s of source %s in %+v", name, sourceID, reg.Snapshot())
	return metrics.Sample{}
}

// metricSampleCount returns how many samples a metric name has.
func metricSampleCount(reg *metrics.Registry, name string) int {
	n := 0
	for _, s := range reg.Snapshot() {
		if s.Name == name {
			n++
		}
	}
	return n
}

// TestFetchCompletionRecordsRunLoopMetrics: a delivered fetch (a stored raw
// record) records the pass duration, advances source_records_total by the
// run's records counter and leaves the rate-limit gauge cleared.
func TestFetchCompletionRecordsRunLoopMetrics(t *testing.T) {
	reg := metrics.New()
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID: "run-1", RawRecordID: "raw-1", Status: application.SourceRunStatusSucceeded,
		Counters: application.SourceRunCounters{Records: 1},
	}}
	jobs, err := NewSourceJobs(runner, kevResolver(), kevRegistry, reg, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}

	if err := jobs.handleFetch(context.Background(), fetchEvent("ev-1", "src-kev", fetchPlanTime, "")); err != nil {
		t.Fatalf("handleFetch: %v", err)
	}

	if s := metricSample(t, reg, metricSourceRecordsTotal, "src-kev"); s.Value != 1 {
		t.Fatalf("records_total = %v, want 1", s.Value)
	}
	if s := metricSample(t, reg, metricSourceRateLimited, "src-kev"); s.Value != 0 {
		t.Fatalf("rate_limited gauge = %v, want 0", s.Value)
	}
	if s := metricSample(t, reg, metricSourceRunDurationSeconds, "src-kev"); s.Kind != metrics.KindSeconds || s.Count != 1 || s.Value < 0 {
		t.Fatalf("duration sample = %+v, want one non-negative observation", s)
	}
}

// TestRateLimitedFetchSetsGaugeWithoutRecords: a rate-limited fetch is not
// a source fault (ch. 14.2): the gauge is set, no records advance and the
// pass duration is still observed.
func TestRateLimitedFetchSetsGaugeWithoutRecords(t *testing.T) {
	reg := metrics.New()
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID:  "run-1",
		Status: application.SourceRunStatusFailed,
		Meta:   application.FetchMeta{RateLimited: true, RetryAfter: 90}, // the stable rate-limit outcome (ch. 14.2)
	}}
	jobs, err := NewSourceJobs(runner, kevResolver(), kevRegistry, reg, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}

	if err := jobs.handleFetch(context.Background(), fetchEvent("ev-1", "src-kev", fetchPlanTime, "")); err == nil {
		t.Fatal("rate-limited fetch must stay claimable (Retry), got nil")
	}
	if s := metricSample(t, reg, metricSourceRateLimited, "src-kev"); s.Value != 1 {
		t.Fatalf("rate_limited gauge = %v, want 1", s.Value)
	}
	if metricSampleCount(reg, metricSourceRecordsTotal) != 0 {
		t.Fatalf("rate-limited fetch must not advance records_total: %+v", reg.Snapshot())
	}
	if s := metricSample(t, reg, metricSourceRunDurationSeconds, "src-kev"); s.Count != 1 {
		t.Fatalf("duration sample = %+v, want one observation", s)
	}
}

// TestNormalizeCompletionRecordsIsolatedErrors: a delivered normalize pass
// records the pass duration and advances source_errors_total by the
// isolated records of the committed counters.
func TestNormalizeCompletionRecordsIsolatedErrors(t *testing.T) {
	reg := metrics.New()
	runner := &scriptedRunner{normRes: application.NormalizeSourceResult{
		RunID:  "run-2",
		Status: application.SourceRunStatusSucceeded,
		Counters: application.SourceRunCounters{
			Records: 1, Normalized: 10, Errors: 3, Quarantined: 3,
		},
	}}
	jobs, err := NewSourceJobs(runner, kevResolver(), kevRegistry, reg, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}

	event := normalizeEvent("ev-2", "raw-1", "src-kev")
	if err := jobs.handleNormalize(context.Background(), event); err != nil {
		t.Fatalf("handleNormalize: %v", err)
	}
	if s := metricSample(t, reg, metricSourceErrorsTotal, "src-kev"); s.Value != 3 {
		t.Fatalf("errors_total = %v, want 3", s.Value)
	}
	if metricSampleCount(reg, metricEpssRowsTotal) != 0 {
		t.Fatalf("a non-epss pass must not record epss rows: %+v", reg.Snapshot())
	}
	if s := metricSample(t, reg, metricSourceRunDurationSeconds, "src-kev"); s.Count != 1 {
		t.Fatalf("duration sample = %+v, want one observation", s)
	}
}

// TestEpssNormalizeCompletionRecordsLoadedRows: an epss normalize pass
// advances epss_rows_total by the row count of the loaded daily set (the
// pass's normalized counter) next to the errors counter.
func TestEpssNormalizeCompletionRecordsLoadedRows(t *testing.T) {
	reg := metrics.New()
	runner := &scriptedRunner{normRes: application.NormalizeSourceResult{
		RunID:  "run-3",
		Status: application.SourceRunStatusSucceeded,
		Counters: application.SourceRunCounters{
			Records: 1, Normalized: 201234, Errors: 2, Quarantined: 2,
		},
	}}
	adapters := map[application.SourceType]application.SourcePort{
		application.SourceTypeEPSS: &stubSource{typ: application.SourceTypeEPSS},
	}
	resolver := &mapResolver{sources: map[string]application.SourceDescriptor{
		"src-epss": {ID: "src-epss", Type: application.SourceTypeEPSS},
	}}
	jobs, err := NewSourceJobs(runner, resolver, adapters, reg, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}

	event := normalizeEvent("ev-3", "raw-1", "src-epss")
	if err := jobs.handleNormalize(context.Background(), event); err != nil {
		t.Fatalf("handleNormalize: %v", err)
	}
	if s := metricSample(t, reg, metricEpssRowsTotal, "src-epss"); s.Value != 201234 {
		t.Fatalf("epss_rows_total = %v, want 201234", s.Value)
	}
	if s := metricSample(t, reg, metricSourceErrorsTotal, "src-epss"); s.Value != 2 {
		t.Fatalf("errors_total = %v, want 2", s.Value)
	}
}

// TestJobsWithoutRegistryRecordNothing: a jobs instance wired without a
// metrics registry delivers jobs without recording (the disable path).
func TestJobsWithoutRegistryRecordNothing(t *testing.T) {
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID: "run-1", RawRecordID: "raw-1", Status: application.SourceRunStatusSucceeded,
		Counters: application.SourceRunCounters{Records: 1},
	}}
	jobs, err := NewSourceJobs(runner, kevResolver(), kevRegistry, nil, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}
	if err := jobs.handleFetch(context.Background(), fetchEvent("ev-1", "src-kev", fetchPlanTime, "")); err != nil {
		t.Fatalf("handleFetch: %v", err)
	}
	// No panic and no state: nothing to assert beyond the successful run —
	// the disabled path must be a silent no-op.
}

// fetchPlanTime is the fixed plan time of the fetch events of these tests.
var fetchPlanTime = time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

// normalizeEvent builds one claimed source.normalize event.
func normalizeEvent(id, rawRecordID, src string) ClaimedEvent {
	payload := application.SourceNormalizeJobPayload{RawRecordID: rawRecordID, SourceID: src}
	body, _ := json.Marshal(payload)
	return ClaimedEvent{ID: id, Type: application.EventTypeSourceNormalize, Payload: body, Attempts: 1}
}
