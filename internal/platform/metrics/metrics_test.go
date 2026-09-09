package metrics

// Unit tests of the in-process metrics registry (DEV-043, concept ch.
// 16.2): counter accumulation, gauge current-state semantics, duration
// observations, labeled series isolation, snapshot stability and the
// misuse guards (a wrong-kind write and a drifting re-declaration panic —
// metric wiring bugs surface at the first write instead of corrupting the
// exposition).

import (
	"strings"
	"sync"
	"testing"
)

func TestCounterAccumulatesAndSeparatesSeries(t *testing.T) {
	r := New()
	records := r.Counter("source_records_total", "records processed by the source passes")
	srcA := Labels{"source_id": "a", "source_type": "nvd"}
	srcB := Labels{"source_id": "b", "source_type": "kev"}

	records.With(srcA).Add(1)
	records.With(srcA).Add(2)
	records.With(srcB).Inc()

	snapshot := r.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot has %d samples, want 2: %+v", len(snapshot), snapshot)
	}
	byLabel := map[string]Sample{}
	for _, s := range snapshot {
		if s.Name != "source_records_total" || s.Kind != KindCounter || s.Count != 0 || s.Sum != 0 {
			t.Fatalf("sample = %+v", s)
		}
		byLabel[s.Labels["source_id"]] = s
	}
	if byLabel["a"].Value != 3 || byLabel["b"].Value != 1 {
		t.Fatalf("values = %+v, want a=3 b=1", byLabel)
	}
}

func TestGaugeHoldsCurrentValue(t *testing.T) {
	r := New()
	limited := r.Gauge("source_rate_limited", "latest fetch outcome was rate-limited")
	src := Labels{"source_id": "a"}

	limited.With(src).Set(1)
	if got := r.Snapshot()[0].Value; got != 1 {
		t.Fatalf("gauge = %v, want 1", got)
	}
	limited.With(src).Set(0) // a later successful fetch clears the flag
	if got := r.Snapshot()[0].Value; got != 0 {
		t.Fatalf("gauge = %v, want 0", got)
	}
}

func TestSecondsObservationsKeepCountSumLast(t *testing.T) {
	r := New()
	duration := r.Seconds("source_run_duration_seconds", "duration of one completed source pass")
	src := Labels{"source_id": "a"}

	duration.With(src).Observe(1.5)
	duration.With(src).Observe(2.5)

	samples := r.Snapshot()
	if len(samples) != 1 {
		t.Fatalf("snapshot has %d samples, want 1", len(samples))
	}
	s := samples[0]
	if s.Kind != KindSeconds || s.Value != 2.5 || s.Count != 2 || s.Sum != 4 {
		t.Fatalf("seconds sample = %+v, want last 2.5, count 2, sum 4", s)
	}
}

func TestUnlabeledAndLabeledSeriesCoexist(t *testing.T) {
	r := New()
	c := r.Counter("epss_rows_total", "rows loaded into the current EPSS set")
	c.Inc() // unlabeled series
	c.With(Labels{"source_id": "a"}).Add(5)

	samples := r.Snapshot()
	if len(samples) != 2 {
		t.Fatalf("snapshot has %d samples, want 2", len(samples))
	}
	total := 0.0
	for _, s := range samples {
		total += s.Value
	}
	if total != 6 {
		t.Fatalf("total = %v, want 6", total)
	}
}

func TestSnapshotOrderIsStable(t *testing.T) {
	r := New()
	r.Gauge("z_metric", "z").With(Labels{"b": "1"}).Set(1)
	r.Gauge("a_metric", "a").With(Labels{"a": "2"}).Set(2)
	r.Gauge("a_metric", "a").With(Labels{"a": "1"}).Set(3)

	snapshot := r.Snapshot()
	if len(snapshot) != 3 {
		t.Fatalf("snapshot has %d samples, want 3", len(snapshot))
	}
	wantNames := []string{"a_metric", "a_metric", "z_metric"}
	for i, s := range snapshot {
		if s.Name != wantNames[i] {
			t.Fatalf("sample %d name = %q, want %q (order must be stable)", i, s.Name, wantNames[i])
		}
	}
	// Two snapshots are byte-identical in content order.
	second := r.Snapshot()
	if len(second) != len(snapshot) {
		t.Fatalf("snapshot length changed between reads")
	}
	for i := range snapshot {
		if snapshot[i].Name != second[i].Name || labelsKey(snapshot[i].Labels) != labelsKey(second[i].Labels) {
			t.Fatalf("snapshot %d differs between reads: %+v vs %+v", i, snapshot[i], second[i])
		}
	}
}

func TestWrongKindWritePanics(t *testing.T) {
	r := New()
	gauge := r.Gauge("source_rate_limited", "flag")
	defer func() {
		if recover() == nil {
			t.Fatal("Add on a gauge must panic")
		}
	}()
	gauge.Add(1)
}

func TestRedeclarationWithDifferentKindPanics(t *testing.T) {
	r := New()
	r.Gauge("source_data_age_seconds", "data age of a source")
	defer func() {
		if recover() == nil {
			t.Fatal("re-declaring a metric with a different kind must panic")
		}
	}()
	r.Counter("source_data_age_seconds", "data age of a source")
}

func TestNegativeObservationPanics(t *testing.T) {
	r := New()
	seconds := r.Seconds("source_run_duration_seconds", "duration")
	defer func() {
		if recover() == nil {
			t.Fatal("a negative duration observation must panic")
		}
	}()
	seconds.Observe(-1)
}

func TestConcurrentWritesAreSafe(t *testing.T) {
	r := New()
	counter := r.Counter("source_records_total", "records")
	src := Labels{"source_id": "a"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				counter.With(src).Inc()
			}
			r.Snapshot()
		}()
	}
	wg.Wait()

	if got := r.Snapshot()[0].Value; got != 800 {
		t.Fatalf("counter = %v, want 800", got)
	}
}

func TestWithCopiesLabels(t *testing.T) {
	r := New()
	counter := r.Counter("source_errors_total", "errors")
	labels := Labels{"source_id": "a"}
	handle := counter.With(labels)
	labels["source_id"] = "mutated" // must not affect the bound series
	handle.Inc()

	samples := r.Snapshot()
	if len(samples) != 1 {
		t.Fatalf("snapshot has %d samples, want 1", len(samples))
	}
	if samples[0].Labels["source_id"] != "a" {
		t.Fatalf("series label mutated: %+v", samples[0].Labels)
	}
}

func TestHelpTextRecordedInSnapshot(t *testing.T) {
	r := New()
	const help = "records processed by the source's passes"
	r.Counter("source_records_total", help).Inc()
	if got := r.Snapshot()[0].Help; got != help {
		t.Fatalf("help = %q, want %q", got, help)
	}
}

// TestKindNameIsStable pins the kind strings of the misuse panics.
func TestKindNameIsStable(t *testing.T) {
	if kindName(KindCounter) != "counter" || kindName(KindGauge) != "gauge" || kindName(KindSeconds) != "seconds" {
		t.Fatal("kind names drifted")
	}
	if !strings.Contains(kindName(Kind(9)), "unknown") {
		t.Fatal("unknown kinds must render as unknown")
	}
}
