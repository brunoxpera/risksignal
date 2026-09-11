package observability_test

// Unit tests of the §16.2 metric-sampler coverage (ARCH-007 §5/§16.2,
// WP-6.08/6.12 follow-up / DEV-138 and DEV-142). The coverage guard is the
// regression guard for the DEV-120 gap: every declared §16.2 family — gauge,
// counter and summary — must have a writer, sampled by the collector or
// recorded at an event point by the component that owns it. A new family
// declared in internal/platform/metrics without a writer fails the guard
// instead of silently under-reporting the exposition.

import (
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/adapters/observability"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// inProcessGauges are the §16.2 gauge families written at their event points,
// not by this collector: http_inflight (the httpapi metrics middleware) and
// jobs_queue_depth (the outbox relay's drain). They are the complement of the
// collector's set in the declared gauge vocabulary.
var inProcessGauges = map[string]bool{
	metrics.NameHTTPInflight:   true,
	metrics.NameJobsQueueDepth: true,
}

// eventWrittenFamilies aggregates the §16.2 families the other components
// record at their event points: the httpapi request middleware, the worker
// source/relay/SLA jobs, the notify delivery dispatcher and the postgres
// query/transaction recorders. It is the complement of the collector's
// sampled gauge set in the declared vocabulary.
func eventWrittenFamilies() map[string]string {
	written := map[string]string{}
	add := func(writer string, names []string) {
		for _, name := range names {
			written[name] = writer
		}
	}
	add("httpapi.MetricsMiddleware", httpapi.MetricFamilies())
	add("worker event points", worker.MetricFamilies())
	add("notify.Dispatcher", notify.MetricFamilies())
	add("postgres query/transaction recorders", postgres.MetricFamilies())
	return written
}

// TestI6ExitCriteriaMetricFamiliesHaveWriters is the NFR-010 coverage guard:
// every declared §16.2 family — gauge, counter or summary — has a writer, and
// every family a writer claims is a declared family. It closes the class of
// gap DEV-138 (declared-but-unwritten gauges) and DEV-142 (declared-but-
// unrecorded counters/summaries).
func TestI6ExitCriteriaMetricFamiliesHaveWriters(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)

	sampledGauges := map[string]bool{}
	for _, name := range observability.GaugeFamilies() {
		sampledGauges[name] = true
	}
	event := eventWrittenFamilies()

	declaredKinds := map[string]metrics.Kind{}
	for _, fam := range reg.Families() {
		declaredKinds[fam.Name] = fam.Kind
		if !sampledGauges[fam.Name] && event[fam.Name] == "" {
			t.Errorf("declared §16.2 family %q has no writer (not sampled, not an event-written family)", fam.Name)
		}
		if sampledGauges[fam.Name] && event[fam.Name] != "" {
			t.Errorf("family %q is both sampled and event-written — ambiguous authority", fam.Name)
		}
	}
	if len(declaredKinds) == 0 {
		t.Fatal("no §16.2 families declared — the vocabulary regressed")
	}

	// Every family a writer claims must be a real declared family — a typo or
	// a stale name would otherwise hide a gap.
	for name, writer := range event {
		if _, ok := declaredKinds[name]; !ok {
			t.Errorf("writer %s claims family %q, which is not a declared §16.2 family", writer, name)
		}
	}
	for name := range sampledGauges {
		if kind, ok := declaredKinds[name]; !ok {
			t.Errorf("collector samples %q, which is not a declared §16.2 family", name)
		} else if kind != metrics.KindGauge {
			t.Errorf("collector samples %q, which is not a gauge family", name)
		}
	}
}

// TestGaugeFamiliesCoverEveryDeclaredGauge asserts that every gauge family
// RegisterStandard declares is written — by the collector or at an event point
// — so no declared-but-unwritten gauge can regress into the exposition.
func TestGaugeFamiliesCoverEveryDeclaredGauge(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)

	collected := map[string]bool{}
	for _, name := range observability.GaugeFamilies() {
		if collected[name] {
			t.Errorf("collector lists gauge family %q twice", name)
		}
		collected[name] = true
	}

	declaredGauges := 0
	for _, fam := range reg.Families() {
		if fam.Kind != metrics.KindGauge {
			continue
		}
		declaredGauges++
		if !collected[fam.Name] && !inProcessGauges[fam.Name] {
			t.Errorf("declared gauge family %q has no writer (not collected, not an in-process gauge)", fam.Name)
		}
	}
	if declaredGauges == 0 {
		t.Fatal("no gauge families declared — the vocabulary regressed")
	}

	// Every name the collector claims must be a real declared gauge — a typo
	// in the reference set would otherwise hide a gap.
	for name := range collected {
		found := false
		for _, fam := range reg.Families() {
			if fam.Name == name && fam.Kind == metrics.KindGauge {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("collector claims to sample %q, which is not a declared gauge family", name)
		}
	}
}

// TestGaugeFamiliesIsACopy asserts the accessor returns a copy: a caller cannot
// mutate the collector's reference set.
func TestGaugeFamiliesIsACopy(t *testing.T) {
	got := observability.GaugeFamilies()
	if len(got) == 0 {
		t.Fatal("GaugeFamilies is empty")
	}
	got[0] = "mutated"
	if observability.GaugeFamilies()[0] == "mutated" {
		t.Fatal("GaugeFamilies returned the backing slice, not a copy")
	}
}
