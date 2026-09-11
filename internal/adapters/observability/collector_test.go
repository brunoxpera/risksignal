package observability_test

// Unit tests of the §16.2 gauge sampler (ARCH-007 §5/§16.2, WP-6.08/6.12
// follow-up / DEV-138). The coverage test is the regression guard for the
// DEV-120 gap: every declared §16.2 gauge family must have a writer — either
// sampled here or written at an event point (http_inflight by the httpapi
// middleware, jobs_queue_depth by the outbox relay). A new gauge declared
// without a writer fails this test instead of silently under-reporting the
// exposition.

import (
	"testing"

	"github.com/brunoxpera/risksignal/internal/adapters/observability"
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
