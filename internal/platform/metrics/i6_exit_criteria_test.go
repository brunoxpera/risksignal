package metrics

// I6 exit-criteria consolidation (ARCH-007 §5/§12 NFR-010, WP-6.12 /
// DEV-134): the §16.2 metrics-family exposition as an `I6ExitCriteria`-named
// gate. Each subtest delegates to the landed proof (WP-6.08 / DEV-120).

import "testing"

// TestI6ExitCriteriaMetricsFamilies is the NFR-010 acceptance case: a freshly
// registered registry renders the HELP/TYPE of every §16.2 family (so the
// exposition contract is complete before the first observation), records
// render by value / as a summary, and two renders are byte-identical.
func TestI6ExitCriteriaMetricsFamilies(t *testing.T) {
	t.Run("every §16.2 family renders", func(t *testing.T) {
		TestRegisterStandardRendersEveryFamily(t)
	})
	t.Run("counter/gauge/summary render", func(t *testing.T) {
		TestPrometheusRendersCounterGaugeAndSummary(t)
	})
	t.Run("exposition is deterministic", func(t *testing.T) {
		TestPrometheusIsDeterministic(t)
	})
}
