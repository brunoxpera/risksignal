package metrics

// Unit tests of the Prometheus text exposition (concept ch. 16.2, ARCH-007
// §5, WP-6.08 / DEV-120): the §16.2 family set renders HELP/TYPE even before
// the first observation, counters/gauges render their value, _seconds render
// as a summary (_count/_sum) and the document is deterministic with escaped
// labels.

import (
	"strings"
	"testing"
)

// TestRegisterStandardRendersEveryFamily: a freshly registered, untouched
// registry renders the HELP and TYPE of every §16.2 family — the exposition
// contract is visible on a freshly started process.
func TestRegisterStandardRendersEveryFamily(t *testing.T) {
	r := New()
	RegisterStandard(r)
	out := r.Prometheus()

	for _, tc := range []struct {
		name string
		kind string
	}{
		{NameHTTPRequestsTotal, "counter"},
		{NameHTTPRequestDuration, "summary"},
		{NameHTTPResponsesByStatus, "counter"},
		{NameHTTPInflight, "gauge"},
		{NameSourceRunDuration, "summary"},
		{NameSourceRecordsTotal, "counter"},
		{NameSourceErrorsTotal, "counter"},
		{NameSourceDataAge, "gauge"},
		{NameJobsQueueDepth, "gauge"},
		{NameJobsOldestAge, "gauge"},
		{NameJobsAttemptsTotal, "counter"},
		{NameJobsDeadLettersTotal, "counter"},
		{NameSignalsOpenByPriority, "gauge"},
		{NameSignalsSLARemaining, "gauge"},
		{NameSignalsSLABreachesTotal, "counter"},
		{NameSignalsUnassigned, "gauge"},
		{NameDatabaseConnections, "gauge"},
		{NameDatabaseQueryDuration, "summary"},
		{NameDatabaseTransactionErrors, "counter"},
		{NameDatabaseSizeBytes, "gauge"},
		{NameNotificationsDeliveries, "counter"},
		{NameNotificationsFailures, "counter"},
		{NameNotificationsRetryAge, "gauge"},
	} {
		if !strings.Contains(out, "# TYPE "+tc.name+" "+tc.kind+"\n") {
			t.Errorf("exposition lacks '# TYPE %s %s':\n%s", tc.name, tc.kind, out)
		}
		if !strings.Contains(out, "# HELP "+tc.name+" ") {
			t.Errorf("exposition lacks '# HELP %s':\n%s", tc.name, out)
		}
	}
}

// TestPrometheusRendersCounterGaugeAndSummary: the recorded values render in
// the text format, counters/gauges by value and _seconds as a summary.
func TestPrometheusRendersCounterGaugeAndSummary(t *testing.T) {
	r := New()
	RegisterStandard(r)
	r.Counter(NameHTTPRequestsTotal, HelpHTTPRequestsTotal).With(Labels{"method": "GET", "path": "/health/live"}).Add(3)
	r.Gauge(NameHTTPInflight, HelpHTTPInflight).Set(2)
	r.Seconds(NameHTTPRequestDuration, HelpHTTPRequestDuration).With(Labels{"method": "GET"}).Observe(0.5)
	r.Seconds(NameHTTPRequestDuration, HelpHTTPRequestDuration).With(Labels{"method": "GET"}).Observe(1.5)

	out := r.Prometheus()
	for _, want := range []string{
		`http_requests_total{method="GET",path="/health/live"} 3`,
		`http_inflight 2`,
		`http_request_duration_seconds_count{method="GET"} 2`,
		`http_request_duration_seconds_sum{method="GET"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition lacks %q:\n%s", want, out)
		}
	}
}

// TestPrometheusEscapesLabelValues: quote, backslash and newline in a label
// value are escaped, so a value can never break the document.
func TestPrometheusEscapesLabelValues(t *testing.T) {
	r := New()
	c := r.Counter("test_total", "help")
	c.With(Labels{"k": "a\"b\\c\nd"}).Inc()
	out := r.Prometheus()
	if !strings.Contains(out, `test_total{k="a\"b\\c\nd"} 1`) {
		t.Fatalf("label value not escaped:\n%s", out)
	}
}

// TestPrometheusIsDeterministic: two renders of the same registry are
// byte-identical (family order and series order are stable).
func TestPrometheusIsDeterministic(t *testing.T) {
	r := New()
	RegisterStandard(r)
	r.Counter(NameHTTPRequestsTotal, HelpHTTPRequestsTotal).With(Labels{"path": "/b", "method": "GET"}).Inc()
	r.Counter(NameHTTPRequestsTotal, HelpHTTPRequestsTotal).With(Labels{"path": "/a", "method": "GET"}).Inc()

	if a, b := r.Prometheus(), r.Prometheus(); a != b {
		t.Fatalf("Prometheus() is not deterministic:\n%s\nvs\n%s", a, b)
	}
}
