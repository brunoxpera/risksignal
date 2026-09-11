package metrics

// Prometheus text exposition (concept ch. 16.2, ARCH-007 §5, WP-6.08 /
// DEV-120). Registry.Prometheus renders the current registry in the
// Prometheus text format (version 0.0.4), the format the internal GET
// /metrics endpoint serves. The output is deterministic — families sorted by
// name, series by label key — so tests and scrapers see a stable document.
//
// Kind mapping:
//
//	KindCounter -> counter (the name already ends in _total, e.g.
//	               http_requests_total)
//	KindGauge   -> gauge
//	KindSeconds -> summary, rendered from the kept count and sum as the
//	               standard <name>_count and <name>_sum series (the average
//	               is sum/count at scrape time).
//
// A declared family with no series still emits its HELP and TYPE lines, so
// the §16.2 contract is visible on a freshly started process.

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// contentType is the Content-Type of the Prometheus text exposition format
// (version 0.0.4), the value the /metrics handler must send.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// ContentType returns the Content-Type of the Prometheus text exposition.
// The /metrics handler sets it; it is exported so the handler and its tests
// share the constant.
func ContentType() string { return contentType }

// Prometheus renders the registry in the Prometheus text exposition format.
func (r *Registry) Prometheus() string {
	var b strings.Builder
	// Writing into a strings.Builder never fails.
	_ = r.WritePrometheus(&b)
	return b.String()
}

// WritePrometheus writes the registry in the Prometheus text exposition
// format to w. The registry is rendered under its lock, so a concurrent
// recorder cannot mutate a family mid-render.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	names := make([]string, 0, len(r.families))
	for name := range r.families {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fam := r.families[name]
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n", fam.name, escapeHelp(fam.help)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", fam.name, prometheusKind(fam.kind)); err != nil {
			return err
		}
		keys := seriesKeys(fam)
		for _, key := range keys {
			s := fam.series[key]
			labels := renderLabels(s.labels)
			switch fam.kind {
			case KindCounter, KindGauge:
				if _, err := fmt.Fprintf(w, "%s%s %s\n", fam.name, labels, formatValue(s.value)); err != nil {
					return err
				}
			case KindSeconds:
				if _, err := fmt.Fprintf(w, "%s_sum%s %s\n", fam.name, labels, formatValue(s.sum)); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "%s_count%s %s\n", fam.name, labels, formatValue(s.count)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// seriesKeys returns the series keys of a family in a stable order.
func seriesKeys(fam *family) []string {
	keys := make([]string, 0, len(fam.series))
	for k := range fam.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// prometheusKind maps a Kind to its Prometheus type keyword.
func prometheusKind(kind Kind) string {
	switch kind {
	case KindCounter:
		return "counter"
	case KindGauge:
		return "gauge"
	case KindSeconds:
		return "summary"
	}
	return "untyped"
}

// formatValue renders a metric value the Prometheus way: the shortest
// round-tripping representation, never an exponent-only float for integers.
func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// renderLabels renders a label set as the Prometheus label block
// (`{k="v",k2="v2"}`, keys sorted), or the empty string when there is no
// label. Values are escaped (backslash, double quote, newline).
func renderLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeHelp escapes a HELP text: backslash and newline only, per the text
// format rules (a HELP line is the text up to the closing newline).
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// escapeLabelValue escapes a label value: backslash, double quote and
// newline, per the Prometheus text format.
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}
