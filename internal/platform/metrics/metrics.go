// Package metrics provides the minimal in-process metrics registry of the
// platform (implementation concept ch. 16.2 "Metriken"): Prometheus-
// compatible metric names recorded in process, with no external dependency
// (stdlib only). The registry is the substrate of the operator-facing
// metrics exposition — the dedicated HTTP /metrics endpoint is the later
// iteration I6 (WP-2.11+ / I6), so nothing here renders the Prometheus
// text format yet; the snapshot read (Registry.Snapshot) is the contract
// tests and the future exposition use.
//
// Design: metric names follow the Prometheus naming convention
// (ch. 16.2 examples: records_total, errors_total, data_age_seconds); a
// metric is a named family of labeled series. Three kinds exist:
//
//	KindCounter — a monotone within-process counter (Inc/Add), e.g. the
//	records and errors totals accumulated at the source run-loop
//	completion points.
//	KindGauge   — a current-state value (Set), e.g. the rate-limited flag
//	of the latest fetch outcome.
//	KindSeconds — duration observations (Observe, in seconds) of a named
//	_seconds metric; the series keeps count/sum/last so the exposition
//	can derive averages and totals.
//
// Every write is safe for concurrent use (the worker's relay dispatches
// sequentially, but the composition root must be free to read snapshots
// from another goroutine). A metric handle is a value type: With returns a
// new handle bound to one series, and the series is registered lazily at
// the first write, so declaring metrics costs nothing until they are
// recorded.
//
// The in-process values accumulate per process. They are distinct from the
// durable per-run facts the source monitor projection reads back from the
// database (ARCH-002 §5): the worker records each run-loop completion as
// it happens; `source status` reports the current values as measured from
// the projection at read time. Both serve the same ch. 16.2 names.
package metrics

import (
	"fmt"
	"sort"
	"sync"
)

// Kind names the update semantics of a metric series.
type Kind int

const (
	// KindCounter is a monotone within-process counter.
	KindCounter Kind = iota
	// KindGauge is a current-state value.
	KindGauge
	// KindSeconds is a series of duration observations in seconds
	// (count/sum/last kept for the exposition).
	KindSeconds
)

// Labels identifies one series of a metric family. Labels is nil for an
// unlabeled metric.
type Labels map[string]string

// Registry is a set of metric families. The zero value is not usable;
// create registries with New.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{families: map[string]*family{}}
}

// family is one named metric: its kind and its labeled series.
type family struct {
	name   string
	help   string
	kind   Kind
	series map[string]*Series
}

// Series is one labeled series of a metric family: the accumulated state.
// Series values are written through the metric handle methods; reading is
// done through Registry.Snapshot.
type Series struct {
	labels Labels
	value  float64 // KindCounter: total; KindGauge: current; KindSeconds: last observation
	count  float64 // KindSeconds: number of observations; 0 otherwise
	sum    float64 // KindSeconds: sum of observed seconds; 0 otherwise
}

// Metric is a handle to one metric family, optionally bound to one series
// (With). Handles are value types; the methods on a handle write to the
// series it names.
type Metric struct {
	reg    *Registry
	name   string
	help   string
	kind   Kind
	labels Labels
}

// Counter declares a monotone counter family of the given name and help
// text. The returned handle is unlabeled; call With to bind a series.
func (r *Registry) Counter(name, help string) *Metric {
	return r.declare(name, help, KindCounter)
}

// Gauge declares a current-state gauge family.
func (r *Registry) Gauge(name, help string) *Metric {
	return r.declare(name, help, KindGauge)
}

// Seconds declares a duration-observation family in seconds (a _seconds
// metric of ch. 16.2). Observe records one observation; the series keeps
// the count, the sum and the last value.
func (r *Registry) Seconds(name, help string) *Metric {
	return r.declare(name, help, KindSeconds)
}

// declare registers the family if it is not yet present and returns a
// handle to it. A family that is re-declared with a different kind or help
// is a programming error — the metric contract must not drift.
func (r *Registry) declare(name, help string, kind Kind) *Metric {
	if name == "" {
		panic("metrics: metric name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.families[name]; ok {
		if existing.kind != kind || existing.help != help {
			panic(fmt.Sprintf("metrics: metric %q re-declared with a different kind or help", name))
		}
		return &Metric{reg: r, name: name, help: help, kind: kind}
	}
	r.families[name] = &family{name: name, help: help, kind: kind, series: map[string]*Series{}}
	return &Metric{reg: r, name: name, help: help, kind: kind}
}

// With returns a handle bound to the series identified by the labels. The
// labels are copied: mutating the passed map afterwards does not affect the
// series key. Each distinct label set is one series.
func (m *Metric) With(labels Labels) *Metric {
	bound := *m
	bound.labels = copyLabels(labels)
	return &bound
}

// Inc increments a counter by one. Inc on a non-counter handle panics.
func (m *Metric) Inc() { m.Add(1) }

// Add increments a counter by v. Add on a non-counter handle panics.
func (m *Metric) Add(v float64) {
	m.requireKind(KindCounter)
	m.mu().update(m.name, m.labels, func(s *Series) { s.value += v })
}

// Set fixes a gauge to v. Set on a non-gauge handle panics.
func (m *Metric) Set(v float64) {
	m.requireKind(KindGauge)
	m.mu().update(m.name, m.labels, func(s *Series) { s.value = v })
}

// Observe records one duration observation of seconds seconds. Observe on a
// non-Seconds handle panics. A negative observation is rejected: measured
// durations are never negative and a negative value would corrupt the sum.
func (m *Metric) Observe(seconds float64) {
	m.requireKind(KindSeconds)
	if seconds < 0 {
		panic(fmt.Sprintf("metrics: negative observation of %s: %v", m.name, seconds))
	}
	m.mu().update(m.name, m.labels, func(s *Series) {
		s.value = seconds
		s.count++
		s.sum += seconds
	})
}

// requireKind panics when the handle's kind does not match the operation —
// a programming error in the metric wiring, surfaced at the first write.
func (m *Metric) requireKind(kind Kind) {
	if m.kind != kind {
		panic(fmt.Sprintf("metrics: %s is not a %s metric (kind %d)", m.name, kindName(kind), m.kind))
	}
}

// mu resolves the registry of the handle (nil only when the handle is a
// zero value — a wiring error).
func (m *Metric) mu() *Registry {
	if m.reg == nil {
		panic("metrics: metric handle is not bound to a registry")
	}
	return m.reg
}

// update applies fn to the series of one metric and label set, creating
// the family and the series on first use.
func (r *Registry) update(name string, labels Labels, fn func(*Series)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fam, ok := r.families[name]
	if !ok {
		panic(fmt.Sprintf("metrics: metric %q was not declared", name))
	}
	key := labelsKey(labels)
	s, ok := fam.series[key]
	if !ok {
		s = &Series{labels: copyLabels(labels)}
		fam.series[key] = s
	}
	fn(s)
}

// Sample is one point-in-time reading of a metric series: the current
// value and, for a KindSeconds series, the observation count and sum.
type Sample struct {
	Name   string
	Help   string
	Kind   Kind
	Labels Labels
	Value  float64 // counter total / gauge current / seconds last observation
	Count  float64 // seconds: number of observations (0 otherwise)
	Sum    float64 // seconds: sum of observed seconds (0 otherwise)
}

// Snapshot returns the current readings of every series of the registry,
// ordered by metric name and then by label key — a stable order for tests
// and the future exposition.
func (r *Registry) Snapshot() []Sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	var samples []Sample
	for _, fam := range r.families {
		for _, s := range fam.series {
			samples = append(samples, Sample{
				Name:   fam.name,
				Help:   fam.help,
				Kind:   fam.kind,
				Labels: copyLabels(s.labels),
				Value:  s.value,
				Count:  s.count,
				Sum:    s.sum,
			})
		}
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Name != samples[j].Name {
			return samples[i].Name < samples[j].Name
		}
		return labelsKey(samples[i].Labels) < labelsKey(samples[j].Labels)
	})
	return samples
}

// copyLabels copies a label set; nil stays nil.
func copyLabels(labels Labels) Labels {
	if labels == nil {
		return nil
	}
	cp := make(Labels, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}

// labelsKey renders a stable series key of a label set: sorted
// "key=value" pairs joined by commas. Label keys are recorded in the key,
// so two series with the same values but different keys never collide.
func labelsKey(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	key := ""
	for i, k := range keys {
		if i > 0 {
			key += ","
		}
		key += k + "=" + labels[k]
	}
	return key
}

func kindName(kind Kind) string {
	switch kind {
	case KindCounter:
		return "counter"
	case KindGauge:
		return "gauge"
	case KindSeconds:
		return "seconds"
	}
	return "unknown"
}
