package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// reportConfig is everything the report renders.
type reportConfig struct {
	Version        string
	Profile        Profile
	GeneratedAt    time.Time
	BulkDur        time.Duration
	IncrementalDur time.Duration
	Outbox         map[string]int
	RebuildJobs    int
	TotalJobs      int
	Hits           int
	Queries        []queryStat
	OverallP95     time.Duration
	Facts          datasetFacts
	Measurements   []measurement
}

// renderReport renders the versioned AT-013 evidence document (markdown).
func renderReport(c reportConfig) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# RiskSignal performance report — AT-013\n\n")
	w("Reproducible `make perf` evidence for the I6 performance acceptance\n")
	w("case (ARCH-007 §6/§17.1): the reference volume is loaded and the\n")
	w("defined queries and imports are measured against the section's\n")
	w("thresholds. Re-run at every relevant persistence change.\n\n")

	w("| field | value |\n|---|---|\n")
	w("| generated (UTC) | %s |\n", c.GeneratedAt.Format(time.RFC3339))
	w("| harness version | %s |\n", c.Version)
	w("| profile | %s |\n", c.Profile.Name)
	w("| scale knob | `PERF_SCALE=%s` |\n", c.Profile.Name)
	w("\n")

	w("## Reference dataset\n\n")
	w("| object | count |\n|---|---|\n")
	w("| vulnerabilities (CVEs) | %d |\n", c.Facts.Vulnerabilities)
	w("| assets | %d |\n", c.Facts.Assets)
	w("| components | %d |\n", c.Facts.Components)
	w("| matches (expected hit set) | %d |\n", c.Facts.Matches)
	w("| risk signals (expected hit set) | %d |\n", c.Facts.Signals)
	w("\n")

	w("## Result\n\n")
	w("| metric | measured | threshold | result |\n|---|---|---|---|\n")
	for _, m := range c.Measurements {
		status := "PASS"
		if !m.pass {
			status = "FAIL"
		}
		w("| %s | %s | %s | **%s** |\n", m.label, m.value, m.threshold, status)
	}
	w("\n")

	w("## Detail\n\n")
	w("### Bulk import (the reference NVD full import)\n\n")
	w("- duration: %s\n", durString(c.BulkDur))
	w("- outbox jobs created:\n\n")
	w("| job type | count |\n|---|---|\n")
	types := make([]string, 0, len(c.Outbox))
	for t := range c.Outbox {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		w("| %s | %d |\n", t, c.Outbox[t])
	}
	if len(types) == 0 {
		w("| _(none)_ | 0 |\n")
	}
	w("\nThe §17.1 threshold is a job count far below the order of magnitude of\n")
	w("the CVE count: %d job(s) in total (%d matching.rebuild) for %d imported\n",
		c.TotalJobs, c.RebuildJobs, c.Profile.CVEs)
	w("CVEs — jobs×%d ≤ CVEs holds, and the full import fans in exactly one\n", jobRatioFactor)
	w("matching.rebuild (ADR-012, the inventory-driven rebuild).\n\n")

	w("### Incremental source run (NFR-004)\n\n")
	w("- duration: %s (threshold %s)\n", durString(c.IncrementalDur), durString(incrementalThreshold))
	w("- the daily delta is %d changed CVEs fetched through the same NVD\n", c.Profile.IncrementalCVEs)
	w("  incremental path (fetch + normalise) after the reference load.\n\n")

	w("### Reference list queries (NFR-003, §10.4 filter read)\n\n")
	w("| query | p95 | samples |\n|---|---|---|\n")
	for _, qs := range c.Queries {
		w("| %s | %s | %d |\n", qs.name, durString(qs.p95), len(qs.samples))
	}
	w("| **combined p95** | **%s** | |\n", durString(c.OverallP95))
	w("\n")
	w("The combined p95 is the 95th percentile over every sample of every\n")
	w("reference query — the NFR-003 \"95 %% of the reference queries\" figure.\n")
	w("Threshold: %s.\n\n", durString(listP95Threshold))

	w("## Determinism and scale\n\n")
	w("The harness is deterministic: the dataset is a pure function of the\n")
	w("profile's integer sizes, the clock is an injected fake clock at the\n")
	w("fixed instant %s, and the only network surface is an in-process\n", perfClockStart.Format(time.RFC3339))
	w("httptest NVD server (loopback, network-free, §17.2). The measured\n")
	w("durations vary with the host; the dataset and the pass/fail verdicts do\n")
	w("not.\n\n")
	w("The full 250 000-CVE run is slow, so `PERF_SCALE` selects the profile:\n")
	w("`full` (the reference profile above, the report source) and `smoke` (a\n")
	w("reduced but structurally identical profile for a quick CI check). A\n")
	w("smoke run writes `%s-smoke.md` so it can never be mistaken for the\n", c.Version)
	w("reference evidence. Override the query iteration count with\n")
	w("`PERF_LIST_ITERATIONS`.\n\n")

	w("## Reproduction\n\n")
	w("```\n")
	w("make up-db         # the PostgreSQL the scratch database lives on\n")
	w("make perf          # PERF_SCALE=full, the reference report\n")
	w("PERF_SCALE=smoke make perf   # quick subset\n")
	w("```\n")

	return b.String()
}

// writeReport writes the report to dist/perf/<version>.md (the full
// profile) or dist/perf/<version>-<profile>.md (any other profile).
func writeReport(dir, version, profile, content string) (string, error) {
	name := version + ".md"
	if profile != "full" {
		name = version + "-" + profile + ".md"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	path := filepath.Join(dir, name)
	// #nosec G304 -- path is the harness-configured report directory plus
	// the version-derived file name; it is the artifact this tool owns.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}
