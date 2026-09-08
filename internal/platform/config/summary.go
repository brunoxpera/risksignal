package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Summary renders the startup provenance report (concept ch. 3.3): every
// security-relevant key with the source it was resolved from — but never the
// content of a value that could carry credentials (http.addr, database.url,
// oidc.issuer). Only non-secret descriptors are shown: the schema version,
// the mode, the bypass flag state and the worker scheduler interval.
func (c *Config) Summary() string {
	var b strings.Builder
	for _, l := range c.summaryRows() {
		fmt.Fprintf(&b, "config: %-20s %s (source=%s)\n", l.key+":", l.state, l.source)
	}
	return b.String()
}

// sourceOf resolves the provenance of one configuration leaf, defaulting to
// SourceDefault for configurations that never went through Load.
func (c *Config) sourceOf(key string) Source {
	if s, ok := c.sources[key]; ok {
		return s
	}
	return SourceDefault
}

// summaryRow is one row of the provenance report.
type summaryRow struct {
	key    string
	state  string
	source Source
}

// summaryRows lists the report rows in a stable order. Keys that can carry
// credentials (http.addr, database.url, oidc.issuer) report presence ("set")
// only; the schema version, the mode, the bypass flag and the worker
// interval report their value. summaryRows and JSONSummary describe the
// same key set and must stay in lockstep with the schema (Config).
func (c *Config) summaryRows() []summaryRow {
	src := func(key string) Source { return c.sourceOf(key) }
	return []summaryRow{
		{key: "schema_version", state: strconv.Itoa(c.SchemaVersion), source: src("schema_version")},
		{key: "env", state: c.Env, source: src("env")},
		{key: "http.addr", state: "set", source: src("http.addr")},
		{key: "database.url", state: "set", source: src("database.url")},
		{key: "oidc.issuer", state: "set", source: src("oidc.issuer")},
		{key: "auth.bypass_enabled", state: strconv.FormatBool(c.Auth.BypassEnabled), source: src("auth.bypass_enabled")},
		{key: "worker.interval", state: c.Worker.Interval.String(), source: src("worker.interval")},
	}
}

// JSONSummary carries the provenance report (same key set and secrecy rules
// as Summary) as machine-readable data for the CLI's --output json envelope
// (WP-1a.09). The schema is stable: the field set below is fixed and must
// not drift; keys that can carry credentials report presence and source
// only, never content.
type JSONSummary struct {
	SchemaVersion     ScalarSummary[int]    `json:"schema_version"`
	Env               ScalarSummary[string] `json:"env"`
	HTTPAddr          PresenceSummary       `json:"http.addr"`
	DatabaseURL       PresenceSummary       `json:"database.url"`
	OIDCIssuer        PresenceSummary       `json:"oidc.issuer"`
	AuthBypassEnabled ScalarSummary[bool]   `json:"auth.bypass_enabled"`
	WorkerInterval    ScalarSummary[string] `json:"worker.interval"`
}

// ScalarSummary reports the value and provenance of a leaf that cannot carry
// credentials.
type ScalarSummary[T any] struct {
	Value  T      `json:"value"`
	Source Source `json:"source"`
}

// PresenceSummary reports that a secret-capable leaf is set, plus its
// provenance — never its content.
type PresenceSummary struct {
	Set    bool   `json:"set"`
	Source Source `json:"source"`
}

// JSONSummary renders the provenance report for the CLI. A Configuration
// built without Load reports every source as SourceDefault.
func (c *Config) JSONSummary() JSONSummary {
	return JSONSummary{
		SchemaVersion:     ScalarSummary[int]{Value: c.SchemaVersion, Source: c.sourceOf("schema_version")},
		Env:               ScalarSummary[string]{Value: c.Env, Source: c.sourceOf("env")},
		HTTPAddr:          PresenceSummary{Set: true, Source: c.sourceOf("http.addr")},
		DatabaseURL:       PresenceSummary{Set: true, Source: c.sourceOf("database.url")},
		OIDCIssuer:        PresenceSummary{Set: true, Source: c.sourceOf("oidc.issuer")},
		AuthBypassEnabled: ScalarSummary[bool]{Value: c.Auth.BypassEnabled, Source: c.sourceOf("auth.bypass_enabled")},
		WorkerInterval:    ScalarSummary[string]{Value: c.Worker.Interval.String(), Source: c.sourceOf("worker.interval")},
	}
}
