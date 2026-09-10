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
		{key: "oidc.client_id", state: c.OIDC.ClientID, source: src("oidc.client_id")},
		{key: "oidc.client_secret_ref", state: "set", source: src("oidc.client_secret_ref")},
		{key: "oidc.redirect_url", state: "set", source: src("oidc.redirect_url")},
		{key: "oidc.scopes", state: strings.Join(c.OIDC.Scopes, " "), source: src("oidc.scopes")},
		{key: "oidc.roles_claim", state: c.OIDC.RolesClaim, source: src("oidc.roles_claim")},
		{key: "oidc.role_mappings", state: roleMappingsState(c.OIDC.RoleMappings), source: src("oidc.role_mappings")},
		{key: "oidc.audience", state: c.OIDC.Audience, source: src("oidc.audience")},
		{key: "oidc.session_cookie_name", state: c.OIDC.SessionCookieName, source: src("oidc.session_cookie_name")},
		{key: "oidc.session_ttl", state: c.OIDC.SessionTTL.String(), source: src("oidc.session_ttl")},
		{key: "auth.bypass_enabled", state: strconv.FormatBool(c.Auth.BypassEnabled), source: src("auth.bypass_enabled")},
		{key: "auth.bypass_principal", state: c.Auth.BypassPrincipal, source: src("auth.bypass_principal")},
		{key: "worker.interval", state: c.Worker.Interval.String(), source: src("worker.interval")},
		{key: "worker.sla_evaluate_interval", state: c.Worker.SLAEvaluateInterval.String(), source: src("worker.sla_evaluate_interval")},
		{key: "worker.sla_reminder_cadence", state: c.Worker.SLAReminderCadence.String(), source: src("worker.sla_reminder_cadence")},
		{key: "worker.retention_schedule", state: c.Worker.RetentionSchedule.String(), source: src("worker.retention_schedule")},
		{key: "worker.export_sweep_interval", state: c.Worker.ExportSweepInterval.String(), source: src("worker.export_sweep_interval")},
		{key: "export.dir", state: c.Export.Dir, source: src("export.dir")},
		{key: "export.ttl", state: c.Export.TTL.String(), source: src("export.ttl")},
		{key: "export.max_rows", state: strconv.Itoa(c.Export.MaxRows), source: src("export.max_rows")},
		{key: "notify.p2_active", state: strconv.FormatBool(c.Notify.P2Active), source: src("notify.p2_active")},
		{key: "notify.smtp.enabled", state: strconv.FormatBool(c.Notify.SMTP.Enabled), source: src("notify.smtp.enabled")},
		{key: "notify.smtp.addr", state: "set", source: src("notify.smtp.addr")},
		{key: "notify.smtp.from", state: "set", source: src("notify.smtp.from")},
		{key: "notify.smtp.to", state: "set", source: src("notify.smtp.to")},
		{key: "notify.webhook.enabled", state: strconv.FormatBool(c.Notify.Webhook.Enabled), source: src("notify.webhook.enabled")},
		{key: "notify.webhook.url", state: "set", source: src("notify.webhook.url")},
		{key: "notify.webhook.secret", state: "set", source: src("notify.webhook.secret")},
	}
}

// JSONSummary carries the provenance report (same key set and secrecy rules
// as Summary) as machine-readable data for the CLI's --output json envelope
// (WP-1a.09). The schema is stable: the field set below is fixed and must
// not drift; keys that can carry credentials report presence and source
// only, never content.
type JSONSummary struct {
	SchemaVersion       ScalarSummary[int]    `json:"schema_version"`
	Env                 ScalarSummary[string] `json:"env"`
	HTTPAddr            PresenceSummary       `json:"http.addr"`
	DatabaseURL         PresenceSummary       `json:"database.url"`
	OIDCIssuer          PresenceSummary       `json:"oidc.issuer"`
	OIDCClientID        ScalarSummary[string] `json:"oidc.client_id"`
	OIDCClientSecret    PresenceSummary       `json:"oidc.client_secret_ref"`
	OIDCRedirectURL     PresenceSummary       `json:"oidc.redirect_url"`
	OIDCScopes          ScalarSummary[string] `json:"oidc.scopes"`
	OIDCRolesClaim      ScalarSummary[string] `json:"oidc.roles_claim"`
	OIDCRoleMappings    ScalarSummary[string] `json:"oidc.role_mappings"`
	OIDCAudience        ScalarSummary[string] `json:"oidc.audience"`
	OIDCSessionCookie   ScalarSummary[string] `json:"oidc.session_cookie_name"`
	OIDCSessionTTL      ScalarSummary[string] `json:"oidc.session_ttl"`
	AuthBypassEnabled   ScalarSummary[bool]   `json:"auth.bypass_enabled"`
	AuthBypassPrincipal ScalarSummary[string] `json:"auth.bypass_principal"`
	WorkerInterval      ScalarSummary[string] `json:"worker.interval"`
	WorkerSLAEval       ScalarSummary[string] `json:"worker.sla_evaluate_interval"`
	WorkerSLAReminder   ScalarSummary[string] `json:"worker.sla_reminder_cadence"`
	WorkerRetention     ScalarSummary[string] `json:"worker.retention_schedule"`
	WorkerExportSweep   ScalarSummary[string] `json:"worker.export_sweep_interval"`

	ExportDir     ScalarSummary[string] `json:"export.dir"`
	ExportTTL     ScalarSummary[string] `json:"export.ttl"`
	ExportMaxRows ScalarSummary[int]    `json:"export.max_rows"`

	NotifyP2Active    ScalarSummary[bool] `json:"notify.p2_active"`
	NotifySMTPEnabled ScalarSummary[bool] `json:"notify.smtp.enabled"`
	NotifySMTPAddr    PresenceSummary     `json:"notify.smtp.addr"`
	NotifySMTPFrom    PresenceSummary     `json:"notify.smtp.from"`
	NotifySMTPTo      PresenceSummary     `json:"notify.smtp.to"`
	NotifyWebhookOn   ScalarSummary[bool] `json:"notify.webhook.enabled"`
	NotifyWebhookURL  PresenceSummary     `json:"notify.webhook.url"`
	NotifyWebhookSec  PresenceSummary     `json:"notify.webhook.secret"`
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

// roleMappingsState renders the roles-claim mapping as a stable, secret-free
// descriptor: the number of mapped claim values (the mapping is configuration,
// not a credential). An empty mapping (the default — fail closed) reports zero.
func roleMappingsState(m map[string]string) string {
	return strconv.Itoa(len(m)) + " mapping(s)"
}

// JSONSummary renders the provenance report for the CLI. A Configuration
// built without Load reports every source as SourceDefault.
func (c *Config) JSONSummary() JSONSummary {
	return JSONSummary{
		SchemaVersion:       ScalarSummary[int]{Value: c.SchemaVersion, Source: c.sourceOf("schema_version")},
		Env:                 ScalarSummary[string]{Value: c.Env, Source: c.sourceOf("env")},
		HTTPAddr:            PresenceSummary{Set: true, Source: c.sourceOf("http.addr")},
		DatabaseURL:         PresenceSummary{Set: true, Source: c.sourceOf("database.url")},
		OIDCIssuer:          PresenceSummary{Set: true, Source: c.sourceOf("oidc.issuer")},
		OIDCClientID:        ScalarSummary[string]{Value: c.OIDC.ClientID, Source: c.sourceOf("oidc.client_id")},
		OIDCClientSecret:    PresenceSummary{Set: true, Source: c.sourceOf("oidc.client_secret_ref")},
		OIDCRedirectURL:     PresenceSummary{Set: true, Source: c.sourceOf("oidc.redirect_url")},
		OIDCScopes:          ScalarSummary[string]{Value: strings.Join(c.OIDC.Scopes, " "), Source: c.sourceOf("oidc.scopes")},
		OIDCRolesClaim:      ScalarSummary[string]{Value: c.OIDC.RolesClaim, Source: c.sourceOf("oidc.roles_claim")},
		OIDCRoleMappings:    ScalarSummary[string]{Value: roleMappingsState(c.OIDC.RoleMappings), Source: c.sourceOf("oidc.role_mappings")},
		OIDCAudience:        ScalarSummary[string]{Value: c.OIDC.Audience, Source: c.sourceOf("oidc.audience")},
		OIDCSessionCookie:   ScalarSummary[string]{Value: c.OIDC.SessionCookieName, Source: c.sourceOf("oidc.session_cookie_name")},
		OIDCSessionTTL:      ScalarSummary[string]{Value: c.OIDC.SessionTTL.String(), Source: c.sourceOf("oidc.session_ttl")},
		AuthBypassEnabled:   ScalarSummary[bool]{Value: c.Auth.BypassEnabled, Source: c.sourceOf("auth.bypass_enabled")},
		AuthBypassPrincipal: ScalarSummary[string]{Value: c.Auth.BypassPrincipal, Source: c.sourceOf("auth.bypass_principal")},
		WorkerInterval:      ScalarSummary[string]{Value: c.Worker.Interval.String(), Source: c.sourceOf("worker.interval")},
		WorkerSLAEval:       ScalarSummary[string]{Value: c.Worker.SLAEvaluateInterval.String(), Source: c.sourceOf("worker.sla_evaluate_interval")},
		WorkerSLAReminder:   ScalarSummary[string]{Value: c.Worker.SLAReminderCadence.String(), Source: c.sourceOf("worker.sla_reminder_cadence")},
		WorkerRetention:     ScalarSummary[string]{Value: c.Worker.RetentionSchedule.String(), Source: c.sourceOf("worker.retention_schedule")},
		WorkerExportSweep:   ScalarSummary[string]{Value: c.Worker.ExportSweepInterval.String(), Source: c.sourceOf("worker.export_sweep_interval")},
		ExportDir:           ScalarSummary[string]{Value: c.Export.Dir, Source: c.sourceOf("export.dir")},
		ExportTTL:           ScalarSummary[string]{Value: c.Export.TTL.String(), Source: c.sourceOf("export.ttl")},
		ExportMaxRows:       ScalarSummary[int]{Value: c.Export.MaxRows, Source: c.sourceOf("export.max_rows")},
		NotifyP2Active:      ScalarSummary[bool]{Value: c.Notify.P2Active, Source: c.sourceOf("notify.p2_active")},
		NotifySMTPEnabled:   ScalarSummary[bool]{Value: c.Notify.SMTP.Enabled, Source: c.sourceOf("notify.smtp.enabled")},
		NotifySMTPAddr:      PresenceSummary{Set: true, Source: c.sourceOf("notify.smtp.addr")},
		NotifySMTPFrom:      PresenceSummary{Set: true, Source: c.sourceOf("notify.smtp.from")},
		NotifySMTPTo:        PresenceSummary{Set: true, Source: c.sourceOf("notify.smtp.to")},
		NotifyWebhookOn:     ScalarSummary[bool]{Value: c.Notify.Webhook.Enabled, Source: c.sourceOf("notify.webhook.enabled")},
		NotifyWebhookURL:    PresenceSummary{Set: true, Source: c.sourceOf("notify.webhook.url")},
		NotifyWebhookSec:    PresenceSummary{Set: true, Source: c.sourceOf("notify.webhook.secret")},
	}
}
