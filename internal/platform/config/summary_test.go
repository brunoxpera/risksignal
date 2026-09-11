package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// JSONSummary must carry the same provenance data as Summary() with the same
// secrecy rules — that is the contract the CLI's --output json relies on for
// `diagnose config` (WP-1a.09): secret-capable keys report presence and
// source only, never content.

func TestJSONSummaryReportsProvenanceWithoutSecrets(t *testing.T) {
	cfg := mustLoad(t, "", map[string]string{
		"database.url": "postgres://alice:hunter2secret@db.internal.example:5432/risksignal",
		"oidc.issuer":  "https://auth.example/token-secret-path",
	})

	js := cfg.JSONSummary()
	if js.SchemaVersion.Value != SchemaVersion {
		t.Errorf("JSONSummary.SchemaVersion.Value = %d, want %d", js.SchemaVersion.Value, SchemaVersion)
	}
	if js.SchemaVersion.Source != SourceDefault {
		t.Errorf("JSONSummary.SchemaVersion.Source = %q, want %q", js.SchemaVersion.Source, SourceDefault)
	}
	if js.Env.Value != "local" {
		t.Errorf("JSONSummary.Env.Value = %q, want %q", js.Env.Value, "local")
	}
	if !js.DatabaseURL.Set || js.DatabaseURL.Source != SourceEnv {
		t.Errorf("JSONSummary.DatabaseURL = %+v, want set with source env", js.DatabaseURL)
	}
	if !js.OIDCIssuer.Set || js.OIDCIssuer.Source != SourceEnv {
		t.Errorf("JSONSummary.OIDCIssuer = %+v, want set with source env", js.OIDCIssuer)
	}
	if !js.HTTPAddr.Set || js.HTTPAddr.Source != SourceDefault {
		t.Errorf("JSONSummary.HTTPAddr = %+v, want set with source default", js.HTTPAddr)
	}
	if js.AuthBypassEnabled.Value {
		t.Error("JSONSummary.AuthBypassEnabled.Value = true, want false")
	}

	b, err := json.Marshal(js)
	if err != nil {
		t.Fatalf("marshal JSONSummary: %v", err)
	}
	rendered := string(b)
	// The secrecy contract: neither the database password nor any other
	// secret-capable content may ever reach the machine-readable output.
	for _, secret := range []string{"hunter2secret", "alice", "token-secret-path", "db.internal.example"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("JSONSummary leaks %q: %s", secret, rendered)
		}
	}
}

// TestJSONSummaryIsDeterministic pins the schema: the same configuration
// yields byte-identical output, so automation can rely on the fixed key set.
func TestJSONSummaryIsDeterministic(t *testing.T) {
	cfg := mustLoad(t, "", validEnv())

	first, err := json.Marshal(cfg.JSONSummary())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := json.Marshal(cfg.JSONSummary())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("JSONSummary is not deterministic:\n%s\nvs\n%s", first, second)
	}

	// encoding/json renders struct fields in declaration order, so the key
	// set can be pinned exactly: the fixed key set (schema, mode, the I5a
	// oidc/auth section, the I4 notify channels), no drift.
	want := `{"schema_version":{"value":1,"source":"default"},` +
		`"env":{"value":"local","source":"default"},` +
		`"http.addr":{"set":true,"source":"default"},` +
		`"database.url":{"set":true,"source":"env"},` +
		`"oidc.issuer":{"set":true,"source":"env"},` +
		`"oidc.client_id":{"value":"","source":"default"},` +
		`"oidc.client_secret_ref":{"set":true,"source":"default"},` +
		`"oidc.redirect_url":{"set":true,"source":"default"},` +
		`"oidc.scopes":{"value":"openid profile email","source":"default"},` +
		`"oidc.roles_claim":{"value":"roles","source":"default"},` +
		`"oidc.role_mappings":{"value":"0 mapping(s)","source":"default"},` +
		`"oidc.audience":{"value":"","source":"default"},` +
		`"oidc.session_cookie_name":{"value":"risksignal_session","source":"default"},` +
		`"oidc.session_ttl":{"value":"8h0m0s","source":"default"},` +
		`"auth.bypass_enabled":{"value":false,"source":"default"},` +
		`"auth.bypass_principal":{"value":"local-developer","source":"default"},` +
		`"worker.interval":{"value":"30s","source":"default"},` +
		`"worker.sla_evaluate_interval":{"value":"1m0s","source":"default"},` +
		`"worker.sla_reminder_cadence":{"value":"1h0m0s","source":"default"},` +
		`"worker.export_sweep_interval":{"value":"24h0m0s","source":"default"},` +
		`"export.dir":{"value":"var/exports","source":"default"},` +
		`"export.ttl":{"value":"168h0m0s","source":"default"},` +
		`"export.max_rows":{"value":100000,"source":"default"},` +
		`"retention.closed_signal_years":{"value":5,"source":"default"},` +
		`"retention.pseudonymise_years":{"value":0,"source":"default"},` +
		`"retention.batch_size":{"value":500,"source":"default"},` +
		`"retention.schedule":{"value":"720h0m0s","source":"default"},` +
		`"notify.p2_active":{"value":true,"source":"default"},` +
		`"notify.smtp.enabled":{"value":false,"source":"default"},` +
		`"notify.smtp.addr":{"set":true,"source":"default"},` +
		`"notify.smtp.from":{"set":true,"source":"default"},` +
		`"notify.smtp.to":{"set":true,"source":"default"},` +
		`"notify.webhook.enabled":{"value":false,"source":"default"},` +
		`"notify.webhook.url":{"set":true,"source":"default"},` +
		`"notify.webhook.secret":{"set":true,"source":"default"},` +
		`"observability.metrics_enabled":{"value":false,"source":"default"},` +
		`"observability.metrics_addr":{"set":true,"source":"default"},` +
		`"observability.otlp_endpoint":{"set":true,"source":"default"}}`
	if string(first) != want {
		t.Fatalf("JSONSummary rendered %s, want %s", first, want)
	}
}

// TestJSONSummaryMatchesSummarySources: the human Summary() and the
// machine-readable JSONSummary both describe the same key set with the same
// sources — the two renderings must never drift apart.
func TestJSONSummaryMatchesSummarySources(t *testing.T) {
	cfg := mustLoad(t, "", validEnv())

	sum := cfg.Summary()
	js := cfg.JSONSummary()
	cases := []struct {
		key   string
		jsSrc Source
	}{
		{"schema_version", js.SchemaVersion.Source},
		{"env", js.Env.Source},
		{"http.addr", js.HTTPAddr.Source},
		{"database.url", js.DatabaseURL.Source},
		{"oidc.issuer", js.OIDCIssuer.Source},
		{"auth.bypass_enabled", js.AuthBypassEnabled.Source},
		{"worker.interval", js.WorkerInterval.Source},
	}
	for _, c := range cases {
		line := summaryLine(sum, c.key)
		if line == "" {
			t.Fatalf("Summary() has no line for %s", c.key)
		}
		if !strings.Contains(line, "(source="+string(c.jsSrc)+")") {
			t.Errorf("source mismatch for %s: Summary() line %q vs JSONSummary source %q", c.key, line, c.jsSrc)
		}
	}
}
