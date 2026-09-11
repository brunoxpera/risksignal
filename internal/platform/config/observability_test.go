package config

// Tests of the I6 observability configuration (ARCH-007 §5/§10, WP-6.08 /
// DEV-120): the additive observability.* keys, their defaults, the
// env/file override layers and the "never public" validation — loopback in
// local, internal-only (not all-interfaces) in demo/production, OTLP off by
// default and only a parseable URL when set.

import (
	"strings"
	"testing"
)

func TestObservabilityDefaults(t *testing.T) {
	d := Defaults()
	if d.Observability.MetricsEnabled {
		t.Error("Defaults().Observability.MetricsEnabled = true, want false (opt-in)")
	}
	if d.Observability.MetricsAddr != defaultMetricsAddr {
		t.Errorf("Defaults().Observability.MetricsAddr = %q, want %q", d.Observability.MetricsAddr, defaultMetricsAddr)
	}
	if d.Observability.OTLPEndpoint != "" {
		t.Errorf("Defaults().Observability.OTLPEndpoint = %q, want empty (off)", d.Observability.OTLPEndpoint)
	}
}

func TestObservabilityEnvOverrides(t *testing.T) {
	env := validEnv()
	env["observability.metrics_enabled"] = "true"
	env["observability.metrics_addr"] = "127.0.0.1:9191"
	env["observability.otlp_endpoint"] = "http://127.0.0.1:4318"
	cfg := mustLoad(t, "", env)

	if !cfg.Observability.MetricsEnabled {
		t.Error("MetricsEnabled = false, want true from env")
	}
	if cfg.Observability.MetricsAddr != "127.0.0.1:9191" {
		t.Errorf("MetricsAddr = %q", cfg.Observability.MetricsAddr)
	}
	if cfg.Observability.OTLPEndpoint != "http://127.0.0.1:4318" {
		t.Errorf("OTLPEndpoint = %q", cfg.Observability.OTLPEndpoint)
	}

	js := cfg.JSONSummary()
	if js.ObservabilityMetricsEnabled.Value != true || js.ObservabilityMetricsEnabled.Source != SourceEnv {
		t.Errorf("JSONSummary observability.metrics_enabled = %+v, want true/env", js.ObservabilityMetricsEnabled)
	}
	if !js.ObservabilityMetricsAddr.Set || js.ObservabilityMetricsAddr.Source != SourceEnv {
		t.Errorf("JSONSummary observability.metrics_addr = %+v, want set/env", js.ObservabilityMetricsAddr)
	}
	// The addresses are presence-only: the summary never renders content.
	sum := cfg.Summary()
	if strings.Contains(sum, "9191") || strings.Contains(sum, "4318") {
		t.Errorf("Summary() renders the observability address content:\n%s", sum)
	}
	if line := summaryLine(sum, "observability.metrics_enabled"); !strings.Contains(line, "true (source=env)") {
		t.Errorf("Summary() observability.metrics_enabled line = %q", line)
	}
}

func TestObservabilityFileOverrides(t *testing.T) {
	file := writeConfigFile(t, `{
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {"issuer": "https://issuer.file.example/"},
		"observability": {"metrics_enabled": true, "metrics_addr": "127.0.0.1:9192", "otlp_endpoint": "https://otel.example/"}
	}`)
	cfg := mustLoad(t, file, nil)
	if !cfg.Observability.MetricsEnabled || cfg.Observability.MetricsAddr != "127.0.0.1:9192" ||
		cfg.Observability.OTLPEndpoint != "https://otel.example/" {
		t.Fatalf("file layer did not carry the observability keys: %+v", cfg.Observability)
	}
}

// TestValidateMetricsEnabledRequiresLoopbackInLocal: the local exposition may
// only bind loopback (ARCH-007 §5).
func TestValidateMetricsEnabledRequiresLoopbackInLocal(t *testing.T) {
	env := validEnv()
	env["observability.metrics_enabled"] = "true"
	env["observability.metrics_addr"] = "0.0.0.0:9091"
	mustFail(t, "", env, "observability.metrics_addr")
}

// TestValidateMetricsEnabledRejectsWildcardOutsideLocal: outside local the
// exposition must never bind all interfaces (an empty host is the wildcard).
func TestValidateMetricsEnabledRejectsWildcardOutsideLocal(t *testing.T) {
	env := validEnv()
	env["env"] = "demo"
	env["observability.metrics_enabled"] = "true"
	env["observability.metrics_addr"] = ":9091"
	mustFail(t, "", env, "observability.metrics_addr")
}

// TestValidateMetricsEnabledInternalAddrOutsideLocalOK: an explicit,
// internal-only host is accepted outside local.
func TestValidateMetricsEnabledInternalAddrOutsideLocalOK(t *testing.T) {
	env := validEnv()
	env["env"] = "demo"
	env["observability.metrics_enabled"] = "true"
	env["observability.metrics_addr"] = "10.0.0.5:9091"
	cfg := mustLoad(t, "", env)
	if cfg.Observability.MetricsAddr != "10.0.0.5:9091" {
		t.Errorf("MetricsAddr = %q", cfg.Observability.MetricsAddr)
	}
}

// TestValidateMetricsAddrShape: an enabled exposition with an unparsable
// bind address is rejected.
func TestValidateMetricsAddrShape(t *testing.T) {
	env := validEnv()
	env["observability.metrics_enabled"] = "true"
	env["observability.metrics_addr"] = "not-a-host-port"
	mustFail(t, "", env, "observability.metrics_addr")
}

// TestValidateOTLPEndpointURL: a set OTLP target must be a parseable URL;
// the invalid value is never echoed.
func TestValidateOTLPEndpointURL(t *testing.T) {
	env := validEnv()
	env["observability.otlp_endpoint"] = "not a url"
	err := mustFailErr(t, "", env, "observability.otlp_endpoint")
	if strings.Contains(err.Error(), "not a url") {
		t.Errorf("Load() error echoes the offending value: %v", err)
	}
}
