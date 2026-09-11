package config

// DEV-132 — ARCH-007 §8 negative-startup proof ("no bypass" / demo lockdown)
// and the private-demo-overlay guard.
//
// The §8 proof: in the online modes (demo, production) the single startup
// gate refuses both the local authentication bypass (auth.bypass_enabled,
// TR-010 / FR-029) and the private-source relaxation (sources.allow_private,
// ARCH-007 §7 control 1). config.Load is that gate — risksignal-server,
// risksignal-worker and the risksignal CLI load and validate the
// configuration first and exit non-zero without binding on an invalid one
// (cmd/*, main) — so asserting Load fails is asserting the process exits
// non-zero before it binds any listener. This is the §8 "no bypass" proof
// alongside the I5a bypass lock test (i5a_bypass_exit_criteria_test.go): that
// test pins the online bypass refusal, this one adds the sources.allow_private
// half and the overlay guard the demo overlay (DEV-131) depends on.
//
// The overlay guard reads deploy/demo/compose.yaml (ARCH-007 §8, the hardened
// private demo topology) and asserts it expresses the lockdown — env=demo and
// both risky flags explicitly false — and never carries a bypass/allow_private
// env set to true. A future edit that silently re-enabled either flag would
// fail here instead of only at a demo deploy.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestArch007DemoStartupLockdown is the ARCH-007 §8 negative-startup proof:
// env=demo + auth.bypass_enabled and env=demo + sources.allow_private are
// refused (non-zero exit), the same holds for production, and the two flags
// stay legal in local mode (the loopback development environment).
func TestArch007DemoStartupLockdown(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string // non-empty ⇒ Load must fail naming this key
	}{
		// §8 "no bypass": the demo mode refuses the bypass and private sources.
		{"demo-bypass-refused", map[string]string{"env": "demo", "auth.bypass_enabled": "true"}, "auth.bypass_enabled"},
		{"demo-allow-private-refused", map[string]string{"env": "demo", "sources.allow_private": "true"}, "sources.allow_private"},
		// The same lockdown holds in production.
		{"production-bypass-refused", map[string]string{"env": "production", "auth.bypass_enabled": "true"}, "auth.bypass_enabled"},
		{"production-allow-private-refused", map[string]string{"env": "production", "sources.allow_private": "true"}, "sources.allow_private"},
		// A clean demo configuration (both flags off) starts.
		{"demo-clean-ok", map[string]string{"env": "demo"}, ""},
		{"demo-flags-false-ok", map[string]string{"env": "demo", "auth.bypass_enabled": "false", "sources.allow_private": "false"}, ""},
		// local mode may opt into the loopback development affordances.
		{"local-allow-private-ok", map[string]string{"env": "local", "sources.allow_private": "true"}, ""},
		{"local-bypass-loopback-ok", map[string]string{"env": "local", "auth.bypass_enabled": "true"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv()
			// A loopback bind keeps the local-bypass case valid (the §4.1 lock).
			env["http.addr"] = "127.0.0.1:8080"
			for k, v := range tc.env {
				env[k] = v
			}

			cfg, err := loadWithEnv(t, "", env)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v, want success", err)
				}
				// The requested flags are applied when they were set.
				if v := env["auth.bypass_enabled"]; v == "true" && !cfg.Auth.BypassEnabled {
					t.Fatalf("Load() did not apply the requested bypass")
				}
				if v := env["sources.allow_private"]; v == "true" && !cfg.Sources.AllowPrivate {
					t.Fatalf("Load() did not apply the requested allow_private")
				}
				return
			}
			if err == nil {
				t.Fatalf("Load() succeeded, want a non-zero-exit failure naming %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load() error %q does not reference %q", err, tc.wantErr)
			}
		})
	}
}

// overlayPath is the private demo overlay, relative to this package directory
// (go test runs with the package directory as the working directory):
// internal/platform/config → repo root is three levels up.
const overlayPath = "../../../deploy/demo/compose.yaml"

// TestDemoOverlayCarriesNoBypassEnv is the DEV-132 overlay guard (ARCH-007
// §8): the private demo overlay must run env=demo with the local bypass and
// private sources explicitly refused, and must never carry either flag set to
// true. It is a textual guard (no YAML dependency) over the committed overlay.
func TestDemoOverlayCarriesNoBypassEnv(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(overlayPath))
	if err != nil {
		t.Fatalf("read %s: %v", overlayPath, err)
	}
	body := string(raw)

	// The overlay is the demo environment.
	if !regexp.MustCompile(`(?m)^\s*RISKSIGNAL_ENV:\s*"?demo"?\s*$`).MatchString(body) {
		t.Errorf("%s: no 'RISKSIGNAL_ENV: demo' — the overlay is not the demo mode", overlayPath)
	}

	// Neither risky flag may be set to true. The overlay must express the
	// lockdown explicitly (false) so the intent is unambiguous.
	trueFlag := func(key string) *regexp.Regexp {
		return regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(key) + `:\s*"?true"?\s*$`)
	}
	falseFlag := func(key string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `:\s*"?false"?\s*$`)
	}
	for _, key := range []string{"RISKSIGNAL_AUTH_BYPASS_ENABLED", "RISKSIGNAL_SOURCES_ALLOW_PRIVATE"} {
		if m := trueFlag(key).FindString(body); m != "" {
			t.Errorf("%s: %q must never be set to true in the demo overlay (ARCH-007 §8)", overlayPath, strings.TrimSpace(m))
		}
		if !falseFlag(key).MatchString(body) {
			t.Errorf("%s: %s is not explicitly set to false — the demo lockdown must be explicit (ARCH-007 §8)", overlayPath, key)
		}
	}
}
