package config

// I5a exit-criterion proof (b) — the negative-startup bypass lock
// (ARCH-005 §4, §8(b); FR-029, NFR-014, TR-010).
//
// This is the consolidated proof of the online-bypass lock: with
// auth.bypass_enabled set, config.Load must fail for env=demo and
// env=production (TR-010's half, already enforced) and, since the I5a
// loopback hardening (ARCH-005 §4.1), must also fail in env=local unless
// http.addr binds a loopback interface (127.0.0.0/8 or ::1). Only
// env=local + loopback + bypass starts.
//
// config.Load is the single startup gate: risksignal-server, risksignal-worker
// and the risksignal CLI all load and validate the configuration first and
// exit non-zero without binding when it is invalid (cmd/*, main). Asserting
// Load here is therefore asserting "the binaries exit before binding".

import (
	"strings"
	"testing"
)

// TestI5aExitCriteriaBypassLock is the ARCH-005 §8(b) negative-startup proof.
func TestI5aExitCriteriaBypassLock(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		addr    string
		bypass  string
		wantErr string // non-empty ⇒ Load must fail naming this key; empty ⇒ Load must succeed
	}{
		// TR-010: the bypass is refused in every online mode.
		{"demo-bypass-refused", "demo", "127.0.0.1:8080", "true", "auth.bypass_enabled"},
		{"production-bypass-refused", "production", "127.0.0.1:8080", "true", "auth.bypass_enabled"},
		// The loopback lock (§4.1): local + bypass is valid only on loopback.
		{"local-bypass-loopback-ok", "local", "127.0.0.1:8080", "true", ""},
		{"local-bypass-loopback-v6-ok", "local", "[::1]:8080", "true", ""},
		{"local-bypass-localhost-ok", "local", "localhost:8080", "true", ""},
		{"local-bypass-all-interfaces-refused", "local", ":8080", "true", "loopback"},
		{"local-bypass-wildcard-refused", "local", "0.0.0.0:8080", "true", "loopback"},
		{"local-bypass-hostname-refused", "local", "signals.example:8080", "true", "loopback"},
		// A disabled bypass is valid in every mode and on every binding.
		{"production-no-bypass-ok", "production", "0.0.0.0:8080", "false", ""},
		{"local-no-bypass-offloopback-ok", "local", "0.0.0.0:8080", "false", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv()
			env["env"] = tc.env
			env["http.addr"] = tc.addr
			env["auth.bypass_enabled"] = tc.bypass

			cfg, err := loadWithEnv(t, "", env)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v, want success", err)
				}
				if !cfg.Auth.BypassEnabled && tc.bypass == "true" {
					t.Fatalf("Load() disabled the requested bypass")
				}
				return
			}
			if err == nil {
				t.Fatalf("Load() succeeded, want failure naming %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load() error %q does not reference %q", err, tc.wantErr)
			}
		})
	}
}
