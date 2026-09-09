package main

// Unit tests of the demo dispatch and argument contract (WP-1b.05 /
// DEV-019): subcommand validation and the --yes gate of `demo reset` fail
// as validation errors (exit 2) before any configuration or database
// access. The database-driving demo tests live in demo_integration_test.go.

import (
	"strings"
	"testing"
)

// TestDemoDispatchValidation covers the argument-level failures of the demo
// command tree: a missing or unknown subcommand and unexpected positional
// arguments are validation errors (exit 2), and none of them touches the
// configuration or the database (no environment is needed).
func TestDemoDispatchValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"missing subcommand", []string{"demo"}, "missing subcommand"},
		{"unknown subcommand", []string{"demo", "bogus"}, "unknown subcommand"},
		{"seed with positional argument", []string{"demo", "seed", "extra"}, "unexpected argument"},
		{"run with positional argument", []string{"demo", "run", "extra"}, "unexpected argument"},
		{"reset with positional argument", []string{"demo", "reset", "extra"}, "unexpected argument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, tc.args...)
			if code != exitValidation {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitValidation, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on validation failure", stdout)
			}
			if !strings.Contains(stderr, tc.wantMsg) {
				t.Errorf("stderr %q does not contain %q", stderr, tc.wantMsg)
			}
		})
	}
}

// TestDemoResetRequiresYes pins the destructive-command gate (concept
// ch. 11.3, ARCH-001 §3): `demo reset` without --yes fails as a validation
// error (exit 2) and names the confirmation flag — the CLI never prompts
// and never truncates without complete parameters.
func TestDemoResetRequiresYes(t *testing.T) {
	for _, args := range [][]string{{"demo", "reset"}, {"demo", "reset", "--output", "json"}} {
		code, stdout, stderr := runCLI(t, nil, args...)
		if code != exitValidation {
			t.Fatalf("demo reset without --yes: exit code = %d, want %d (stderr: %s)", code, exitValidation, stderr)
		}
		if !strings.Contains(stderr, "--yes") && !strings.Contains(stdout, "--yes") {
			t.Fatalf("demo reset without --yes output stdout %q stderr %q does not name --yes", stdout, stderr)
		}
		if !strings.Contains(stdout, "--yes") {
			// text mode: refusal on stderr, empty stdout; json mode: the
			// envelope on stdout. The --yes mention must appear somewhere.
			if stdout != "" || !strings.Contains(stderr, "--yes") {
				t.Errorf("text mode: stdout = %q, stderr = %q, want refusal on stderr", stdout, stderr)
			}
		}
	}
}
