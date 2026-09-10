package main

// Unit tests for the WP-1a.09 CLI contract: dispatch, exit codes per failure
// class, the non-interactive argument handling and the schema-stable
// --output json envelope. These tests need no PostgreSQL; the integration
// tests that do live in cli_db_test.go. The CLI under test is driven
// through run() with in-memory writers, so os.Exit is never exercised here.

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// cliEnvKeys mirrors every loader input of the config package (config file
// selector plus all RISKSIGNAL_* overrides) so tests start from a clean
// environment.
var cliEnvKeys = []string{
	"RISKSIGNAL_CONFIG_FILE",
	"RISKSIGNAL_ENV",
	"RISKSIGNAL_HTTP_ADDR",
	"RISKSIGNAL_DATABASE_URL",
	"RISKSIGNAL_OIDC_ISSUER",
	"RISKSIGNAL_AUTH_BYPASS_ENABLED",
}

// resetCLIEnv removes every CLI-relevant environment variable and restores
// it when the test ends.
func resetCLIEnv(t *testing.T) {
	t.Helper()
	for _, k := range cliEnvKeys {
		prev, wasSet := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unsetenv %s: %v", k, err)
		}
		t.Cleanup(func() {
			if wasSet {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

// cliValidEnv returns the minimal valid configuration environment used by
// most unit tests.
func cliValidEnv() map[string]string {
	return map[string]string{
		"RISKSIGNAL_DATABASE_URL": "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable",
		"RISKSIGNAL_OIDC_ISSUER":  "http://127.0.0.1:9000/oidc",
	}
}

// runCLI resets the environment, applies env and runs the CLI with args,
// returning the exit code and the captured stdout/stderr.
func runCLI(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	resetCLIEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
	var stdout, stderr strings.Builder
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// rawEnvelope mirrors the fixed JSON envelope for strict decoding: unknown
// keys are rejected, so a schema drift (added/renamed envelope key) fails
// the tests.
type rawEnvelope struct {
	SchemaVersion int             `json:"schema_version"`
	Command       string          `json:"command"`
	ExitCode      int             `json:"exit_code"`
	Status        string          `json:"status"`
	Result        json.RawMessage `json:"result"`
	Error         *errPayload     `json:"error"`
}

// decodeJSONStrict decodes one JSON document and rejects unknown keys and
// trailing content.
func decodeJSONStrict(t *testing.T, data string, dst any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("decode json %q: %v", data, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing content after json document %q: %v", data, err)
	}
}

// decodeEnvelope strictly decodes an --output json envelope.
func decodeEnvelope(t *testing.T, stdout string) rawEnvelope {
	t.Helper()
	var env rawEnvelope
	decodeJSONStrict(t, stdout, &env)
	return env
}

// assertValidationFailure asserts the text-mode verdict of a validation
// error: exit code 2, empty stdout, message on stderr.
func assertValidationFailure(t *testing.T, code int, stdout, stderr, wantMessage string) {
	t.Helper()
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitValidation, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on validation failure", stdout)
	}
	if !strings.Contains(stderr, wantMessage) {
		t.Errorf("stderr %q does not contain %q", stderr, wantMessage)
	}
}

func TestRunNoCommandIsValidation(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil)
	assertValidationFailure(t, code, stdout, stderr, "missing command")

	code, stdout, stderr = runCLI(t, nil, "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "" || env.ExitCode != exitValidation || env.Status != "error" ||
		env.Error == nil || env.Error.Class != classValidation || string(env.Result) != "null" {
		t.Fatalf("envelope = %+v, want validation error for the empty command", env)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty in json mode", stderr)
	}
}

func TestRunUnknownCommandIsValidation(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "badcmd")
	assertValidationFailure(t, code, stdout, stderr, "unknown command")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "badcmd", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "badcmd" || env.ExitCode != exitValidation || env.Status != "error" ||
		env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error naming command badcmd", env)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty in json mode", stderr)
	}
}

func TestRunGlobalOutputFlagPositionAndForms(t *testing.T) {
	// The --output flag is accepted before and after the command and in both
	// spellings; it is consumed globally and never reaches the subcommand.
	code, stdout, stderr := runCLI(t, cliValidEnv(), "--output=json", "diagnose", "config")
	if code != exitOK || stderr != "" {
		t.Fatalf("--output=json before command: code %d, stderr %q", code, stderr)
	}
	if env := decodeEnvelope(t, stdout); env.Status != "ok" {
		t.Fatalf("envelope = %+v, want ok", env)
	}

	code, stdout, _ = runCLI(t, cliValidEnv(), "diagnose", "config", "--output", "json")
	if code != exitOK {
		t.Fatalf("--output after command: code %d", code)
	}
	if env := decodeEnvelope(t, stdout); env.Status != "ok" {
		t.Fatalf("envelope = %+v, want ok", env)
	}
}

func TestRunHelpTextOnlyExitZero(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"--output", "json", "help"}} {
		code, stdout, stderr := runCLI(t, nil, args...)
		if code != exitOK {
			t.Errorf("%v: exit code = %d, want 0", args, code)
		}
		if !strings.Contains(stdout, "usage: risksignal") {
			t.Errorf("%v: stdout does not contain usage text: %q", args, stdout)
		}
		if stderr != "" {
			t.Errorf("%v: stderr = %q, want empty", args, stderr)
		}
	}
}

func TestRunMaintenanceDispatchValidation(t *testing.T) {
	// Missing subcommand.
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance")
	assertValidationFailure(t, code, stdout, stderr, "missing subcommand")

	// Unknown subcommand (text and json).
	code, stdout, stderr = runCLI(t, cliValidEnv(), "maintenance", "bogus")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")

	code, stdout, _ = runCLI(t, cliValidEnv(), "maintenance", "bogus", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "maintenance bogus" || env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error for maintenance bogus", env)
	}
}

func TestRunDiagnoseDispatchValidation(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "diagnose")
	assertValidationFailure(t, code, stdout, stderr, "missing subcommand")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "diagnose", "bogus")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")

	code, stdout, _ = runCLI(t, cliValidEnv(), "diagnose", "bogus", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "diagnose bogus" || env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error for diagnose bogus", env)
	}
}

func TestRunSourceDispatchValidation(t *testing.T) {
	// Missing subcommand.
	code, stdout, stderr := runCLI(t, cliValidEnv(), "source")
	assertValidationFailure(t, code, stdout, stderr, "missing subcommand")

	// Unknown subcommand (text and json) — the monitor subcommands (list,
	// status) land with DEV-043.
	code, stdout, stderr = runCLI(t, cliValidEnv(), "source", "bogus")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")

	code, stdout, _ = runCLI(t, cliValidEnv(), "source", "bogus", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "source bogus" || env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error for source bogus", env)
	}

	// The manual trigger is documented in the usage text.
	code, stdout, stderr = runCLI(t, nil, "help")
	if code != exitOK || !strings.Contains(stdout, "source run <type|id>") {
		t.Fatalf("help: code %d stdout %q, want the source run usage documented", code, stdout)
	}
	if stderr != "" {
		t.Fatalf("help: stderr = %q, want empty", stderr)
	}
}

func TestRunQuarantineDispatchValidation(t *testing.T) {
	// Missing subcommand.
	code, stdout, stderr := runCLI(t, cliValidEnv(), "quarantine")
	assertValidationFailure(t, code, stdout, stderr, "missing subcommand")

	// Unknown subcommand (text and json).
	code, stdout, stderr = runCLI(t, cliValidEnv(), "quarantine", "bogus")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")

	code, stdout, _ = runCLI(t, cliValidEnv(), "quarantine", "bogus", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "quarantine bogus" || env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error for quarantine bogus", env)
	}

	// The subcommands are documented in the usage text.
	code, stdout, stderr = runCLI(t, nil, "help")
	if code != exitOK {
		t.Fatalf("help: code %d stderr %q", code, stderr)
	}
	for _, piece := range []string{"quarantine list", "quarantine ack <id>", "quarantine reprocess <id>"} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("help: stdout does not contain %q", piece)
		}
	}
	if stderr != "" {
		t.Fatalf("help: stderr = %q, want empty", stderr)
	}
}

func TestRunArgumentValidation(t *testing.T) {
	// Validation failures must not depend on the configuration: argument
	// problems are reported before any config load.
	cases := []struct {
		name        string
		args        []string
		wantMessage string
	}{
		{"diagnose config extra arg", []string{"diagnose", "config", "extra"}, "unexpected argument"},
		{"migrate extra arg", []string{"maintenance", "migrate", "extra"}, "unexpected argument"},
		{"migrate unknown flag", []string{"maintenance", "migrate", "--bogus"}, "flag provided but not defined"},
		{"diagnose health extra arg", []string{"diagnose", "health", "extra"}, "unexpected argument"},
		{"source run missing arg", []string{"source", "run"}, "takes exactly one argument"},
		{"source run extra args", []string{"source", "run", "a", "b"}, "takes exactly one argument"},
		{"source run unknown flag", []string{"source", "run", "--bogus", "nvd"}, "flag provided but not defined"},
		{"quarantine ack missing arg", []string{"quarantine", "ack"}, "takes exactly one argument"},
		{"quarantine ack extra args", []string{"quarantine", "ack", "a", "b"}, "takes exactly one argument"},
		{"quarantine ack unknown flag", []string{"quarantine", "ack", "--bogus", "x"}, "flag provided but not defined"},
		{"quarantine reprocess missing arg", []string{"quarantine", "reprocess"}, "takes exactly one argument"},
		{"quarantine reprocess extra args", []string{"quarantine", "reprocess", "a", "b"}, "takes exactly one argument"},
		{"quarantine reprocess unknown flag", []string{"quarantine", "reprocess", "--bogus", "x"}, "flag provided but not defined"},
		{"quarantine list extra arg", []string{"quarantine", "list", "extra"}, "unexpected argument"},
		{"quarantine list unknown flag", []string{"quarantine", "list", "--bogus"}, "flag provided but not defined"},
		{"quarantine list invalid status", []string{"quarantine", "list", "--status", "bogus"}, "invalid QuarantineStatus"},
		{"quarantine list zero limit", []string{"quarantine", "list", "--limit", "0"}, "--limit must be >= 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, tc.args...)
			assertValidationFailure(t, code, stdout, stderr, tc.wantMessage)
		})
	}

	// The same verdict in json mode.
	code, stdout, stderr := runCLI(t, nil, "diagnose", "config", "extra", "--output", "json")
	if code != exitValidation || stderr != "" {
		t.Fatalf("code %d stderr %q, want validation with empty stderr", code, stderr)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "diagnose config" || env.Error == nil || env.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error", env)
	}
}

func TestRunOutputFlagValidation(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "--output", "xml", "diagnose", "config")
	assertValidationFailure(t, code, stdout, stderr, "unsupported format")

	code, stdout, stderr = runCLI(t, nil, "--output")
	assertValidationFailure(t, code, stdout, stderr, "--output requires a value")

	code, stdout, stderr = runCLI(t, nil, "--output=xml", "badcmd", "--output", "json")
	// Both problems are validation failures; the verdict is what matters.
	assertValidationFailure(t, code, stdout, stderr, "unsupported format")
}

func TestRunNotImplementedCommandsExitGeneric(t *testing.T) {
	for _, sub := range []string{"retention", "recompute"} {
		args := []string{"maintenance", sub}
		code, stdout, stderr := runCLI(t, cliValidEnv(), args...)
		if code != exitGeneric {
			t.Errorf("%v: exit code = %d, want %d", args, code, exitGeneric)
		}
		if stdout != "" {
			t.Errorf("%v: stdout = %q, want empty", args, stdout)
		}
		if !strings.Contains(stderr, "not yet implemented") {
			t.Errorf("%v: stderr %q does not say not yet implemented", args, stderr)
		}

		code, stdout, stderr = runCLI(t, cliValidEnv(), append(args, "--output", "json")...)
		if code != exitGeneric || stderr != "" {
			t.Fatalf("%v: code %d stderr %q, want %d with empty stderr", args, code, stderr, exitGeneric)
		}
		env := decodeEnvelope(t, stdout)
		if env.Command != strings.Join(args, " ") || env.Status != "error" ||
			env.Error == nil || env.Error.Class != classGeneric || string(env.Result) != "null" {
			t.Fatalf("%v: envelope = %+v, want generic error", args, env)
		}
	}

	// A stub accepts no options yet — even --yes is rejected until the real
	// implementation defines its contract.
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance", "retention", "--yes")
	assertValidationFailure(t, code, stdout, stderr, "unexpected argument")
}

func TestRunInvalidConfigurationIsValidation(t *testing.T) {
	// Missing mandatory values name the keys only, never secret content.
	code, _, stderr := runCLI(t, nil, "diagnose", "config")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	for _, key := range []string{"database.url", "oidc.issuer"} {
		if !strings.Contains(stderr, key) {
			t.Errorf("stderr %q does not reference %s", stderr, key)
		}
	}

	// An unreadable config file is a configuration failure: exit 2.
	code, stdout, stderr := runCLI(t, map[string]string{"RISKSIGNAL_CONFIG_FILE": "/nonexistent/config.json"}, "diagnose", "config")
	assertValidationFailure(t, code, stdout, stderr, "invalid configuration")

	// The bypass lock (TR-010): production mode with the bypass enabled
	// refuses to start; the message never echoes the flag value.
	env := cliValidEnv()
	env["RISKSIGNAL_ENV"] = "production"
	env["RISKSIGNAL_AUTH_BYPASS_ENABLED"] = "true"
	code, stdout, _ = runCLI(t, env, "diagnose", "config", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit code = %d, want %d", code, exitValidation)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Error == nil || envJSON.Error.Class != classValidation {
		t.Fatalf("envelope = %+v, want validation error", envJSON)
	}
	if !strings.Contains(envJSON.Error.Message, "auth.bypass_enabled") {
		t.Errorf("error message %q does not reference the config key", envJSON.Error.Message)
	}
	if strings.Contains(envJSON.Error.Message, "true") {
		t.Errorf("error message %q echoes the offending value", envJSON.Error.Message)
	}
}

func TestDiagnoseConfigTextRendersProvenanceWithoutSecrets(t *testing.T) {
	env := map[string]string{
		"RISKSIGNAL_DATABASE_URL": "postgres://alice:hunter2secret@db.internal.example:5432/risksignal",
		"RISKSIGNAL_OIDC_ISSUER":  "https://auth.example/oidc-secret",
	}
	code, stdout, stderr := runCLI(t, env, "diagnose", "config")
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	want := []string{
		"config: schema_version:", "1 (source=default)",
		"config: env:", "local (source=default)",
		"config: http.addr:", "set (source=default)",
		"config: database.url:", "set (source=env)",
		"config: oidc.issuer:", "set (source=env)",
		"config: auth.bypass_enabled:", "false (source=default)",
		"config: worker.interval:", "30s (source=default)",
	}
	for _, piece := range want {
		if !strings.Contains(stdout, piece) {
			t.Errorf("stdout does not contain %q:\n%s", piece, stdout)
		}
	}
	for _, secret := range []string{"hunter2secret", "alice", "oidc-secret", "db.internal.example"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("output leaks %q:\n%s", secret, stdout+stderr)
		}
	}
}

// goldenDiagnoseConfigJSON pins the exact bytes of `diagnose config
// --output json` for the cliValidEnv() configuration. Schema stability means
// the keys, their nesting and the null/empty conventions never change.
const goldenDiagnoseConfigJSON = `{
  "schema_version": 1,
  "command": "diagnose config",
  "exit_code": 0,
  "status": "ok",
  "result": {
    "schema_version": {
      "value": 1,
      "source": "default"
    },
    "env": {
      "value": "local",
      "source": "default"
    },
    "http.addr": {
      "set": true,
      "source": "default"
    },
    "database.url": {
      "set": true,
      "source": "env"
    },
    "oidc.issuer": {
      "set": true,
      "source": "env"
    },
    "oidc.client_id": {
      "value": "",
      "source": "default"
    },
    "oidc.client_secret_ref": {
      "set": true,
      "source": "default"
    },
    "oidc.redirect_url": {
      "set": true,
      "source": "default"
    },
    "oidc.scopes": {
      "value": "openid profile email",
      "source": "default"
    },
    "oidc.roles_claim": {
      "value": "roles",
      "source": "default"
    },
    "oidc.role_mappings": {
      "value": "0 mapping(s)",
      "source": "default"
    },
    "oidc.audience": {
      "value": "",
      "source": "default"
    },
    "oidc.session_cookie_name": {
      "value": "risksignal_session",
      "source": "default"
    },
    "oidc.session_ttl": {
      "value": "8h0m0s",
      "source": "default"
    },
    "auth.bypass_enabled": {
      "value": false,
      "source": "default"
    },
    "auth.bypass_principal": {
      "value": "local-developer",
      "source": "default"
    },
    "worker.interval": {
      "value": "30s",
      "source": "default"
    },
    "worker.sla_evaluate_interval": {
      "value": "1m0s",
      "source": "default"
    },
    "worker.sla_reminder_cadence": {
      "value": "1h0m0s",
      "source": "default"
    },
    "worker.retention_schedule": {
      "value": "720h0m0s",
      "source": "default"
    },
    "worker.export_sweep_interval": {
      "value": "24h0m0s",
      "source": "default"
    },
    "export.dir": {
      "value": "var/exports",
      "source": "default"
    },
    "export.ttl": {
      "value": "168h0m0s",
      "source": "default"
    },
    "export.max_rows": {
      "value": 100000,
      "source": "default"
    },
    "notify.p2_active": {
      "value": true,
      "source": "default"
    },
    "notify.smtp.enabled": {
      "value": false,
      "source": "default"
    },
    "notify.smtp.addr": {
      "set": true,
      "source": "default"
    },
    "notify.smtp.from": {
      "set": true,
      "source": "default"
    },
    "notify.smtp.to": {
      "set": true,
      "source": "default"
    },
    "notify.webhook.enabled": {
      "value": false,
      "source": "default"
    },
    "notify.webhook.url": {
      "set": true,
      "source": "default"
    },
    "notify.webhook.secret": {
      "set": true,
      "source": "default"
    }
  },
  "error": null
}
`

func TestDiagnoseConfigJSONIsSchemaStable(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "diagnose", "config", "--output", "json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty in json mode", stderr)
	}
	// Byte-exact golden: any key drift, reordering or secret leak breaks the
	// pin. This is the schema-stability contract of WP-1a.09.
	if stdout != goldenDiagnoseConfigJSON {
		t.Fatalf("stdout differs from the golden envelope:\n--- got ---\n%s--- want ---\n%s", stdout, goldenDiagnoseConfigJSON)
	}

	// A second run is byte-identical (no timestamps, no drift).
	_, second, _ := runCLI(t, cliValidEnv(), "diagnose", "config", "--output", "json")
	if second != stdout {
		t.Fatalf("second run differs from the first:\n%s\nvs\n%s", second, stdout)
	}

	// The envelope decodes strictly into the documented shape and the result
	// decodes strictly into the documented config summary.
	env := decodeEnvelope(t, stdout)
	if env.SchemaVersion != envelopeSchemaVersion || env.Command != "diagnose config" ||
		env.ExitCode != exitOK || env.Status != "ok" || env.Error != nil {
		t.Fatalf("envelope = %+v, want a successful diagnose config envelope", env)
	}
	var sum config.JSONSummary
	decodeJSONStrict(t, string(env.Result), &sum)
	if sum.SchemaVersion.Value != 1 || sum.Env.Value != "local" || sum.AuthBypassEnabled.Value {
		t.Fatalf("result = %+v, want the provenance summary of the defaults", sum)
	}
}

// closedTCPAddr returns a loopback host:port that nothing listens on, so a
// dial refuses instantly instead of hanging.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// openTCPAddr returns a loopback host:port that accepts TCP connections; the
// listener stays open until the test ends.
func openTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String()
}

func TestDiagnoseConnectivityUnreachableIsInfrastructure(t *testing.T) {
	env := cliValidEnv()
	env["RISKSIGNAL_DATABASE_URL"] = "postgres://risksignal:risksignal@" + closedTCPAddr(t) + "/risksignal?sslmode=disable"

	code, stdout, stderr := runCLI(t, env, "diagnose", "connectivity")
	if code != exitInfrastructure {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitInfrastructure, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
	if !strings.Contains(stderr, "database host unreachable") {
		t.Errorf("stderr %q does not explain the infrastructure failure", stderr)
	}

	code, stdout, stderr = runCLI(t, env, "diagnose", "connectivity", "--output", "json")
	if code != exitInfrastructure || stderr != "" {
		t.Fatalf("code %d stderr %q, want %d with empty stderr", code, stderr, exitInfrastructure)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.ExitCode != exitInfrastructure || envJSON.Status != "error" ||
		envJSON.Error == nil || envJSON.Error.Class != classInfrastructure || string(envJSON.Result) != "null" {
		t.Fatalf("envelope = %+v, want an infrastructure error", envJSON)
	}
}

func TestDiagnoseConnectivityReachable(t *testing.T) {
	addr := openTCPAddr(t)
	env := cliValidEnv()
	env["RISKSIGNAL_DATABASE_URL"] = "postgres://risksignal:risksignal@" + addr + "/risksignal?sslmode=disable"

	code, stdout, stderr := runCLI(t, env, "diagnose", "connectivity")
	if code != exitOK || stderr != "" {
		t.Fatalf("code %d stderr %q, want 0 with empty stderr", code, stderr)
	}
	if !strings.Contains(stdout, "reachable (TCP)") {
		t.Errorf("stdout %q does not report reachability", stdout)
	}

	code, stdout, _ = runCLI(t, env, "diagnose", "connectivity", "--output", "json")
	if code != exitOK {
		t.Fatalf("json: exit code = %d, want 0", code)
	}
	envJSON := decodeEnvelope(t, stdout)
	var res connectivityResult
	decodeJSONStrict(t, string(envJSON.Result), &res)
	if res.Target != addr || !res.Reachable {
		t.Fatalf("result = %+v, want target %s reachable", res, addr)
	}
}

func TestDiagnoseHealthReachable(t *testing.T) {
	addr := openTCPAddr(t)
	env := cliValidEnv()
	env["RISKSIGNAL_DATABASE_URL"] = "postgres://risksignal:risksignal@" + addr + "/risksignal?sslmode=disable"

	code, stdout, stderr := runCLI(t, env, "diagnose", "health")
	if code != exitOK || stderr != "" {
		t.Fatalf("code %d stderr %q, want 0", code, stderr)
	}
	for _, piece := range []string{"process: running", "config: valid", "reachable (TCP)", "health: ok"} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("stdout does not contain %q:\n%s", piece, stdout)
		}
	}

	code, stdout, _ = runCLI(t, env, "diagnose", "health", "--output", "json")
	if code != exitOK {
		t.Fatalf("json: exit code = %d, want 0", code)
	}
	envJSON := decodeEnvelope(t, stdout)
	var res healthResult
	decodeJSONStrict(t, string(envJSON.Result), &res)
	if !res.Process.Running || !res.Config.Valid || res.Config.Env != "local" ||
		!res.Database.Reachable || res.Database.Target != addr {
		t.Fatalf("result = %+v, want healthy report", res)
	}
}

func TestDiagnoseHealthUnreachableIsInfrastructure(t *testing.T) {
	env := cliValidEnv()
	env["RISKSIGNAL_DATABASE_URL"] = "postgres://risksignal:risksignal@" + closedTCPAddr(t) + "/risksignal?sslmode=disable"

	code, stdout, stderr := runCLI(t, env, "diagnose", "health")
	if code != exitInfrastructure {
		t.Fatalf("exit code = %d, want %d", code, exitInfrastructure)
	}
	// Text mode still renders the partial report before failing.
	for _, piece := range []string{"process: running", "config: valid", "unreachable", "health: FAIL"} {
		if !strings.Contains(stdout, piece) {
			t.Errorf("stdout does not contain %q:\n%s", piece, stdout)
		}
	}
	if !strings.Contains(stderr, "database host unreachable") {
		t.Errorf("stderr %q does not explain the failure", stderr)
	}

	code, stdout, _ = runCLI(t, env, "diagnose", "health", "--output", "json")
	if code != exitInfrastructure {
		t.Fatalf("json: exit code = %d, want %d", code, exitInfrastructure)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Error == nil || envJSON.Error.Class != classInfrastructure {
		t.Fatalf("envelope = %+v, want an infrastructure error", envJSON)
	}
}

func TestMigrateUnreachableDatabaseIsInfrastructure(t *testing.T) {
	env := cliValidEnv()
	env["RISKSIGNAL_DATABASE_URL"] = "postgres://risksignal:risksignal@" + closedTCPAddr(t) + "/risksignal?sslmode=disable"

	code, stdout, stderr := runCLI(t, env, "maintenance", "migrate")
	if code != exitInfrastructure {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitInfrastructure, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}

	code, stdout, _ = runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitInfrastructure {
		t.Fatalf("json: exit code = %d, want %d", code, exitInfrastructure)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Error == nil || envJSON.Error.Class != classInfrastructure {
		t.Fatalf("envelope = %+v, want an infrastructure error", envJSON)
	}
}

func TestMigrateHelpExitsZero(t *testing.T) {
	code, _, stderr := runCLI(t, nil, "maintenance", "migrate", "--help")
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "usage: risksignal maintenance migrate") {
		t.Errorf("stderr %q does not show the migrate usage", stderr)
	}
}

func TestDBTCPTarget(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    string
		wantErr string
	}{
		{"explicit port", "postgres://u:p@db.example:5432/rs", "db.example:5432", ""},
		{"postgres default port", "postgres://u:p@db.example/rs", "db.example:5432", ""},
		{"postgresql scheme default port", "postgresql://u:p@db.example/rs", "db.example:5432", ""},
		{"ipv6 literal", "postgres://u:p@[::1]:5544/rs", "[::1]:5544", ""},
		{"no host", "postgres:///rs?host=/var/run/postgresql", "", "does not name a host"},
		{"non-postgres scheme without port", "http://u:p@db.example/rs", "", "declares no port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dbTCPTarget(tc.url)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("dbTCPTarget(%s) error = %v, want %q", tc.url, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("dbTCPTarget(%s): %v", tc.url, err)
			}
			if got != tc.want {
				t.Fatalf("dbTCPTarget(%s) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}

	// Errors never echo credentials or the full URL.
	_, err := dbTCPTarget("http://user:hunter2secret@db.example/rs")
	if err == nil {
		t.Fatal("dbTCPTarget(http url without port) succeeded, want error")
	}
	if strings.Contains(err.Error(), "hunter2secret") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("error echoes credentials: %v", err)
	}
}
