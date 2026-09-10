package main

// Unit tests of the WP-5b.08 (I5b) CLI surface (DEV-105, closing the DEV-103
// review finding): the mandatory-field validation of the signal/user/auth
// subcommands (exit 2), the not-logged-in and expired verdicts of
// `auth status` (exit 3) and the schema-stable --output json envelope
// round-trip of the auth subcommands. They follow the cli_test.go pattern —
// the CLI under test is driven through run() with in-memory writers and a
// temp credential store, so os.Exit is never exercised and no PostgreSQL is
// needed. The signal/user success round-trips that do need a database live in
// cli_i5b_integration_test.go.

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/oidc"
	"github.com/brunoxpera/risksignal/internal/platform/config"
	"github.com/brunoxpera/risksignal/internal/platform/credstore"
)

// assertEnvelopeOK strictly decodes an --output json success envelope and
// asserts the fixed schema keys, the command path and an ok status with a
// non-null result and a null error. It returns the decoded envelope so the
// caller can decode the command payload.
func assertEnvelopeOK(t *testing.T, command, stdout, stderr string) rawEnvelope {
	t.Helper()
	if stderr != "" {
		t.Errorf("stderr = %q, want empty in json mode", stderr)
	}
	env := decodeEnvelope(t, stdout)
	if env.SchemaVersion != envelopeSchemaVersion {
		t.Errorf("schema_version = %d, want %d", env.SchemaVersion, envelopeSchemaVersion)
	}
	if env.Command != command {
		t.Errorf("command = %q, want %q", env.Command, command)
	}
	if env.ExitCode != exitOK || env.Status != "ok" || env.Error != nil {
		t.Errorf("envelope = %+v, want exit_code %d, status ok, error null", env, exitOK)
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		t.Errorf("result = %s, want a command payload on success", env.Result)
	}
	return env
}

// TestRunI5bMandatoryFieldValidation asserts the exit-2 validation verdict of
// the mandatory flags the I5b subcommands declare (the same fields the API's
// per-command if/then requires). Validation runs before any config load and
// any database work, so a nil environment is enough.
func TestRunI5bMandatoryFieldValidation(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantMessage string
	}{
		{"assign missing version", []string{"signal", "assign", "--signal", "sig-1", "--owner", "user-1"}, "--version is mandatory"},
		{"assign owner and clear", []string{"signal", "assign", "--signal", "sig-1", "--owner", "user-1", "--clear", "--version", "1"}, "exactly one of --owner or --clear"},
		{"assign neither owner nor clear", []string{"signal", "assign", "--signal", "sig-1", "--version", "1"}, "exactly one of --owner or --clear"},
		{"transition missing version", []string{"signal", "transition", "--signal", "sig-1", "--to", "in_review"}, "--version is mandatory"},
		{"transition missing to", []string{"signal", "transition", "--signal", "sig-1", "--version", "1"}, "--to is mandatory"},
		{"comment missing comment", []string{"signal", "comment", "--signal", "sig-1"}, "--comment is mandatory"},
		{"signal comment missing signal", []string{"signal", "comment", "--comment", "hello"}, "--signal is mandatory"},
		{"pause missing target", []string{"signal", "pause", "--signal", "sig-1"}, "--target is mandatory for pause/resume"},
		{"pause missing reason", []string{"signal", "pause", "--signal", "sig-1", "--target", "notification"}, "--reason is mandatory"},
		{"resume missing target", []string{"signal", "resume", "--signal", "sig-1"}, "--target is mandatory for pause/resume"},
		{"resume missing reason", []string{"signal", "resume", "--signal", "sig-1", "--target", "decision"}, "--reason is mandatory"},
		{"user deactivate without yes", []string{"user", "deactivate", "--user", "user-1"}, "--yes"},
		{"user deactivate missing user", []string{"user", "deactivate", "--yes"}, "--user is mandatory"},
		{"user grant invalid role", []string{"user", "grant", "--user", "user-1", "--role", "bogus"}, "invalid role"},
		{"user revoke invalid role", []string{"user", "revoke", "--user", "user-1", "--role", "bogus"}, "invalid role"},
		{"user grant missing user", []string{"user", "grant", "--role", "auditor"}, "--user is mandatory"},
		{"auth login invalid flow", []string{"auth", "login", "--flow", "bogus"}, "invalid --flow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, tc.args...)
			assertValidationFailure(t, code, stdout, stderr, tc.wantMessage)
		})
	}

	// The same verdict in json mode: an exit-2 envelope, empty stderr.
	code, stdout, stderr := runCLI(t, nil, "signal", "pause", "--signal", "sig-1", "--output", "json")
	if code != exitValidation || stderr != "" {
		t.Fatalf("code %d stderr %q, want validation with empty stderr", code, stderr)
	}
	env := decodeEnvelope(t, stdout)
	if env.Command != "signal pause" || env.ExitCode != exitValidation ||
		env.Status != "error" || env.Error == nil || env.Error.Class != classValidation ||
		string(env.Result) != "null" {
		t.Fatalf("envelope = %+v, want a validation error for signal pause", env)
	}
}

// TestRunI5bDispatchValidation asserts the missing/unknown-subcommand verdict
// (exit 2) of the three new command groups, in text and json mode.
func TestRunI5bDispatchValidation(t *testing.T) {
	for _, cmd := range []string{"signal", "user", "auth"} {
		code, stdout, stderr := runCLI(t, nil, cmd)
		assertValidationFailure(t, code, stdout, stderr, "missing subcommand")

		code, stdout, stderr = runCLI(t, nil, cmd, "bogus")
		assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")

		code, stdout, _ = runCLI(t, nil, cmd, "bogus", "--output", "json")
		if code != exitValidation {
			t.Fatalf("%s bogus: exit code = %d, want %d", cmd, code, exitValidation)
		}
		env := decodeEnvelope(t, stdout)
		if env.Command != cmd+" bogus" || env.ExitCode != exitValidation ||
			env.Status != "error" || env.Error == nil || env.Error.Class != classValidation {
			t.Fatalf("%s bogus: envelope = %+v, want a validation error", cmd, env)
		}
	}
}

// authTestEnv returns a command environment that isolates the credential
// store in a temp file, so the auth tests never read or write the operator's
// real store.
func authTestEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	env := map[string]string{
		"RISKSIGNAL_DATABASE_URL":    "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable",
		"RISKSIGNAL_OIDC_ISSUER":     "http://127.0.0.1:9000/oidc",
		"RISKSIGNAL_OIDC_CLIENT_ID":  "risksignal-cli",
		"RISKSIGNAL_CREDENTIAL_FILE": path,
	}
	return env, path
}

// TestRunAuthStatusNotLoggedInIsAuthentication asserts the exit-3 verdict of
// `auth status` when the store holds no credential.
func TestRunAuthStatusNotLoggedInIsAuthentication(t *testing.T) {
	env, _ := authTestEnv(t)

	code, stdout, stderr := runCLI(t, env, "auth", "status")
	if code != exitAuthentication {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitAuthentication, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
	if !strings.Contains(stderr, "not logged in") {
		t.Errorf("stderr %q does not report the missing login", stderr)
	}

	code, stdout, stderr = runCLI(t, env, "auth", "status", "--output", "json")
	if code != exitAuthentication || stderr != "" {
		t.Fatalf("json: code %d stderr %q, want %d with empty stderr", code, stderr, exitAuthentication)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Command != "auth status" || envJSON.ExitCode != exitAuthentication ||
		envJSON.Status != "error" || envJSON.Error == nil ||
		envJSON.Error.Class != classAuthentication || string(envJSON.Result) != "null" {
		t.Fatalf("envelope = %+v, want an authentication error for auth status", envJSON)
	}
}

// TestRunAuthStatusExpiredIsAuthentication asserts that an expired stored
// credential is an authentication failure (exit 3) and that the verdict never
// echoes the stored token.
func TestRunAuthStatusExpiredIsAuthentication(t *testing.T) {
	env, path := authTestEnv(t)
	store := credstore.OpenPath(path)
	if err := store.Save(credstore.Credential{
		Issuer:      env["RISKSIGNAL_OIDC_ISSUER"],
		SubjectID:   "local::security-analyst",
		DisplayName: "Security Analyst",
		AccessToken: "super-secret-access",
		ObtainedAt:  time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	code, stdout, stderr := runCLI(t, env, "auth", "status", "--output", "json")
	if code != exitAuthentication || stderr != "" {
		t.Fatalf("code %d stderr %q, want %d with empty stderr", code, stderr, exitAuthentication)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.ExitCode != exitAuthentication || envJSON.Error == nil || envJSON.Error.Class != classAuthentication {
		t.Fatalf("envelope = %+v, want an authentication error", envJSON)
	}
	if strings.Contains(stdout+stderr, "super-secret-access") {
		t.Fatalf("output leaks the stored token:\n%s%s", stdout, stderr)
	}
}

// TestRunAuthLoginStatusLogoutJSONRoundTrip drives the full auth lifecycle
// with a deterministic, network-free login runner and asserts one schema-
// stable --output json success envelope per subcommand.
func TestRunAuthLoginStatusLogoutJSONRoundTrip(t *testing.T) {
	env, _ := authTestEnv(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	prev := authLoginRunner
	authLoginRunner = func(context.Context, *config.Config, string, string, io.Writer) (oidc.Tokens, error) {
		return oidc.Tokens{
			Identity:     oidc.Identity{SubjectID: "local::security-analyst", DisplayName: "Security Analyst"},
			AccessToken:  "access-secret",
			RefreshToken: "refresh-secret",
			IDToken:      "id-secret",
			TokenType:    "Bearer",
			ExpiresAt:    expires,
		}, nil
	}
	t.Cleanup(func() { authLoginRunner = prev })

	// login: identity only, tokens stored and never rendered.
	code, stdout, stderr := runCLI(t, env, "auth", "login", "--output", "json")
	if code != exitOK {
		t.Fatalf("login: exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	loginEnv := assertEnvelopeOK(t, "auth login", stdout, stderr)
	var loginView authLoginView
	decodeJSONStrict(t, string(loginEnv.Result), &loginView)
	if !loginView.Stored || loginView.SubjectID != "local::security-analyst" || loginView.TokenType != "Bearer" {
		t.Fatalf("login result = %+v, want the stored non-secret identity", loginView)
	}
	for _, secret := range []string{"access-secret", "refresh-secret", "id-secret"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Fatalf("login output leaks %q:\n%s%s", secret, stdout, stderr)
		}
	}

	// status: the stored, non-secret identity.
	code, stdout, stderr = runCLI(t, env, "auth", "status", "--output", "json")
	if code != exitOK {
		t.Fatalf("status: exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	statusEnv := assertEnvelopeOK(t, "auth status", stdout, stderr)
	var statusView authStatusView
	decodeJSONStrict(t, string(statusEnv.Result), &statusView)
	if statusView.SubjectID != "local::security-analyst" || statusView.Expired {
		t.Fatalf("status result = %+v, want the active logged-in identity", statusView)
	}

	// logout: the stored login is removed.
	code, stdout, stderr = runCLI(t, env, "auth", "logout", "--output", "json")
	if code != exitOK {
		t.Fatalf("logout: exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	logoutEnv := assertEnvelopeOK(t, "auth logout", stdout, stderr)
	var logoutView authLogoutView
	decodeJSONStrict(t, string(logoutEnv.Result), &logoutView)
	if logoutView.Removed != 1 || len(logoutView.Issuers) != 1 {
		t.Fatalf("logout result = %+v, want one removed login", logoutView)
	}
}
