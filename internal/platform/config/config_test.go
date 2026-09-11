package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envKeys lists every loader input that tests must isolate: the optional
// config file selector plus all RISKSIGNAL_* overrides.
var envKeys = []string{
	envVarConfigFile,
	envName("env"),
	envName("http.addr"),
	envName("database.url"),
	envName("oidc.issuer"),
	envName("oidc.client_id"),
	envName("oidc.client_secret_ref"),
	envName("oidc.redirect_url"),
	envName("oidc.scopes"),
	envName("oidc.roles_claim"),
	envName("oidc.role_mappings"),
	envName("oidc.audience"),
	envName("oidc.session_cookie_name"),
	envName("oidc.session_ttl"),
	envName("auth.bypass_enabled"),
	envName("auth.bypass_principal"),
	envName("worker.interval"),
}

// resetEnv removes every loader input so each test starts from pure
// defaults, mirroring an empty process environment.
func resetEnv(t *testing.T) {
	t.Helper()
	for _, k := range envKeys {
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

// writeConfigFile writes a JSON config file into a temp dir and returns its
// path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// loadWithEnv points the loader at a config file and environment values
// expressed as key -> value pairs, then runs Load. Keys absent from the map
// stay unset.
func loadWithEnv(t *testing.T, file string, env map[string]string) (*Config, error) {
	t.Helper()
	resetEnv(t)
	if file != "" {
		t.Setenv(envVarConfigFile, file)
	}
	for k, v := range env {
		t.Setenv(envName(k), v)
	}
	return Load()
}

// validEnv returns a minimal environment that passes validation when the
// defaults are used.
func validEnv() map[string]string {
	return map[string]string{
		"database.url": "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal",
		"oidc.issuer":  "https://auth.local.example/",
	}
}

func mustLoad(t *testing.T, file string, env map[string]string) *Config {
	t.Helper()
	cfg, err := loadWithEnv(t, file, env)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	return cfg
}

func mustFail(t *testing.T, file string, env map[string]string, wantKey string) {
	t.Helper()
	_ = mustFailErr(t, file, env, wantKey)
}

// mustFailErr runs the mustFail assertions and returns the error for call
// sites that also inspect it.
func mustFailErr(t *testing.T, file string, env map[string]string, wantKey string) error {
	t.Helper()
	_, err := loadWithEnv(t, file, env)
	if err == nil {
		t.Fatalf("Load() succeeded (env=%v), want failure naming %q", env, wantKey)
	}
	if wantKey != "" && !strings.Contains(err.Error(), wantKey) {
		t.Fatalf("Load() error %q does not reference %q", err, wantKey)
	}
	return err
}

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.SchemaVersion != SchemaVersion {
		t.Errorf("Defaults().SchemaVersion = %d, want %d", d.SchemaVersion, SchemaVersion)
	}
	if d.Env != "local" {
		t.Errorf("Defaults().Env = %q, want %q", d.Env, "local")
	}
	if d.HTTP.Addr != "127.0.0.1:8080" {
		t.Errorf("Defaults().HTTP.Addr = %q, want loopback default", d.HTTP.Addr)
	}
	if d.Database.URL != "" {
		t.Errorf("Defaults().Database.URL = %q, want empty (mandatory, runtime-injected)", d.Database.URL)
	}
	if d.OIDC.Issuer != "" {
		t.Errorf("Defaults().OIDC.Issuer = %q, want empty (mandatory, runtime-injected)", d.OIDC.Issuer)
	}
	if d.Auth.BypassEnabled {
		t.Error("Defaults().Auth.BypassEnabled = true, want false (secure default)")
	}
	if d.Worker.Interval != 30*time.Second {
		t.Errorf("Defaults().Worker.Interval = %s, want 30s", d.Worker.Interval)
	}
}

func TestLoadMissingMandatoryValues(t *testing.T) {
	t.Run("database.url", func(t *testing.T) {
		mustFail(t, "", map[string]string{"oidc.issuer": "https://auth.local.example/"}, "database.url")
	})
	t.Run("oidc.issuer", func(t *testing.T) {
		mustFail(t, "", map[string]string{"database.url": "postgres://u@h/db"}, "oidc.issuer")
	})
	t.Run("http.addr overridden empty", func(t *testing.T) {
		env := validEnv()
		env["http.addr"] = ""
		mustFail(t, "", env, "http.addr")
	})
}

func TestLoadInvalidURLs(t *testing.T) {
	t.Run("oidc.issuer without scheme", func(t *testing.T) {
		env := validEnv()
		env["oidc.issuer"] = "auth.local.example"
		mustFail(t, "", env, "oidc.issuer")
	})
	t.Run("oidc.issuer without host", func(t *testing.T) {
		env := validEnv()
		env["oidc.issuer"] = "https:///path-only"
		mustFail(t, "", env, "oidc.issuer")
	})
	t.Run("database.url without host", func(t *testing.T) {
		env := validEnv()
		env["database.url"] = "postgres:///db-only"
		mustFail(t, "", env, "database.url")
	})
}

// TestValidateControlCharacterURL covers input that cannot be transported
// through an environment variable (os.Setenv rejects NUL bytes).
func TestValidateControlCharacterURL(t *testing.T) {
	cfg := Defaults()
	cfg.Database.URL = "postgres://user:secret@127.0.0.1:5432/db\x00name"
	cfg.OIDC.Issuer = "https://auth.local.example/"
	errs := Validate(&cfg)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "database.url") {
			found = true
		}
	}
	if !found {
		t.Errorf("Validate() errors %v do not reject the control-character database.url", errs)
	}
}

func TestLoadInvalidEnvMode(t *testing.T) {
	env := validEnv()
	env["env"] = "staging"
	mustFail(t, "", env, "env")
}

func TestLoadInvalidHTTPAddr(t *testing.T) {
	env := validEnv()
	env["http.addr"] = "127.0.0.1" // host without port
	mustFail(t, "", env, "http.addr")
}

// TestLoadInvalidBypassEnvValue proves a malformed boolean env value fails
// without echoing the offending value in the error.
func TestLoadInvalidBypassEnvValue(t *testing.T) {
	env := validEnv()
	env["auth.bypass_enabled"] = "yes"
	err := mustFailErr(t, "", env, "auth.bypass_enabled")
	if strings.Contains(err.Error(), "yes") {
		t.Errorf("Load() error echoes the offending value: %v", err)
	}
}

// TestValidateBypassLock is the pure-validation matrix for TR-010.
func TestValidateBypassLock(t *testing.T) {
	for _, env := range []string{"local", "demo", "production"} {
		for _, bypass := range []bool{false, true} {
			t.Run(env+"/bypass="+boolStr(bypass), func(t *testing.T) {
				cfg := Defaults()
				cfg.Env = env
				cfg.Auth.BypassEnabled = bypass
				cfg.Database.URL = "postgres://u@h/db"
				cfg.OIDC.Issuer = "https://auth.local.example/"
				errs := Validate(&cfg)
				wantErr := bypass && env != "local"
				gotErr := len(errs) > 0
				if gotErr != wantErr {
					t.Fatalf("Validate() errs = %v, wantErr = %v", errs, wantErr)
				}
				if wantErr {
					found := false
					for _, e := range errs {
						if strings.Contains(e.Error(), "auth.bypass_enabled") {
							found = true
						}
					}
					if !found {
						t.Errorf("Validate() errors %v do not name auth.bypass_enabled", errs)
					}
				}
			})
		}
	}
}

// TestLoadWorkerIntervalFromEnv resolves the scheduler interval from the
// environment and reports its provenance.
func TestLoadWorkerIntervalFromEnv(t *testing.T) {
	env := validEnv()
	env["worker.interval"] = "45s"
	cfg := mustLoad(t, "", env)
	if cfg.Worker.Interval != 45*time.Second {
		t.Errorf("Worker.Interval = %s, want 45s", cfg.Worker.Interval)
	}
	line := summaryLine(cfg.Summary(), "worker.interval")
	if !strings.Contains(line, "45s (source=env)") {
		t.Errorf("Summary() worker.interval line %q does not render the resolved value with its source", line)
	}
}

// TestLoadWorkerIntervalFromFile resolves the scheduler interval from the
// optional config file.
func TestLoadWorkerIntervalFromFile(t *testing.T) {
	file := writeConfigFile(t, `{
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {"issuer": "https://issuer.file.example/"},
		"worker": {"interval": "1m"}
	}`)
	cfg := mustLoad(t, file, nil)
	if cfg.Worker.Interval != time.Minute {
		t.Errorf("Worker.Interval = %s, want 1m", cfg.Worker.Interval)
	}
	line := summaryLine(cfg.Summary(), "worker.interval")
	if !strings.Contains(line, "1m0s (source=file)") {
		t.Errorf("Summary() worker.interval line %q does not render the file value with its source", line)
	}
}

// TestLoadInvalidWorkerInterval rejects unparsable, empty and non-positive
// durations without echoing the offending value.
func TestLoadInvalidWorkerInterval(t *testing.T) {
	t.Run("unparsable env value", func(t *testing.T) {
		env := validEnv()
		env["worker.interval"] = "fast"
		err := mustFailErr(t, "", env, "worker.interval")
		if strings.Contains(err.Error(), "fast") {
			t.Errorf("Load() error echoes the offending value: %v", err)
		}
	})
	t.Run("empty env value", func(t *testing.T) {
		env := validEnv()
		env["worker.interval"] = ""
		mustFail(t, "", env, "worker.interval")
	})
	t.Run("unparsable file value", func(t *testing.T) {
		file := writeConfigFile(t, `{
			"worker": {"interval": "often"}
		}`)
		err := mustFailErr(t, file, validEnv(), "worker.interval")
		if strings.Contains(err.Error(), "often") {
			t.Errorf("Load() error echoes the offending value: %v", err)
		}
	})
}

// TestValidateWorkerIntervalRequiresPositiveValue is the pure-validation
// matrix for the scheduler interval: zero and negative values are invalid.
func TestValidateWorkerIntervalRequiresPositiveValue(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			cfg := Defaults()
			cfg.Database.URL = "postgres://u@h/db"
			cfg.OIDC.Issuer = "https://auth.local.example/"
			cfg.Worker.Interval = interval
			errs := Validate(&cfg)
			found := false
			for _, e := range errs {
				if strings.Contains(e.Error(), "worker.interval") {
					found = true
				}
			}
			if !found {
				t.Errorf("Validate() errors %v do not reject worker.interval %s", errs, interval)
			}
		})
	}
}

func TestLoadBypassAllowedInLocalMode(t *testing.T) {
	env := validEnv()
	env["auth.bypass_enabled"] = "true"
	cfg := mustLoad(t, "", env)
	if !cfg.Auth.BypassEnabled {
		t.Error("Auth.BypassEnabled = false, want true")
	}
	if cfg.Env != "local" {
		t.Errorf("Env = %q, want %q", cfg.Env, "local")
	}
}

func TestLoadBypassForbiddenInOnlineModes(t *testing.T) {
	for _, mode := range []string{"demo", "production"} {
		t.Run(mode, func(t *testing.T) {
			env := validEnv()
			env["env"] = mode
			env["auth.bypass_enabled"] = "true"
			mustFail(t, "", env, "auth.bypass_enabled")
		})
	}
}

// TestPrecedenceEnvOverFileOverDefaults drives all three layers with
// distinct values and asserts both the resolved value and the provenance.
func TestPrecedenceEnvOverFileOverDefaults(t *testing.T) {
	file := writeConfigFile(t, `{
		"schema_version": 1,
		"env": "demo",
		"http": {"addr": "127.0.0.1:9090"},
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {"issuer": "https://issuer.file.example/"}
	}`)
	env := map[string]string{
		"env":          "production",                  // env var overrides the file's demo
		"database.url": "postgres://env@127.0.0.1/db", // env var overrides the file
		// oidc.issuer and http.addr intentionally stay with file values.
	}
	cfg := mustLoad(t, file, env)

	if cfg.Env != "production" {
		t.Errorf("Env = %q, want %q (env beats file)", cfg.Env, "production")
	}
	if cfg.HTTP.Addr != "127.0.0.1:9090" {
		t.Errorf("HTTP.Addr = %q, want %q (file beats default)", cfg.HTTP.Addr, "127.0.0.1:9090")
	}
	if cfg.Database.URL != "postgres://env@127.0.0.1/db" {
		t.Errorf("Database.URL = %q, want env value (env beats file)", cfg.Database.URL)
	}
	if cfg.OIDC.Issuer != "https://issuer.file.example/" {
		t.Errorf("OIDC.Issuer = %q, want %q (file beats default)", cfg.OIDC.Issuer, "https://issuer.file.example/")
	}
	if cfg.Auth.BypassEnabled {
		t.Error("Auth.BypassEnabled = true, want false (default survives untouched)")
	}
	if cfg.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", cfg.SchemaVersion)
	}

	sum := cfg.Summary()
	wantSrc := map[string]string{
		"schema_version": "source=file", // the file declares schema_version 1
		"env":            "source=env",
		"http.addr":      "source=file",
		"database.url":   "source=env",
		"oidc.issuer":    "source=file",
	}
	for key, want := range wantSrc {
		line := summaryLine(sum, key)
		if line == "" {
			t.Errorf("Summary() missing key %q:\n%s", key, sum)
			continue
		}
		if !strings.Contains(line, want) {
			t.Errorf("Summary() key %q line %q does not contain %q", key, line, want)
		}
	}
}

// TestConfigFileOnly runs entirely on file + defaults, proving the file
// layer works without any env override.
func TestConfigFileOnly(t *testing.T) {
	file := writeConfigFile(t, `{
		"env": "local",
		"http": {"addr": "127.0.0.1:9999"},
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {"issuer": "https://issuer.file.example/"},
		"auth": {"bypass_enabled": true}
	}`)
	cfg := mustLoad(t, file, nil)
	if cfg.HTTP.Addr != "127.0.0.1:9999" {
		t.Errorf("HTTP.Addr = %q, want file value", cfg.HTTP.Addr)
	}
	if !cfg.Auth.BypassEnabled {
		t.Error("Auth.BypassEnabled = false, want true from file")
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	resetEnv(t)
	t.Setenv(envVarConfigFile, filepath.Join(t.TempDir(), "missing.json"))
	_, err := Load()
	if err == nil {
		t.Fatal("Load() succeeded with a missing config file, want error")
	}
	if !strings.Contains(err.Error(), "config file") {
		t.Errorf("Load() error %q does not mention the config file", err)
	}
}

func TestLoadConfigFileEmpty(t *testing.T) {
	file := writeConfigFile(t, "")
	mustFail(t, file, validEnv(), "empty file")
}

func TestLoadConfigFileUnknownKey(t *testing.T) {
	file := writeConfigFile(t, `{"env": "local", "databse": {"url": "postgres://typo@h/db"}}`)
	mustFail(t, file, validEnv(), "databse")
}

func TestLoadConfigFileSchemaMismatch(t *testing.T) {
	file := writeConfigFile(t, `{"schema_version": 2, "env": "local"}`)
	mustFail(t, file, validEnv(), "schema_version")
}

// TestLoadConfigFileWithSecretsOnlyFromFile checks the local bypass lock
// against a bypass enabled through the file layer.
func TestLoadConfigFileBypassLockedOnline(t *testing.T) {
	file := writeConfigFile(t, `{
		"env": "production",
		"database": {"url": "postgres://u@h/db"},
		"oidc": {"issuer": "https://issuer.file.example/"},
		"auth": {"bypass_enabled": true}
	}`)
	mustFail(t, file, nil, "auth.bypass_enabled")
}

// TestSummaryRedactsSecrets proves the provenance report names sources but
// never prints values that could carry credentials.
func TestSummaryRedactsSecrets(t *testing.T) {
	secret := "postgres://user:s3cr3t-password@127.0.0.1:5432/risksignal"
	env := map[string]string{
		"http.addr":    "127.0.0.1:8443",
		"database.url": secret,
		"oidc.issuer":  "https://issuer.with-token.example/",
	}
	cfg := mustLoad(t, "", env)
	sum := cfg.Summary()

	for _, leaked := range []string{"s3cr3t-password", secret, "127.0.0.1:8443", "issuer.with-token.example"} {
		if strings.Contains(sum, leaked) {
			t.Errorf("Summary() leaks %q:\n%s", leaked, sum)
		}
	}
	for _, want := range []struct {
		key, fragment string
	}{
		{"database.url", "set (source=env)"},
		{"http.addr", "set (source=env)"},
		{"oidc.issuer", "set (source=env)"},
		{"auth.bypass_enabled", "false (source=default)"},
	} {
		line := summaryLine(sum, want.key)
		if line == "" {
			t.Errorf("Summary() missing key %q:\n%s", want.key, sum)
			continue
		}
		if !strings.Contains(line, want.fragment) {
			t.Errorf("Summary() key %q line %q does not contain %q", want.key, line, want.fragment)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// summaryLine returns the Summary() line that starts with "config: <key>:",
// or "" if there is none.
func summaryLine(sum, key string) string {
	for _, line := range strings.Split(sum, "\n") {
		if strings.HasPrefix(line, "config: "+key+":") || strings.HasPrefix(line, "config: "+key+" ") {
			return line
		}
	}
	return ""
}

// TestValidateBypassRequiresLoopback is the ARCH-005 §4.1 loopback-lock
// matrix: with the bypass on in local mode, only a loopback http.addr may
// start. An all-interfaces or non-loopback address is refused; a 127.0.0.0/8
// or ::1 literal (and "localhost") is accepted.
func TestValidateBypassRequiresLoopback(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:8080", true},
		{"127.5.5.5:8080", true}, // any 127.0.0.0/8 address
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"0.0.0.0:8080", false}, // all interfaces
		{":8080", false},        // all interfaces
		{"192.168.1.5:8080", false},
		{"[2001:db8::1]:8080", false},
		{"example.com:8080", false}, // hostname is not resolved
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			cfg := Defaults()
			cfg.Env = "local"
			cfg.Auth.BypassEnabled = true
			cfg.HTTP.Addr = tc.addr
			cfg.Database.URL = "postgres://u@h/db"
			cfg.OIDC.Issuer = "https://auth.local.example/"
			errs := Validate(&cfg)
			hasBypassErr := false
			for _, e := range errs {
				if strings.Contains(e.Error(), "auth.bypass_enabled") {
					hasBypassErr = true
				}
			}
			if !tc.ok && !hasBypassErr {
				t.Errorf("Validate() accepted non-loopback %q with the bypass on, want rejection", tc.addr)
			}
			if tc.ok && hasBypassErr {
				t.Errorf("Validate() rejected loopback %q with the bypass on: %v", tc.addr, errs)
			}
		})
	}
}

// TestLoadBypassForbiddenOffLoopback proves the lock at the loader: local
// mode + bypass on a non-loopback bind fails before the process binds.
func TestLoadBypassForbiddenOffLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "192.168.1.5:8080", "[2001:db8::1]:8080"} {
		t.Run(addr, func(t *testing.T) {
			env := validEnv()
			env["auth.bypass_enabled"] = "true"
			env["http.addr"] = addr
			mustFail(t, "", env, "auth.bypass_enabled")
		})
	}
}

// TestLoadBypassAllowedOnLoopbackV6 proves a ::1 bind is accepted with the
// bypass on in local mode.
func TestLoadBypassAllowedOnLoopbackV6(t *testing.T) {
	env := validEnv()
	env["auth.bypass_enabled"] = "true"
	env["http.addr"] = "[::1]:8080"
	cfg := mustLoad(t, "", env)
	if !cfg.Auth.BypassEnabled {
		t.Error("Auth.BypassEnabled = false, want true")
	}
	if cfg.Auth.BypassPrincipal != "local-developer" {
		t.Errorf("Auth.BypassPrincipal = %q, want the default local-developer", cfg.Auth.BypassPrincipal)
	}
}

// TestLoadOIDCConfigExtension resolves every new oidc.* key from the
// environment and asserts both the resolved values and the secrecy of the
// provenance report (the secret reference and the provider URLs render as
// presence only).
func TestLoadOIDCConfigExtension(t *testing.T) {
	secretRef := "vault://risksignal/oidc-client-secret"
	env := validEnv()
	env["oidc.client_id"] = "risksignal-web"
	env["oidc.client_secret_ref"] = secretRef
	env["oidc.redirect_url"] = "https://app.example/oidc/callback-secret"
	env["oidc.scopes"] = "openid, profile ,email"
	env["oidc.roles_claim"] = "realm_access.roles"
	env["oidc.role_mappings"] = `{"sec":"security_analyst","adm":"administrator"}`
	env["oidc.audience"] = "risksignal-api"
	env["oidc.session_cookie_name"] = "rs_session"
	env["oidc.session_ttl"] = "2h"

	cfg := mustLoad(t, "", env)
	if cfg.OIDC.ClientID != "risksignal-web" {
		t.Errorf("OIDC.ClientID = %q", cfg.OIDC.ClientID)
	}
	if cfg.OIDC.ClientSecretRef != secretRef {
		t.Errorf("OIDC.ClientSecretRef = %q", cfg.OIDC.ClientSecretRef)
	}
	if cfg.OIDC.RedirectURL != "https://app.example/oidc/callback-secret" {
		t.Errorf("OIDC.RedirectURL = %q", cfg.OIDC.RedirectURL)
	}
	if strings.Join(cfg.OIDC.Scopes, ",") != "openid,profile,email" {
		t.Errorf("OIDC.Scopes = %v, want [openid profile email]", cfg.OIDC.Scopes)
	}
	if cfg.OIDC.RolesClaim != "realm_access.roles" {
		t.Errorf("OIDC.RolesClaim = %q", cfg.OIDC.RolesClaim)
	}
	if cfg.OIDC.RoleMappings["sec"] != "security_analyst" || cfg.OIDC.RoleMappings["adm"] != "administrator" {
		t.Errorf("OIDC.RoleMappings = %v", cfg.OIDC.RoleMappings)
	}
	if cfg.OIDC.Audience != "risksignal-api" {
		t.Errorf("OIDC.Audience = %q", cfg.OIDC.Audience)
	}
	if cfg.OIDC.SessionCookieName != "rs_session" {
		t.Errorf("OIDC.SessionCookieName = %q", cfg.OIDC.SessionCookieName)
	}
	if cfg.OIDC.SessionTTL != 2*time.Hour {
		t.Errorf("OIDC.SessionTTL = %s, want 2h", cfg.OIDC.SessionTTL)
	}

	sum := cfg.Summary()
	for _, leak := range []string{secretRef, "callback-secret"} {
		if strings.Contains(sum, leak) {
			t.Errorf("Summary() leaks %q:\n%s", leak, sum)
		}
	}
	for _, want := range []struct{ key, fragment string }{
		{"oidc.client_id", "risksignal-web (source=env)"},
		{"oidc.client_secret_ref", "set (source=env)"},
		{"oidc.redirect_url", "set (source=env)"},
		{"oidc.scopes", "openid profile email (source=env)"},
		{"oidc.roles_claim", "realm_access.roles (source=env)"},
		{"oidc.role_mappings", "2 mapping(s) (source=env)"},
		{"oidc.audience", "risksignal-api (source=env)"},
		{"oidc.session_cookie_name", "rs_session (source=env)"},
		{"oidc.session_ttl", "2h0m0s (source=env)"},
	} {
		line := summaryLine(sum, want.key)
		if !strings.Contains(line, want.fragment) {
			t.Errorf("Summary() key %q line %q does not contain %q", want.key, line, want.fragment)
		}
	}
}

// TestLoadOIDCConfigFile proves the file layer carries the same keys,
// including the role mapping object.
func TestLoadOIDCConfigFile(t *testing.T) {
	file := writeConfigFile(t, `{
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {
			"issuer": "https://issuer.file.example/",
			"client_id": "file-client",
			"redirect_url": "https://file.example/cb",
			"scopes": ["openid", "email"],
			"roles_claim": "roles",
			"role_mappings": {"analyst": "security_analyst"},
			"session_cookie_name": "file_session",
			"session_ttl": "1h"
		}
	}`)
	cfg := mustLoad(t, file, nil)
	if cfg.OIDC.ClientID != "file-client" {
		t.Errorf("OIDC.ClientID = %q", cfg.OIDC.ClientID)
	}
	if cfg.OIDC.SessionTTL != time.Hour {
		t.Errorf("OIDC.SessionTTL = %s, want 1h", cfg.OIDC.SessionTTL)
	}
	if cfg.OIDC.RoleMappings["analyst"] != "security_analyst" {
		t.Errorf("OIDC.RoleMappings = %v", cfg.OIDC.RoleMappings)
	}
	if cfg.OIDC.SessionCookieName != "file_session" {
		t.Errorf("OIDC.SessionCookieName = %q", cfg.OIDC.SessionCookieName)
	}
}

// TestLoadInvalidRoleMappings rejects a non-object env value without echoing
// it.
func TestLoadInvalidRoleMappings(t *testing.T) {
	env := validEnv()
	env["oidc.role_mappings"] = "not-json"
	err := mustFailErr(t, "", env, "oidc.role_mappings")
	if strings.Contains(err.Error(), "not-json") {
		t.Errorf("Load() error echoes the offending value: %v", err)
	}
}

// TestValidateOIDCScopesAndSessionTTL is the pure-validation matrix for the
// two non-secret oidc defaults: at least one scope, a positive session TTL.
func TestValidateOIDCScopesAndSessionTTL(t *testing.T) {
	t.Run("empty scopes", func(t *testing.T) {
		cfg := Defaults()
		cfg.Database.URL = "postgres://u@h/db"
		cfg.OIDC.Issuer = "https://auth.local.example/"
		cfg.OIDC.Scopes = nil
		errs := Validate(&cfg)
		if !errsContain(errs, "oidc.scopes") {
			t.Errorf("Validate() errors %v do not reject empty oidc.scopes", errs)
		}
	})
	t.Run("non-positive session ttl", func(t *testing.T) {
		for _, ttl := range []time.Duration{0, -time.Minute} {
			cfg := Defaults()
			cfg.Database.URL = "postgres://u@h/db"
			cfg.OIDC.Issuer = "https://auth.local.example/"
			cfg.OIDC.SessionTTL = ttl
			errs := Validate(&cfg)
			if !errsContain(errs, "oidc.session_ttl") {
				t.Errorf("Validate() errors %v do not reject oidc.session_ttl %s", errs, ttl)
			}
		}
	})
}

func errsContain(errs []error, key string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), key) {
			return true
		}
	}
	return false
}

// TestRetentionDefaults pins the built-in retention vocabulary (ARCH-007 §10):
// a five-year period, pseudonymisation defaulting to the retention period
// (0 = inherit), the §14.1 batch size and the monthly cadence.
func TestRetentionDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Retention.ClosedSignalYears != 5 {
		t.Errorf("Retention.ClosedSignalYears = %d, want 5", cfg.Retention.ClosedSignalYears)
	}
	if cfg.Retention.PseudonymiseYears != 0 {
		t.Errorf("Retention.PseudonymiseYears = %d, want 0 (= closed_signal_years)", cfg.Retention.PseudonymiseYears)
	}
	if cfg.Retention.BatchSize != 500 {
		t.Errorf("Retention.BatchSize = %d, want 500", cfg.Retention.BatchSize)
	}
	if cfg.Retention.Schedule != 30*24*time.Hour {
		t.Errorf("Retention.Schedule = %s, want 720h", cfg.Retention.Schedule)
	}
}

// TestLoadRetentionFromEnv resolves every retention key from RISKSIGNAL_*
// environment variables.
func TestLoadRetentionFromEnv(t *testing.T) {
	env := validEnv()
	env["retention.closed_signal_years"] = "7"
	env["retention.pseudonymise_years"] = "3"
	env["retention.batch_size"] = "250"
	env["retention.schedule"] = "1h"
	cfg := mustLoad(t, "", env)
	if cfg.Retention.ClosedSignalYears != 7 || cfg.Retention.PseudonymiseYears != 3 || cfg.Retention.BatchSize != 250 || cfg.Retention.Schedule != time.Hour {
		t.Fatalf("retention = %+v, want 7/3/250/1h", cfg.Retention)
	}
	line := summaryLine(cfg.Summary(), "retention.schedule")
	if !strings.Contains(line, "1h0m0s (source=env)") {
		t.Errorf("Summary() retention.schedule line %q does not render the env value with its source", line)
	}
}

// TestLoadRetentionFromFile resolves the retention keys from the config file.
func TestLoadRetentionFromFile(t *testing.T) {
	file := writeConfigFile(t, `{
		"database": {"url": "postgres://file@127.0.0.1/db"},
		"oidc": {"issuer": "https://issuer.file.example/"},
		"retention": {"closed_signal_years": 6, "batch_size": 100, "schedule": "48h"}
	}`)
	cfg := mustLoad(t, file, nil)
	if cfg.Retention.ClosedSignalYears != 6 || cfg.Retention.BatchSize != 100 || cfg.Retention.Schedule != 48*time.Hour {
		t.Fatalf("retention = %+v, want 6/100/48h", cfg.Retention)
	}
}

// TestValidateRetentionRejectsNonPositive is the pure-validation matrix for
// the retention keys: a non-positive period/batch/schedule and a negative
// pseudonymisation period are invalid.
func TestValidateRetentionRejectsNonPositive(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		key    string
	}{
		{"closed_signal_years", func(c *Config) { c.Retention.ClosedSignalYears = 0 }, "retention.closed_signal_years"},
		{"pseudonymise_years", func(c *Config) { c.Retention.PseudonymiseYears = -1 }, "retention.pseudonymise_years"},
		{"batch_size", func(c *Config) { c.Retention.BatchSize = 0 }, "retention.batch_size"},
		{"schedule", func(c *Config) { c.Retention.Schedule = 0 }, "retention.schedule"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Database.URL = "postgres://u@h/db"
			cfg.OIDC.Issuer = "https://auth.local.example/"
			tc.mutate(&cfg)
			errs := Validate(&cfg)
			found := false
			for _, e := range errs {
				if strings.Contains(e.Error(), tc.key) {
					found = true
				}
			}
			if !found {
				t.Errorf("Validate() errors %v do not reject %s", errs, tc.key)
			}
		})
	}
}

// TestLoadInvalidRetentionValues rejects unparsable retention values without
// echoing the offending value.
func TestLoadInvalidRetentionValues(t *testing.T) {
	t.Run("batch_size", func(t *testing.T) {
		env := validEnv()
		env["retention.batch_size"] = "many"
		err := mustFailErr(t, "", env, "retention.batch_size")
		if strings.Contains(err.Error(), "many") {
			t.Errorf("Load() error echoes the offending value: %v", err)
		}
	})
	t.Run("schedule", func(t *testing.T) {
		env := validEnv()
		env["retention.schedule"] = "soon"
		err := mustFailErr(t, "", env, "retention.schedule")
		if strings.Contains(err.Error(), "soon") {
			t.Errorf("Load() error echoes the offending value: %v", err)
		}
	})
}
