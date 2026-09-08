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
	envName("auth.bypass_enabled"),
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
