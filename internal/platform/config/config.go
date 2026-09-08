// Package config loads and validates process configuration (WP-1a.02).
//
// Configuration follows the implementation concept ch. 3.3
// ("Konfigurationsprinzip") and orchestrator decision D-006:
//
//  1. built-in, versioned defaults (Defaults, SchemaVersion);
//  2. an optional JSON config file selected by RISKSIGNAL_CONFIG_FILE;
//  3. environment variables with the prefix RISKSIGNAL_ (e.g.
//     RISKSIGNAL_DATABASE_URL, RISKSIGNAL_AUTH_BYPASS_ENABLED).
//
// Precedence: environment overrides file overrides defaults. A variable that
// is present but empty counts as set: it overrides with the empty value and
// the startup validation reports it. The schema version itself is fixed by
// the build (SchemaVersion); a config file may declare schema_version, which
// must match.
//
// Startup validation rejects missing mandatory values, unparsable URLs and
// addresses, unknown modes and the local authentication bypass outside local
// mode (TR-010). Every validation error references the configuration key only
// — never the offending value — so that credentials in e.g. database.url can
// never reach an error message. Summary renders the same guarantee as a
// provenance report.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// SchemaVersion is the configuration schema version this build understands.
// Defaults() returns exactly this version; config files that declare a
// different schema_version are rejected at load time.
const SchemaVersion = 1

// Environment variable prefix for all overrides (D-006).
const envVarPrefix = "RISKSIGNAL_"

// envVarConfigFile selects the optional JSON configuration file. It is not a
// configuration value itself; it tells the loader where to look.
const envVarConfigFile = envVarPrefix + "CONFIG_FILE"

// Source records where a configuration value came from.
type Source string

const (
	SourceDefault Source = "default" // built-in defaults
	SourceFile    Source = "file"    // optional JSON config file
	SourceEnv     Source = "env"     // RISKSIGNAL_* environment variable
)

// Config is the process configuration (schema v1).
//
// Keys that may carry credentials (database.url) or provider URLs
// (oidc.issuer) are never rendered with their content — neither in
// validation errors nor in Summary.
type Config struct {
	SchemaVersion int      `json:"schema_version"`
	Env           string   `json:"env"` // local | demo | production
	HTTP          HTTP     `json:"http"`
	Database      Database `json:"database"`
	OIDC          OIDC     `json:"oidc"`
	Auth          Auth     `json:"auth"`

	// sources records the provenance of every leaf key; populated by Load.
	sources map[string]Source
}

// HTTP carries HTTP listener configuration.
type HTTP struct {
	Addr string `json:"addr"` // host:port
}

// Database carries the PostgreSQL connection configuration.
type Database struct {
	URL string `json:"url"` // credentials are runtime-injected, never stored
}

// OIDC carries the OpenID Connect provider configuration.
type OIDC struct {
	Issuer string `json:"issuer"`
}

// Auth carries authentication mode flags.
type Auth struct {
	BypassEnabled bool `json:"bypass_enabled"` // local dev principal, local mode only (TR-010)
}

// Defaults returns the built-in schema-v1 defaults.
//
// The defaults are deliberately development-shaped but fail-secure: local
// mode on a loopback address with the authentication bypass disabled.
// database.url and oidc.issuer have no default — they are mandatory and are
// injected per environment at runtime (concept ch. 3.3: secrets only at
// runtime, never in the repository).
func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Env:           "local",
		HTTP: HTTP{
			Addr: "127.0.0.1:8080", // concept ch. 4.2: loopback by default
		},
		Database: Database{
			URL: "", // mandatory, no baked-in value
		},
		OIDC: OIDC{
			Issuer: "", // mandatory, no baked-in value
		},
		Auth: Auth{
			BypassEnabled: false, // secure default: bypass never on unless asked
		},
	}
}

// envBindings maps every overridable leaf key to its env var name and its
// typed setter. schema_version is deliberately absent: the version is fixed
// by the build and cannot be overridden at runtime.
var envBindings = []struct {
	key string
	set func(*Config, string) error
}{
	{"env", func(c *Config, v string) error { c.Env = strings.TrimSpace(v); return nil }},
	{"http.addr", func(c *Config, v string) error { c.HTTP.Addr = strings.TrimSpace(v); return nil }},
	{"database.url", func(c *Config, v string) error { c.Database.URL = strings.TrimSpace(v); return nil }},
	{"oidc.issuer", func(c *Config, v string) error { c.OIDC.Issuer = strings.TrimSpace(v); return nil }},
	{"auth.bypass_enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			// The stdlib error text quotes the offending value; never surface it.
			return fmt.Errorf("auth.bypass_enabled: %s: must be a boolean (true or false)", envName("auth.bypass_enabled"))
		}
		c.Auth.BypassEnabled = b
		return nil
	}},
}

// envName derives the environment variable name for a leaf key:
// "http.addr" -> "RISKSIGNAL_HTTP_ADDR".
func envName(key string) string {
	return envVarPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// Load loads and validates the process configuration:
// defaults -> optional JSON config file -> RISKSIGNAL_* environment
// variables. It returns an error that joins every validation problem; each
// problem references the configuration key, never a value.
func Load() (*Config, error) {
	cfg := Defaults()
	prov := map[string]Source{
		"schema_version":      SourceDefault,
		"env":                 SourceDefault,
		"http.addr":           SourceDefault,
		"database.url":        SourceDefault,
		"oidc.issuer":         SourceDefault,
		"auth.bypass_enabled": SourceDefault,
	}

	if path := os.Getenv(envVarConfigFile); path != "" {
		if err := applyConfigFile(&cfg, path, prov); err != nil {
			return nil, err
		}
	}
	if err := applyEnv(&cfg, prov); err != nil {
		return nil, err
	}

	if errs := Validate(&cfg); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	cfg.sources = prov
	return &cfg, nil
}

// applyEnv overrides cfg from every RISKSIGNAL_* variable that is present.
func applyEnv(cfg *Config, prov map[string]Source) error {
	for _, b := range envBindings {
		v, ok := os.LookupEnv(envName(b.key))
		if !ok {
			continue
		}
		if err := b.set(cfg, v); err != nil {
			return err
		}
		prov[b.key] = SourceEnv
	}
	return nil
}

// configFile mirrors Config with pointers so that loaders can tell a present
// JSON key apart from an absent one, and can apply strict unknown-key checks.
type configFile struct {
	SchemaVersion *int          `json:"schema_version"`
	Env           *string       `json:"env"`
	HTTP          *fileHTTP     `json:"http"`
	Database      *fileDatabase `json:"database"`
	OIDC          *fileOIDC     `json:"oidc"`
	Auth          *fileAuth     `json:"auth"`
}

type fileHTTP struct {
	Addr *string `json:"addr"`
}

type fileDatabase struct {
	URL *string `json:"url"`
}

type fileOIDC struct {
	Issuer *string `json:"issuer"`
}

type fileAuth struct {
	BypassEnabled *bool `json:"bypass_enabled"`
}

// applyConfigFile reads the JSON config file at path and overrides cfg with
// every key it declares. Unknown keys and schema version mismatches are
// load-time errors, so a typo or a newer schema can never silently degrade
// into defaults.
func applyConfigFile(cfg *Config, path string, prov map[string]Source) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	defer f.Close()

	var fc configFile
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("config file %s: empty file (expected a JSON object)", path)
		}
		return fmt.Errorf("config file %s: invalid JSON: %v", path, err)
	}
	// The decoder accepts one top-level value; reject trailing content.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("config file %s: invalid JSON: trailing content after the top-level value", path)
	}

	if fc.SchemaVersion != nil {
		if *fc.SchemaVersion != SchemaVersion {
			return fmt.Errorf("config file %s: schema_version: unsupported version %d (this build supports version %d)", path, *fc.SchemaVersion, SchemaVersion)
		}
		prov["schema_version"] = SourceFile
	}
	if fc.Env != nil {
		cfg.Env = strings.TrimSpace(*fc.Env)
		prov["env"] = SourceFile
	}
	if fc.HTTP != nil && fc.HTTP.Addr != nil {
		cfg.HTTP.Addr = strings.TrimSpace(*fc.HTTP.Addr)
		prov["http.addr"] = SourceFile
	}
	if fc.Database != nil && fc.Database.URL != nil {
		cfg.Database.URL = strings.TrimSpace(*fc.Database.URL)
		prov["database.url"] = SourceFile
	}
	if fc.OIDC != nil && fc.OIDC.Issuer != nil {
		cfg.OIDC.Issuer = strings.TrimSpace(*fc.OIDC.Issuer)
		prov["oidc.issuer"] = SourceFile
	}
	if fc.Auth != nil && fc.Auth.BypassEnabled != nil {
		cfg.Auth.BypassEnabled = *fc.Auth.BypassEnabled
		prov["auth.bypass_enabled"] = SourceFile
	}
	return nil
}
