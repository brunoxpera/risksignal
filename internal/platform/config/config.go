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
	"time"
)

// SchemaVersion is the configuration schema version this build understands.
// Defaults() returns exactly this version; config files that declare a
// different schema_version are rejected at load time.
const SchemaVersion = 1

// Environment variable prefix for all overrides (D-006).
const envVarPrefix = "RISKSIGNAL_"

// I6 worker/export defaults (ARCH-007 §1.2/§2.4, WP-6.06 / DEV-118): the
// monthly retention dry-run cadence, the daily export-sweep cadence and the
// server-local export spool root.
const (
	// defaultRetentionClosedSignalYears is the default retention period in
	// years (retention.closed_signal_years): a signal is due for retention when
	// closed_at <= now − this many years (ARCH-007 §2.4).
	defaultRetentionClosedSignalYears = 5
	// defaultRetentionBatchSize is the default bounded retention batch size
	// (retention.batch_size, the §14.1 recompute Richtwert).
	defaultRetentionBatchSize = 500
	// defaultRetentionSchedule is the monthly retention dry-run cadence
	// (retention.schedule).
	defaultRetentionSchedule = 30 * 24 * time.Hour
	// defaultExportSweepInterval is the daily export-sweep cadence
	// (worker.export_sweep_interval).
	defaultExportSweepInterval = 24 * time.Hour
	// defaultExportDir is the server-local export spool root (export.dir).
	defaultExportDir = "var/exports"
	// defaultMetricsAddr is the loopback default bind of the internal
	// Prometheus exposition listener (observability.metrics_addr). It is never
	// public: local binds loopback, demo/production an internal-only address
	// (ARCH-007 §5/§10, WP-6.08 / DEV-120).
	defaultMetricsAddr = "127.0.0.1:9091"
	// defaultBackupDir is the off-host (or separate-volume) root the encrypted
	// logical backups are written to and pruned from (backup.dir). It is
	// deliberately not the export spool and never the database data directory
	// (ARCH-007 §4: "ausserhalb des Laufzeithosts").
	defaultBackupDir = "var/backups"
	// defaultBackupRetainDays is the minimum number of daily backup states kept
	// before pruning (backup.retain_days). ARCH-007 §4 requires at least 14.
	defaultBackupRetainDays = 14
	// minBackupRetainDays is the floor the startup validation enforces on
	// backup.retain_days (ARCH-007 §4: "≥14 daily states").
	minBackupRetainDays = 14
)

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
// Keys that may carry credentials (database.url) or provider URLs/secrets
// (oidc.issuer, oidc.client_secret_ref, oidc.redirect_url) are never rendered
// with their content — neither in validation errors nor in Summary.
type Config struct {
	SchemaVersion int       `json:"schema_version"`
	Env           string    `json:"env"` // local | demo | production
	HTTP          HTTP      `json:"http"`
	Database      Database  `json:"database"`
	OIDC          OIDC      `json:"oidc"`
	Auth          Auth      `json:"auth"`
	Worker        Worker    `json:"worker"`
	Notify        Notify    `json:"notify"`
	Export        Export    `json:"export"`
	Retention     Retention `json:"retention"`
	Backup        Backup    `json:"backup"`
	Sources       Sources   `json:"sources"`

	Observability Observability `json:"observability"`

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

// OIDC carries the OpenID Connect provider configuration (ARCH-005 §2).
//
// Issuer, ClientSecretRef and RedirectURL are the URL/secret-capable members:
// like oidc.issuer they are never rendered with their content — Summary and
// JSONSummary report presence and provenance only. ClientID, Scopes,
// RolesClaim, RoleMappings, Audience, SessionCookieName and SessionTTL are
// non-secret descriptors and are rendered by value.
type OIDC struct {
	// Issuer is the OIDC issuer base URL (discovery root).
	Issuer string `json:"issuer"`
	// ClientID is the client registered at the issuer; the expected `aud`
	// (unless Audience overrides) and the `azp` when present.
	ClientID string `json:"client_id"`
	// ClientSecretRef names the runtime-injected client secret (a reference,
	// never the secret); presence-only in Summary.
	ClientSecretRef string `json:"client_secret_ref"`
	// RedirectURL is the browser callback URL registered at the issuer.
	RedirectURL string `json:"redirect_url"`
	// Scopes is the requested scope list; empty falls back to the default
	// (openid profile email).
	Scopes []string `json:"scopes"`
	// RolesClaim is the token claim that carries external role values.
	RolesClaim string `json:"roles_claim"`
	// RoleMappings maps an external roles-claim value onto an internal role
	// machine key. An unmapped value seeds no role (fail closed, ARCH-005 §2).
	RoleMappings map[string]string `json:"role_mappings"`
	// Audience is the expected `aud` claim value; empty defaults to ClientID.
	Audience string `json:"audience"`
	// SessionCookieName is the name of the browser session cookie.
	SessionCookieName string `json:"session_cookie_name"`
	// SessionTTL is the server-side session lifetime.
	SessionTTL time.Duration `json:"session_ttl"`
}

// Auth carries authentication mode flags (ARCH-005 §4).
type Auth struct {
	// BypassEnabled activates the local dev principal. It is valid only in
	// local mode and only on a loopback bind (TR-010, FR-029, ARCH-005 §4).
	BypassEnabled bool `json:"bypass_enabled"`
	// BypassPrincipal is the subject the bypass authenticates as
	// (arch-005 §4.2); the seeded local multi-role user by default.
	BypassPrincipal string `json:"bypass_principal"`
}

// Worker carries the background-worker configuration (WP-1a.10).
type Worker struct {
	// Interval is the scheduler loop period: every interval the worker
	// emits a heartbeat and runs one scheduler cycle (no job types in
	// WP-1a.10). A later job-scheduling work package may split cadences
	// per source and job type (concept ch. 8.1, 14.1); until then this
	// single period drives the whole loop.
	Interval time.Duration `json:"interval"`

	// SLAEvaluateInterval is the cadence of the sla.evaluate breach
	// scheduler (ARCH-004 §4.4, WP-4.05): the worker runs one breach
	// evaluation per cadence on the injected clock. The default is one
	// minute (the "minute cadence" of the scheduler).
	SLAEvaluateInterval time.Duration `json:"sla_evaluate_interval"`

	// SLAReminderCadence is the reminder cadence of an already-escalated P1
	// (ARCH-004 §4.4): after the first escalation a reminder is emitted
	// once per cadence window. It is configuration, never table state.
	SLAReminderCadence time.Duration `json:"sla_reminder_cadence"`

	// ExportSweepInterval is the cadence of the daily export expiry sweep
	// (ARCH-007 §1.2; WP-6.06 / DEV-118): the worker deletes the expired
	// artifacts and marks their rows 'expired' once per cadence on the
	// injected clock. The default is daily (24 hours).
	ExportSweepInterval time.Duration `json:"export_sweep_interval"`
}

// Export carries the I6 export-spool configuration (ARCH-007 §1.2/§10,
// WP-6.06 / DEV-118). The artifact is a file in a server-local spool — never a
// bytea — so it self-expires and stays out of the audit/backup retention path.
type Export struct {
	// Dir is the spool root the export.generate job writes artifacts into and
	// a download/sweep reads them from (export.dir; a volume in the demo
	// deployment).
	Dir string `json:"dir"`
	// TTL is the artifact lifetime (export.ttl); an export expires at
	// created_at + TTL and the sweep then deletes it. The default is 7 days.
	TTL time.Duration `json:"ttl"`
	// MaxRows bounds a single export (export.max_rows, the strict input limit
	// of §12.3): a filter matching more rows is a validation error, never a
	// silent truncation. The default is 100000.
	MaxRows int `json:"max_rows"`
}

// Sources carries the I6 source-fetch configuration (ARCH-007 §7 control 1,
// §10; WP-6.10 / DEV-123). It is the single knob of the source-fetch SSRF
// guard: whether the guard may reach a private, loopback or link-local
// target. It exists only for the local environment's mock sources on
// loopback — demo and production refuse it (Validate) — and defaults to
// false (fail secure).
type Sources struct {
	// AllowPrivate permits the source-fetch guard to reach private
	// (RFC 1918/ULA), loopback and link-local-unicast targets
	// (sources.allow_private). It is valid only in local mode; multicast and
	// unspecified targets are refused regardless. Default false.
	AllowPrivate bool `json:"allow_private"`
}

// Retention carries the I6 retention configuration (ARCH-007 §2.4/§10,
// WP-6.07 / DEV-119). It is the config-not-table-state vocabulary of the
// governed retention run: the five-year period, the pseudonymisation period,
// the bounded batch size and the monthly dry-run cadence.
type Retention struct {
	// ClosedSignalYears is the retention period in years
	// (retention.closed_signal_years): a closed signal is due when
	// closed_at <= now − this many years. The default is 5.
	ClosedSignalYears int `json:"closed_signal_years"`
	// PseudonymiseYears is the pseudonymisation period in years
	// (retention.pseudonymise_years): the standalone/run pseudonymisation
	// cutoff. Zero means "same as closed_signal_years" (the MVP default —
	// pseudonymisation and deletion run in the same pass; configurable shorter
	// per TD-08).
	PseudonymiseYears int `json:"pseudonymise_years"`
	// BatchSize is the bounded retention batch size (retention.batch_size, the
	// §14.1 recompute Richtwert). The default is 500.
	BatchSize int `json:"batch_size"`
	// Schedule is the cadence of the monthly retention dry-run proposal
	// (retention.schedule): the worker proposes one dry-run run per cadence on
	// the injected clock. It is configuration, never table state. The default
	// is monthly (30 days).
	Schedule time.Duration `json:"schedule"`
	// HashChainEnabled gates the optional audit hash chain
	// (retention.hash_chain_enabled, ARCH-007 §7 control 3b): when on,
	// AuditRepo.Append stamps prev_hash/row_hash on every new audit row and
	// the chain-verify command checks the whole trail end-to-end. Off by
	// default; the append path is otherwise unchanged.
	HashChainEnabled bool `json:"hash_chain_enabled"`
}

// Backup carries the I6 encrypted off-host backup configuration (ARCH-007
// §4/§10, WP-6.09 / DEV-122). The backup job is the daily logical `pg_dump
// -Fc` of the whole database, encrypted with `age` and written off-host; it is
// a containerised sidecar/cron, never part of the application process.
//
// EncryptionKeyRef is the only secret-capable member: it names the
// runtime-injected `age` identity (the private key), never the key itself —
// Summary/JSONSummary report presence and provenance only, never content
// (§7 control 6). The `age` recipient used for encryption is derived from the
// identity, so one referenced secret covers both directions.
//
// All three keys are additive to schema v1 (ARCH-007 §10); the schema version
// is unchanged.
type Backup struct {
	// EncryptionKeyRef names the runtime-injected secret that holds the `age`
	// identity (backup.encryption_key_ref). It is a reference, never the key;
	// presence-only in Summary. The empty default means "not configured" — the
	// backup/restore commands then fail with a key-only validation error rather
	// than the process refusing to start (the server/worker never back up).
	EncryptionKeyRef string `json:"encryption_key_ref"`
	// Dir is the off-host (or separate-volume) backup root the encrypted
	// artifacts are written to and pruned from (backup.dir).
	Dir string `json:"dir"`
	// RetainDays is the number of daily backup states kept before pruning
	// (backup.retain_days). ARCH-007 §4 requires at least 14.
	RetainDays int `json:"retain_days"`
}

// Observability carries the I6 observability configuration (ARCH-007 §5/§10,
// WP-6.08 / DEV-120): the internal-only Prometheus exposition and the optional
// OTLP trace export. The exposition is never public — local binds loopback,
// demo/production an internal-only address — and OTLP is off by default.
//
// All three keys are additive to schema v1 (ARCH-007 §10); the schema version
// is unchanged. metrics_addr and otlp_endpoint can carry a host or a target
// URL, so Summary/JSONSummary report presence and provenance only, never
// content (the same rule as http.addr and the oidc URL keys).
type Observability struct {
	// MetricsEnabled gates the internal Prometheus /metrics listener
	// (observability.metrics_enabled). Off by default: an operator opts in,
	// and the endpoint is only ever served on the internal metrics_addr.
	MetricsEnabled bool `json:"metrics_enabled"`
	// MetricsAddr is the internal bind address of the /metrics listener
	// (observability.metrics_addr). It is never public: loopback in local,
	// an internal-only (not all-interfaces) address in demo/production
	// (ARCH-007 §5/§8). Default 127.0.0.1:9091.
	MetricsAddr string `json:"metrics_addr"`
	// OTLPEndpoint is the OTLP/HTTP trace export target
	// (observability.otlp_endpoint). Empty (the default) disables export — no
	// OTel SDK is linked and no network call is made; setting it links the
	// thin OTLP adapter (ARCH-007 §5).
	OTLPEndpoint string `json:"otlp_endpoint"`
}

// Notify carries the I4 notification-channel configuration (ARCH-004 §6.1,
// WP-4.06). It selects which channels an active notification uses and holds
// the local SMTP and webhook targets. There is no production mail/webhook
// target in I4: the channels stay disabled until an operator configures a
// target (the local environment points SMTP at the Compose Mailpit).
type Notify struct {
	// P2Active activates outbound notifications for new P2 signals
	// (FR-023). P1 is always active; P3/P4 are in-app only.
	P2Active bool `json:"p2_active"`
	// SMTP is the SMTP relay target of the active-notification e-mail.
	SMTP NotifySMTP `json:"smtp"`
	// Webhook is the signed outbound webhook target.
	Webhook NotifyWebhook `json:"webhook"`
}

// NotifySMTP is the SMTP relay configuration (Mailpit in the local
// environment, D-004). Enabled turns the channel on; addr/from/to are
// mandatory once it is enabled.
type NotifySMTP struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"` // host:port of the SMTP relay
	From    string `json:"from"` // envelope sender
	To      string `json:"to"`   // recipient (recorded on the notification row)
}

// NotifyWebhook is the signed webhook configuration. Enabled turns the
// channel on; url and secret are mandatory once it is enabled. secret is
// never rendered (Summary/JSONSummary report presence only).
type NotifyWebhook struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Secret  string `json:"secret"`
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
			Issuer:     "", // mandatory, no baked-in value
			Scopes:     []string{"openid", "profile", "email"},
			RolesClaim: "roles",
			// A browser session lives a working day by default.
			SessionCookieName: "risksignal_session",
			SessionTTL:        8 * time.Hour,
		},
		Auth: Auth{
			BypassEnabled: false, // secure default: bypass never on unless asked
			// The seeded local multi-role user (migration 00009, ARCH-005 §4.2).
			BypassPrincipal: "local-developer",
		},
		Worker: Worker{
			// A fresh local worker reports a heartbeat and a completed
			// scheduler run every half minute without configuration.
			Interval: 30 * time.Second,
			// The SLA breach scheduler evaluates every minute (the
			// "minute cadence" of ARCH-004 §4.4) and reminds an already-
			// escalated P1 once per hour without configuration.
			SLAEvaluateInterval: time.Minute,
			SLAReminderCadence:  time.Hour,
			// The retention dry-run is proposed monthly and the export sweep
			// runs daily without configuration (ARCH-007 §2.4/§1.2).
			ExportSweepInterval: defaultExportSweepInterval,
		},
		Notify: Notify{
			// P2 notifications are configurable (FR-023); the active default
			// notifies them. The SMTP and webhook channels stay disabled
			// until an operator configures a target (no production
			// mail/webhook target in I4).
			P2Active: true,
			SMTP:     NotifySMTP{Enabled: false},
			Webhook:  NotifyWebhook{Enabled: false},
		},
		Export: Export{
			// A local worker spools export artifacts under var/exports by
			// default, keeps them for 7 days and bounds an export at 100k rows
			// (ARCH-007 §1.2: export.dir/export.ttl/export.max_rows).
			Dir:     defaultExportDir,
			TTL:     7 * 24 * time.Hour,
			MaxRows: 100000,
		},
		Retention: Retention{
			// The governed retention run defaults to a five-year period, the
			// §14.1 bounded batch size and a monthly dry-run cadence
			// (ARCH-007 §2.4: retention.closed_signal_years/batch_size/schedule).
			// pseudonymise_years defaults to 0 = the same period as
			// closed_signal_years (pseudonymisation and deletion run in the
			// same pass for the MVP). The optional audit hash chain is off by
			// default (retention.hash_chain_enabled, ARCH-007 §7 control 3b).
			ClosedSignalYears: defaultRetentionClosedSignalYears,
			PseudonymiseYears: 0,
			BatchSize:         defaultRetentionBatchSize,
			Schedule:          defaultRetentionSchedule,
			HashChainEnabled:  false,
		},
		Sources: Sources{
			// The source-fetch SSRF guard is fail secure by default: private,
			// loopback and link-local targets are refused. Local mode opts in
			// (sources.allow_private) for its mock sources on loopback;
			// demo/production refuse the flag (ARCH-007 §7 control 1).
			AllowPrivate: false,
		},
		Observability: Observability{
			// The metrics exposition is opt-in and binds loopback by default;
			// OTLP export is off (the empty endpoint links no adapter)
			// (ARCH-007 §5/§10, WP-6.08 / DEV-120).
			MetricsEnabled: false,
			MetricsAddr:    defaultMetricsAddr,
			OTLPEndpoint:   "",
		},
		Backup: Backup{
			// The off-host backup root defaults to var/backups and keeps at
			// least 14 daily states (ARCH-007 §4/§10: backup.dir/
			// backup.retain_days). The age identity is runtime-injected and
			// has no baked-in reference (backup.encryption_key_ref stays empty
			// until an operator names the secret).
			EncryptionKeyRef: "",
			Dir:              defaultBackupDir,
			RetainDays:       defaultBackupRetainDays,
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
	{"oidc.client_id", func(c *Config, v string) error { c.OIDC.ClientID = strings.TrimSpace(v); return nil }},
	{"oidc.client_secret_ref", func(c *Config, v string) error { c.OIDC.ClientSecretRef = strings.TrimSpace(v); return nil }},
	{"oidc.redirect_url", func(c *Config, v string) error { c.OIDC.RedirectURL = strings.TrimSpace(v); return nil }},
	{"oidc.audience", func(c *Config, v string) error { c.OIDC.Audience = strings.TrimSpace(v); return nil }},
	{"oidc.roles_claim", func(c *Config, v string) error { c.OIDC.RolesClaim = strings.TrimSpace(v); return nil }},
	{"oidc.session_cookie_name", func(c *Config, v string) error {
		c.OIDC.SessionCookieName = strings.TrimSpace(v)
		return nil
	}},
	{"oidc.scopes", func(c *Config, v string) error { c.OIDC.Scopes = splitCSV(v); return nil }},
	{"oidc.role_mappings", func(c *Config, v string) error {
		v = strings.TrimSpace(v)
		if v == "" {
			c.OIDC.RoleMappings = nil
			return nil
		}
		m := map[string]string{}
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			// json.Unmarshal quotes content from the input; never surface it.
			return fmt.Errorf("oidc.role_mappings: %s: must be a JSON object mapping a claim value to an internal role", envName("oidc.role_mappings"))
		}
		c.OIDC.RoleMappings = m
		return nil
	}},
	{"oidc.session_ttl", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("oidc.session_ttl: %s: must be a Go duration such as 8h", envName("oidc.session_ttl"))
		}
		c.OIDC.SessionTTL = d
		return nil
	}},
	{"auth.bypass_principal", func(c *Config, v string) error {
		c.Auth.BypassPrincipal = strings.TrimSpace(v)
		return nil
	}},
	{"auth.bypass_enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			// The stdlib error text quotes the offending value; never surface it.
			return fmt.Errorf("auth.bypass_enabled: %s: must be a boolean (true or false)", envName("auth.bypass_enabled"))
		}
		c.Auth.BypassEnabled = b
		return nil
	}},
	{"worker.interval", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			// time.ParseDuration quotes the offending value; never surface it.
			return fmt.Errorf("worker.interval: %s: must be a Go duration such as 30s or 1m", envName("worker.interval"))
		}
		c.Worker.Interval = d
		return nil
	}},
	{"worker.sla_evaluate_interval", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("worker.sla_evaluate_interval: %s: must be a Go duration such as 1m", envName("worker.sla_evaluate_interval"))
		}
		c.Worker.SLAEvaluateInterval = d
		return nil
	}},
	{"worker.sla_reminder_cadence", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("worker.sla_reminder_cadence: %s: must be a Go duration such as 1h", envName("worker.sla_reminder_cadence"))
		}
		c.Worker.SLAReminderCadence = d
		return nil
	}},
	{"retention.closed_signal_years", func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("retention.closed_signal_years: %s: must be an integer", envName("retention.closed_signal_years"))
		}
		c.Retention.ClosedSignalYears = n
		return nil
	}},
	{"retention.pseudonymise_years", func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("retention.pseudonymise_years: %s: must be an integer", envName("retention.pseudonymise_years"))
		}
		c.Retention.PseudonymiseYears = n
		return nil
	}},
	{"retention.batch_size", func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("retention.batch_size: %s: must be an integer", envName("retention.batch_size"))
		}
		c.Retention.BatchSize = n
		return nil
	}},
	{"retention.schedule", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("retention.schedule: %s: must be a Go duration such as 720h", envName("retention.schedule"))
		}
		c.Retention.Schedule = d
		return nil
	}},
	{"retention.hash_chain_enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("retention.hash_chain_enabled: %s: must be a boolean (true or false)", envName("retention.hash_chain_enabled"))
		}
		c.Retention.HashChainEnabled = b
		return nil
	}},
	{"sources.allow_private", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("sources.allow_private: %s: must be a boolean (true or false)", envName("sources.allow_private"))
		}
		c.Sources.AllowPrivate = b
		return nil
	}},
	{"worker.export_sweep_interval", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("worker.export_sweep_interval: %s: must be a Go duration such as 24h", envName("worker.export_sweep_interval"))
		}
		c.Worker.ExportSweepInterval = d
		return nil
	}},
	{"export.dir", func(c *Config, v string) error { c.Export.Dir = strings.TrimSpace(v); return nil }},
	{"export.ttl", func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("export.ttl: %s: must be a Go duration such as 168h", envName("export.ttl"))
		}
		c.Export.TTL = d
		return nil
	}},
	{"export.max_rows", func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("export.max_rows: %s: must be an integer", envName("export.max_rows"))
		}
		c.Export.MaxRows = n
		return nil
	}},
	{"observability.metrics_enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("observability.metrics_enabled: %s: must be a boolean (true or false)", envName("observability.metrics_enabled"))
		}
		c.Observability.MetricsEnabled = b
		return nil
	}},
	{"observability.metrics_addr", func(c *Config, v string) error {
		c.Observability.MetricsAddr = strings.TrimSpace(v)
		return nil
	}},
	{"observability.otlp_endpoint", func(c *Config, v string) error {
		c.Observability.OTLPEndpoint = strings.TrimSpace(v)
		return nil
	}},
	{"backup.encryption_key_ref", func(c *Config, v string) error {
		c.Backup.EncryptionKeyRef = strings.TrimSpace(v)
		return nil
	}},
	{"backup.dir", func(c *Config, v string) error { c.Backup.Dir = strings.TrimSpace(v); return nil }},
	{"backup.retain_days", func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("backup.retain_days: %s: must be an integer", envName("backup.retain_days"))
		}
		c.Backup.RetainDays = n
		return nil
	}},
	{"notify.p2_active", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("notify.p2_active: %s: must be a boolean (true or false)", envName("notify.p2_active"))
		}
		c.Notify.P2Active = b
		return nil
	}},
	{"notify.smtp.enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("notify.smtp.enabled: %s: must be a boolean (true or false)", envName("notify.smtp.enabled"))
		}
		c.Notify.SMTP.Enabled = b
		return nil
	}},
	{"notify.smtp.addr", func(c *Config, v string) error { c.Notify.SMTP.Addr = strings.TrimSpace(v); return nil }},
	{"notify.smtp.from", func(c *Config, v string) error { c.Notify.SMTP.From = strings.TrimSpace(v); return nil }},
	{"notify.smtp.to", func(c *Config, v string) error { c.Notify.SMTP.To = strings.TrimSpace(v); return nil }},
	{"notify.webhook.enabled", func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("notify.webhook.enabled: %s: must be a boolean (true or false)", envName("notify.webhook.enabled"))
		}
		c.Notify.Webhook.Enabled = b
		return nil
	}},
	{"notify.webhook.url", func(c *Config, v string) error { c.Notify.Webhook.URL = strings.TrimSpace(v); return nil }},
	{"notify.webhook.secret", func(c *Config, v string) error { c.Notify.Webhook.Secret = strings.TrimSpace(v); return nil }},
}

// envName derives the environment variable name for a leaf key:
// "http.addr" -> "RISKSIGNAL_HTTP_ADDR".
func envName(key string) string {
	return envVarPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// splitCSV splits a comma-separated list, trimming each element and dropping
// the empty ones (the oidc.scopes env shape: "openid,profile,email").
func splitCSV(s string) []string {
	return trimEach(strings.Split(s, ","))
}

// trimEach trims every element and drops the empty ones.
func trimEach(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Load loads and validates the process configuration:
// defaults -> optional JSON config file -> RISKSIGNAL_* environment
// variables. It returns an error that joins every validation problem; each
// problem references the configuration key, never a value.
func Load() (*Config, error) {
	cfg := Defaults()
	prov := map[string]Source{
		"schema_version":               SourceDefault,
		"env":                          SourceDefault,
		"http.addr":                    SourceDefault,
		"database.url":                 SourceDefault,
		"oidc.issuer":                  SourceDefault,
		"oidc.client_id":               SourceDefault,
		"oidc.client_secret_ref":       SourceDefault,
		"oidc.redirect_url":            SourceDefault,
		"oidc.scopes":                  SourceDefault,
		"oidc.roles_claim":             SourceDefault,
		"oidc.role_mappings":           SourceDefault,
		"oidc.audience":                SourceDefault,
		"oidc.session_cookie_name":     SourceDefault,
		"oidc.session_ttl":             SourceDefault,
		"auth.bypass_enabled":          SourceDefault,
		"auth.bypass_principal":        SourceDefault,
		"notify.p2_active":             SourceDefault,
		"notify.smtp.enabled":          SourceDefault,
		"notify.smtp.addr":             SourceDefault,
		"notify.smtp.from":             SourceDefault,
		"notify.smtp.to":               SourceDefault,
		"notify.webhook.enabled":       SourceDefault,
		"notify.webhook.url":           SourceDefault,
		"notify.webhook.secret":        SourceDefault,
		"backup.encryption_key_ref":    SourceDefault,
		"backup.dir":                   SourceDefault,
		"backup.retain_days":           SourceDefault,
		"sources.allow_private":        SourceDefault,
		"retention.hash_chain_enabled": SourceDefault,
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
	SchemaVersion *int               `json:"schema_version"`
	Env           *string            `json:"env"`
	HTTP          *fileHTTP          `json:"http"`
	Database      *fileDatabase      `json:"database"`
	OIDC          *fileOIDC          `json:"oidc"`
	Auth          *fileAuth          `json:"auth"`
	Worker        *fileWorker        `json:"worker"`
	Notify        *fileNotify        `json:"notify"`
	Export        *fileExport        `json:"export"`
	Retention     *fileRetention     `json:"retention"`
	Backup        *fileBackup        `json:"backup"`
	Sources       *fileSources       `json:"sources"`
	Observability *fileObservability `json:"observability"`
}

type fileSources struct {
	AllowPrivate *bool `json:"allow_private"`
}

type fileBackup struct {
	EncryptionKeyRef *string `json:"encryption_key_ref"`
	Dir              *string `json:"dir"`
	RetainDays       *int    `json:"retain_days"`
}

type fileHTTP struct {
	Addr *string `json:"addr"`
}

type fileDatabase struct {
	URL *string `json:"url"`
}

type fileOIDC struct {
	Issuer            *string            `json:"issuer"`
	ClientID          *string            `json:"client_id"`
	ClientSecretRef   *string            `json:"client_secret_ref"`
	RedirectURL       *string            `json:"redirect_url"`
	Scopes            *[]string          `json:"scopes"`
	RolesClaim        *string            `json:"roles_claim"`
	RoleMappings      *map[string]string `json:"role_mappings"`
	Audience          *string            `json:"audience"`
	SessionCookieName *string            `json:"session_cookie_name"`
	SessionTTL        *string            `json:"session_ttl"` // Go duration, e.g. "8h"
}

type fileAuth struct {
	BypassEnabled   *bool   `json:"bypass_enabled"`
	BypassPrincipal *string `json:"bypass_principal"`
}

type fileWorker struct {
	Interval            *string `json:"interval"`              // Go duration, e.g. "30s"
	SLAEvaluateInterval *string `json:"sla_evaluate_interval"` // Go duration, e.g. "1m"
	SLAReminderCadence  *string `json:"sla_reminder_cadence"`  // Go duration, e.g. "1h"
	ExportSweepInterval *string `json:"export_sweep_interval"` // Go duration, e.g. "24h"
}

type fileExport struct {
	Dir     *string `json:"dir"`
	TTL     *string `json:"ttl"` // Go duration, e.g. "168h"
	MaxRows *int    `json:"max_rows"`
}

type fileRetention struct {
	ClosedSignalYears *int    `json:"closed_signal_years"`
	PseudonymiseYears *int    `json:"pseudonymise_years"`
	BatchSize         *int    `json:"batch_size"`
	Schedule          *string `json:"schedule"` // Go duration, e.g. "720h" (monthly)
	HashChainEnabled  *bool   `json:"hash_chain_enabled"`
}

type fileObservability struct {
	MetricsEnabled *bool   `json:"metrics_enabled"`
	MetricsAddr    *string `json:"metrics_addr"`
	OTLPEndpoint   *string `json:"otlp_endpoint"`
}

type fileNotify struct {
	P2Active *bool              `json:"p2_active"`
	SMTP     *fileNotifySMTP    `json:"smtp"`
	Webhook  *fileNotifyWebhook `json:"webhook"`
}

type fileNotifySMTP struct {
	Enabled *bool   `json:"enabled"`
	Addr    *string `json:"addr"`
	From    *string `json:"from"`
	To      *string `json:"to"`
}

type fileNotifyWebhook struct {
	Enabled *bool   `json:"enabled"`
	URL     *string `json:"url"`
	Secret  *string `json:"secret"`
}

// applyConfigFile reads the JSON config file at path and overrides cfg with
// every key it declares. Unknown keys and schema version mismatches are
// load-time errors, so a typo or a newer schema can never silently degrade
// into defaults.
func applyConfigFile(cfg *Config, path string, prov map[string]Source) error {
	// #nosec G304 G703 — path is the explicit config file from the operator
	// (RISKSIGNAL_CONFIG_FILE / --config-file), never attacker-influenced
	// input; opening it is the documented feature, not file inclusion.
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
	if fc.OIDC != nil {
		if fc.OIDC.ClientID != nil {
			cfg.OIDC.ClientID = strings.TrimSpace(*fc.OIDC.ClientID)
			prov["oidc.client_id"] = SourceFile
		}
		if fc.OIDC.ClientSecretRef != nil {
			cfg.OIDC.ClientSecretRef = strings.TrimSpace(*fc.OIDC.ClientSecretRef)
			prov["oidc.client_secret_ref"] = SourceFile
		}
		if fc.OIDC.RedirectURL != nil {
			cfg.OIDC.RedirectURL = strings.TrimSpace(*fc.OIDC.RedirectURL)
			prov["oidc.redirect_url"] = SourceFile
		}
		if fc.OIDC.Scopes != nil {
			cfg.OIDC.Scopes = trimEach(*fc.OIDC.Scopes)
			prov["oidc.scopes"] = SourceFile
		}
		if fc.OIDC.RolesClaim != nil {
			cfg.OIDC.RolesClaim = strings.TrimSpace(*fc.OIDC.RolesClaim)
			prov["oidc.roles_claim"] = SourceFile
		}
		if fc.OIDC.RoleMappings != nil {
			cfg.OIDC.RoleMappings = *fc.OIDC.RoleMappings
			prov["oidc.role_mappings"] = SourceFile
		}
		if fc.OIDC.Audience != nil {
			cfg.OIDC.Audience = strings.TrimSpace(*fc.OIDC.Audience)
			prov["oidc.audience"] = SourceFile
		}
		if fc.OIDC.SessionCookieName != nil {
			cfg.OIDC.SessionCookieName = strings.TrimSpace(*fc.OIDC.SessionCookieName)
			prov["oidc.session_cookie_name"] = SourceFile
		}
		if fc.OIDC.SessionTTL != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*fc.OIDC.SessionTTL))
			if err != nil {
				return fmt.Errorf("config file %s: oidc.session_ttl: invalid duration (expected a Go duration such as 8h)", path)
			}
			cfg.OIDC.SessionTTL = d
			prov["oidc.session_ttl"] = SourceFile
		}
	}
	if fc.Auth != nil && fc.Auth.BypassEnabled != nil {
		cfg.Auth.BypassEnabled = *fc.Auth.BypassEnabled
		prov["auth.bypass_enabled"] = SourceFile
	}
	if fc.Auth != nil && fc.Auth.BypassPrincipal != nil {
		cfg.Auth.BypassPrincipal = strings.TrimSpace(*fc.Auth.BypassPrincipal)
		prov["auth.bypass_principal"] = SourceFile
	}
	if fc.Worker != nil && fc.Worker.Interval != nil {
		d, err := time.ParseDuration(strings.TrimSpace(*fc.Worker.Interval))
		if err != nil {
			// time.ParseDuration quotes the offending value; never surface it.
			return fmt.Errorf("config file %s: worker.interval: invalid duration (expected a Go duration such as 30s or 1m)", path)
		}
		cfg.Worker.Interval = d
		prov["worker.interval"] = SourceFile
	}
	if fc.Worker != nil && fc.Worker.SLAEvaluateInterval != nil {
		d, err := time.ParseDuration(strings.TrimSpace(*fc.Worker.SLAEvaluateInterval))
		if err != nil {
			return fmt.Errorf("config file %s: worker.sla_evaluate_interval: invalid duration (expected a Go duration such as 1m)", path)
		}
		cfg.Worker.SLAEvaluateInterval = d
		prov["worker.sla_evaluate_interval"] = SourceFile
	}
	if fc.Worker != nil && fc.Worker.SLAReminderCadence != nil {
		d, err := time.ParseDuration(strings.TrimSpace(*fc.Worker.SLAReminderCadence))
		if err != nil {
			return fmt.Errorf("config file %s: worker.sla_reminder_cadence: invalid duration (expected a Go duration such as 1h)", path)
		}
		cfg.Worker.SLAReminderCadence = d
		prov["worker.sla_reminder_cadence"] = SourceFile
	}
	if fc.Worker != nil && fc.Worker.ExportSweepInterval != nil {
		d, err := time.ParseDuration(strings.TrimSpace(*fc.Worker.ExportSweepInterval))
		if err != nil {
			return fmt.Errorf("config file %s: worker.export_sweep_interval: invalid duration (expected a Go duration such as 24h)", path)
		}
		cfg.Worker.ExportSweepInterval = d
		prov["worker.export_sweep_interval"] = SourceFile
	}
	if fc.Export != nil {
		if fc.Export.Dir != nil {
			cfg.Export.Dir = strings.TrimSpace(*fc.Export.Dir)
			prov["export.dir"] = SourceFile
		}
		if fc.Export.TTL != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*fc.Export.TTL))
			if err != nil {
				return fmt.Errorf("config file %s: export.ttl: invalid duration (expected a Go duration such as 168h)", path)
			}
			cfg.Export.TTL = d
			prov["export.ttl"] = SourceFile
		}
		if fc.Export.MaxRows != nil {
			cfg.Export.MaxRows = *fc.Export.MaxRows
			prov["export.max_rows"] = SourceFile
		}
	}
	if fc.Retention != nil {
		if fc.Retention.ClosedSignalYears != nil {
			cfg.Retention.ClosedSignalYears = *fc.Retention.ClosedSignalYears
			prov["retention.closed_signal_years"] = SourceFile
		}
		if fc.Retention.PseudonymiseYears != nil {
			cfg.Retention.PseudonymiseYears = *fc.Retention.PseudonymiseYears
			prov["retention.pseudonymise_years"] = SourceFile
		}
		if fc.Retention.BatchSize != nil {
			cfg.Retention.BatchSize = *fc.Retention.BatchSize
			prov["retention.batch_size"] = SourceFile
		}
		if fc.Retention.Schedule != nil {
			d, err := time.ParseDuration(strings.TrimSpace(*fc.Retention.Schedule))
			if err != nil {
				return fmt.Errorf("config file %s: retention.schedule: invalid duration (expected a Go duration such as 720h)", path)
			}
			cfg.Retention.Schedule = d
			prov["retention.schedule"] = SourceFile
		}
		if fc.Retention.HashChainEnabled != nil {
			cfg.Retention.HashChainEnabled = *fc.Retention.HashChainEnabled
			prov["retention.hash_chain_enabled"] = SourceFile
		}
	}
	if fc.Sources != nil && fc.Sources.AllowPrivate != nil {
		cfg.Sources.AllowPrivate = *fc.Sources.AllowPrivate
		prov["sources.allow_private"] = SourceFile
	}
	if fc.Backup != nil {
		if fc.Backup.EncryptionKeyRef != nil {
			cfg.Backup.EncryptionKeyRef = strings.TrimSpace(*fc.Backup.EncryptionKeyRef)
			prov["backup.encryption_key_ref"] = SourceFile
		}
		if fc.Backup.Dir != nil {
			cfg.Backup.Dir = strings.TrimSpace(*fc.Backup.Dir)
			prov["backup.dir"] = SourceFile
		}
		if fc.Backup.RetainDays != nil {
			cfg.Backup.RetainDays = *fc.Backup.RetainDays
			prov["backup.retain_days"] = SourceFile
		}
	}
	if fc.Observability != nil {
		if fc.Observability.MetricsEnabled != nil {
			cfg.Observability.MetricsEnabled = *fc.Observability.MetricsEnabled
			prov["observability.metrics_enabled"] = SourceFile
		}
		if fc.Observability.MetricsAddr != nil {
			cfg.Observability.MetricsAddr = strings.TrimSpace(*fc.Observability.MetricsAddr)
			prov["observability.metrics_addr"] = SourceFile
		}
		if fc.Observability.OTLPEndpoint != nil {
			cfg.Observability.OTLPEndpoint = strings.TrimSpace(*fc.Observability.OTLPEndpoint)
			prov["observability.otlp_endpoint"] = SourceFile
		}
	}
	if fc.Notify != nil {
		if fc.Notify.P2Active != nil {
			cfg.Notify.P2Active = *fc.Notify.P2Active
			prov["notify.p2_active"] = SourceFile
		}
		if fc.Notify.SMTP != nil {
			if fc.Notify.SMTP.Enabled != nil {
				cfg.Notify.SMTP.Enabled = *fc.Notify.SMTP.Enabled
				prov["notify.smtp.enabled"] = SourceFile
			}
			if fc.Notify.SMTP.Addr != nil {
				cfg.Notify.SMTP.Addr = strings.TrimSpace(*fc.Notify.SMTP.Addr)
				prov["notify.smtp.addr"] = SourceFile
			}
			if fc.Notify.SMTP.From != nil {
				cfg.Notify.SMTP.From = strings.TrimSpace(*fc.Notify.SMTP.From)
				prov["notify.smtp.from"] = SourceFile
			}
			if fc.Notify.SMTP.To != nil {
				cfg.Notify.SMTP.To = strings.TrimSpace(*fc.Notify.SMTP.To)
				prov["notify.smtp.to"] = SourceFile
			}
		}
		if fc.Notify.Webhook != nil {
			if fc.Notify.Webhook.Enabled != nil {
				cfg.Notify.Webhook.Enabled = *fc.Notify.Webhook.Enabled
				prov["notify.webhook.enabled"] = SourceFile
			}
			if fc.Notify.Webhook.URL != nil {
				cfg.Notify.Webhook.URL = strings.TrimSpace(*fc.Notify.Webhook.URL)
				prov["notify.webhook.url"] = SourceFile
			}
			if fc.Notify.Webhook.Secret != nil {
				cfg.Notify.Webhook.Secret = strings.TrimSpace(*fc.Notify.Webhook.Secret)
				prov["notify.webhook.secret"] = SourceFile
			}
		}
	}
	return nil
}
