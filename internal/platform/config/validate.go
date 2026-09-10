package config

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// Validate checks the configuration against the startup rules of concept
// ch. 3.3: mandatory values, parseable URLs and addresses, known modes,
// positive durations and the mutually exclusive mode/flag combination
// behind TR-010.
//
// Every returned error references the configuration key only — never the
// offending value — so credentials can never leak into an error message.
func Validate(c *Config) []error {
	var errs []error

	addr := strings.TrimSpace(c.HTTP.Addr)
	dbURL := strings.TrimSpace(c.Database.URL)
	issuer := strings.TrimSpace(c.OIDC.Issuer)
	env := strings.TrimSpace(c.Env)
	interval := c.Worker.Interval

	// Mandatory values. The empty string is the marker for "not provided":
	// the defaults leave database.url and oidc.issuer empty, and an empty
	// env var or file entry overrides with exactly that.
	if addr == "" {
		errs = append(errs, errors.New("http.addr: mandatory value is empty (set it via a config file or RISKSIGNAL_HTTP_ADDR)"))
	}
	if dbURL == "" {
		errs = append(errs, errors.New("database.url: mandatory value is empty (set it via a config file or RISKSIGNAL_DATABASE_URL)"))
	}
	if issuer == "" {
		errs = append(errs, errors.New("oidc.issuer: mandatory value is empty (set it via a config file or RISKSIGNAL_OIDC_ISSUER)"))
	}

	// Mode must be one of the supported environments.
	switch env {
	case "local", "demo", "production":
	default:
		errs = append(errs, errors.New("env: unsupported mode (allowed: local, demo, production)"))
	}

	// http.addr must be a host:port pair. The stdlib error text quotes the
	// address, so only the verdict is reported.
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			errs = append(errs, errors.New("http.addr: must be a host:port pair (for example 127.0.0.1:8080)"))
		}
	}

	// URLs must parse and carry scheme and host.
	if dbURL != "" && !isValidURL(dbURL) {
		errs = append(errs, errors.New("database.url: invalid URL (must include a scheme and a host)"))
	}
	if issuer != "" && !isValidURL(issuer) {
		errs = append(errs, errors.New("oidc.issuer: invalid URL (must include a scheme and a host)"))
	}

	// TR-010: the local authentication bypass locks the process out of
	// every online mode. demo and production refuse to start with the
	// bypass enabled; only local mode may run it.
	if c.Auth.BypassEnabled && env != "local" {
		errs = append(errs, errors.New("auth.bypass_enabled: local authentication bypass may only be enabled in local mode (TR-010)"))
	}

	// worker.interval must be positive: a zero or negative value would
	// make the scheduler loop spin or never fire (WP-1a.10). Unparsable
	// values are rejected at load time already, before Validate runs.
	if interval <= 0 {
		errs = append(errs, errors.New("worker.interval: must be a positive duration (set it via a config file or RISKSIGNAL_WORKER_INTERVAL)"))
	}

	// worker.sla_evaluate_interval and worker.sla_reminder_cadence must be
	// positive: a non-positive SLA cadence would make the breach scheduler
	// spin or never fire (ARCH-004 §4.4). Unparsable values are rejected at
	// load time already.
	if c.Worker.SLAEvaluateInterval <= 0 {
		errs = append(errs, errors.New("worker.sla_evaluate_interval: must be a positive duration (set it via a config file or RISKSIGNAL_WORKER_SLA_EVALUATE_INTERVAL)"))
	}
	if c.Worker.SLAReminderCadence <= 0 {
		errs = append(errs, errors.New("worker.sla_reminder_cadence: must be a positive duration (set it via a config file or RISKSIGNAL_WORKER_SLA_REMINDER_CADENCE)"))
	}

	return errs
}

// isValidURL reports whether s parses as a URL with a scheme and a host.
// It returns a verdict only; url.Parse errors and the input itself are never
// echoed anywhere.
func isValidURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}
