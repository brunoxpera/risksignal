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

	// ARCH-005 §4.1 loopback lock: even in local mode the bypass may only be
	// served on a loopback bind — the missing half of FR-029 ("technically
	// limited to local use"). A non-loopback or all-interfaces address with
	// the bypass on is refused. The address is only classified when it is a
	// valid host:port (the shape error above already covers the rest).
	if c.Auth.BypassEnabled && env == "local" && addr != "" {
		if _, _, err := net.SplitHostPort(addr); err == nil && !isLoopbackAddr(addr) {
			errs = append(errs, errors.New("auth.bypass_enabled: local authentication bypass requires a loopback http.addr (127.0.0.0/8 or ::1), ARCH-005 §4.1"))
		}
	}

	// oidc.session_ttl must be positive: a non-positive session lifetime
	// would make every browser session expire at once (or never).
	if c.OIDC.SessionTTL <= 0 {
		errs = append(errs, errors.New("oidc.session_ttl: must be a positive duration (set it via a config file or RISKSIGNAL_OIDC_SESSION_TTL)"))
	}

	// oidc.scopes must name at least one scope; an empty list would request
	// an unauthenticated token (ARCH-005 §2).
	if len(trimEach(c.OIDC.Scopes)) == 0 {
		errs = append(errs, errors.New("oidc.scopes: must contain at least one scope (default: openid profile email)"))
	}

	// oidc.role_mappings values must be non-empty. The role vocabulary itself
	// is validated against the domain in the composition root (the platform
	// package never imports the domain).
	for value, role := range c.OIDC.RoleMappings {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(role) == "" {
			errs = append(errs, errors.New("oidc.role_mappings: must map a non-empty claim value to a non-empty role"))
			break
		}
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

	// retention.schedule and worker.export_sweep_interval must be positive: a
	// non-positive cadence would make the retention/sweep schedulers spin or
	// never fire (ARCH-007 §2.4/§1.2, WP-6.06/6.07).
	if c.Retention.Schedule <= 0 {
		errs = append(errs, errors.New("retention.schedule: must be a positive duration (set it via a config file or RISKSIGNAL_RETENTION_SCHEDULE)"))
	}
	if c.Worker.ExportSweepInterval <= 0 {
		errs = append(errs, errors.New("worker.export_sweep_interval: must be a positive duration (set it via a config file or RISKSIGNAL_WORKER_EXPORT_SWEEP_INTERVAL)"))
	}

	// The retention run (ARCH-007 §2.4/§10): a positive retention period, a
	// non-negative pseudonymisation period (0 = the retention period) and a
	// positive batch size. A non-positive period would retain nothing or
	// forever; a non-positive batch would loop.
	if c.Retention.ClosedSignalYears <= 0 {
		errs = append(errs, errors.New("retention.closed_signal_years: must be a positive integer (set it via a config file or RISKSIGNAL_RETENTION_CLOSED_SIGNAL_YEARS)"))
	}
	if c.Retention.PseudonymiseYears < 0 {
		errs = append(errs, errors.New("retention.pseudonymise_years: must not be negative (0 defaults to retention.closed_signal_years)"))
	}
	if c.Retention.BatchSize <= 0 {
		errs = append(errs, errors.New("retention.batch_size: must be a positive integer (set it via a config file or RISKSIGNAL_RETENTION_BATCH_SIZE)"))
	}

	// The export spool (ARCH-007 §1.2): a positive TTL, a positive max-rows
	// bound and a non-empty spool root.
	if strings.TrimSpace(c.Export.Dir) == "" {
		errs = append(errs, errors.New("export.dir: must not be empty (the server-local export spool root)"))
	}
	if c.Export.TTL <= 0 {
		errs = append(errs, errors.New("export.ttl: must be a positive duration (set it via a config file or RISKSIGNAL_EXPORT_TTL)"))
	}
	if c.Export.MaxRows <= 0 {
		errs = append(errs, errors.New("export.max_rows: must be a positive integer (set it via a config file or RISKSIGNAL_EXPORT_MAX_ROWS)"))
	}

	// The notify channels (ARCH-004 §6.1): an enabled SMTP channel needs a
	// host:port relay, a sender and a recipient; an enabled webhook needs a
	// parseable URL and a signing secret. A disabled channel is inert, so
	// its empty target is fine. Errors reference the key only.
	if c.Notify.SMTP.Enabled {
		if strings.TrimSpace(c.Notify.SMTP.Addr) == "" {
			errs = append(errs, errors.New("notify.smtp.addr: mandatory when notify.smtp.enabled is true (a host:port relay)"))
		} else if _, _, err := net.SplitHostPort(strings.TrimSpace(c.Notify.SMTP.Addr)); err != nil {
			errs = append(errs, errors.New("notify.smtp.addr: must be a host:port pair (for example 127.0.0.1:1025)"))
		}
		if strings.TrimSpace(c.Notify.SMTP.From) == "" {
			errs = append(errs, errors.New("notify.smtp.from: mandatory when notify.smtp.enabled is true"))
		}
		if strings.TrimSpace(c.Notify.SMTP.To) == "" {
			errs = append(errs, errors.New("notify.smtp.to: mandatory when notify.smtp.enabled is true"))
		}
	}
	if c.Notify.Webhook.Enabled {
		if !isValidURL(c.Notify.Webhook.URL) {
			errs = append(errs, errors.New("notify.webhook.url: mandatory and must be a valid URL when notify.webhook.enabled is true"))
		}
		if strings.TrimSpace(c.Notify.Webhook.Secret) == "" {
			errs = append(errs, errors.New("notify.webhook.secret: mandatory when notify.webhook.enabled is true"))
		}
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

// isLoopbackAddr reports whether a host:port address binds a loopback
// interface only (127.0.0.0/8 or ::1). An all-interfaces address ("host"
// empty, e.g. ":8080") is not loopback: it would expose the bypass to the
// network. A hostname other than "localhost" is not resolved (resolving
// would make startup depend on the resolver) and counts as non-loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	// Strip an IPv6 zone id (e.g. "::1%lo0").
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
