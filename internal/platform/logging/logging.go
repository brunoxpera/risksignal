// Package logging provides the RiskSignal structured logger (implementation
// concept ch. 16.1 "Strukturierte Logs"; WP-1a.08).
//
// # Output and uniform fields
//
// New builds a logger whose records always carry the uniform fields
// timestamp, level, service, version and environment; request-scoped records
// additionally carry correlation_id, taken from the request context (store it
// with WithCorrelationID — the httpapi correlation middleware does this for
// every inbound request). demo and production environments write JSON;
// local writes human-readable text.
//
// # Redaction
//
// Every record — from any handler or middleware — passes a redacting
// slog.Handler (redact.go) before it is written. Known secret keys,
// free-text/payload fields, token-shaped strings and whole objects are never
// written out, so a carelessly constructed log call cannot leak a token,
// secret or complete payload (TR-013). Logged objects carry only their
// internal ID; whole objects are redacted regardless of their key.
//
// # Security events
//
// Security logs security-relevant events under the dedicated category
// attribute "security", so collectors and retention rules can treat them
// separately from operational records (concept ch. 16.1: security events own
// a category with more restrictive access and retention rules).
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Environment values mirror the allowed env values of the config schema v1
// (internal/platform/config). Logging derives its output format from them:
// local writes text, demo and production write JSON.
const (
	EnvLocal      = "local"
	EnvDemo       = "demo"
	EnvProduction = "production"
)

// SecurityCategory is the value of the category attribute on security
// records (see Security). Filters and retention rules select on
// category=security to keep security events separate from operational logs.
const SecurityCategory = "security"

// Options configures the logger built by New. Only Environment decides the
// output format; Service and Version are attached to every record and should
// identify the running binary and its build.
type Options struct {
	Service     string    // process role, e.g. "risksignal-server"
	Version     string    // build version (WP-1a.07 will wire commit metadata)
	Environment string    // local | demo | production (config schema v1)
	Writer      io.Writer // log destination; defaults to os.Stderr
}

// New builds the RiskSignal structured logger. Environment selects the
// output format (local: text; demo/production: JSON). Empty options fall
// back to local-friendly defaults: text output on os.Stderr, service
// "unknown" and version "dev".
func New(opts Options) *slog.Logger {
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}
	env := strings.TrimSpace(opts.Environment)
	if env == "" {
		env = EnvLocal
	}
	service := opts.Service
	if service == "" {
		service = "unknown"
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}

	// Unknown environments fall back to JSON: an unrecognised value must
	// never silently switch an online deployment to text logs.
	handlerOptions := &slog.HandlerOptions{ReplaceAttr: renameTime}
	var handler slog.Handler = slog.NewTextHandler(opts.Writer, handlerOptions)
	if env != EnvLocal {
		handler = slog.NewJSONHandler(opts.Writer, handlerOptions)
	}

	return slog.New(&redactHandler{next: handler}).With(
		slog.String("service", service),
		slog.String("version", version),
		slog.String("environment", env),
	)
}

// renameTime renders the record time under the uniform key "timestamp"
// (concept ch. 16.1) instead of slog's default "time". Level and message
// keep slog's conventional "level" and "msg" keys.
func renameTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		a.Key = "timestamp"
	}
	return a
}

// correlationIDContextKey is the unexported context key for the correlation
// ID. A dedicated key type prevents collisions with other context values.
type correlationIDContextKey struct{}

// WithCorrelationID returns a copy of ctx carrying id. Records logged with a
// context from WithCorrelationID automatically carry the uniform
// correlation_id field (concept ch. 16.1); the httpapi correlation
// middleware stores every request's effective ID this way.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDContextKey{}, id)
}

// CorrelationIDFrom returns the correlation ID stored by WithCorrelationID.
// The bool is false when the context carries none.
func CorrelationIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(correlationIDContextKey{}).(string)
	return id, ok
}

// Security logs a security-relevant event under its own category (concept
// ch. 16.1: dedicated category with more restrictive access and retention
// rules). event is a stable, machine-readable event name (e.g.
// "login_failed"); msg describes the event for humans. The record carries
// category=security and event=<event> beside the uniform fields, so filters
// and retention can select security events without scanning message text.
// args are key/value pairs as in slog; they pass through the same redaction
// as any other record.
func Security(ctx context.Context, logger *slog.Logger, event, msg string, args ...any) {
	all := make([]any, 0, len(args)+2)
	all = append(all, slog.String("category", SecurityCategory), slog.String("event", event))
	logger.Log(ctx, slog.LevelInfo, msg, append(all, args...)...)
}
