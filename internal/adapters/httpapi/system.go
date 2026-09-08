// System endpoints of the "System" resource (concept ch. 10.2, WP-1a.07):
// GET /health/live, GET /health/ready and GET /version. The routes live
// outside the /api/v1 contract — they are operational probes for
// orchestrators and operators (concept ch. 16.3 "Health und Readiness") and
// deliberately answer plain JSON instead of the RFC 9457 problem-detail
// schema of ch. 10.1: a not-ready response is a state report, not a failed
// API request. Every response is fixed-key JSON so automation can rely on
// the shape.
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xpera/risksignal/internal/platform/buildinfo"
)

// probeTimeout bounds one readiness probe. Readiness must never hang an
// orchestrator: when the database blackholes instead of refusing, the probe
// context — not the caller — gives up first (the pool's own connect timeout
// is the same order of magnitude). It is a var, not a const, so tests in
// this package can shorten it; nothing outside the package touches it.
var probeTimeout = 5 * time.Second

// checkOK is the checks-map value of a probe that passed; any other value is
// the reason the probe failed.
const checkOK = "ok"

// LiveHandler returns the liveness endpoint. Liveness checks exclusively
// that the process responds (concept ch. 16.3): external sources and the
// database are deliberately not criteria, so this handler has no
// dependencies and answers 200 for as long as the process runs.
func LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: "ok"})
	})
}

// Probe is one named readiness criterion (concept ch. 16.3: readiness
// checks the database, completed migrations and mandatory configuration).
// Check returns nil when the criterion is met and an error otherwise; the
// error text becomes the per-check reason in the readiness report, so it
// must be safe to show to operators (no credentials, no full URLs with
// secrets). Name is the stable JSON key of the check.
type Probe struct {
	Name  string
	Check func(ctx context.Context) error
}

// readyReport is the fixed-key body of GET /health/ready. Checks always
// lists every probe; a passing check has the value "ok", a failing one the
// reason of its failure.
type readyReport struct {
	Status string            `json:"status"` // "ready" | "not_ready"
	Checks map[string]string `json:"checks"`
}

// ReadyHandler returns the readiness endpoint. It runs every probe and
// answers 200 {"status":"ready"} when all of them pass; when any probe
// fails it answers 503 {"status":"not_ready"} with a distinct reason per
// failing check, so an orchestrator can tell a dead database apart from
// pending migrations apart from an invalid configuration.
func ReadyHandler(probes []Probe) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := readyReport{Status: "ready", Checks: make(map[string]string, len(probes))}
		for _, p := range probes {
			if p.Name == "" || p.Check == nil {
				continue // a probe without identity or check contributes nothing
			}
			ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
			err := p.Check(ctx)
			cancel()
			if err != nil {
				report.Status = "not_ready"
				report.Checks[p.Name] = err.Error()
			} else {
				report.Checks[p.Name] = checkOK
			}
		}
		status := http.StatusOK
		if report.Status != "ready" {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, report)
	})
}

// VersionHandler returns the build-metadata endpoint: the commit, version
// and build time injected at link time (buildinfo, Makefile build target).
// The response is a snapshot taken at handler construction — the metadata
// never changes while a process runs.
func VersionHandler(info buildinfo.Info) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, info)
	})
}

// writeJSON answers status with v encoded as JSON. Encoding a fixed
// struct or map of strings cannot fail; a write error after the header is
// on the wire is not recoverable and is left to net/http to report.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
