// Package buildinfo carries the build metadata of the running binary
// (WP-1a.07: GET /version as the "Build-Nachweis" of concept ch. 10.2) and
// fills the version field of the structured log lines of ch. 16.1 — server
// access logs and the worker heartbeat of ch. 16.3.
//
// The values are injected at link time. The Makefile build target compiles
// every binary with
//
//	go build -ldflags "-X github.com/xpera/risksignal/internal/platform/buildinfo.Version=... \
//	                  -X .../buildinfo.Commit=... -X .../buildinfo.BuildTime=..."
//
// so the version that answers requests is the version that was built. A
// binary compiled without ldflags (plain go build, go run, go test, IDE
// runs) keeps the development defaults below: Version "dev" and "unknown"
// for commit and build time — deliberately non-empty, so a consumer never
// has to distinguish "unset" from "empty".
package buildinfo

// Version, Commit and BuildTime are the link-time-injected build metadata.
// They are variables — not constants — because -ldflags -X can only set
// variables. Do not assign to them outside this package.
var (
	// Version is the release version of the build ("dev" for local builds,
	// overridden by the Makefile VERSION variable).
	Version = "dev"

	// Commit is the git commit the binary was built from (short hash).
	Commit = "unknown"

	// BuildTime is the build time in RFC 3339 UTC.
	BuildTime = "unknown"
)

// Info is the machine-readable build metadata report served by GET /version
// (concept ch. 10.2 "System" resource). The field set is fixed: automation
// may rely on the keys version, commit and build_time, which are always
// present.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Current returns the build metadata of this binary as a snapshot. Call it
// once at startup; the variables never change after link time.
func Current() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
