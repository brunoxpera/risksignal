// Command risksignal-server serves the RiskSignal REST API and web frontend.
//
// Process role per implementation concept ch. 4.1: REST API, web UI, OIDC
// sessions, synchronous use cases and health endpoints. WP-1a.02: it loads
// and validates its configuration on startup (defaults -> optional JSON
// config file -> RISKSIGNAL_* environment variables), prints a provenance
// summary and exits. An invalid configuration exits 1 without starting; a
// valid one prints the summary and exits 0. The HTTP server loop lands in
// WP-1a.06.
package main

import (
	"fmt"
	"os"

	"github.com/xpera/risksignal/internal/platform/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal-server: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())
	fmt.Println("risksignal-server starting (skeleton) — API and web; server loop lands in WP-1a.06")
}
