// Command risksignal-worker runs the RiskSignal background worker.
//
// Process role per implementation concept ch. 4.1: source fetching,
// normalisation, matching, prioritisation, SLA escalation, retention, outbox
// and notifications. WP-1a.02: it loads and validates its configuration on
// startup (defaults -> optional JSON config file -> RISKSIGNAL_* environment
// variables), prints a provenance summary and exits. An invalid configuration
// exits 1 without starting; a valid one prints the summary and exits 0. The
// scheduler loop lands in WP-1a.10.
package main

import (
	"fmt"
	"os"

	"github.com/xpera/risksignal/internal/platform/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal-worker: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())
	fmt.Println("risksignal-worker starting (skeleton) — jobs and scheduler; scheduler loop lands in WP-1a.10")
}
