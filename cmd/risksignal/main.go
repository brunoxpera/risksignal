// Command risksignal is the RiskSignal administrative CLI.
//
// Process role per implementation concept ch. 4.1: administrative and
// automated commands against the API or against local maintenance ports.
// WP-1a.02: it loads and validates its configuration on startup (defaults ->
// optional JSON config file -> RISKSIGNAL_* environment variables), prints a
// provenance summary and exits. An invalid configuration exits 1 without
// running; a valid one prints the summary and exits 0. The subcommand
// structure lands in WP-1a.09.
package main

import (
	"fmt"
	"os"

	"github.com/xpera/risksignal/internal/platform/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())
	fmt.Println("risksignal CLI starting (skeleton) — subcommands land in WP-1a.09")
}
