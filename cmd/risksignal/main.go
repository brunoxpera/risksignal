// Command risksignal is the RiskSignal administrative CLI.
//
// Process role per implementation concept ch. 4.1: administrative and
// automated commands. The command model follows concept ch. 11.3 and
// WP-1a.09: `risksignal <command> <subcommand>` with strict, deterministic
// behaviour for automation:
//
//   - human-readable output by default; --output json emits one stable
//     machine-readable envelope per command (see envelope in cli.go);
//   - defined exit codes (0 success, 1 generic, 2 validation, 3
//     authentication, 4 authorisation, 5 conflict, 6 infrastructure);
//   - strictly non-interactive: the CLI never prompts and never reads hidden
//     defaults from a terminal; destructive maintenance commands require
//     complete parameters (--yes once implemented), never a dialogue;
//   - every command that needs it loads and validates the configuration
//     first (WP-1a.02); invalid configuration exits 2 and never echoes a
//     secret value (validation errors reference configuration keys only).
//
// Implemented commands: maintenance migrate (WP-1a.04, checksum-guarded
// runner), maintenance retention/recompute (stubs), diagnose config
// (provenance report), diagnose connectivity (TCP probe of the database
// host), diagnose health (process and connectivity report). Authentication
// and authorisation exit codes are defined but not exercised until the
// identity work package lands (non-goal of WP-1a.09).
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
