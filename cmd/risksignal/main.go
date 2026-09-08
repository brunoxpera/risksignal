// Command risksignal is the RiskSignal administrative CLI.
//
// Process role per implementation concept ch. 4.1: administrative and
// automated commands against the API or against local maintenance ports.
// WP-1a.02: it loads and validates its configuration on startup (defaults ->
// optional JSON config file -> RISKSIGNAL_* environment variables), prints a
// provenance summary and exits. An invalid configuration exits 1 without
// running; a valid one prints the summary and exits 0.
//
// WP-1a.04 adds the first real subcommand, risksignal maintenance migrate,
// which runs the checksum-guarded schema migrations (ADR-010) against the
// database from database.url. The full subcommand structure lands in
// WP-1a.09; until then any other invocation keeps the skeleton behaviour.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/xpera/risksignal/internal/platform/config"
)

func main() {
	// Help must work without a valid configuration; everything else loads
	// and validates the configuration first (WP-1a.02).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "-h", "--help":
			printUsage()
			os.Exit(0)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "maintenance":
			os.Exit(runMaintenance(cfg, os.Args[2:]))
		}
	}

	// Skeleton behaviour until WP-1a.09: prove the configuration, then exit.
	fmt.Print(cfg.Summary())
	fmt.Println("risksignal CLI starting (skeleton) — subcommands land in WP-1a.09")
}

// printUsage prints the top-level CLI usage.
func printUsage() {
	fmt.Println(`usage: risksignal <command>

commands:
  maintenance migrate   run the schema migrations (WP-1a.04, see --help on the
                        subcommand for its flags)

The full CLI structure lands in WP-1a.09; without a command the binary
validates the configuration and exits.`)
}

// runMaintenance dispatches the maintenance subcommands.
func runMaintenance(cfg *config.Config, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "risksignal maintenance: missing subcommand (supported: migrate)")
		return 2
	}
	switch args[0] {
	case "migrate":
		return runMigrate(cfg, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "risksignal maintenance: unknown subcommand %q (supported: migrate)\n", args[0])
		return 2
	}
}

// runMigrate runs risksignal maintenance migrate: the checksum-guarded
// migration runner (WP-1a.04, ADR-010) against cfg.Database.URL.
func runMigrate(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false,
		"verify checksums and report pending migrations without changing the database")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: risksignal maintenance migrate [--dry-run]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "risksignal maintenance migrate: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	runner, err := migrate.Open(ctx, cfg.Database.URL, migrations.FS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal maintenance migrate: %v\n", err)
		return 1
	}
	defer runner.Close()

	res, err := runner.Migrate(ctx, *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal maintenance migrate: %v\n", err)
		return 1
	}
	printMigrateResult(res)
	return 0
}

// printMigrateResult renders the migration run outcome.
func printMigrateResult(res *migrate.Result) {
	if res.DryRun {
		if len(res.Pending) == 0 && len(res.Recovered) == 0 {
			fmt.Printf("dry run: verified checksums of %d applied migration(s); nothing to do\n", res.Verified)
			return
		}
		fmt.Printf("dry run: verified checksums of %d applied migration(s); no changes were made\n", res.Verified)
		for _, p := range res.Pending {
			fmt.Printf("  would apply   %s (version %d)\n", filepath.Base(p.Path), p.Version)
		}
		for _, r := range res.Recovered {
			fmt.Printf("  would record  %s (version %d) in the checksum log\n", filepath.Base(r.Path), r.Version)
		}
		return
	}
	fmt.Printf("verified checksums of %d applied migration(s)\n", res.Verified)
	for _, a := range res.Applied {
		fmt.Printf("  applied   %s (version %d, %s)\n", filepath.Base(a.Path), a.Version, a.Duration.Round(time.Millisecond))
	}
	for _, r := range res.Recovered {
		fmt.Printf("  recorded  %s (version %d) in the checksum log (was applied but unlogged)\n", filepath.Base(r.Path), r.Version)
	}
	if len(res.Applied) == 0 && len(res.Recovered) == 0 {
		fmt.Println("no pending migrations")
	}
}
