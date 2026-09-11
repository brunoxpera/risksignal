// diagnose subcommands (WP-1a.09): read-only reports for operators and
// automation. diagnose config prints the WP-1a.02 provenance summary
// (sources, never secret values); diagnose connectivity probes the database
// host from the configuration with a plain TCP dial; diagnose health
// combines the two into a process + connectivity report. There is no HTTP
// client beyond the TCP dial (non-goal of WP-1a.09).

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// runDiagnose dispatches `risksignal diagnose ...`.
func runDiagnose(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("diagnose", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: config, connectivity, health, backup, restore-test)"))
	}
	command := "diagnose " + args[0]
	switch args[0] {
	case "config":
		return e.emit(command, e.cmdDiagnoseConfig(args[1:]))
	case "connectivity":
		return e.emit(command, e.cmdDiagnoseConnectivity(args[1:]))
	case "health":
		return e.emit(command, e.cmdDiagnoseHealth(args[1:]))
	case "backup":
		return e.emit(command, e.cmdBackup(args[1:]))
	case "restore-test":
		return e.emit(command, e.cmdRestoreTest(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: config, connectivity, health, backup, restore-test)"))
	}
}

// cmdDiagnoseConfig prints the configuration provenance report. In text mode
// it renders the WP-1a.02 summary; with --output json the same key set and
// secrecy rules are emitted as the envelope result. An invalid configuration
// is a validation failure (exit 2) whose message references keys only.
func (e *cmdEnv) cmdDiagnoseConfig(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal diagnose config")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	if e.format == formatText {
		fmt.Fprint(e.stdout, cfg.Summary())
	}
	return e.ok(cfg.JSONSummary())
}

// connectivityResult is the machine-readable payload of the connectivity
// probes (diagnose connectivity and the database probe of diagnose health).
type connectivityResult struct {
	Target    string `json:"target"`    // host:port that was dialed
	Reachable bool   `json:"reachable"` // TCP connect succeeded
}

// cmdDiagnoseConnectivity TCP-dials the database host:port from the
// configuration. An unreachable host is an infrastructure failure (exit 6).
// The probe proves reachability only — never credentials or schema state.
func (e *cmdEnv) cmdDiagnoseConnectivity(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal diagnose connectivity")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	target, err := probeDatabase(cfg)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "database host unreachable: %v", err)
	}
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "database %s: reachable (TCP)\n", target)
	}
	return e.ok(connectivityResult{Target: target, Reachable: true})
}

// healthResult is the machine-readable payload of diagnose health.
type healthResult struct {
	Process  processProbe       `json:"process"`
	Config   configProbe        `json:"config"`
	Database connectivityResult `json:"database"`
}

// processProbe reports that the CLI process itself is running. There is no
// deeper liveness state to check in a short-lived CLI process.
type processProbe struct {
	Running bool `json:"running"`
}

// configProbe reports the validated configuration that the report is based
// on. Only the non-secret environment name is rendered.
type configProbe struct {
	Valid bool   `json:"valid"`
	Env   string `json:"env"`
}

// cmdDiagnoseHealth reports the process state, the validated configuration
// and the database TCP reachability. The process always reports running (the
// report only exists while the process runs); the database probe failure
// makes the whole command fail with exit 6 (infrastructure).
func (e *cmdEnv) cmdDiagnoseHealth(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal diagnose health")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	target, probeErr := probeDatabase(cfg)

	if e.format == formatText {
		fmt.Fprintln(e.stdout, "process: running")
		fmt.Fprintf(e.stdout, "config: valid (env %s)\n", cfg.Env)
		if probeErr != nil {
			if target != "" {
				fmt.Fprintf(e.stdout, "database: %s unreachable (%v)\n", target, probeErr)
			} else {
				fmt.Fprintf(e.stdout, "database: unreachable (%v)\n", probeErr)
			}
		} else {
			fmt.Fprintf(e.stdout, "database: %s reachable (TCP)\n", target)
		}
		if probeErr != nil {
			fmt.Fprintln(e.stdout, "health: FAIL")
		} else {
			fmt.Fprintln(e.stdout, "health: ok")
		}
	}
	if probeErr != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "database host unreachable: %v", probeErr)
	}
	return e.ok(healthResult{
		Process:  processProbe{Running: true},
		Config:   configProbe{Valid: true, Env: cfg.Env},
		Database: connectivityResult{Target: target, Reachable: true},
	})
}

// probeDatabase resolves the database host:port from the configuration and
// TCP-dials it, returning the target on success. On failure it returns the
// dial error. The full database.url is never rendered — only the resolved
// host:port appears in any message.
func probeDatabase(cfg *config.Config) (string, error) {
	target, err := dbTCPTarget(cfg.Database.URL)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		return target, err
	}
	_ = conn.Close()
	return target, nil
}

// dbTCPTarget extracts the TCP host:port of a PostgreSQL connection URL.
// PostgreSQL URLs default to port 5432; a URL that names no TCP endpoint is
// an error. Errors reference the scheme and host only — never credentials
// and never the full URL.
func dbTCPTarget(databaseURL string) (string, error) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return "", errors.New("database url is not a valid URL")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("database url does not name a host")
	}
	port := u.Port()
	if port == "" {
		if !strings.HasPrefix(u.Scheme, "postgres") {
			return "", fmt.Errorf("database url scheme %q declares no port (only postgres/postgresql default to 5432)", u.Scheme)
		}
		port = "5432"
	}
	return net.JoinHostPort(host, port), nil
}
